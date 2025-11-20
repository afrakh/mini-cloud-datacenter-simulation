# ryu-lb.py
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4
import random
import threading
import time

class MultiLayerLB(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    # configuration
    LAYERS = {
        "web": ["10.0.0.1", "10.0.0.2"],
        "app": ["10.0.0.3"],
        "db":  ["10.0.0.4"]
    }
    WEIGHTS = {"10.0.0.1": 2, "10.0.0.2": 1, "10.0.0.3": 1, "10.0.0.4": 1}
    DEFAULT_POLICY = "round_robin"   # "round_robin" | "weighted" | "dynamic"
    VIPS = {"web": "10.0.0.100", "app": "10.0.0.110", "db": "10.0.0.120"}
    VIP_MAC = "00:aa:bb:00:00:01"     # virtual MAC announced for VIPs

    def __init__(self, *args, **kwargs):
        super(MultiLayerLB, self).__init__(*args, **kwargs)
        self.rr_index = {layer: 0 for layer in self.LAYERS}
        self.active_flows = {srv: 0 for layer in self.LAYERS for srv in self.LAYERS[layer]}
        # pre-populate server info (MAC/port learned later)
        self.server_info = {srv: {'dpid': None, 'port': None, 'mac': None} for layer in self.LAYERS for srv in self.LAYERS[layer]}
        self.mac_to_port = {}   # dpid -> {mac:port}
        self.policy = self.DEFAULT_POLICY
        self._lock = threading.Lock()
        self.logger.info("🔀 Multi-Layer Load Balancer started (policy=%s)" % self.policy)
        self.start_housekeeper()

    # --- OF helpers
    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        if not actions:
            return
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                match=match, instructions=inst,
                                idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        datapath.send_msg(mod)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info("🔌 Switch %s features handled" % datapath.id)

    # --- PacketIn
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        in_port = msg.match.get('in_port')

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)
        if not eth:
            return
        eth = eth[0]

        # learn mac->port
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port

        # ignore LLDP
        if eth.ethertype == 0x88cc:
            return

        # ARP handling
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            self._handle_arp(datapath, in_port, eth, arp_pkt, msg)
            return

        # IPv4 handling
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            self._handle_ipv4(datapath, in_port, eth, ipv4_pkt, msg)
            return

    # --- ARP processing
    def _handle_arp(self, datapath, in_port, eth, arp_pkt, msg):
        dpid = datapath.id
        src_ip = arp_pkt.src_ip
        src_mac = arp_pkt.src_mac

        # learn server attachment if server IP
        if src_ip in self.server_info:
            self.server_info[src_ip].update({'dpid': dpid, 'port': in_port, 'mac': src_mac})
            self.logger.info(f"ARP learning: {src_ip} -> dpid {dpid}, port {in_port}, mac {src_mac}")

        # reply to VIP ARP
        if arp_pkt.opcode == arp.ARP_REQUEST:
            for layer, vip in self.VIPS.items():
                if vip == arp_pkt.dst_ip:
                    parser = datapath.ofproto_parser
                    ofproto = datapath.ofproto
                    reply = packet.Packet()
                    eth_reply = ethernet.ethernet(dst=eth.src, src=self.VIP_MAC, ethertype=0x0806)
                    arp_reply = arp.arp(opcode=arp.ARP_REPLY,
                                        src_mac=self.VIP_MAC,
                                        src_ip=arp_pkt.dst_ip,
                                        dst_mac=arp_pkt.src_mac,
                                        dst_ip=arp_pkt.src_ip)
                    reply.add_protocol(eth_reply)
                    reply.add_protocol(arp_reply)
                    reply.serialize()
                    actions = [parser.OFPActionOutput(in_port)]
                    out = parser.OFPPacketOut(datapath=datapath,
                                              buffer_id=ofproto.OFP_NO_BUFFER,
                                              in_port=ofproto.OFPP_CONTROLLER,
                                              actions=actions,
                                              data=reply.data)
                    datapath.send_msg(out)
                    self.logger.info(f"Replied ARP for VIP {arp_pkt.dst_ip} -> MAC {self.VIP_MAC} (to {arp_pkt.src_ip})")
                    return

    # --- IPv4 / LB
    def _handle_ipv4(self, datapath, in_port, eth, ipv4_pkt, msg):
        dpid = datapath.id
        src_ip = ipv4_pkt.src
        dst_ip = ipv4_pkt.dst
        layer = self._vip_to_layer(dst_ip)
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        if not layer:
            # normal learning behavior
            out_port = self.mac_to_port.get(dpid, {}).get(eth.dst, ofproto.OFPP_FLOOD)
            actions = [parser.OFPActionOutput(out_port)]
            data = None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data
            out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=msg.buffer_id,
                                      in_port=in_port,
                                      actions=actions,
                                      data=data)
            datapath.send_msg(out)
            return

        # pick a server
        server_ip = self.select_server_for_layer(layer)
        server = self.server_info.get(server_ip)

        if not server or server['port'] is None or server['mac'] is None:
            # flood first packet to learn server MAC/port
            self.logger.warning(f"Server {server_ip} info unknown yet; flooding packet to learn.")
            actions = [parser.OFPActionOutput(ofproto.OFPP_FLOOD)]
            data = None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data
            out = parser.OFPPacketOut(datapath=datapath,
                                      buffer_id=msg.buffer_id,
                                      in_port=in_port,
                                      actions=actions,
                                      data=data)
            datapath.send_msg(out)
            return

        actions = [
            parser.OFPActionSetField(eth_dst=server['mac']),
            parser.OFPActionSetField(ipv4_dst=server_ip),
            parser.OFPActionOutput(int(server['port']))
        ]

        match = parser.OFPMatch(eth_type=0x0800, ipv4_src=src_ip, ipv4_dst=dst_ip)
        self.add_flow(datapath, priority=10, match=match, actions=actions, idle_timeout=15, hard_timeout=60)
        self.logger.info(f"LB assign: {src_ip} -> {server_ip} (policy={self.policy})")

        # send current packet
        data = None if msg.buffer_id != ofproto.OFP_NO_BUFFER else msg.data
        out = parser.OFPPacketOut(datapath=datapath,
                                  buffer_id=msg.buffer_id,
                                  in_port=in_port,
                                  actions=actions,
                                  data=data)
        datapath.send_msg(out)

        # update dynamic counters
        if self.policy == "dynamic":
            with self._lock:
                self.active_flows[server_ip] += 1

    # --- selection algorithms
    def select_server_for_layer(self, layer):
        pool = list(self.LAYERS.get(layer, []))
        if self.policy == "round_robin":
            idx = self.rr_index[layer] % len(pool)
            server = pool[idx]
            self.rr_index[layer] = (self.rr_index[layer] + 1) % (1 << 30)
            return server
        elif self.policy == "weighted":
            weighted = []
            for srv in pool:
                w = int(self.WEIGHTS.get(srv, 1))
                weighted.extend([srv] * max(1, w))
            return random.choice(weighted)
        elif self.policy == "dynamic":
            with self._lock:
                return min(pool, key=lambda s: self.active_flows.get(s, 0))
        return random.choice(pool)

    def _vip_to_layer(self, vip_ip):
        for layer, vip in self.VIPS.items():
            if vip == vip_ip:
                return layer
        return None

    def set_policy(self, policy_name):
        if policy_name not in ("round_robin", "weighted", "dynamic"):
            raise ValueError("unknown policy")
        self.policy = policy_name
        self.logger.info("LB policy changed to %s" % self.policy)

    # --- Housekeeper to decay dynamic counters
    def start_housekeeper(self, interval=5):
        def _house():
            while True:
                time.sleep(interval)
                with self._lock:
                    for s in self.active_flows:
                        self.active_flows[s] = max(0, self.active_flows[s] - 1)
        t = threading.Thread(target=_house, daemon=True)
        t.start()
        self.logger.info("Housekeeper started (dynamic counters decaying).")
