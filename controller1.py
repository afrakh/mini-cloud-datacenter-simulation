# controller.py - Smart DataCenter Controller with Live Stats Push
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, arp, ipv4
from ryu.topology import event
from ryu.topology.api import get_all_switch, get_all_link
import time
import requests
import threading

# ------------------- CONFIGURATION -------------------
ALL_HOSTS = [
    {"id": "c1", "ip": "10.0.0.11"},
    {"id": "c2", "ip": "10.0.0.12"},
    {"id": "c3", "ip": "10.0.0.13"},
]

ALL_SERVERS = [
    {"id": "web1", "ip": "10.0.0.1"},
    {"id": "web2", "ip": "10.0.0.2"},
    {"id": "app1", "ip": "10.0.0.3"},
    {"id": "db1", "ip": "10.0.0.4"},
]

FLASK_STATS_URL = "http://127.0.0.1:5000/api/push-stats"
FLASK_HOSTS_URL = "http://127.0.0.1:5000/api/push-hosts"

HOST_TIMEOUT = 10  # seconds before a host/server is considered DOWN

# ------------------- CONTROLLER -------------------
class SmartDCController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SmartDCController, self).__init__(*args, **kwargs)

        # MAC learning & topology
        self.mac_to_port = {}     # {dpid: {mac: port}}
        self.net = {}             # adjacency graph
        self.datapaths = {}       # {dpid: datapath}

        # Host/server tracking
        self.host_last_seen = {}  # {ip: timestamp}
        self.server_last_seen = {}  # {ip: timestamp}

        # Traffic stats
        self.packet_count = 0
        self.bytes_count = 0
        self.last_ts = time.time()

        # Start background push thread
        threading.Thread(target=self.push_loop, daemon=True).start()
        self.logger.info("🚀 Smart DataCenter Controller started (OpenFlow 1.3)")

    # ---------------- STATE CHANGE ----------------
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, CONFIG_DISPATCHER])
    def _state_change(self, ev):
        dp = ev.datapath
        if not dp:
            return

        if ev.state in [MAIN_DISPATCHER, CONFIG_DISPATCHER]:
            if dp.id not in self.datapaths:
                self.datapaths[dp.id] = dp
                self.logger.info(f"✅ Datapath registered: {dp.id}")
        else:
            if dp.id in self.datapaths:
                del self.datapaths[dp.id]
                self.logger.info(f"❌ Datapath unregistered: {dp.id}")

    # ---------------- SWITCH FEATURES ----------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Table-miss flow
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info(f"🟢 Switch {datapath.id} connected")

    # ---------------- ADD FLOW ----------------
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)

    # ---------------- PACKET IN ----------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        if not dp:
            return
        dpid = dp.id
        parser = dp.ofproto_parser
        ofproto = dp.ofproto
        in_port = msg.match.get('in_port')

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth:
            return

        # Ignore LLDP
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src

        # MAC learning
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # Track hosts and servers
        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        ip = None
        if arp_pkt:
            ip = arp_pkt.src_ip
        elif ipv4_pkt:
            ip = ipv4_pkt.src

        if ip:
            if ip in [h["ip"] for h in ALL_HOSTS]:
                self.host_last_seen[ip] = time.time()
            if ip in [s["ip"] for s in ALL_SERVERS]:
                self.server_last_seen[ip] = time.time()

        # Count traffic for stats
        self.packet_count += 1
        self.bytes_count += len(msg.data)

        # Determine out port
        out_port = ofproto.OFPP_FLOOD
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]

        actions = [parser.OFPActionOutput(out_port)]
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)
            self.add_flow(dp, 1, match, actions, msg.buffer_id)

        out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        dp.send_msg(out)

    # ---------------- TOPOLOGY HANDLERS ----------------
    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        self.update_topology("switch-enter")

    @set_ev_cls(event.EventLinkAdd)
    def link_add_handler(self, ev):
        self.update_topology("link-add")

    @set_ev_cls(event.EventLinkDelete)
    def link_delete_handler(self, ev):
        self.update_topology("link-delete")

    def update_topology(self, reason="unknown"):
        switches = get_all_switch(self)
        links = get_all_link(self)
        self.net.clear()
        for link in links:
            self.net.setdefault(link.src.dpid, set()).add(link.dst.dpid)
        self.logger.info(f"🌐 Topology updated ({reason}): {len(switches)} switches, {len(links)} links")

    # ---------------- BACKGROUND PUSH ----------------
    def push_loop(self):
        while True:
            time.sleep(2)
            self.push_stats()

    def push_stats(self):
        now = time.time()
        diff = now - self.last_ts
        self.last_ts = now
        if diff <= 0:
            diff = 0.1

        # Real-time stats
        requests_per_sec = round(self.packet_count / diff, 2)
        bandwidth_kbps = round((self.bytes_count * 8) / 1000 / diff, 2)

        payload = [{"ts": int(now), "requests": requests_per_sec, "bandwidth": bandwidth_kbps}]

        # Reset counters
        self.packet_count = 0
        self.bytes_count = 0

        try:
            requests.post(FLASK_STATS_URL, json=payload, timeout=0.5)
        except:
            pass

        # Push host/server status
        self.push_hosts_servers()

    def push_hosts_servers(self):
        now_ts = time.time()
        hosts_payload = []
        for h in ALL_HOSTS:
            last_seen = self.host_last_seen.get(h["ip"], 0)
            status = "UP" if now_ts - last_seen <= HOST_TIMEOUT else "DOWN"
            hosts_payload.append({"id": h["id"], "ip": h["ip"], "status": status, "type": "client"})

        servers_payload = []
        for s in ALL_SERVERS:
            last_seen = self.server_last_seen.get(s["ip"], 0)
            status = "UP" if now_ts - last_seen <= HOST_TIMEOUT else "DOWN"
            servers_payload.append({"id": s["id"], "ip": s["ip"], "status": status, "type": "server"})

        data = {"hosts": hosts_payload, "servers": servers_payload}

        try:
            requests.post(FLASK_HOSTS_URL, json=data, timeout=0.5)
        except:
            pass
