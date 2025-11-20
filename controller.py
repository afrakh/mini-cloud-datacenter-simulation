# controller.py - Smart DataCenter Controller with Live Stats Push
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ether_types, ipv4
from ryu.topology import event
from ryu.topology.api import get_all_switch, get_all_link
import time
import requests
import threading
# Configuration
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

FLASK_URL = "http://127.0.0.1:5000/api/push-stats"
FLASK_HOSTS_URL = "http://127.0.0.1:5000/api/push-hosts"

STATS_WINDOW = 50

class SmartDCController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SmartDCController, self).__init__(*args, **kwargs)
        
        # MAC learning and topology
        self.mac_to_port = {}      # per-switch MAC learning
        self.net = {}              # adjacency: {src: set([dst,...])}
        self.datapaths = {}        # datapath.id -> datapath
        
        # Host/Server tracking
        self.observed_hosts = set()
        self.observed_servers = set()
        self.stats_history = []        # store stats for graph
        self.host_last_seen = {}       # track host last-seen timestamps
        self.server_last_seen = {}          
        # Real-time stats
        self.last_ts = time.time()
        self.bytes_count = 0
        self.packet_count = 0
        
        self.logger.info("🚀 Smart DataCenter Controller started (OpenFlow 1.3)")
        
        # Start background stats push thread
        threading.Thread(target=self.push_loop, daemon=True).start()

    # ==================== STATE CHANGE HANDLER ====================
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

    # ==================== SWITCH FEATURES HANDLER ====================
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Install table-miss flow entry
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.add_flow(datapath, 0, match, actions)
        self.logger.info(f"🟢 Switch {datapath.id} connected")

    # ==================== FLOW INSTALLATION ====================
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match, instructions=inst)
        else:
            mod = parser.OFPFlowMod(datapath=datapath,
                                    priority=priority, match=match, instructions=inst)
        datapath.send_msg(mod)

    # ==================== PACKET IN HANDLER ====================
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        if not datapath:
            return
        
        dpid = datapath.id
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match.get('in_port')

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth:
            return

        # Ignore LLDP packets
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dst = eth.dst
        src = eth.src

        # Track hosts and servers based on MAC/IP observation
        # This is a simple heuristic - improve based on your needs
        for h in ALL_HOSTS:
            if h["ip"] in str(pkt):  # Simple check if IP appears in packet
                self.observed_hosts.add(h["ip"])
        
        for s in ALL_SERVERS:
            if s["ip"] in str(pkt):  # Simple check if IP appears in packet
                self.observed_servers.add(s["ip"])

        # Count live traffic for stats
        self.packet_count += 1
        self.bytes_count += len(msg.data)

        # MAC learning
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # Determine output port
        out_port = ofproto.OFPP_FLOOD
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]

        actions = [parser.OFPActionOutput(out_port)]
        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None

        # Install flow for known destination (not flooding)
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_src=src, eth_dst=dst)
            self.add_flow(datapath, 1, match, actions, msg.buffer_id)

        # Send packet out
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)
        self.logger.debug(f"📦 Packet: {src} -> {dst} on s{dpid} port {in_port}")

    # ==================== TOPOLOGY EVENT HANDLERS ====================
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
        switch_list = get_all_switch(self)
        link_list = get_all_link(self)

        self.net.clear()
        for link in link_list:
            src = link.src.dpid
            dst = link.dst.dpid
            self.net.setdefault(src, set()).add(dst)

        self.logger.info(f"🌐 Topology updated ({reason}): "
                         f"{len(switch_list)} switches, {len(link_list)} links")
        
        for s, nbrs in self.net.items():
            self.logger.debug(f"adj[{s}] = {nbrs}")

    # ==================== BACKGROUND STATS PUSH ====================
    def push_loop(self):
        """Background thread that periodically pushes stats to Flask"""
        while True:
            time.sleep(2)  # Push every 2 seconds
            self.push_stats()

    def push_stats(self):
        now = time.time()
        diff = now - self.last_ts
        if diff <= 0:
            diff = 0.1
        self.last_ts = now

        requests_per_sec = round(self.packet_count / diff, 2)
        bandwidth_kbps = round((self.bytes_count * 8) / 1000 / diff, 2)

        # Reset counters
        self.packet_count = 0
        self.bytes_count = 0
        self.stats_history.append({
            "ts": int(now),
            "requests": requests_per_sec,
            "bandwidth": bandwidth_kbps
        })
        if len(self.stats_history) > STATS_WINDOW:
            self.stats_history.pop(0)

        try:
            requests.post(FLASK_STATS_URL, json=self.stats_history, timeout=0.5)
            self.logger.info(f"📊 Pushed stats: {requests_per_sec} req/s, {bandwidth_kbps} kbps")
        except Exception as e:
            self.logger.debug(f"Failed to push stats: {e}")

        # Push host/server status
        self.push_hosts_servers()

    def push_hosts_servers(self):
        now_ts = int(time.time() * 1000)  # milliseconds for Chart.js
        hosts_payload = []
        for h in ALL_HOSTS:
            last_seen = self.host_last_seen.get(h["ip"], now_ts / 1000)
            status = "UP"  # mark always UP for now
            hosts_payload.append({"id": h["id"], "ip": h["ip"], "status": "UP", "type": "client"})

        servers_payload = []
        for s in ALL_SERVERS:
            last_seen = self.server_last_seen.get(s["ip"], now_ts / 1000)
            status = "UP"
            servers_payload.append({"id": s["id"], "ip": s["ip"], "status": "UP", "type": "server"})

        data = {"hosts": hosts_payload, "servers": servers_payload}

        try:
            requests.post(FLASK_HOSTS_URL, json=data, timeout=0.5)
        except Exception as e:
            self.logger.debug(f"Failed to push hosts/servers: {e}")
