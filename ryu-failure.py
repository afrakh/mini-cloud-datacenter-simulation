from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.topology.api import get_switch, get_link
from ryu.topology import event
from ryu.ofproto import ofproto_v1_3
import networkx as nx
import logging


class FailureRecoveryDynamic(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(FailureRecoveryDynamic, self).__init__(*args, **kwargs)
        self.logger.info("✅ Failure Recovery module loaded (Dijkstra rerouting)")
        self.net = nx.Graph()
        self.connections = {}  # switch_id → datapath
        self.hosts = {}        # ip → (mac, sw, port)

    # -----------------------------------------
    # Switch Connection
    # -----------------------------------------
    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter(self, ev):
        switch_list = get_switch(self)
        self.net.add_nodes_from([sw.dp.id for sw in switch_list])

        self.update_topology("switch-enter")

    @set_ev_cls(event.EventSwitchLeave)
    def switch_leave(self, ev):
        sw = ev.switch.dp.id
        if sw in self.net:
            self.net.remove_node(sw)

        self.update_topology("switch-leave")

    # -----------------------------------------
    # Link Events
    # -----------------------------------------
    @set_ev_cls(event.EventLinkAdd)
    def link_add(self, ev):
        src = ev.link.src.dpid
        dst = ev.link.dst.dpid
        self.net.add_edge(src, dst)

        self.update_topology("link-add")

    @set_ev_cls(event.EventLinkDelete)
    def link_delete(self, ev):
        src = ev.link.src.dpid
        dst = ev.link.dst.dpid
        if self.net.has_edge(src, dst):
            self.net.remove_edge(src, dst)

        self.logger.warning(f"⚠️ Link down: {src} <-> {dst}")
        self.update_topology("link-delete")
        self.recompute_all_paths()

    # -----------------------------------------
    # Datapath Tracking
    # -----------------------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, ev):
        dp = ev.msg.datapath
        self.connections[dp.id] = dp
        self.logger.info(f"🟢 Switch {dp.id} connected")

    # -----------------------------------------
    # Host Learning (ARP)
    # -----------------------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        dpid = dp.id
        ofp = dp.ofproto
        parser = dp.ofproto_parser

        pkt = msg.data

        # Learn host from ARP packets
        if pkt[12:14] == b'\x08\x06':   # ARP
            src_mac = pkt[6:12].hex()
            src_ip = ".".join(str(b) for b in pkt[28:32])
            in_port = msg.match['in_port']

            self.hosts[src_ip] = (src_mac, dpid, in_port)
            self.logger.info(f"📡 Learned host: {src_ip} -> S{dpid}:{in_port}")

    # -----------------------------------------
    # Helper: Update Current Topology
    # -----------------------------------------
    def update_topology(self, event_type):
        switches = list(self.net.nodes())
        links = list(self.net.edges())
        self.logger.info(f"🌐 Topology updated ({event_type}): {len(switches)} switches, {len(links)} links")

    # -----------------------------------------
    # Failure Recovery: Recompute Paths
    # -----------------------------------------
    def recompute_all_paths(self):
        self.logger.warning("♻️ Recomputing all alternate paths...")

        for dst_ip, (mac, sw, port) in self.hosts.items():
            for src_ip, (mac2, sw2, port2) in self.hosts.items():
                if src_ip == dst_ip:
                    continue

                try:
                    path = nx.shortest_path(self.net, source=sw2, target=sw)
                    self.logger.info(f"🔄 Alternate path for {src_ip} → {dst_ip}: {path}")
                except:
                    self.logger.error(f"❌ No alternate path {src_ip} → {dst_ip}")
