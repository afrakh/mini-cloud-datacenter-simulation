#!/usr/bin/env python3
"""
ryu_failure_recovery.py

Intelligent failure recovery using Dijkstra (networkx).
Features:
 - topology discovery (Ryu topology events) with per-edge port mapping
 - host learning (ARP / IPv4)
 - compute/install symmetric eth-src/eth-dst flows along shortest paths
 - track flows -> path mapping so on link/switch failure we only recompute affected flows
 - OpenFlow 1.3

Run:
  ryu-manager --verbose ryu_failure_recovery.py
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, arp, ipv4
from ryu.topology import event
from ryu.topology.api import get_all_switch, get_all_link
from ryu.lib import hub

import networkx as nx
import logging
import time

LOG = logging.getLogger('ryu.app.failure_recovery')
LOG.setLevel(logging.WARNING)

class RyuFailureRecovery(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(RyuFailureRecovery, self).__init__(*args, **kwargs)

        # Directed graph so we can keep port number for each direction
        # node = dpid (int), edge attributes: {'port': <out_port>}
        self.net = nx.DiGraph()

        # datapaths: dpid -> datapath object
        self.datapaths = {}

        # host tables
        # mac -> {'dpid': dpid, 'port': port, 'ip': ip}
        self.hosts = {}

        # ip -> mac
        self.ip_to_mac = {}

        # flow tracking:
        # flow_key = (src_mac, dst_mac) -> {'path': [dpid,...], 'last_installed': timestamp}
        self.flow_paths = {}

        # mapping dpid -> {mac:port} for local forwarding decisions
        self.mac_to_port = {}

        # background monitor thread (optional periodic maintenance)
        self.monitor_thread = hub.spawn(self._monitor)

        LOG.info("✅ Ryu Failure Recovery app initialized")

    # --------------------------
    # Topology events
    # --------------------------
    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter(self, ev):
        dp = ev.switch.dp
        self.net.add_node(dp.id)
        LOG.info("🟢 Switch entered: %s", dp.id)

    @set_ev_cls(event.EventSwitchLeave)
    def switch_leave(self, ev):
        dp = ev.switch.dp
        if self.net.has_node(dp.id):
            self.net.remove_node(dp.id)
        LOG.warning("🔴 Switch left: %s", dp.id)
        # recovery: treat as node removal
        hub.spawn(self._recover_for_failed_element, dp.id, None)

    @set_ev_cls(event.EventLinkAdd)
    def link_add(self, ev):
        l = ev.link
        src = l.src
        dst = l.dst
        # add directed edges with port numbers (from src.dpid -> dst.dpid port src.port_no)
        self.net.add_edge(src.dpid, dst.dpid, port=src.port_no)
        # add reverse direction as well (discovery gives both links but safe to set)
        self.net.add_edge(dst.dpid, src.dpid, port=dst.port_no)
        LOG.info("🔗 Link added: %s:%s -> %s:%s", src.dpid, src.port_no, dst.dpid, dst.port_no)

    @set_ev_cls(event.EventLinkDelete)
    def link_del(self, ev):
        l = ev.link
        src = l.src; dst = l.dst
        if self.net.has_edge(src.dpid, dst.dpid):
            self.net.remove_edge(src.dpid, dst.dpid)
        if self.net.has_edge(dst.dpid, src.dpid):
            self.net.remove_edge(dst.dpid, src.dpid)
        LOG.warning("⚠️ Link removed: %s <-> %s", src.dpid, dst.dpid)
        # spawn recovery only for flows that traverse this edge
        hub.spawn(self._recover_for_failed_element, src.dpid, dst.dpid)

    # --------------------------
    # Datapath connect / disconnect
    # --------------------------
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if dp.id not in self.datapaths:
                self.datapaths[dp.id] = dp
                self.mac_to_port.setdefault(dp.id, {})
                LOG.info("🔌 Datapath registered: %s", dp.id)
        elif ev.state == DEAD_DISPATCHER:
            if dp.id in self.datapaths:
                del self.datapaths[dp.id]
                LOG.info("❌ Datapath unregistered: %s", dp.id)
                # remove node and recover
                if self.net.has_node(dp.id):
                    self.net.remove_node(dp.id)
                hub.spawn(self._recover_for_failed_element, dp.id, None)

    # --------------------------
    # PacketIn: learn hosts, install path flows
    # --------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        parser = dp.ofproto_parser
        ofp = dp.ofproto
        in_port = msg.match['in_port']
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        src = eth.src
        dst = eth.dst
        dpid = dp.id

        # learn source mac -> (dpid,port). Update if moved.
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # learn host ip if ARP / IPv4
        arp_pkt = pkt.get_protocol(arp.arp)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        host_ip = None
        if arp_pkt:
            host_ip = arp_pkt.src_ip
        elif ip_pkt:
            host_ip = ip_pkt.src

        if host_ip:
            prev = self.hosts.get(src)
            self.hosts[src] = {'dpid': dpid, 'port': in_port, 'ip': host_ip}
            self.ip_to_mac[host_ip] = src
            if prev is None or prev['dpid'] != dpid or prev['port'] != in_port:
                LOG.info("👤 Learned host %s -> %s:%s (ip=%s)", src, dpid, in_port, host_ip)

        # If dst is a known host, compute path & install flow(s)
        if dst in self.hosts:
            src_info = self.hosts.get(src) or {'dpid': dpid, 'port': in_port}
            dst_info = self.hosts[dst]
            # same switch?
            if src_info['dpid'] == dst_info['dpid']:
                out_port = dst_info['port']
                # install local flow on that switch
                self._install_simple_flow(self.datapaths.get(dpid), src, dst, out_port)
                # send current packet out
                self._packet_out(dp, msg, out_port)
                return

            # compute shortest path between their attachment switches
            try:
                path = nx.shortest_path(self.net, source=src_info['dpid'], target=dst_info['dpid'])
            except Exception:
                LOG.warning("❌ No path found %s -> %s", src_info['dpid'], dst_info['dpid'])
                # fallback: flood
                self._packet_out(dp, msg, ofp.OFPP_FLOOD)
                return

            # install symmetric flows and record path
            self._install_path_for_flow(src, dst, path)
            # forward current packet via first hop
            first_out = self._get_out_port(path[0], path[1]) if len(path) > 1 else dst_info['port']
            self._packet_out(dp, msg, first_out)
            return

        # else unknown dst: flood
        self._packet_out(dp, msg, ofp.OFPP_FLOOD)

    # --------------------------
    # Flow installation utilities
    # --------------------------
    def _install_simple_flow(self, datapath, src_mac, dst_mac, out_port, idle_timeout=30):
        """Install flow on a single switch (match eth_src+eth_dst)"""
        if datapath is None:
            return
        parser = datapath.ofproto_parser
        ofp = datapath.ofproto
        match = parser.OFPMatch(eth_src=src_mac, eth_dst=dst_mac)
        actions = [parser.OFPActionOutput(out_port)]
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        fm = parser.OFPFlowMod(datapath=datapath, priority=200, match=match,
                               instructions=inst, idle_timeout=idle_timeout)
        datapath.send_msg(fm)
        LOG.debug("Installed local flow on %s: %s -> %s out:%s", datapath.id, src_mac, dst_mac, out_port)

    def _install_path_for_flow(self, src_mac, dst_mac, path, idle_timeout=60):
        """
        Install a flow along the path (list of dpids). Also install reverse flow.
        Store path in flow_paths for future recovery.
        """
        if len(path) < 1:
            return

        # install forward
        for i, dpid in enumerate(path):
            dp = self.datapaths.get(dpid)
            if dp is None:
                LOG.warning("No datapath %s while installing flow %s->%s", dpid, src_mac, dst_mac)
                continue

            parser = dp.ofproto_parser
            ofp = dp.ofproto
            match = parser.OFPMatch(eth_src=src_mac, eth_dst=dst_mac)

            if i == len(path) - 1:
                # last switch -> output to host port
                dst_info = self.hosts.get(dst_mac)
                if not dst_info:
                    continue
                out_port = dst_info['port']
            else:
                # forward towards next hop
                out_port = self._get_out_port(dpid, path[i + 1])
                if out_port is None:
                    # cannot determine out port: skip
                    continue

            actions = [parser.OFPActionOutput(out_port)]
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            fm = parser.OFPFlowMod(datapath=dp, priority=300, match=match,
                                   instructions=inst, idle_timeout=idle_timeout)
            dp.send_msg(fm)
            LOG.debug("Flow %s->%s installed on %s out:%s", src_mac, dst_mac, dpid, out_port)

        # install reverse path (symmetric)
        rpath = list(reversed(path))
        for i, dpid in enumerate(rpath):
            dp = self.datapaths.get(dpid)
            if dp is None:
                continue
            parser = dp.ofproto_parser
            ofp = dp.ofproto
            match = parser.OFPMatch(eth_src=dst_mac, eth_dst=src_mac)
            if i == len(rpath) - 1:
                out_port = self.hosts.get(src_mac)['port'] if self.hosts.get(src_mac) else None
            else:
                out_port = self._get_out_port(dpid, rpath[i + 1])
                if out_port is None:
                    continue
            actions = [parser.OFPActionOutput(out_port)]
            inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
            fm = parser.OFPFlowMod(datapath=dp, priority=300, match=match,
                                   instructions=inst, idle_timeout=idle_timeout)
            dp.send_msg(fm)
            LOG.debug("Reverse flow %s->%s installed on %s out:%s", dst_mac, src_mac, dpid, out_port)

        # record the path (forward)
        self.flow_paths[(src_mac, dst_mac)] = {'path': path.copy(), 'last_installed': time.time()}
        LOG.info("➡️ Flow recorded %s -> %s via %s", src_mac, dst_mac, path)

    def _get_out_port(self, src_dpid, dst_dpid):
        """Return port on src_dpid that leads to dst_dpid (if known)"""
        if not self.net.has_edge(src_dpid, dst_dpid):
            return None
        # edge attribute 'port' stored when link added
        attr = self.net.get_edge_data(src_dpid, dst_dpid)
        if not attr:
            return None
        return attr.get('port')

    # --------------------------
    # PacketOut helper
    # --------------------------
    def _packet_out(self, datapath, msg, out_port):
        parser = datapath.ofproto_parser
        ofp = datapath.ofproto
        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data
        actions = [parser.OFPActionOutput(out_port)]
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=msg.match['in_port'], actions=actions, data=data)
        datapath.send_msg(out)

    # --------------------------
    # Recovery logic
    # --------------------------
    def _recover_for_failed_element(self, a, b):
        """
        a,b: failure identifiers.
         - if b is None => node (switch) failure of 'a'
         - else => link failure between a and b
        Strategy:
         - find all tracked flows whose recorded path contains the failed element
         - recompute shortest path between the two endpoints (their attached dpids)
         - if new path found -> install; else log unreachable
        """
        LOG.warning("♻️ Starting recovery for failure: %s <-> %s", a, b)
        affected = []

        # iterate copy because we may update flow_paths inside loop
        for flow_key, meta in list(self.flow_paths.items()):
            path = meta.get('path', [])
            # check if path touches failed node/link
            if b is None:
                # node failure: check presence of node in path
                if a in path:
                    affected.append(flow_key)
            else:
                # link failure: check both directions in list of edges
                # check adjacent pairs
                pairs = list(zip(path, path[1:]))
                if (a, b) in pairs or (b, a) in pairs:
                    affected.append(flow_key)

        LOG.info("Flows affected: %s", affected)

        for (src_mac, dst_mac) in affected:
            src_info = self.hosts.get(src_mac)
            dst_info = self.hosts.get(dst_mac)
            if not src_info or not dst_info:
                LOG.warning("Host info missing for flow %s->%s, removing record", src_mac, dst_mac)
                self.flow_paths.pop((src_mac, dst_mac), None)
                continue

            try:
                new_path = nx.shortest_path(self.net, source=src_info['dpid'], target=dst_info['dpid'])
            except Exception:
                LOG.error("❌ No alternate path for flow %s->%s after failure", src_mac, dst_mac)
                # remove recorded entry (can't route)
                self.flow_paths.pop((src_mac, dst_mac), None)
                continue

            # install new path
            LOG.info("🔁 Reinstalling flow %s->%s via %s", src_mac, dst_mac, new_path)
            self._install_path_for_flow(src_mac, dst_mac, new_path)
            # update record already done inside _install_path_for_flow

    # --------------------------
    # Monitoring (optional)
    # --------------------------
    def _monitor(self):
        while True:
            # prune stale flow records (optional)
            now = time.time()
            removed = []
            for k, v in list(self.flow_paths.items()):
                # if not used for 20 minutes, remove record (example policy)
                if now - v['last_installed'] > 20 * 60:
                    removed.append(k)
                    self.flow_paths.pop(k, None)
            if removed:
                LOG.info("Pruned stale flow records: %s", removed)
            hub.sleep(30)
