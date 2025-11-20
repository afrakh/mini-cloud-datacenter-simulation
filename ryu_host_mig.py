# ryu_host_mig.py
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.topology import event
from ryu.lib.packet import packet, ethernet, arp
from ryu.ofproto import ofproto_v1_3
from ryu.app.wsgi import WSGIApplication, ControllerBase, route
from webob import Response
import json
import logging
import networkx as nx

LOG = logging.getLogger("HostMigration")
MIGRATE_INSTANCE_NAME = "host_migration_api"


class HostMigration(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(HostMigration, self).__init__(*args, **kwargs)

        # WSGI REST registration
        wsgi = kwargs["wsgi"]
        wsgi.register(HostMigrationAPI, {MIGRATE_INSTANCE_NAME: self})

        # Internal state
        # hosts: ip -> (dpid, port)
        self.hosts = {}
        # connections: dpid -> datapath
        self.connections = {}
        # optionally keep a graph of switches/links if you need it later
        self.net = nx.Graph()

        LOG.info("✅ Host Migration module loaded (REST 8080 enabled)")

    # When a switch connects, store datapath
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, ev):
        dp = ev.msg.datapath
        self.connections[dp.id] = dp
        LOG.info(f"🟢 Switch connected: {dp.id}")

    # Learn host attachments from topology EventHostAdd if available
    @set_ev_cls(event.EventHostAdd)
    def host_add(self, ev):
        host = ev.host
        # host.ipv4 may not exist; guard
        if hasattr(host, "ipv4") and host.ipv4:
            try:
                ip = host.ipv4[0]
                dpid = host.port.dpid
                port = host.port.port_no
                self.hosts[ip] = (dpid, port)
                LOG.info(f"🏠 Host added (EventHostAdd): {ip} @ {dpid}:{port}")
            except Exception as e:
                LOG.warning(f"⚠️ HostAdd event parsing error: {e}")

    # Also learn hosts from ARP packets (hybrid)
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        dpid = datapath.id
        in_port = msg.match.get('in_port')
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if not eth:
            return

        # ARP
        if eth.ethertype == 0x0806:
            arp_pkt = pkt.get_protocol(arp.arp)
            if arp_pkt:
                # learn the host IPv4 -> (dpid, port)
                ip = arp_pkt.src_ip
                self.hosts[ip] = (dpid, in_port)
                LOG.info(f"🏠 Learned host (ARP): {ip} @ {dpid}:{in_port}")
                # don't interfere with other apps: return and let controller handle rest
                return

    # -------------------------
    # Migration logic
    # -------------------------
    def migrate_host(self, ip, new_dpid, new_port):
        """
        Migrate host IP to (new_dpid, new_port).
        This deletes flows that match IPv4 dst == ip on the old switch (if known),
        updates the hosts mapping, and logs the operation.
        Returns True on success, False on error.
        """
        if ip not in self.hosts:
            LOG.error(f"❌ Cannot migrate unknown host {ip}")
            return False

        old_dpid, old_port = self.hosts[ip]
        LOG.info(f"🔁 Migration request: {ip} {old_dpid}:{old_port} -> {new_dpid}:{new_port}")

        # Ensure new datapath exists
        if new_dpid not in self.connections:
            LOG.error(f"❌ Switch {new_dpid} not connected")
            return False

        # Delete flows that send traffic to the old host IP on the old switch
        try:
            if old_dpid in self.connections:
                old_dp = self.connections[old_dpid]
                parser = old_dp.ofproto_parser
                ofproto = old_dp.ofproto

                match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=ip)
                mod = parser.OFPFlowMod(
                    datapath=old_dp,
                    command=ofproto_v1_3.OFPFC_DELETE,
                    out_port=ofproto.OFPP_ANY,
                    out_group=ofproto.OFPG_ANY,
                    match=match
                )
                old_dp.send_msg(mod)
                LOG.info(f"♻️ Flows for {ip} deleted from old switch {old_dpid}")
        except Exception as e:
            LOG.exception(f"⚠️ Error deleting flows for {ip} on {old_dpid}: {e}")

        # Update host location
        self.hosts[ip] = (new_dpid, new_port)
        LOG.info(f"🚚 Host {ip} migrated to {new_dpid}:{new_port}")

        # OPTIONAL: you could proactively push flows to edge switches to forward to the new location.
        # For now we rely on learning+failure recovery & reactive flows to populate forwarding rules.

        return True


# ======================================================
# REST API (WSGI app)
# ======================================================
class HostMigrationAPI(ControllerBase):
    def __init__(self, req, link, data, **config):
        super(HostMigrationAPI, self).__init__(req, link, data, **config)
        self.app = data[MIGRATE_INSTANCE_NAME]

    @route('hostmig', '/migrate', methods=['POST'])
    def migrate(self, req, **kwargs):
        # Parse JSON body safely
        try:
            body = req.body.decode('utf-8') if isinstance(req.body, (bytes, bytearray)) else req.body
            data = json.loads(body)
        except Exception:
            return Response(json_body={"error": "Invalid JSON"}, status=400)

        ip = data.get("ip")
        try:
            new_dpid = int(data.get("new_dpid"))
            new_port = int(data.get("new_port"))
        except Exception:
            return Response(json_body={"error": "Invalid or missing dpid/port"}, status=400)

        if not ip:
            return Response(json_body={"error": "Missing parameter: ip"}, status=400)

        ok = self.app.migrate_host(ip, new_dpid, new_port)
        if ok:
            return Response(json_body={"result": "Host migrated", "ip": ip, "new_dpid": new_dpid, "new_port": new_port}, status=200)
        else:
            return Response(json_body={"error": "Migration failed (check logs)"}, status=500)
