from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.topology import event
from ryu.lib.packet import packet, ethernet, ipv4
from ryu.ofproto import ofproto_v1_3
from ryu.app.wsgi import WSGIApplication, ControllerBase, route
from webob import Response
import logging
import json
import time
import threading

LOG = logging.getLogger("AutoScale")

MIGRATE_INSTANCE_NAME = "autoscale_api"


class AutoScale(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    _CONTEXTS = {"wsgi": WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(AutoScale, self).__init__(*args, **kwargs)

        wsgi = kwargs["wsgi"]
        wsgi.register(AutoScaleAPI, {MIGRATE_INSTANCE_NAME: self})

        self.servers = ["10.0.0.2", "10.0.0.3"]        # initial active servers
        self.server_load = {"10.0.0.2": 0, "10.0.0.3": 0}         # Server load table: ip -> load %
        # Servers currently active
        # Datapaths
        self.datapaths = {}    

        # Thresholds
        self.scale_up_threshold = 70
        self.scale_down_threshold = 30

        # Start auto-scaling monitor thread
        self.monitor_thread = threading.Thread(target=self.monitor_load)
        self.monitor_thread.start()

        LOG.info("✅ Realistic Auto-Scaling module loaded (REST 8080 enabled)")

    # -------------------------
    # Switch connection
    # -------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features(self, ev):
        dp = ev.msg.datapath
        self.datapaths[dp.id] = dp
        LOG.info(f"🟢 Switch connected: {dp.id}")

    # -------------------------
    # Packet in (for traffic counting)
    # -------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in(self, ev):
        msg = ev.msg
        dp = msg.datapath
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if ip_pkt and ip_pkt.dst in self.server_load:
            # Simple packet count as load measure
            self.server_load[ip_pkt.dst] += 1

    # -------------------------
    # Monitor and scale
    # -------------------------
    def monitor_load(self):
        while True:
            time.sleep(5)  # Check every 5 sec
            if not self.servers:
                continue

            # Convert packet count to %
            for ip in self.server_load:
                self.server_load[ip] = min(self.server_load[ip], 100)

            avg_load = sum(self.server_load.values()) / len(self.server_load)

            LOG.info(f"📊 Average load: {avg_load:.1f}% | Servers: {self.servers}")

            if avg_load > self.scale_up_threshold:
                self.scale_up()
            elif avg_load < self.scale_down_threshold and len(self.servers) > 1:
                self.scale_down()

            # Reset counts
            for ip in self.server_load:
                self.server_load[ip] = 0

    # -------------------------
    # Scale up / down
    # -------------------------
    def scale_up(self):
        # Add a new server (simulated host in Mininet)
        new_server_ip = f"10.0.0.{len(self.servers) + 2}"  # Example IP
        self.servers.append(new_server_ip)
        self.server_load[new_server_ip] = 0
        LOG.info(f"⬆️ Scaling UP: Added server {new_server_ip}")

    def scale_down(self):
        # Remove the last server
        removed_server = self.servers.pop()
        self.server_load.pop(removed_server, None)
        LOG.info(f"⬇️ Scaling DOWN: Removed server {removed_server}")

# ======================================================
# REST API
# ======================================================
class AutoScaleAPI(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(AutoScaleAPI, self).__init__(req, link, data, **config)
        self.app = data[MIGRATE_INSTANCE_NAME]

    @route('autoscale', '/autoscale', methods=['GET'])
    def list_servers(self, req, **kwargs):
        return Response(json_body={"servers": self.app.servers, "load": self.app.server_load}, status=200)
