# ryu-push.py
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet, arp, ipv4
import requests
import time
from threading import Thread

FLASK_URL = "http://127.0.0.1:5000/update_status"
PUSH_INTERVAL = 5          # seconds
HOST_TIMEOUT = 15           # seconds after which host is considered DOWN

# -----------------------------
# Define all known hosts and servers here
# -----------------------------
KNOWN_HOSTS = {
    "10.0.0.12": {"id": "10.0.0.12", "ip": "10.0.0.12", "status": "UP"},
    "10.0.0.13": {"id": "10.0.0.13", "ip": "10.0.0.13", "status": "UP"},
    "10.0.0.14": {"id": "10.0.0.14", "ip": "10.0.0.14", "status": "UP"},
    "10.0.0.11": {"id": "10.0.0.11", "ip": "10.0.0.11", "status": "UP"}  # example c1
}

KNOWN_SERVERS = {
    "10.0.0.1": {"id": "10.0.0.1", "ip": "10.0.0.1", "status": "UP"},
    "10.0.0.2": {"id": "10.0.0.2", "ip": "10.0.0.2", "status": "UP"},
    "10.0.0.3": {"id": "10.0.0.3", "ip": "10.0.0.3", "status": "UP"},
    "10.0.0.4": {"id": "10.0.0.4", "ip": "10.0.0.4", "status": "UP"}
}

class RyuPushLiveHosts(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(RyuPushLiveHosts, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.hosts_last_seen = {}   # key: host_ip, value: timestamp of last packet
        self.logger.info("RyuPushLiveHosts initialized")

        # Start the periodic push thread
        t = Thread(target=self.push_loop)
        t.daemon = True
        t.start()

    # -----------------------------
    # Periodically push to Flask
    # -----------------------------
    def push_loop(self):
        while True:
            now = time.time()

            # Update host statuses based on last_seen
            for ip, info in KNOWN_HOSTS.items():
                last_seen = self.hosts_last_seen.get(ip, 0)
                if now - last_seen > HOST_TIMEOUT:
                    info["status"] = "UP"
                else:
                    info["status"] = "UP"

            # Update server statuses (optional: can use same logic)
            for ip, info in KNOWN_SERVERS.items():
                # Servers could also have heartbeat tracking if needed
                info["status"] = "UP"  # For now, assume servers are always UP

            # Prepare push
            data = {
                "hosts": list(KNOWN_HOSTS.values()),
                "servers": list(KNOWN_SERVERS.values())
            }

            try:
                requests.post(FLASK_URL, json=data)
                self.logger.info("Pushed to Flask: %s", data)
            except Exception as e:
                self.logger.error("Failed to push to Flask: %s", e)

            time.sleep(PUSH_INTERVAL)

    # -----------------------------
    # Track switches
    # -----------------------------
    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, MAIN_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        self.datapaths[dp.id] = dp
        self.logger.info("Switch connected: %s", dp.id)

    # -----------------------------
    # Handle incoming packets
    # -----------------------------
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # ignore LLDP
        if eth.ethertype == 35020:
            return

        # handle ARP
        arp_pkt = pkt.get_protocol(arp.arp)
        if arp_pkt:
            host_ip = arp_pkt.src_ip
            if host_ip in KNOWN_HOSTS:
                self.hosts_last_seen[host_ip] = time.time()
                KNOWN_HOSTS[host_ip]["status"] = "UP"
                self.logger.info("Host seen via ARP: %s", host_ip)
            return

        # handle IPv4
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)
        if ipv4_pkt:
            host_ip = ipv4_pkt.src
            if host_ip in KNOWN_HOSTS:
                self.hosts_last_seen[host_ip] = time.time()
                KNOWN_HOSTS[host_ip]["status"] = "UP"
                self.logger.info("Host seen via IPv4: %s", host_ip)
            return
