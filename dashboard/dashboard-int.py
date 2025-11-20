from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet, arp, ipv4
import requests
import json

FLASK_URL = "http://127.0.0.1:5000/api/update"

class DashboardIntegration(app_manager.RyuApp):
    def __init__(self, *args, **kwargs):
        super(DashboardIntegration, self).__init__(*args, **kwargs)
        self.hosts = {}    # { mac: {"ip": ip, "sw": dp_id } }
        self.servers = {"web1", "web2", "app1", "db1"}  # you can edit this

    # Capture packet-in to detect active hosts
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        in_port = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)

        # Ignore LLDP
        if eth.ethertype == 0x88cc:
            return

        arp_pkt = pkt.get_protocol(arp.arp)
        ipv4_pkt = pkt.get_protocol(ipv4.ipv4)

        # Host detected via ARP
        if arp_pkt:
            mac = eth.src
            ip = arp_pkt.src_ip

            self.hosts[mac] = {
                "ip": ip,
                "switch": dp.id,
                "port": in_port,
                "status": "UP"
            }
            self.send_update()

        # Host detected via IP packet
        if ipv4_pkt:
            mac = eth.src
            ip = ipv4_pkt.src

            self.hosts[mac] = {
                "ip": ip,
                "switch": dp.id,
                "port": in_port,
                "status": "UP"
            }
            self.send_update()

    # Send data to Flask
    def send_update(self):
        data = {"hosts": list(self.hosts.values())}

        try:
            requests.post(FLASK_URL, json=data, timeout=0.2)
        except:
            pass
