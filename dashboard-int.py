# ryu_dashboard_integration.py
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls
from ryu.lib import hub
from ryu.topology import event, switches
from ryu.topology.api import get_all_host
import requests
import time
import logging

LOG = logging.getLogger('ryu.app.ryu_dashboard_integration')
logging.basicConfig(level=logging.INFO)

FLASK_URL = "http://127.0.0.1:5000/update_status"  # Flask endpoint

# Adjust server names used in your topology
SERVER_NAMES = set(['web1', 'web2', 'app1', 'db1'])

class RyuDashboardIntegration(app_manager.RyuApp):
    _CONTEXTS = {}

    def __init__(self, *args, **kwargs):
        super(RyuDashboardIntegration, self).__init__(*args, **kwargs)
        self.monitor_thread = hub.spawn(self._periodic_report)
        LOG.info("RyuDashboardIntegration started")

    def send_to_flask(self, payload):
        try:
            requests.post(FLASK_URL, json=payload, timeout=2)
            LOG.debug("Posted payload to Flask: %s", payload)
        except Exception as e:
            LOG.warning("Failed to send to Flask: %s", e)

    def build_payload_from_hosts(self, hosts):
        servers = []
        clients = []
        for h in hosts:
            # host object may have .mac, .ipv4 and .port info
            mac = getattr(h, 'mac', None)
            # try ipv4 list, or 'ipv4' attribute
            ip = None
            if hasattr(h, 'ip'):
                ip = h.ip
            elif hasattr(h, 'ipv4'):
                ips = getattr(h, 'ipv4')
                if isinstance(ips, (list, tuple)) and len(ips) > 0:
                    ip = ips[0]
            elif hasattr(h, 'ipv4s'):
                ips = getattr(h, 'ipv4s')
                if isinstance(ips, (list, tuple)) and len(ips) > 0:
                    ip = ips[0]

            name = getattr(h, 'name', None) or mac or ip or "host"
            # determine status: Ryu host object doesn't carry 'alive' flag, but presence means known
            status = "UP"
            entry = {"id": name, "mac": mac, "ip": ip, "status": status}
            if name in SERVER_NAMES or (ip and ip.startswith("10.0.0.") and name in SERVER_NAMES):
                servers.append(entry)
            else:
                clients.append(entry)
        payload = {"servers": servers, "hosts": clients, "ts": time.time()}
        return payload

    def _periodic_report(self):
        """
        Periodically gather hosts from topology and send to Flask.
        """
        while True:
            try:
                hosts = get_all_host(self)
                if hosts is None:
                    hosts = []
                payload = self.build_payload_from_hosts(hosts)
                self.send_to_flask(payload)
            except Exception as e:
                LOG.exception("Error in periodic_report: %s", e)
            hub.sleep(2)  # every 2 seconds

    @set_ev_cls(event.EventHostAdd)
    def host_add(self, ev):
        """
        On host add, immediately push an update to Flask.
        """
        try:
            hosts = get_all_host(self) or []
            payload = self.build_payload_from_hosts(hosts)
            self.send_to_flask(payload)
            LOG.info("EventHostAdd: pushed update to Flask")
        except Exception as e:
            LOG.exception("host_add handler error: %s", e)
