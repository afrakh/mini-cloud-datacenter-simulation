#!/usr/bin/python3

from mininet.topo import Topo
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.link import TCLink
from mininet.log import setLogLevel
import time

class EnhancedDC(Topo):
    def build(self):
        # Switches
        core = self.addSwitch('s1')      # Core
        agg1 = self.addSwitch('s2')      # Aggregation 1
        agg2 = self.addSwitch('s3')      # Aggregation 2

        # Servers
        web1 = self.addHost('web1', ip='10.0.0.1')
        web2 = self.addHost('web2', ip='10.0.0.2')
        app1 = self.addHost('app1', ip='10.0.0.3')
        db1  = self.addHost('db1', ip='10.0.0.4')

        # Clients
        c1 = self.addHost('c1', ip='10.0.0.11')
        c2 = self.addHost('c2', ip='10.0.0.12')
        c3 = self.addHost('c3', ip='10.0.0.13')
        c4 = self.addHost('c4', ip='10.0.0.14')

        # Core ↔ Aggregation
        self.addLink(core, agg1, cls=TCLink, bw=1000, delay='2ms', loss=0)
        self.addLink(core, agg2, cls=TCLink, bw=1000, delay='2ms', loss=0)

        # Redundant link (keep for failure recovery)
        self.addLink(agg1, agg2, cls=TCLink, bw=800, delay='3ms', loss=0)

        # Aggregation ↔ Servers
        self.addLink(agg1, web1, cls=TCLink, bw=500, delay='5ms', loss=0)
        self.addLink(agg1, web2, cls=TCLink, bw=500, delay='5ms', loss=0)
        self.addLink(agg2, app1, cls=TCLink, bw=300, delay='10ms', loss=0)
        self.addLink(agg2, db1, cls=TCLink, bw=300, delay='15ms', loss=0)

        # Aggregation ↔ Clients
        self.addLink(agg1, c1, cls=TCLink, bw=100, delay='1ms', loss=0)
        self.addLink(agg1, c2, cls=TCLink, bw=100, delay='1ms', loss=0)
        self.addLink(agg2, c3, cls=TCLink, bw=100, delay='1ms', loss=0)
        self.addLink(agg2, c4, cls=TCLink, bw=100, delay='1ms', loss=0)

def run_topo():
    topo = EnhancedDC()
    net = Mininet(
        topo=topo,
        controller=lambda name: RemoteController(name, ip='127.0.0.1', port=6653),
        link=TCLink,
        switch=OVSSwitch,
        autoSetMacs=True
    )
    net.start()

    time.sleep(10)  # wait for all switches to register

    # Enable OpenFlow13 + STP
    for s in net.switches:
        s.cmd(f'ovs-vsctl set bridge {s.name} protocols=OpenFlow13')
        s.cmd(f'ovs-vsctl set bridge {s.name} stp_enable=true')

    print("\n✅ Enhanced Cloud Data Center topology is running with STP enabled!")
    print("   Try 'pingall' or simulate failure: 'link s2 s3 down' / 'link s1 s2 down'")

    CLI(net)
    net.stop()

if __name__ == '__main__':
    setLogLevel('info')
    run_topo()
