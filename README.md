

# Mini Cloud Data Center Simulation

## Project Overview

This project presents the design and implementation of a **Software-Defined Networking (SDN) based cloud data center** that integrates intelligent management, automated operations, and real-time monitoring. The system provides a sophisticated simulation of modern cloud infrastructure by leveraging SDN principles to build a flexible and programmable network environment.

Built on the **Mininet emulation platform** and controlled through a **custom Ryu controller**, the architecture demonstrates how centralized control and automation can effectively overcome traditional networking challenges.

## Architecture

### Three-Tier Data Center Design

The project implements an enhanced three-tier data center architecture that clearly separates server and client functionalities:

- **Core Layer**: Switch `s1` functions as the central backbone
- **Aggregation Layer**: Switches `s2` and `s3` aggregate traffic from access layer
- **Access Layer**: Hosts directly connected to aggregation switches

**Key Features:**
- Redundant link between s2 and s3 for failure recovery
- Diverse bandwidth and latency parameters for different service tiers
- Hierarchical routing and differentiated service tiers

### Server Infrastructure
- **Web Tier**: web1, web2
- **Application Tier**: app1
- **Database Tier**: db1
- **Client Nodes**: c1, c2, c3, c4

## Key Features

### Ryu SDN Controller
- Full OpenFlow 1.3 support
- Real-time topology discovery using LLDP packets
- Global MAC learning across entire network
- Reactive flow installation mechanism
- Event-driven design with comprehensive logging
- Extensible modular structure

###  Intelligent Load Balancing
- **Multi-tier load balancing** for each service tier
- **Virtual IP (VIP) abstraction** for centralized traffic management
- **Multiple algorithms supported**:
  - Round-Robin (RR)
  - Weighted Round-Robin (WRR)
  - Dynamic/Least-Load/Least-Connections
- ARP proxy handling for optimal traffic distribution

###  Automated Failure Recovery
- Real-time detection of network failures
- **Dijkstra's shortest-path algorithm** for optimal alternative paths
- Proactive installation of new OpenFlow rules
- Handles single or multiple simultaneous failures
- Minimal disruption to ongoing sessions

###  Live Host Migration
- **Live relocation of hosts** between switches without service interruption
- REST API triggered migration operations
- Automatic flow cleanup and updates
- Validated target location checks
- Seamless traffic forwarding during migration

###  Centralized Monitoring & Logging
- **Flask-based dashboard** for real-time monitoring
- Dynamic graphs for server load and bandwidth utilization
- Centralized logging system with timestamped files
- Comprehensive event tracking and auditing
- Real-time network state visualization

##  Technical Implementation

### Technologies Used
- **Mininet**: Network emulation platform
- **Ryu SDN Framework**: OpenFlow 1.3 controller
- **Open vSwitch (OVS)**: Data-plane forwarding
- **NetworkX**: Graph-based path computation
- **Flask**: Web dashboard framework
- **Python**: Core implementation language

### Network Topology
```python
# Core components
core = self.addSwitch('s1')
agg1 = self.addSwitch('s2') 
agg2 = self.addSwitch('s3')

# Servers with tier-specific parameters
web1 = self.addHost('web1', ip='10.0.0.1')  # 500Mbps, 5ms delay
web2 = self.addHost('web2', ip='10.0.0.2')  # 500Mbps, 5ms delay  
app1 = self.addHost('app1', ip='10.0.0.3')  # 300Mbps, 10ms delay
db1 = self.addHost('db1', ip='10.0.0.4')   # 300Mbps, 15ms delay
```

##  Getting Started

### Prerequisites
- Mininet
- Ryu SDN Framework
- Python 3.x
- Open vSwitch
- NetworkX library

### Installation & Execution
1. Clone the repository
2. Install required dependencies
3. Start the Ryu controller:
   ```bash
   ryu-manager your_controller.py
   ```
4. Launch the Mininet topology:
   ```bash
   sudo python topology.py
   ```
5. Access the Flask dashboard
   ```bash
   python app.py
   ```
