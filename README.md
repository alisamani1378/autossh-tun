<div align="center">

🚀 Multi-Tunnel SSH with Automatic Load Balancing
</div>

<p align="center">
<img alt="Version" src="https://img.shields.io/badge/version-5.1-blue.svg">
<img alt="License" src="https://img.shields.io/badge/license-MIT-green.svg">
<img alt="Shell" src="https://img.shields.io/badge/shell-bash-lightgrey.svg">
</p>

This script automates the setup of multiple, parallel, and persistent Layer 3 SSH tunnels between two servers. It leverages autossh for stability and iptables to load balance incoming connections across the tunnels, making it ideal for high-availability and scalable services.

✨ Key Features
🚀 Multi-Tunnel Parallelism: Creates a user-defined number of parallel SSH tunnels to scale bandwidth and processing.

⚖️ Round-Robin Load Balancing: Automatically distributes new incoming connections evenly across all active tunnels.

🛡️ High Stability & Auto-Recovery: Uses autossh to monitor and restart tunnels instantly if they drop.

⚡️ Performance Optimized: Implements a fast cipher (chacha20-poly1305) and MTU/MSS Clamping to maximize throughput.

🤖 Interactive & Smart Setup: Performs a pre-flight SSH check and intelligently handles existing configurations.

🧹 Automatic Cleanup: A robust trap mechanism reverts all changes if the script fails, leaving the system clean.

🔥 Flexible Port Forwarding: Forward specific ports, ranges, or even all traffic with a simple keyword.

✅ Requirements
Two servers running a Debian-based OS (e.g., Ubuntu).

root or sudo access on both servers.

SSH access from the Local Server (VPS) to the Remote Server (IR).

🚀 Quick Start: One-Line Execution
To run the script, simply execute the following command on your Local Server (VPS). It will download the script from this repository and run it.
```bash

bash -c "$(curl -sSL https://raw.githubusercontent.com/alisamani1378/autossh-tun/main/autossh-tun.sh)"

```
The script is fully interactive and will guide you through the setup process.

🛠️ How It Works
The architecture involves two main components:

Local Server (VPS):

Runs multiple autossh processes, each maintaining a persistent SSH tunnel.

Each tunnel gets a virtual tun interface (tun0, tun1, etc.).

Manages firewall rules to route traffic from the tunnels to the internet.

Remote Server (IR):

Accepts the incoming SSH connections.

Uses iptables statistic module to act as a load balancer, distributing connections across the tunnels.

Uses MASQUERADE to correctly NAT the traffic as it enters the tunnels.

This symmetric, multi-path setup ensures that both CPU load and network traffic are distributed, preventing a single point of failure.

⚙️ Configuration
While the script is interactive, you can modify the following parameters at the top of the autossh-tun.sh file for advanced customization:

TUN_NET_BASE: The base IP network for the tunnels (e.g., "10.250").

LAN_CIDR: The IP range of a local network behind the VPS that should have its traffic routed through the tunnels.

TUNNEL_MTU: The Maximum Transmission Unit for the tunnel interfaces.

CLAMP_MSS: The TCP Maximum Segment Size, automatically calculated from the MTU.

📄 License
This project is licensed under the MIT License.
