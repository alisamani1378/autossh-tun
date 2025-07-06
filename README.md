Multi-Tunnel SSH with Load Balancing
This script automates the setup of multiple, parallel, and persistent Layer 3 SSH tunnels between two servers (a VPS and a destination server, e.g., inside Iran). It leverages autossh for stability and iptables with the statistic module to load balance incoming connections across the tunnels in a round-robin fashion.

This architecture is designed for high availability and scalability, making it ideal for managing a large number of users or high-traffic services that need to be routed through a secure, multi-path connection.

Key Features
🚀 Multi-Tunnel Parallelism: Creates a user-defined number of parallel SSH tunnels to scale bandwidth and processing.

⚖️ Round-Robin Load Balancing: Automatically distributes new incoming connections evenly across all active tunnels using iptables.

🛡️ High Stability & Auto-Recovery: Uses autossh to monitor and restart tunnels instantly if they drop. Includes optimized SSH KeepAlive settings and smart systemd restart policies.

⚡️ Performance Optimized:

Uses a fast, modern cipher (chacha20-poly1305) for high throughput.

Implements MTU/MSS Clamping to prevent packet fragmentation and improve TCP performance.

🤖 Interactive & Smart Setup:

Performs a pre-flight SSH check to validate credentials before making any changes.

Intelligently detects existing configurations and asks for user permission to overwrite them.

🧹 Automatic Cleanup: A robust trap mechanism ensures that if the script fails at any point, all created interfaces, services, and firewall rules are automatically removed, leaving the system clean.

🔥 Flexible Port Forwarding: Forward specific ports, port ranges, or even all traffic with a simple keyword.

Requirements
Two servers running a Debian-based OS (e.g., Ubuntu).

Local Server (VPS): The public-facing server where you run this script.

Remote Server (IR): The destination server the tunnels will connect to.

root or sudo access on both servers.

SSH access from the Local Server to the Remote Server (password or key-based).

🚀 Quick Start: One-Line Execution
To run the script, simply execute the following command on your Local Server (VPS). It will download the script from this repository and run it.

bash <(curl -sSL https://raw.githubusercontent.com/alisamani1378/autossh-tun/main/install.sh)

The script is fully interactive and will guide you through the setup process.

How It Works
The architecture involves two main components:

Local Server (VPS):

Runs multiple autossh processes, each maintaining a persistent SSH tunnel to the remote server.

Each tunnel is assigned a virtual network interface (tun0, tun1, etc.).

Manages firewall rules to allow traffic to flow from the tunnels to the internet.

Remote Server (IR):

Accepts the incoming SSH connections.

Uses iptables statistic module to act as a load balancer. It distributes incoming connections from the public internet across the available tunnels.

Uses MASQUERADE to correctly NAT the traffic as it enters the tunnels.

This symmetric, multi-path setup ensures that both CPU load and network traffic are distributed, preventing a single point of failure or performance bottleneck.

⚙️ Configuration
While the script is interactive, you can modify the following parameters at the top of the autossh-tun.sh file for advanced customization:

TUN_NET_BASE: The base IP network for the tunnels (e.g., "10.250").

LAN_CIDR: The IP range of a local network behind the VPS that should have its traffic routed through the tunnels.

TUNNEL_MTU: The Maximum Transmission Unit for the tunnel interfaces.

CLAMP_MSS: The TCP Maximum Segment Size, automatically calculated from the MTU.

📄 License
This project is licensed under the MIT License.
