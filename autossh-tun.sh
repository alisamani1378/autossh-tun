#!/usr/bin/env bash
# autossh-tun.sh – persistent SSH -w tunnel (VPS ➜ IR) + optional DNAT rules
# Version: 5.3 (English - Final Fix for Remote Script Creation)
# Description: This script establishes multiple, parallel layer 3 SSH tunnels
# and creates a systemd service on the remote server to ensure tunnel
# interfaces persist after a reboot.

set -eo pipefail # Exit on error, but allow pipefails to be checked manually

### ── Adjustable parameters ──────────────────────────────── ###
# Base for the /30 network. The script will increment the third octet on retries.
TUN_NET_BASE="10.250"
# The CIDR of the local network behind the VPS that needs internet access.
LAN_CIDR="172.22.22.0/24"
# MTU for the tunnel interface. 1400 is a safe value for most networks.
TUNNEL_MTU=1400
# MSS value for TCP clamping. Should be MTU - 40.
CLAMP_MSS=1360
################################################################

# --- Global state variables for cleanup --- #
CLEANUP_REMOTE=false
CLEANUP_SYSCTL=false
CLEANUP_LOCAL_NAT=false
TUNNELS_CREATED=() # Array to track created tunnels for cleanup

# --- Helper functions for colored output --- #
ok()  { echo -e "\e[32m$*\e[0m"; }
err() { echo -e "\e[31m$*\e[0m"; }
warn(){ echo -e "\e[33m$*\e[0m"; }

# --- Cleanup function to revert all *new* changes on script failure --- #
cleanup_on_error() {
    local exit_code=$?
    trap - EXIT ERR SIGINT SIGTERM # Disable the trap to prevent recursion

    if [[ $exit_code -ne 0 ]]; then
        err "\n\n!!! An error occurred. Reverting all changes made by this script... !!!"
    else
        ok "\nScript finished successfully. No cleanup needed."
        exit 0
    fi

    if [[ ${#TUNNELS_CREATED[@]} -gt 0 ]]; then
        warn "◽ Removing configurations for ${#TUNNELS_CREATED[@]} created tunnel(s)..."
        # Also remove the remote persistence service
        if [[ "$AUTH_METHOD" == "password" ]]; then
            sshpass -e $SSH_CMD "sudo systemctl stop persistent-tunnels.service &>/dev/null; sudo systemctl disable persistent-tunnels.service &>/dev/null; sudo rm -f /etc/systemd/system/persistent-tunnels.service /usr/local/bin/create-persistent-tunnels.sh"
        else
            $SSH_CMD "sudo systemctl stop persistent-tunnels.service &>/dev/null; sudo systemctl disable persistent-tunnels.service &>/dev/null; sudo rm -f /etc/systemd/system/persistent-tunnels.service /usr/local/bin/create-persistent-tunnels.sh"
        fi

        for i in "${TUNNELS_CREATED[@]}"; do
            remove_existing_config "$i" "cleanup"
        done
    fi

    if [[ "$CLEANUP_LOCAL_NAT" = true ]]; then
        warn "◽ Removing local NAT rule..."
        DEF_IFACE=$(ip -o -4 route show to default | awk '{print $5; exit}')
        iptables -t nat -D POSTROUTING -s "$LAN_CIDR" -o "$DEF_IFACE" -j MASQUERADE &>/dev/null
        netfilter-persistent save &>/dev/null
    fi

    if [[ "$CLEANUP_SYSCTL" = true ]]; then
        warn "◽ Removing local sysctl config..."
        rm -f /etc/sysctl.d/99-autossh-tun.conf
        sysctl -w net.ipv4.ip_forward=0 &>/dev/null
    fi

    err "\n✅ Cleanup complete. System state has been restored."
    exit 1
}

# --- Set trap to call cleanup function on exit/error --- #
trap cleanup_on_error EXIT ERR SIGINT SIGTERM

# --- Function to build load-balanced DNAT and FORWARD rules --- #
build_forwarding_rules() {
    local rule="$1" tun_base_ip="$2" tun_iface_base="$3" total_tunnels="$4"
    local listen_part dest_port
    if [[ $rule == *":"* ]]; then
        listen_part="${rule%%:*}"
        dest_port="${rule#*:}"
    else
        listen_part="$rule"
        dest_port=""
    fi

    local start_port end_port
    if [[ $listen_part == *"-"* ]]; then
        start_port="${listen_part%%-*}"
        end_port="${listen_part#*-}"
    else
        start_port="$listen_part"
        end_port="$listen_part"
    fi

    for p in $(seq "$start_port" "$end_port"); do
        local target_port=${dest_port:-$p}
        for i in $(seq 0 $((total_tunnels - 1))); do
            local current_tun_ip="$tun_base_ip.$i.2"
            local current_tun_iface="$tun_iface_base$i"
            # TCP Rules with Load Balancing
            echo "sudo iptables -t nat -A PREROUTING -i \$REMOTE_PUB_IF -p tcp --dport $p -m statistic --mode nth --every $total_tunnels --packet $i -j DNAT --to-destination $current_tun_ip:$target_port"
            echo "sudo iptables -A FORWARD -i \$REMOTE_PUB_IF -o $current_tun_iface -p tcp --dport $p -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT"
            # UDP Rules with Load Balancing
            echo "sudo iptables -t nat -A PREROUTING -i \$REMOTE_PUB_IF -p udp --dport $p -m statistic --mode nth --every $total_tunnels --packet $i -j DNAT --to-destination $current_tun_ip:$target_port"
            echo "sudo iptables -A FORWARD -i \$REMOTE_PUB_IF -o $current_tun_iface -p udp --dport $p -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT"
        done
    done
}


# --- Function to remove a specific, existing configuration --- #
remove_existing_config() {
    local index=$1
    local mode=${2:-"interactive"} # 'interactive' or 'cleanup'
    local iface="tun$index"
    local service="autossh-tun$index"
    
    if [[ "$mode" == "interactive" ]]; then
        warn "\n◽ Removing existing configuration for '$iface'..."
    fi

    # Remove local components
    systemctl stop "$service" &>/dev/null || true
    systemctl disable "$service" &>/dev/null || true
    rm -f "/etc/systemd/system/$service.service"
    systemctl daemon-reload || true
    ip link del "$iface" &>/dev/null || true
    local local_pub_if
    local_pub_if=$(ip -o -4 route show to default | awk '{print $5; exit}')
    iptables -D FORWARD -i "$iface" -o "$local_pub_if" -j ACCEPT &>/dev/null || true
    iptables -D FORWARD -i "$local_pub_if" -o "$iface" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT &>/dev/null || true
    iptables -t mangle -D FORWARD -p tcp --tcp-flags SYN,RST SYN -o "$iface" -j TCPMSS --set-mss $CLAMP_MSS &>/dev/null || true
    
    # Remote components are removed by the main cleanup function if starting fresh
    if [[ "$mode" == "interactive" ]]; then
        ok "  - Existing configuration for '$iface' removed."
    fi
}


# --- User Input --- #
clear
echo "--- Multi-Tunnel SSH Setup with Load Balancing ---"
echo "----------------------------------------------------"
read -rp "Enter remote server (IR) IP / domain : " IR_HOST
read -rp "Enter SSH username on remote server    : " TUN_USER
read -rp "Enter remote SSH port (default: 22)  : " -i "22" -e SSH_PORT

while [[ -z "$AUTH_METHOD" ]]; do
    read -rp "Authenticate with key (k) or password (p)? [k/p]: " AUTH_CHOICE
    case "${AUTH_CHOICE,,}" in
        k)
            read -rp "Enter full path to private SSH key (e.g., /root/.ssh/id_rsa): " KEY_PATH
            [[ ! -f "$KEY_PATH" ]] && { err "Error: Key file not found."; continue; }
            SSH_EXTRA_ARGS="-i $KEY_PATH"
            AUTH_METHOD="key"
            ;;
        p)
            warn "\nWarning: Using a password is not secure."
            read -rsp "Enter password for $TUN_USER@$IR_HOST: " SSH_PASS; echo
            command -v sshpass &>/dev/null || { ok "◽ Installing sshpass..."; apt-get update -qq && apt-get install -y sshpass >/dev/null; }
            SSH_EXTRA_ARGS="-o PreferredAuthentications=password -o PubkeyAuthentication=no"
            export SSHPASS="$SSH_PASS"
            AUTH_METHOD="password"
            ;;
        *) err "Invalid input. Please enter 'k' or 'p'.";;
    esac
done

# --- Pre-flight SSH Connection Check ---
ok "\n[Pre-flight Check] Testing SSH connection to remote server..."
SSH_CHECK_CMD="ssh -p $SSH_PORT $SSH_EXTRA_ARGS -o BatchMode=yes -o StrictHostKeyChecking=accept-new -o ConnectTimeout=10 $TUN_USER@$IR_HOST"

if [[ "$AUTH_METHOD" == "password" ]]; then
    if ! sshpass -e $SSH_CHECK_CMD exit; then
        err "\nError: SSH connection to the remote server failed."
        err "This remote server is not eligible for this tunnel."
        err "Please check the IP address, username, password, and network status."
        trap - EXIT ERR SIGINT SIGTERM
        exit 1
    fi
else
    if ! $SSH_CHECK_CMD exit; then
        err "\nError: SSH connection to the remote server failed."
        err "This remote server is not eligible for this tunnel."
        err "Please check the IP address, username, private key path, and network status."
        trap - EXIT ERR SIGINT SIGTERM
        exit 1
    fi
fi
ok "  - SSH connection successful. Proceeding with setup..."

# --- Check for existing persistent tunnel service ---
SSH_CMD="ssh -p $SSH_PORT $SSH_EXTRA_ARGS -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new $TUN_USER@$IR_HOST"
if $SSH_CMD "sudo systemctl cat persistent-tunnels.service" &>/dev/null; then
    warn "\nConflict detected: A persistent tunnel configuration already exists on the remote server."
    read -rp "Do you want to completely REMOVE the old setup and start fresh? (This is irreversible) [y/n]: " choice
    if [[ "${choice,,}" == "y" ]];
    then
        warn "  - Removing all old configurations..."
        # This command stops and removes all related services and firewall rules on the remote server.
        $SSH_CMD "
            sudo systemctl stop 'autossh-tun*' &>/dev/null
            sudo systemctl disable 'autossh-tun*' &>/dev/null
            sudo rm -f /etc/systemd/system/autossh-tun*.service
            sudo systemctl stop persistent-tunnels.service &>/dev/null
            sudo systemctl disable persistent-tunnels.service &>/dev/null
            sudo rm -f /etc/systemd/system/persistent-tunnels.service /usr/local/bin/create-persistent-tunnels.sh
            sudo systemctl daemon-reload
            sudo iptables -F; sudo iptables -t nat -F; sudo iptables -t mangle -F;
            sudo netfilter-persistent save
        "
        # Also remove local services
        systemctl stop 'autossh-tun*' &>/dev/null
        systemctl disable 'autossh-tun*' &>/dev/null
        rm -f /etc/systemd/system/autossh-tun*.service
        systemctl daemon-reload
        ok "  - Old configurations removed from both servers."
    else
        err "Aborting to prevent conflicts. Please manually clean the remote server first."
        trap - EXIT ERR SIGINT SIGTERM
        exit 1
    fi
fi


read -rp "How many parallel tunnels do you want to create? [1-254]: " NUM_TUNNELS
if ! [[ "$NUM_TUNNELS" =~ ^[0-9]+$ ]] || [[ "$NUM_TUNNELS" -lt 1 ]] || [[ "$NUM_TUNNELS" -gt 254 ]]; then
    err "Error: Please enter a number between 1 and 254."
    exit 1
fi

cat <<'EOT'

[*] Port Forwarding Options:
    - To forward specific ports, enter them separated by commas.
      Connections to these ports will be load-balanced across all tunnels.
      Examples:
        - 80,443              (Forwards ports 80 and 443)
        - 8080:80,9000-9010   (Forwards 8080 to 80, and the range 9000-9010)
EOT
read -rp "[*] Enter port forwarding rules (or leave blank for none): " FWD_RULES

read -rp "Flush all existing firewall rules on the remote server first? [y/n]: " choice
FLUSH_REMOTE_RULES="n"
if [[ "${choice,,}" == "y" ]]; then
    FLUSH_REMOTE_RULES="y"
fi

# --- Initial System-Wide Setup ---
ok "\n--- Starting Setup for $NUM_TUNNELS Tunnel(s) ---"
ok "[Step 1] Configuring local server (VPS)..."
apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y autossh iptables-persistent >/dev/null
sysctl -w net.ipv4.ip_forward=1
echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-autossh-tun.conf
CLEANUP_SYSCTL=true
DEF_IFACE=$(ip -o -4 route show to default | awk '{print $5; exit}')
iptables -t nat -C POSTROUTING -s "$LAN_CIDR" -o "$DEF_IFACE" -j MASQUERADE &>/dev/null || iptables -t nat -A POSTROUTING -s "$LAN_CIDR" -o "$DEF_IFACE" -j MASQUERADE
CLEANUP_LOCAL_NAT=true
netfilter-persistent save >/dev/null

# --- Remote Server Initial Setup ---
ok "[Step 2] Configuring remote server (IR)..."
# Build the script that will be run by the remote persistence service
PERSISTENCE_SCRIPT_CONTENT="#!/bin/bash\nsudo modprobe tun\n"
for i in $(seq 0 $((NUM_TUNNELS - 1))); do
    PERSISTENCE_SCRIPT_CONTENT+="sudo ip tuntap add dev tun$i mode tun user $TUN_USER &>/dev/null || true\n"
    PERSISTENCE_SCRIPT_CONTENT+="sudo ip link set tun$i up mtu $TUNNEL_MTU\n"
    PERSISTENCE_SCRIPT_CONTENT+="sudo ip addr add $TUN_NET_BASE.$i.1/30 dev tun$i\n"
done
# Base64 encode the script to pass it safely
ENCODED_PERSISTENCE_SCRIPT=$(echo -e "$PERSISTENCE_SCRIPT_CONTENT" | base64 -w 0)

# Build the systemd service file content
PERSISTENCE_SERVICE_CONTENT=$(cat <<'EOSERVICE'
[Unit]
Description=Persistent Tunnel Interface Creator
After=network.target
[Service]
Type=oneshot
ExecStart=/usr/local/bin/create-persistent-tunnels.sh
RemainAfterExit=true
[Install]
WantedBy=multi-user.target
EOSERVICE
)

# Build the main remote command block
REMOTE_SETUP_CMDS="
# Create and enable the persistence service
echo '$PERSISTENCE_SERVICE_CONTENT' | sudo tee /etc/systemd/system/persistent-tunnels.service > /dev/null
echo '$ENCODED_PERSISTENCE_SCRIPT' | base64 -d | sudo tee /usr/local/bin/create-persistent-tunnels.sh > /dev/null
sudo chmod +x /usr/local/bin/create-persistent-tunnels.sh
sudo systemctl daemon-reload
sudo systemctl enable --now persistent-tunnels.service

# Now, configure the rest
sudo sysctl -w net.ipv4.ip_forward=1
export REMOTE_PUB_IF=\$(ip -o -4 route show to default | awk '{print \$5; exit}')
if ! sudo grep -q '^PermitTunnel' /etc/ssh/sshd_config; then
  echo -e '\nPermitTunnel yes\nAllowTcpForwarding yes\nGatewayPorts yes' | sudo tee -a /etc/ssh/sshd_config > /dev/null && sudo systemctl reload sshd
fi
"

if [[ "$FLUSH_REMOTE_RULES" == "y" ]]; then
    warn "  - Flushing remote firewall rules as requested."
    REMOTE_SETUP_CMDS+=$'\n'"sudo iptables -F; sudo iptables -t nat -F; sudo iptables -t mangle -F;"
fi

# Add load balancing rules if ports are specified
if [[ -n "$FWD_RULES" ]]; then
    IFS=',' read -ra rules_array <<< "$FWD_RULES"
    for rule in "${rules_array[@]}"; do
        REMOTE_SETUP_CMDS+=$'\n'"$(build_forwarding_rules "$rule" "$TUN_NET_BASE" "tun" "$NUM_TUNNELS")"
    done
fi

# Add per-tunnel FORWARD and MASQUERADE rules
for i in $(seq 0 $((NUM_TUNNELS - 1))); do
    REMOTE_SETUP_CMDS+="
# Rules for tun$i
sudo iptables -A FORWARD -i tun$i -o \$REMOTE_PUB_IF -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
sudo iptables -t nat -A POSTROUTING -o tun$i -j MASQUERADE
sudo iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -o tun$i -j TCPMSS --set-mss $CLAMP_MSS
"
done

# --- Main loop to create each tunnel on the LOCAL machine --- #
for i in $(seq 0 $((NUM_TUNNELS - 1))); do
    LOCAL_TUN_IFACE="tun$i"
    SERVICE_NAME="autossh-tun$i"
    TUN_NET="$TUN_NET_BASE.$i"
    LOCAL_IP="$TUN_NET.2"
    
    ok "\n--- [Tunnel $i] Setting up local service for $LOCAL_TUN_IFACE ---"
    
    # Local FORWARD rules
    iptables -A FORWARD -i "$LOCAL_TUN_IFACE" -o "$DEF_IFACE" -j ACCEPT
    iptables -t mangle -A FORWARD -p tcp --tcp-flags SYN,RST SYN -o "$LOCAL_TUN_IFACE" -j TCPMSS --set-mss $CLAMP_MSS
    
    # Local Tunnel Interface Setup
    ip tuntap add dev "$LOCAL_TUN_IFACE" mode tun user root &>/dev/null || true
    ip link set "$LOCAL_TUN_IFACE" up mtu $TUNNEL_MTU
    ip addr replace "$LOCAL_IP/30" dev "$LOCAL_TUN_IFACE"

    # Systemd Service Setup
    AUTOSSH_CMD="/usr/bin/autossh -M 0 -NT \
-o ServerAliveInterval=30 -o ServerAliveCountMax=3 \
-o TCPKeepAlive=yes -o ConnectTimeout=10 \
-o ExitOnForwardFailure=yes \
-c chacha20-poly1305@openssh.com \
-w $i:$i $SSH_EXTRA_ARGS -p $SSH_PORT $TUN_USER@$IR_HOST"
    
    cat > "/etc/systemd/system/$SERVICE_NAME.service" <<EOF
[Unit]
Description=Persistent SSH tunnel #$i to $IR_HOST ($LOCAL_TUN_IFACE)
After=network-online.target
Wants=network-online.target

[Service]
Environment="AUTOSSH_GATETIME=0"
User=root
ExecStart=$AUTOSSH_CMD
Restart=always
RestartSec=10
StartLimitIntervalSec=300
StartLimitBurst=5

[Install]
WantedBy=multi-user.target
EOF
    TUNNELS_CREATED+=("$i")
done

# --- Finalize and Execute ---
REMOTE_SETUP_CMDS+=$'\n'"sudo netfilter-persistent save"
REMOTE_CLEANUP_CMDS="" # Cleanup is now handled by the initial check and full removal

ok "\n[Step 3] Executing all commands on remote server..."
remote_err_file=$(mktemp)

if [[ "$AUTH_METHOD" == "password" ]]; then
    if ! sshpass -e $SSH_CMD "$REMOTE_SETUP_CMDS" >/dev/null 2>"$remote_err_file"; then
        err "   An error occurred on the remote server:"
        err "$(cat "$remote_err_file")"
        rm -f "$remote_err_file"
        exit 1
    fi
else
    if ! $SSH_CMD "$REMOTE_SETUP_CMDS" >/dev/null 2>"$remote_err_file"; then
        err "   An error occurred on the remote server:"
        err "$(cat "$remote_err_file")"
        rm -f "$remote_err_file"
        exit 1
    fi
fi
rm -f "$remote_err_file"
ok "   Remote server configured successfully."

ok "\n[Step 4] Starting all local services..."
systemctl daemon-reload
for i in "${TUNNELS_CREATED[@]}"; do
    service="autossh-tun$i"
    ok "  - Enabling and starting $service..."
    systemctl enable --now "$service"
done

# Final check
sleep 3
ALL_OK=true
for i in "${TUNNELS_CREATED[@]}"; do
    service="autossh-tun$i"
    if ! systemctl is-active --quiet "$service"; then
        err "   Error: Service '$service' failed to start."
        warn "   Check logs with: journalctl -u $service -n 50"
        ALL_OK=false
    fi
done

if [[ "$ALL_OK" = false ]]; then
    err "One or more services failed to start. Aborting."
    exit 1
fi

ok "\n✅✅✅ All $NUM_TUNNELS tunnels are up and running! ✅✅✅"
echo "------------------------------------------------"
echo "Load balancing is active for the following ports: ${FWD_RULES:-None}"
echo "To check status, run: systemctl status 'autossh-tun*'"
echo "------------------------------------------------"

trap - EXIT ERR SIGINT SIGTERM
exit 0
