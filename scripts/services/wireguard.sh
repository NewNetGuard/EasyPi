#!/bin/bash
set -euo pipefail
umask 077

# WireGuard Installation and Management Script for EasyPi
# Usage: wireguard.sh <command> [options]

# Directories
DATA_DIR="/var/lib/easypi/wireguard"
CLIENTS_DIR="$DATA_DIR/clients"
META_FILE="$DATA_DIR/meta.json"
EASYPI_GROUP="easypi"
WG_DIR="/etc/wireguard"
SERVER_KEY="$WG_DIR/privatekey"
SERVER_PUB="$WG_DIR/publickey"
WG_CONF="$WG_DIR/wg0.conf"

# Default values
DEFAULT_PORT=51820
DEFAULT_CIDR="10.8.0.0/24"
DEFAULT_DNS="1.1.1.1"
DEFAULT_ENDPOINT=""
UFW_COMMENT="EasyPi WireGuard"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Logging functions
log_info() {
    echo -e "${GREEN}==>${NC} $1"
}

log_error() {
    echo -e "${RED}ERROR:${NC} $1" >&2
}

log_warn() {
    echo -e "${YELLOW}WARNING:${NC} $1"
}

require_option_value() {
    [[ $# -ge 2 && -n "${2:-}" ]] || {
        log_error "Missing value for ${1:-option}"
        exit 1
    }
}

validate_peer_name() {
    [[ "$1" =~ ^[a-zA-Z0-9._-]{1,32}$ ]]
}

validate_install_values() {
    /usr/bin/python3 - "$1" "$2" "$3" "$4" <<'PY'
import ipaddress
import re
import sys

cidr, dns, endpoint, port_text = sys.argv[1:]
network = ipaddress.ip_network(cidr, strict=True)
if network.version != 4 or network.prefixlen != 24:
    raise SystemExit("CIDR must be an IPv4 /24 network address")
dns_items = [item.strip() for item in dns.split(",")]
if not dns_items or len(dns_items) > 4 or any(not item for item in dns_items):
    raise SystemExit("DNS must contain one to four IPv4 addresses")
for item in dns_items:
    dns_ip = ipaddress.ip_address(item)
    if dns_ip.version != 4:
        raise SystemExit("DNS must contain only IPv4 addresses")
port = int(port_text)
if not 1024 <= port <= 65535:
    raise SystemExit("port must be between 1024 and 65535")
if endpoint:
    match = re.fullmatch(r"(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?):([0-9]{1,5})", endpoint)
    if not match or not 1 <= int(match.group(2)) <= 65535:
        raise SystemExit("endpoint must be host:port")
PY
}

validate_allowed_ips() {
    /usr/bin/python3 - "$1" <<'PY'
import ipaddress
import sys

items = sys.argv[1].split(",")
if not items or len(items) > 32:
    raise SystemExit(1)
for item in items:
    ipaddress.ip_network(item, strict=False)
PY
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root"
   exit 1
fi

secure_state_dirs() {
    install -d -o root -g "$EASYPI_GROUP" -m 0750 "$(dirname "$DATA_DIR")"
    install -d -o root -g "$EASYPI_GROUP" -m 0750 "$DATA_DIR" "$CLIENTS_DIR"
}

acquire_state_lock() {
    secure_state_dirs
    exec 9>"$DATA_DIR/.lock"
    chown root:"$EASYPI_GROUP" "$DATA_DIR/.lock"
    chmod 640 "$DATA_DIR/.lock"
    flock -x 9
}

# Initialize directories
init_dirs() {
    secure_state_dirs
    mkdir -p "$WG_DIR"
    chmod 700 "$WG_DIR"
    
    # Initialize meta.json if it doesn't exist
    if [[ ! -f "$META_FILE" ]]; then
        echo '{"port":51820,"cidr":"10.8.0.0/24","dns":"1.1.1.1","endpoint":"","peers":[]}' > "$META_FILE"
        chown root:"$EASYPI_GROUP" "$META_FILE"
        chmod 640 "$META_FILE"
    fi
}

ufw_is_active() {
    command -v ufw &>/dev/null && ufw status 2>/dev/null | grep -q '^Status: active'
}

ensure_ufw_rule() {
    local port="$1"

    if ! ufw_is_active; then
        return
    fi

    # Respect an existing administrator-managed allow rule. EasyPi only owns
    # rules carrying its explicit comment, so reset/uninstall cannot remove a
    # firewall exception created outside EasyPi.
    if ufw status 2>/dev/null | grep -F "${port}/udp" | grep -q 'ALLOW'; then
        log_info "UFW already allows WireGuard UDP port ${port}"
        return
    fi

    log_info "Allowing WireGuard UDP port ${port} in UFW"
    ufw allow "${port}/udp" comment "$UFW_COMMENT" >/dev/null
}

remove_owned_ufw_rules() {
    local port="$1"
    local rule_number=""

    if ! command -v ufw &>/dev/null; then
        return
    fi

    # Delete by both port and EasyPi's comment. Rule numbers are recalculated
    # after every deletion because UFW renumbers the remaining entries.
    while true; do
        rule_number="$(
            ufw status numbered 2>/dev/null |
                sed -n -E "/${port}\/udp.*${UFW_COMMENT}/ { s/^\[[[:space:]]*([0-9]+)\].*/\1/p; q; }"
        )"
        [[ -n "$rule_number" ]] || break
        ufw --force delete "$rule_number" >/dev/null
    done
}

ensure_meta() {
    secure_state_dirs
    chmod 700 "$WG_DIR" 2>/dev/null || true

    if [[ -f "$META_FILE" ]]; then
        return
    fi

    log_warn "meta.json missing, rebuilding from existing config"

    local port="$DEFAULT_PORT"
    local cidr="$DEFAULT_CIDR"
    local dns="$DEFAULT_DNS"
    local endpoint="$DEFAULT_ENDPOINT"
    local wg_port=""
    local wg_addr=""

    if [[ -f "$WG_CONF" ]]; then
        wg_port=$(awk -F'=' '/^ListenPort/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' "$WG_CONF")
        wg_addr=$(awk -F'=' '/^Address/ {gsub(/[[:space:]]/, "", $2); print $2; exit}' "$WG_CONF")

        if [[ -n "$wg_port" ]]; then
            port="$wg_port"
        fi

        if [[ -n "$wg_addr" ]]; then
            local ip="${wg_addr%%/*}"
            local mask="${wg_addr##*/}"
            if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
                IFS='.' read -r o1 o2 o3 o4 <<< "$ip"
                cidr="${o1}.${o2}.${o3}.0/${mask}"
            fi
        fi
    fi

    if [[ -z "$endpoint" ]]; then
        local public_ip=""
        if command -v curl &>/dev/null; then
            public_ip=$(curl -4 -s ifconfig.me || curl -4 -s icanhazip.com || curl -4 -s api.ipify.org || true)
        fi
        if [[ -z "$public_ip" ]]; then
            public_ip=$(hostname -I | awk '{print $1}')
        fi
        if [[ -n "$public_ip" ]]; then
            endpoint="${public_ip}:${port}"
        fi
    fi

    echo "{\"port\":${port},\"cidr\":\"${cidr}\",\"dns\":\"${dns}\",\"endpoint\":\"${endpoint}\",\"peers\":[]}" > "$META_FILE"
    chown root:"$EASYPI_GROUP" "$META_FILE"
    chmod 640 "$META_FILE"
}

# Get next available IP in subnet
get_next_ip() {
    local cidr=$1
    local base_ip="${cidr%/*}"
    local IFS=.
    read -r i1 i2 i3 i4 <<< "$base_ip"
    
    # Start from .2 (server is .1)
    local next=2
    
    # Get existing IPs from meta.json
    if [[ -f "$META_FILE" ]]; then
        local used_ips=$(jq -r '.peers[].address' "$META_FILE" 2>/dev/null | cut -d'/' -f1 | cut -d'.' -f4 || echo "")
        
        # Find first available
        while echo "$used_ips" | grep -q "^${next}$"; do
            next=$((next + 1))
            if [[ $next -gt 254 ]]; then
                log_error "No available IPs in subnet"
                exit 1
            fi
        done
    fi
    
    echo "${i1}.${i2}.${i3}.${next}"
}

# Update meta.json field
update_meta() {
    local key=$1
    local value=$2
    
    local tmp
    tmp=$(mktemp "$DATA_DIR/meta.XXXXXX")
    jq --arg key "$key" --arg value "$value" '.[$key] = $value' "$META_FILE" > "$tmp"
    chown root:"$EASYPI_GROUP" "$tmp"
    chmod 640 "$tmp"
    mv "$tmp" "$META_FILE"
}

# Add peer to meta.json
add_peer_meta() {
    local name=$1
    local address=$2
    local pubkey=$3
    
    local tmp
    tmp=$(mktemp "$DATA_DIR/meta.XXXXXX")
    jq --arg name "$name" --arg addr "$address" --arg key "$pubkey" \
        '.peers += [{"name": $name, "address": $addr, "public_key": $key, "created_at": (now | todate)}]' \
        "$META_FILE" > "$tmp"
    chown root:"$EASYPI_GROUP" "$tmp"
    chmod 640 "$tmp"
    mv "$tmp" "$META_FILE"
}

# Remove peer from meta.json
remove_peer_meta() {
    local name=$1
    
    local tmp
    tmp=$(mktemp "$DATA_DIR/meta.XXXXXX")
    jq --arg name "$name" '.peers = [.peers[] | select(.name != $name)]' "$META_FILE" > "$tmp"
    chown root:"$EASYPI_GROUP" "$tmp"
    chmod 640 "$tmp"
    mv "$tmp" "$META_FILE"
}

remove_peer_from_config() {
    local public_key="$1"

    [[ -f "$WG_CONF" ]] || {
        log_error "WireGuard configuration is missing"
        return 1
    }

    /usr/bin/python3 - "$WG_CONF" "$public_key" <<'PY'
import os
from pathlib import Path
import re
import sys
import tempfile

path = Path(sys.argv[1])
target = sys.argv[2]
lines = path.read_text(encoding="utf-8").splitlines(keepends=True)
blocks: list[list[str]] = []
current: list[str] = []
for line in lines:
    if re.match(r"^\s*\[[^]]+\]\s*$", line):
        if current:
            blocks.append(current)
        current = [line]
    else:
        current.append(line)
if current:
    blocks.append(current)

kept: list[str] = []
for block in blocks:
    is_peer = bool(block and re.match(r"^\s*\[Peer\]\s*$", block[0], re.IGNORECASE))
    has_key = any(
        match and match.group(1).strip() == target
        for line in block
        if (match := re.match(r"^\s*PublicKey\s*=\s*(.*?)\s*$", line, re.IGNORECASE))
    )
    if not (is_peer and has_key):
        kept.extend(block)

stat = path.stat()
fd, temporary_name = tempfile.mkstemp(prefix="wg0.", dir=path.parent)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.writelines(kept)
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary_name, 0o600)
    os.chown(temporary_name, stat.st_uid, stat.st_gid)
    os.replace(temporary_name, path)
finally:
    try:
        os.unlink(temporary_name)
    except FileNotFoundError:
        pass
PY
}

rollback_new_peer() {
    local public_key="$1"
    shift
    wg set wg0 peer "$public_key" remove >/dev/null 2>&1 || true
    wg-quick save wg0 >/dev/null 2>&1 || true
    remove_peer_from_config "$public_key" >/dev/null 2>&1 || true
    remove_peer_meta "${1:-}" >/dev/null 2>&1 || true
    rm -f -- "${@:2}"
}

# Install WireGuard
cmd_install() {
    local port=$DEFAULT_PORT
    local cidr=$DEFAULT_CIDR
    local dns=$DEFAULT_DNS
    local endpoint=$DEFAULT_ENDPOINT
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --port)
                require_option_value "$@"
                port="$2"
                shift 2
                ;;
            --cidr)
                require_option_value "$@"
                cidr="$2"
                shift 2
                ;;
            --dns)
                require_option_value "$@"
                dns="$2"
                shift 2
                ;;
            --endpoint)
                require_option_value "$@"
                endpoint="$2"
                shift 2
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done

    validate_install_values "$cidr" "$dns" "$endpoint" "$port" || {
        log_error "Invalid WireGuard installation parameters"
        exit 1
    }
    
    log_info "Starting WireGuard installation..."
    
    # Check if already installed
    if systemctl is-active --quiet wg-quick@wg0; then
        log_warn "WireGuard is already installed and running"
        ensure_meta
        ensure_ufw_rule "$port"
        echo "==> Status: Already installed"
        exit 0
    fi
    
    echo "==> Step 1/6: Installing packages"
    export DEBIAN_FRONTEND=noninteractive
    
    # Fix any interrupted dpkg operations
    dpkg --configure -a 2>/dev/null || true
    
    # Update package list quietly
    apt-get update -qq 2>&1 | grep -v "^Get:" | grep -v "^Ign:" || true
    
    # Install WireGuard and dependencies
    if ! dpkg -l | grep -q "^ii  wireguard "; then
        log_info "Installing wireguard..."
        if ! apt-get install -y -qq wireguard 2>/dev/null; then
            # Retry once if failed
            log_warn "First attempt failed, retrying..."
            dpkg --configure -a 2>/dev/null || true
            apt-get install -y -qq wireguard 2>/dev/null || exit 100
        fi
    else
        log_info "wireguard already installed"
    fi
    
    if ! dpkg -l | grep -q "^ii  qrencode "; then
        log_info "Installing qrencode..."
        apt-get install -y -qq qrencode >/dev/null 2>&1
    else
        log_info "qrencode already installed"
    fi
    
    if ! command -v jq &>/dev/null; then
        log_info "Installing jq..."
        apt-get install -y -qq jq >/dev/null 2>&1
    fi
    
    echo "==> Step 2/6: Initializing directories"
    init_dirs
    
    echo "==> Step 3/6: Generating server keys"
    if [[ ! -f "$SERVER_KEY" ]]; then
        log_info "Generating new server keys..."
        wg genkey | tee "$SERVER_KEY" | wg pubkey > "$SERVER_PUB"
        chmod 600 "$SERVER_KEY" "$SERVER_PUB"
    else
        log_info "Server keys already exist, skipping generation"
    fi
    
    local server_privkey=$(cat "$SERVER_KEY")
    local server_pubkey=$(cat "$SERVER_PUB")
    local server_ip="${cidr%.*}.1/24"
    
    echo "==> Step 4/6: Creating wg0.conf"
    cat > "$WG_CONF" <<EOF
[Interface]
Address = $server_ip
ListenPort = $port
PrivateKey = $server_privkey
SaveConfig = true

# NAT and forwarding rules for both eth0 and wlan0
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -t nat -A POSTROUTING -s $cidr -o eth0 -j MASQUERADE; iptables -t nat -A POSTROUTING -s $cidr -o wlan0 -j MASQUERADE; ip6tables -A FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -A POSTROUTING -o eth0 -j MASQUERADE; ip6tables -t nat -A POSTROUTING -o wlan0 -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -t nat -D POSTROUTING -s $cidr -o eth0 -j MASQUERADE; iptables -t nat -D POSTROUTING -s $cidr -o wlan0 -j MASQUERADE; ip6tables -D FORWARD -i wg0 -j ACCEPT; ip6tables -t nat -D POSTROUTING -o eth0 -j MASQUERADE; ip6tables -t nat -D POSTROUTING -o wlan0 -j MASQUERADE

EOF
    chmod 600 "$WG_CONF"
    
    echo "==> Step 5/6: Enabling IP forwarding"
    # Enable IP forwarding
    if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    if ! grep -q "^net.ipv6.conf.all.forwarding=1" /etc/sysctl.conf; then
        echo "net.ipv6.conf.all.forwarding=1" >> /etc/sysctl.conf
    fi
    sysctl -p >/dev/null 2>&1
    
    echo "==> Step 6/6: Starting WireGuard service"
    systemctl enable wg-quick@wg0 >/dev/null 2>&1
    systemctl start wg-quick@wg0
    ensure_ufw_rule "$port"
    
    # Update meta.json
    update_meta "port" "$port"
    update_meta "cidr" "$cidr"
    update_meta "dns" "$dns"
    update_meta "endpoint" "$endpoint"
    
    log_info "WireGuard installation complete!"
    echo "==> Server public key: $server_pubkey"
    echo "==> Listening on port: $port"
    echo "==> Server address: $server_ip"
}

# Add peer
cmd_add_peer() {
    local name=""
    local allowed="0.0.0.0/0,::/0"
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --name)
                require_option_value "$@"
                name="$2"
                shift 2
                ;;
            --allowed)
                require_option_value "$@"
                allowed="$2"
                shift 2
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    if [[ -z "$name" ]]; then
        log_error "Peer name is required (--name)"
        exit 1
    fi
    
    # Validate name
    if ! validate_peer_name "$name"; then
        log_error "Invalid peer name. Use only: a-z, A-Z, 0-9, ., _, - (max 32 chars)"
        exit 1
    fi
    validate_allowed_ips "$allowed" || {
        log_error "Invalid AllowedIPs value"
        exit 1
    }
    
    # Check if WireGuard is installed
    if [[ ! -f "$SERVER_PUB" ]]; then
        log_error "WireGuard server is not installed. Run 'install' first."
        exit 1
    fi
    if ! systemctl is-active --quiet wg-quick@wg0 2>/dev/null; then
        log_error "WireGuard server is not running. Start it before adding a peer."
        exit 1
    fi

    ensure_meta
    acquire_state_lock

    # Repeat state checks after taking the lock so parallel API requests cannot
    # allocate the same address or overwrite one another's artifacts.
    if ! systemctl is-active --quiet wg-quick@wg0 2>/dev/null; then
        log_error "WireGuard server stopped before the peer could be added"
        exit 1
    fi
    if [[ -e "$CLIENTS_DIR/${name}.conf" || -e "$CLIENTS_DIR/${name}.png" ]] ||
        jq -e --arg name "$name" '.peers[]? | select(.name == $name)' "$META_FILE" >/dev/null; then
        log_error "Peer '$name' already exists"
        exit 1
    fi
    
    log_info "Adding peer: $name"
    
    # Load meta
    local cidr=$(jq -r '.cidr' "$META_FILE")
    local dns=$(jq -r '.dns' "$META_FILE")
    local endpoint=$(jq -r '.endpoint' "$META_FILE")
    local server_pubkey=$(cat "$SERVER_PUB")
    
    # Generate client keys
    echo "==> Generating client keys..."
    local client_privkey=$(wg genkey)
    local client_pubkey=$(echo "$client_privkey" | wg pubkey)
    
    # Get next available IP
    local client_ip=$(get_next_ip "$cidr")
    local client_address="${client_ip}/32"
    
    echo "==> Assigned address: $client_address"
    
    # Create client config in the protected state directory.
    local client_conf="$CLIENTS_DIR/${name}.conf"
    local client_png="$CLIENTS_DIR/${name}.png"
    local client_tmp qr_tmp
    client_tmp="$(mktemp "$CLIENTS_DIR/client.XXXXXX")"
    qr_tmp="$(mktemp "$CLIENTS_DIR/qr.XXXXXX")"
    cat > "$client_tmp" <<EOF
[Interface]
PrivateKey = $client_privkey
Address = $client_address
DNS = $dns

[Peer]
PublicKey = $server_pubkey
AllowedIPs = $allowed
Endpoint = $endpoint
PersistentKeepalive = 25
EOF
    echo "==> Generating QR code..."
    if ! qrencode -t PNG -o "$qr_tmp" < "$client_tmp"; then
        rm -f -- "$client_tmp" "$qr_tmp"
        log_error "Failed to generate the client QR code"
        exit 1
    fi
    chown root:"$EASYPI_GROUP" "$client_tmp" "$qr_tmp"
    chmod 640 "$client_tmp" "$qr_tmp"
    
    echo "==> Adding peer to server..."
    if ! wg set wg0 peer "$client_pubkey" allowed-ips "$client_address"; then
        rm -f -- "$client_tmp" "$qr_tmp"
        log_error "Failed to add peer to the running WireGuard interface"
        exit 1
    fi
    
    # A peer is successful only when runtime state, persistent configuration,
    # metadata, and both client artifacts have all been committed.
    if ! wg-quick save wg0 >/dev/null 2>&1; then
        rollback_new_peer "$client_pubkey" "$name" "$client_tmp" "$qr_tmp" "$client_conf" "$client_png"
        log_error "Failed to persist the WireGuard peer"
        exit 1
    fi
    
    if ! add_peer_meta "$name" "$client_address" "$client_pubkey" ||
        ! mv -T "$client_tmp" "$client_conf" ||
        ! mv -T "$qr_tmp" "$client_png"; then
        rollback_new_peer "$client_pubkey" "$name" "$client_tmp" "$qr_tmp" "$client_conf" "$client_png"
        log_error "Failed to commit WireGuard peer artifacts"
        exit 1
    fi
    
    log_info "Peer '$name' added successfully"
    echo "==> Client IP: $client_ip"
    echo "==> Config: $client_conf"
    echo "==> QR code: $CLIENTS_DIR/${name}.png"
}

# Remove peer
cmd_remove_peer() {
    local name=""
    
    # Parse arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            --name)
                require_option_value "$@"
                name="$2"
                shift 2
                ;;
            *)
                log_error "Unknown option: $1"
                exit 1
                ;;
        esac
    done
    
    if [[ -z "$name" ]]; then
        log_error "Peer name is required (--name)"
        exit 1
    fi
    validate_peer_name "$name" || {
        log_error "Invalid peer name"
        exit 1
    }

    if [[ ! -f "$SERVER_PUB" ]]; then
        log_error "WireGuard server is not installed. Run 'install' first."
        exit 1
    fi

    ensure_meta
    acquire_state_lock
    
    log_info "Removing peer: $name"
    
    # Get peer public key from meta
    local peer_pubkey=$(jq -r --arg name "$name" '.peers[] | select(.name == $name) | .public_key' "$META_FILE")
    
    if [[ -z "$peer_pubkey" || "$peer_pubkey" == "null" ]]; then
        log_error "Peer '$name' not found"
        exit 1
    fi
    
    echo "==> Removing peer from server..."
    if systemctl is-active --quiet wg-quick@wg0 2>/dev/null; then
        if ! wg set wg0 peer "$peer_pubkey" remove; then
            log_error "Failed to revoke peer from the running WireGuard interface"
            exit 1
        fi
        # SaveConfig normally writes the runtime state. The explicit config
        # edit below is still required as a fail-safe if saving fails.
        wg-quick save wg0 >/dev/null 2>&1 || true
    fi

    if ! remove_peer_from_config "$peer_pubkey"; then
        log_error "Failed to revoke peer from the persistent WireGuard configuration"
        exit 1
    fi
    
    echo "==> Removing client files..."
    rm -f "$CLIENTS_DIR/${name}.conf" "$CLIENTS_DIR/${name}.png"
    
    # Update meta.json
    remove_peer_meta "$name"
    
    log_info "Peer '$name' removed successfully"
}

# Get status
cmd_status() {
    local installed=false
    local running=false
    
    # Check if installed
    if [[ -f "$WG_CONF" ]] && command -v wg &>/dev/null; then
        installed=true
    fi
    
    # Check if running
    if systemctl is-active --quiet wg-quick@wg0 2>/dev/null; then
        running=true
    fi
    
    if [[ "$installed" == false ]]; then
        echo '{"installed":false,"running":false}'
        exit 0
    fi
    
    # Load meta
    local port=$(jq -r '.port' "$META_FILE" 2>/dev/null || echo "51820")
    local cidr=$(jq -r '.cidr' "$META_FILE" 2>/dev/null || echo "10.8.0.0/24")
    local dns=$(jq -r '.dns' "$META_FILE" 2>/dev/null || echo "1.1.1.1")
    local endpoint=$(jq -r '.endpoint' "$META_FILE" 2>/dev/null || echo "")
    local server_pubkey=$(cat "$SERVER_PUB" 2>/dev/null || echo "")
    
    # Get peers info from wg show
    local peers_json="[]"
    if [[ "$running" == true ]]; then
        peers_json=$(wg show wg0 dump | tail -n +2 | awk '{
            printf "{\"public_key\":\"%s\",\"rx_bytes\":%s,\"tx_bytes\":%s,\"latest_handshake\":\"%s\"},", 
            $1, $6, $7, $5
        }' | sed 's/,$//')
        
        if [[ -n "$peers_json" ]]; then
            peers_json="[$peers_json]"
        else
            peers_json="[]"
        fi
    fi
    
    # Merge with meta.json peers
    local meta_peers=$(jq -c '.peers' "$META_FILE" 2>/dev/null || echo "[]")
    
    # Build final JSON
    cat <<EOF
{
  "installed": $installed,
  "running": $running,
  "port": $port,
  "cidr": "$cidr",
  "dns": "$dns",
  "endpoint": "$endpoint",
  "server_public_key": "$server_pubkey",
  "peers": $meta_peers,
  "peers_stats": $peers_json
}
EOF
}

# Reset WireGuard (remove config and clients, keep packages)
cmd_reset() {
    log_warn "Resetting WireGuard configuration..."

    acquire_state_lock

    local port="$DEFAULT_PORT"
    if [[ -f "$META_FILE" ]]; then
        port="$(jq -r '.port // empty' "$META_FILE" 2>/dev/null || true)"
        [[ "$port" =~ ^[0-9]+$ ]] || port="$DEFAULT_PORT"
    fi

    systemctl stop wg-quick@wg0 2>/dev/null || true
    systemctl disable wg-quick@wg0 2>/dev/null || true
    remove_owned_ufw_rules "$port"

    rm -f "$WG_CONF" "$SERVER_KEY" "$SERVER_PUB"
    rm -rf "$DATA_DIR"

    log_info "WireGuard reset complete"
}

# Uninstall WireGuard (reset + remove packages if possible)
cmd_uninstall() {
    cmd_reset

    if command -v apt-get &>/dev/null; then
        log_info "Removing WireGuard packages..."
        apt-get remove -y -qq wireguard qrencode >/dev/null 2>&1 || log_warn "Failed to remove WireGuard packages"
    else
        log_warn "apt-get not found. Skipping package removal."
    fi

    log_info "WireGuard uninstall complete"
}

# Restart service
cmd_restart() {
    log_info "Restarting WireGuard..."
    
    if ! systemctl is-enabled --quiet wg-quick@wg0 2>/dev/null; then
        log_error "WireGuard service is not installed"
        exit 1
    fi
    
    systemctl restart wg-quick@wg0
    
    log_info "WireGuard restarted successfully"
}

# Main command dispatcher
COMMAND="${1:-}"
shift || true

case "$COMMAND" in
    install)
        cmd_install "$@"
        ;;
    add-peer)
        cmd_add_peer "$@"
        ;;
    remove-peer)
        cmd_remove_peer "$@"
        ;;
    status)
        [[ $# -eq 0 ]] || { log_error "status takes no arguments"; exit 1; }
        cmd_status "$@"
        ;;
    reset)
        [[ $# -eq 0 ]] || { log_error "reset takes no arguments"; exit 1; }
        cmd_reset "$@"
        ;;
    uninstall)
        [[ $# -eq 0 ]] || { log_error "uninstall takes no arguments"; exit 1; }
        cmd_uninstall "$@"
        ;;
    restart)
        [[ $# -eq 0 ]] || { log_error "restart takes no arguments"; exit 1; }
        cmd_restart "$@"
        ;;
    *)
        log_error "Unknown command: $COMMAND"
        echo "Usage: $0 {install|add-peer|remove-peer|status|reset|uninstall|restart} [options]"
        exit 1
        ;;
esac

exit 0
