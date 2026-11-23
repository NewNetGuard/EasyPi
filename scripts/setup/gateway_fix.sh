#!/bin/bash
# EasyPi Gateway Fix Script
# Detects and fixes gateway loop when EasyPi is set as network gateway
# This runs at boot and periodically to ensure proper routing

set -euo pipefail

LOG_DIR="/var/log/easypi"
LOGFILE="$LOG_DIR/gateway_fix.log"
install -d -o root -g easypi -m 0750 "$LOG_DIR"
if [[ -L "$LOGFILE" ]]; then
    echo "Refusing symlink log file: $LOGFILE" >&2
    exit 1
fi
touch "$LOGFILE"
chown root:easypi "$LOGFILE"
chmod 0640 "$LOGFILE"

STATE_FILE="/opt/EasyPi/data/network/gateway_mode.json"

log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOGFILE"
}

# The timer and the UI can request a repair at the same time.  Serialise them:
# concurrent iptables/UFW edits can otherwise remove each other's rules and
# produce a false success or a partially applied ruleset.
LOCK_FILE="/run/lock/easypi-gateway-fix.lock"
exec 9>"$LOCK_FILE"
if ! flock -w 15 9; then
    log "ERROR: Another gateway repair is still running"
    exit 75
fi

IP_CMD="$(command -v ip || command -v /usr/sbin/ip || command -v /sbin/ip || echo ip)"
IPTABLES_CMD="$(command -v iptables || command -v /usr/sbin/iptables || command -v /sbin/iptables || echo iptables)"

load_gateway_state() {
    STATE_FILE="$STATE_FILE" python3 - <<'PY'
import ipaddress
import json
import os
import re
import stat
import sys

path = os.environ.get("STATE_FILE", "")
try:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > 64 * 1024:
            raise ValueError("invalid gateway state file")
        with os.fdopen(fd, "r", encoding="utf-8") as f:
            fd = -1
            data = json.load(f)
    finally:
        if fd >= 0:
            os.close(fd)
except Exception:
    sys.exit(1)

try:
    iface = str(data["interface"]).strip()
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,15}", iface):
        raise ValueError("invalid interface")
    address = str(ipaddress.IPv4Address(str(data["easypi_ip"]).strip()))
    gateway = str(ipaddress.IPv4Address(str(data["real_gateway"]).strip()))
    prefix_len = int(data["prefix_len"])
    if not 1 <= prefix_len <= 32:
        raise ValueError("invalid prefix")
except Exception:
    sys.exit(1)

print(iface)
print(address)
print(gateway)
print(prefix_len)
PY
}

get_iface_ipv4_cidr() {
    local iface="${1:-}"
    if [ -z "$iface" ]; then
        return 1
    fi
    "$IP_CMD" -4 -o addr show dev "$iface" scope global 2>/dev/null | awk '{print $4}' | head -1
}

get_current_gateway() {
    "$IP_CMD" route show default 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="via") {print $(i+1); exit}}'
}

get_interface() {
    "$IP_CMD" route show default 2>/dev/null | awk '{for (i=1;i<=NF;i++) if ($i=="dev") {print $(i+1); exit}}'
}

extract_ipv4() {
    echo "$1" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | head -1 || true
}

find_real_gateway() {
    local my_ip="$1"
    local subnet
    subnet=$(echo "$my_ip" | sed 's/\.[0-9]*$/./')
    
    # Common gateway addresses to try
    local candidates=("${subnet}1" "${subnet}254")
    
    for gw in "${candidates[@]}"; do
        if [ "$gw" != "$my_ip" ]; then
            # Check if this IP responds and can route to internet
            if ping -c 1 -W 1 "$gw" >/dev/null 2>&1; then
                log "Found potential gateway: $gw" >&2
                echo "$gw"
                return 0
            fi
        fi
    done
    
    # Scan ARP table for other devices that might be gateway
    "$IP_CMD" neigh show | grep -v "$my_ip" | grep -oP '\d+(\.\d+){3}' | while read -r ip; do
        if [ "$(echo "$ip" | sed 's/\.[0-9]*$//')" = "$(echo "$my_ip" | sed 's/\.[0-9]*$//')" ]; then
            # Same subnet, check if it's a gateway (ends in .1 or .254)
            local last_octet
            last_octet=$(echo "$ip" | grep -oP '\d+$')
            if [ "$last_octet" = "1" ] || [ "$last_octet" = "254" ]; then
                if ping -c 1 -W 1 "$ip" >/dev/null 2>&1; then
                    echo "$ip"
                    return 0
                fi
            fi
        fi
    done
    
    return 1
}

ensure_forwarding_rules() {
    local iface="$1"
    if [ -z "$iface" ]; then
        return 0
    fi

    # Keep forwarding authorization inside UFW. Do not prepend a broad ACCEPT to
    # the built-in FORWARD chain: doing so bypasses EasyPi/PRISM device controls
    # and every UFW forwarding rule that follows it.
    if command -v ufw &>/dev/null; then
        if ufw status 2>/dev/null | grep -q "Status: active"; then
            # A healthy timer tick must be read-only. Full UFW reloads briefly
            # remove its chains and switch built-in policies to ACCEPT.
            if ! "$IPTABLES_CMD" -C ufw-user-forward -i "$iface" -o "$iface" -j ACCEPT 2>/dev/null; then
                ufw route allow in on "$iface" out on "$iface" >/dev/null 2>&1 \
                    || { log "ERROR: Failed to ensure UFW gateway route"; return 1; }
                # UFW applies a newly added rule itself. Do not turn a runtime
                # inconsistency into an unconditional whole-firewall reload.
                "$IPTABLES_CMD" -C ufw-user-forward -i "$iface" -o "$iface" -j ACCEPT 2>/dev/null \
                    || { log "ERROR: UFW gateway route is absent at runtime"; return 1; }
                log "UFW gateway route added for $iface -> $iface"
            fi
        else
            log "WARNING: UFW is inactive; preserving the existing forwarding policy"
        fi
    else
        log "WARNING: UFW is unavailable; preserving the existing forwarding policy"
    fi

    # Remove rules written by older EasyPi releases after checking the managed
    # route, so a persisted legacy ruleset cannot bypass the forwarding policy.
    while "$IPTABLES_CMD" -C FORWARD -i "$iface" -o "$iface" -j ACCEPT 2>/dev/null; do
        "$IPTABLES_CMD" -D FORWARD -i "$iface" -o "$iface" -j ACCEPT \
            || return 1
        log "Removed legacy broad FORWARD ACCEPT rule for $iface -> $iface"
    done
    while "$IPTABLES_CMD" -C FORWARD -i "$iface" -o "$iface" \
        -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; do
        "$IPTABLES_CMD" -D FORWARD -i "$iface" -o "$iface" \
            -m state --state RELATED,ESTABLISHED -j ACCEPT || return 1
        log "Removed legacy early FORWARD state rule for $iface -> $iface"
    done
}

setup_nat() {
    local iface="$1"
    
    # Enable IP forwarding
    if [ "$(cat /proc/sys/net/ipv4/ip_forward)" != "1" ]; then
        echo 1 > /proc/sys/net/ipv4/ip_forward
        log "Enabled IP forwarding"
    fi

    # Never teach same-subnet clients to bypass EasyPi and route directly via
    # the upstream router. Apply both defaults and the already-created device.
    sysctl -q -w net.ipv4.conf.all.send_redirects=0
    sysctl -q -w net.ipv4.conf.default.send_redirects=0
    sysctl -q -w "net.ipv4.conf.${iface}.send_redirects=0"
    
    # Make IP forwarding persistent
    if [ ! -f /etc/sysctl.d/99-easypi-ip-forward.conf ] || ! grep -q "net.ipv4.ip_forward = 1" /etc/sysctl.d/99-easypi-ip-forward.conf 2>/dev/null; then
        printf '%s\n' \
            'net.ipv4.ip_forward = 1' \
            'net.ipv4.conf.all.send_redirects = 0' \
            'net.ipv4.conf.default.send_redirects = 0' \
            > /etc/sysctl.d/99-easypi-ip-forward.conf
        log "Made IP forwarding persistent"
    fi
    
    # Add NAT rule if not exists
    if ! "$IPTABLES_CMD" -t nat -C POSTROUTING -o "$iface" -j MASQUERADE 2>/dev/null; then
        "$IPTABLES_CMD" -t nat -A POSTROUTING -o "$iface" -j MASQUERADE
        log "Added NAT MASQUERADE rule for $iface"
    fi

    # Ensure forwarding rules are present
    ensure_forwarding_rules "$iface" || return 1
    
    # easypi-gateway-fix.service recreates this runtime rule after networking
    # comes up. Never overwrite the administrator's global rules.v4 snapshot.
}

get_active_connection() {
    # Get active NetworkManager connection name, prefer the one bound to interface.
    local iface="${1:-}"
    local first=""
    if ! command -v nmcli &>/dev/null; then
        return 1
    fi
    if [ -n "$iface" ]; then
        local nm_conn=""
        nm_conn=$(nmcli -g GENERAL.CONNECTION device show "$iface" 2>/dev/null | head -n 1 | tr -d '\r')
        if [ -n "$nm_conn" ] && [ "$nm_conn" != "--" ] && [ "$nm_conn" != "unknown" ]; then
            echo "$nm_conn"
            return 0
        fi
        nm_conn=$(nmcli -t -f DEVICE,CONNECTION device status 2>/dev/null | awk -F: -v dev="$iface" '$1==dev{print $2; exit}')
        if [ -n "$nm_conn" ] && [ "$nm_conn" != "--" ]; then
            echo "$nm_conn"
            return 0
        fi
    fi
    while IFS=: read -r name device type; do
        case "$type" in
            ethernet|802-11-wireless|wifi) ;;
            *) continue ;;
        esac
        if [ -n "$iface" ] && [ "$device" = "$iface" ]; then
            echo "$name"
            return 0
        fi
        if [ -z "$first" ]; then
            first="$name"
        fi
    done < <(nmcli -t -f NAME,DEVICE,TYPE connection show --active 2>/dev/null)
    if [ -n "$first" ]; then
        echo "$first"
        return 0
    fi
    return 1
}

is_static_ip_configured() {
    local conn_name="$1"
    local method
    method=$(nmcli -t -f ipv4.method connection show "$conn_name" 2>/dev/null | cut -d: -f2)
    [ "$method" = "manual" ]
}

configure_static_ip() {
    local conn_name="$1"
    local my_ip="$2"
    local prefix_len="$3"
    local real_gw="$4"
    
    log "Configuring static IP via NetworkManager..."
    log "Connection: $conn_name, IP: $my_ip/$prefix_len, Gateway: $real_gw"
    
    # Set static IP configuration
    if nmcli connection modify "$conn_name" \
        ipv4.addresses "${my_ip}/${prefix_len}" \
        ipv4.gateway "$real_gw" \
        ipv4.dns "$real_gw" \
        ipv4.method manual 2>/dev/null; then
        log "Static IP configured successfully"
        # Reactivate connection to apply changes
        nmcli connection up "$conn_name" 2>/dev/null || true
        return 0
    else
        log "ERROR: Failed to configure static IP"
        return 1
    fi
}

main() {
    log "=== Gateway Fix Check Started ==="

    # Load persisted state from backend (if available).
    local state_output=""
    local state_values=()
    state_output="$(load_gateway_state 2>/dev/null || true)"
    if [ -n "$state_output" ]; then
        mapfile -t state_values <<< "$state_output"
    fi
    local STATE_INTERFACE="${state_values[0]:-}"
    local STATE_IP="${state_values[1]:-}"
    local STATE_REAL_GW="${state_values[2]:-}"
    local STATE_PREFIX_LEN="${state_values[3]:-}"
    
    local current_gw
    current_gw=$(get_current_gateway)
    log "Current gateway: ${current_gw:-none}"
    
    local iface
    iface="${STATE_INTERFACE:-}"
    if [ -z "$iface" ]; then
        iface=$(get_interface)
    fi
    iface="${iface:-}"
    log "Interface: $iface"

    local cidr=""
    if [ -n "${STATE_IP:-}" ]; then
        cidr="${STATE_IP}/${STATE_PREFIX_LEN:-}"
    fi
    if [ -z "$cidr" ] || [[ "$cidr" == */ ]]; then
        cidr="$(get_iface_ipv4_cidr "$iface" || true)"
    fi

    local my_ip=""
    local prefix_len=""
    if [ -n "$cidr" ] && [[ "$cidr" == */* ]]; then
        my_ip="${cidr%/*}"
        prefix_len="${cidr#*/}"
    fi
    prefix_len="${prefix_len:-${STATE_PREFIX_LEN:-24}}"
    if [ -z "$my_ip" ]; then
        log "ERROR: Could not determine EasyPi IPv4 address for interface: ${iface:-unknown}"
        return 1
    fi
    log "My IP: $my_ip/$prefix_len"
    
    # Get active NetworkManager connection
    local conn_name
    conn_name=$(get_active_connection "$iface" || true)
    log "Connection: ${conn_name:-unknown}"
    
    # Check if gateway points to ourselves (loop!)
    if [ "$current_gw" = "$my_ip" ] || [ -z "$current_gw" ]; then
        log "WARNING: Gateway loop detected or no gateway set!"
        
        # Remove the bad route first
        "$IP_CMD" route del default via "$my_ip" 2>/dev/null || true
        local real_gw=""
        real_gw="$(extract_ipv4 "${STATE_REAL_GW:-}")"
        if [ -z "$real_gw" ] || [ "$real_gw" = "$my_ip" ]; then
            if ! real_gw=$(find_real_gateway "$my_ip"); then
                real_gw=""
            fi
            real_gw="$(extract_ipv4 "$real_gw")"
        fi
    
        if [ -n "$real_gw" ] && [ "$real_gw" != "$my_ip" ]; then
            log "Setting gateway to: $real_gw"
            
            # Configure static IP via NetworkManager if available
            if [ -n "$conn_name" ] && command -v nmcli &>/dev/null; then
                if ! is_static_ip_configured "$conn_name"; then
                    configure_static_ip "$conn_name" "$my_ip" "$prefix_len" "$real_gw"
                else
                    log "Static IP already configured"
                    # Just fix the route immediately
                    "$IP_CMD" route replace default via "$real_gw" dev "$iface"
                fi
            else
                # Fallback: just fix the route (won't persist after DHCP refresh)
                "$IP_CMD" route replace default via "$real_gw" dev "$iface"
                log "WARNING: NetworkManager not available, route fix may not persist"
            fi
            
            # Verify
            sleep 2
            if ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
                log "SUCCESS: Internet connectivity restored"
            else
                log "WARNING: Gateway set but no internet. Check upstream router."
            fi
        else
            log "ERROR: Could not find a valid gateway"
            return 1
        fi
    else
        log "Gateway is OK (not pointing to self)"
        
        # Remove any duplicate bad routes pointing to self
        "$IP_CMD" route del default via "$my_ip" 2>/dev/null || true
        
        # Check if static IP is configured (prevents future DHCP issues)
        if [ -n "$conn_name" ] && command -v nmcli &>/dev/null; then
            if ! is_static_ip_configured "$conn_name"; then
                log "Configuring static IP to prevent future DHCP issues..."
                if [ -n "$current_gw" ] && [ "$current_gw" != "$my_ip" ]; then
                    configure_static_ip "$conn_name" "$my_ip" "$prefix_len" "$current_gw"
                fi
            fi
        fi
        
        # Verify internet
        if ! ping -c 1 -W 2 8.8.8.8 >/dev/null 2>&1; then
            log "WARNING: Gateway set but no internet connectivity"
        fi
    fi
    
    # Setup NAT for gateway mode
    if ! setup_nat "$iface"; then
        log "ERROR: Failed to apply secure gateway forwarding rules"
        return 1
    fi
    
    log "=== Gateway Fix Check Completed ==="
}

main "$@"
