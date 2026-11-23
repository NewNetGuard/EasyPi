#!/bin/bash
#
# Monitor and block Tor traffic in real-time
# Detects suspicious HTTPS connections and adds them to blocklist
#

TOR_IPSET="easypi_tor_nodes"
LOG_FILE="/var/log/easypi/tor_monitor.log"
MONITORED_IPS_FILE="/opt/EasyPi/data/netprotection/monitored_ips.txt"

# Create log directory
mkdir -p "$(dirname "$LOG_FILE")"
mkdir -p "$(dirname "$MONITORED_IPS_FILE")"

log_message() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOG_FILE"
}

# Get IPs that should be monitored from devices.json
get_monitored_ips() {
    python3 -c "
import json
try:
    with open('/opt/EasyPi/data/netprotection/devices.json') as f:
        devices = json.load(f)
    for device in devices:
        if not device.get('enabled', True):
            continue
        blocked_services = device.get('blocked_services', [])
        if 'tor' in blocked_services:
            print(device.get('ip', ''))
except: pass
" 2>/dev/null
}

# Analyze connection patterns to detect Tor bridges
analyze_connections() {
    local client_ip="$1"
    
    # Get recent connections to port 443 (last 60 seconds)
    local suspicious_ips=()
    
    # Use conntrack to find active connections
    while IFS= read -r line; do
        if [[ -n "$line" ]]; then
            suspicious_ips+=("$line")
        fi
    done < <(conntrack -L 2>/dev/null | \
             grep "src=$client_ip" | \
             grep "dport=443" | \
             awk '{for(i=1;i<=NF;i++){if($i~/^dst=/){sub(/dst=/,"",$i); print $i}}}' | \
             sort -u)
    
    # Check each IP against Tor project databases
    for ip in "${suspicious_ips[@]}"; do
        # Skip if already in ipset
        if ipset test "$TOR_IPSET" "$ip" 2>/dev/null; then
            continue
        fi
        
        # Check if IP belongs to known cloud providers (common for Tor bridges)
        local is_cloud=false
        local cloud_ranges=(
            "162.159."  # Cloudflare
            "34.36."    # Google Cloud
            "35."       # Google Cloud
            "18."       # AWS
            "3."        # AWS
            "20."       # Azure
            "40."       # Azure
            "51."       # Azure/OVH
            "139."      # Linode
            "45."       # Various VPS
        )
        
        for range in "${cloud_ranges[@]}"; do
            if [[ "$ip" =~ ^$range ]]; then
                is_cloud=true
                break
            fi
        done
        
        if [[ "$is_cloud" == "true" ]]; then
            # Try to query online Tor databases
            local is_tor_relay=false
            
            # Check against Tor bulk exit list (dan.me.uk mirror)
            if timeout 5 curl -sf "https://www.dan.me.uk/torcheck?ip=$ip" | grep -q "Tor"; then
                is_tor_relay=true
            fi
            
            if [[ "$is_tor_relay" == "true" ]]; then
                ipset add "$TOR_IPSET" "$ip" 2>/dev/null
                log_message "Blocked Tor relay/bridge: $ip (detected from $client_ip)"
            else
                # Log for manual review
                log_message "Suspicious cloud IP: $ip from $client_ip (not confirmed as Tor)"
            fi
        fi
    done
}

# Main monitoring loop
log_message "Tor traffic monitoring started"

# Get list of IPs to monitor
mapfile -t monitored_ips < <(get_monitored_ips)

if [[ ${#monitored_ips[@]} -eq 0 ]]; then
    log_message "No IPs to monitor"
    exit 0
fi

log_message "Monitoring ${#monitored_ips[@]} IP(s) for Tor traffic"

# Run monitoring for 5 minutes (called periodically by cron)
for ((i=0; i<30; i++)); do
    for ip in "${monitored_ips[@]}"; do
        if [[ -n "$ip" ]]; then
            analyze_connections "$ip"
        fi
    done
    sleep 10
done

log_message "Monitoring cycle completed"
