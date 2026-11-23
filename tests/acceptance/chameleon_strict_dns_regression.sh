#!/usr/bin/env bash
set -euo pipefail

[[ "${EUID}" -eq 0 ]] || {
    echo "This regression test requires root network-namespace privileges" >&2
    exit 77
}

for command_name in ip iptables python3 setpriv; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "Missing required command: $command_name" >&2
        exit 77
    }
done
id -u nobody >/dev/null 2>&1 || {
    echo "The nobody account is required" >&2
    exit 77
}

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
stealth_script="$root_dir/scripts/settings/stealth_vpn.sh"

# Reproduce the first Safe Update activation without touching the host. Starting
# the DNS unit represents systemd starting its guard dependency; policy must be
# visible before that happens or the dependency can clear the new rules.
(
    source "$stealth_script" || true
    activation_events=""
    activation_policy="false"
    install_strict_dns_routing_rules() { activation_events+="rules "; }
    write_dns_policy() { activation_policy="$1"; activation_events+="policy "; }
    systemctl() {
        [[ "$1" == "start" && "$activation_policy" == "true" ]] || return 1
        activation_events+="start"
    }
    activate_strict_dns_policy selected 192.168.1.20 02:00:00:00:00:20 true
    [[ "$activation_events" == "rules policy start" ]]
) || {
    echo "Safe Update started strict DNS before publishing its policy" >&2
    exit 1
}

suffix="$$"
gateway_ns="epsg${suffix}"
direct_ns="epsd${suffix}"
tunnel_ns="epst${suffix}"
gateway_wan="epsw${suffix}"
direct_link="epsd${suffix}"
gateway_tun="epsc${suffix}"
tunnel_link="epst${suffix}"
tmp_dir="$(mktemp -d)"
dns_pid=""
proxy_pid=""

cleanup() {
    for process_id in "$proxy_pid" "$dns_pid"; do
        if [[ -n "$process_id" ]]; then
            kill "$process_id" >/dev/null 2>&1 || true
            wait "$process_id" >/dev/null 2>&1 || true
        fi
    done
    ip netns delete "$gateway_ns" >/dev/null 2>&1 || true
    ip netns delete "$direct_ns" >/dev/null 2>&1 || true
    ip netns delete "$tunnel_ns" >/dev/null 2>&1 || true
    rm -rf -- "$tmp_dir"
}
trap cleanup EXIT

ip netns add "$gateway_ns"
ip netns add "$direct_ns"
ip netns add "$tunnel_ns"
ip link add "$gateway_wan" type veth peer name "$direct_link"
ip link add "$gateway_tun" type veth peer name "$tunnel_link"
ip link set "$gateway_wan" netns "$gateway_ns"
ip link set "$direct_link" netns "$direct_ns"
ip link set "$gateway_tun" netns "$gateway_ns"
ip link set "$tunnel_link" netns "$tunnel_ns"
ip -n "$gateway_ns" link set "$gateway_wan" name wan0
ip -n "$direct_ns" link set "$direct_link" name eth0
ip -n "$gateway_ns" link set "$gateway_tun" name cham0
ip -n "$tunnel_ns" link set "$tunnel_link" name eth0

for namespace in "$gateway_ns" "$direct_ns" "$tunnel_ns"; do
    ip -n "$namespace" link set lo up
done
ip -n "$gateway_ns" address add 192.0.2.1/24 dev wan0
ip -n "$direct_ns" address add 192.0.2.2/24 dev eth0
ip -n "$gateway_ns" address add 10.252.2.1/24 dev cham0
ip -n "$tunnel_ns" address add 1.1.1.1/32 dev eth0
ip -n "$gateway_ns" link set wan0 up
ip -n "$direct_ns" link set eth0 up
ip -n "$gateway_ns" link set cham0 up
ip -n "$tunnel_ns" link set eth0 up
ip -n "$gateway_ns" route add default via 192.0.2.2
ip -n "$tunnel_ns" route add 10.252.2.0/24 dev eth0
tunnel_mac="$(ip -n "$tunnel_ns" -o link show eth0 | awk '{print $17}')"
gateway_tun_mac="$(ip -n "$gateway_ns" -o link show cham0 | awk '{print $17}')"
ip -n "$gateway_ns" neigh add 1.1.1.1 lladdr "$tunnel_mac" dev cham0 nud permanent
ip -n "$tunnel_ns" neigh add 10.252.2.1 lladdr "$gateway_tun_mac" dev eth0 nud permanent
for scope in all default eth0; do
    ip netns exec "$tunnel_ns" sysctl -q -w "net.ipv4.conf.${scope}.rp_filter=0"
done

# Count every plain DNS packet that reaches the direct WAN peer.
ip netns exec "$direct_ns" iptables -t mangle -A PREROUTING -i eth0 \
    -p udp --dport 53 -j ACCEPT
ip netns exec "$tunnel_ns" iptables -t mangle -A PREROUTING -i eth0 \
    -p udp --dport 53 -j ACCEPT

cat >"$tmp_dir/dns_server.py" <<'PY'
import socket

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.bind(("1.1.1.1", 53))
    while True:
        query, peer = sock.recvfrom(4096)
        if len(query) >= 12:
            response = query[:2] + b"\x81\x80\x00\x01\x00\x00\x00\x00\x00\x00" + query[12:]
            sock.sendto(response, peer)
            print(f"answered {peer}", flush=True)
PY

cat >"$tmp_dir/query.py" <<'PY'
import socket
import sys

query = b"\x45\x50\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01"
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.settimeout(1.5)
    sock.sendto(query, ("127.0.0.1", 5455))
    try:
        response, _ = sock.recvfrom(4096)
    except (TimeoutError, OSError):
        raise SystemExit(1)
if len(response) < 12 or response[:2] != query[:2]:
    raise SystemExit(2)
print("DNS_OK")
PY

ip netns exec "$tunnel_ns" python3 "$tmp_dir/dns_server.py" \
    >"$tmp_dir/server.log" 2>&1 &
dns_pid="$!"

# Install only the production routing primitive. Service lifecycle is tested
# separately; this namespace supplies its own restricted proxy process.
dns_group="$(id -gn nobody)"
ip netns exec "$gateway_ns" bash -s -- "$stealth_script" "$dns_group" <<'BASH'
source "$1"
DNS_PROXY_USER="nobody"
DNS_PROXY_GROUP="$2"
install_strict_dns_routing_rules
BASH

nobody_uid="$(id -u nobody)"
nobody_gid="$(id -g nobody)"
ip netns exec "$gateway_ns" setpriv \
    --reuid="$nobody_uid" --regid="$nobody_gid" --clear-groups \
    env EASYPI_STEALTH_DNS_UPSTREAMS=1.1.1.1 \
    EASYPI_STEALTH_DNS_TIMEOUT=0.3 \
    python3 "$root_dir/easypi_netprotection/stealth_dns.py" \
    >"$tmp_dir/proxy.log" 2>&1 &
proxy_pid="$!"
sleep 0.4

# The ordinary main route still uses WAN, proving the fixture can detect a leak.
ip netns exec "$gateway_ns" python3 - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
    sock.sendto(b"ordinary", ("1.1.1.1", 53))
PY
sleep 0.1
ordinary_count="$(ip netns exec "$direct_ns" iptables -t mangle -L PREROUTING -n -v -x \
    | awk '/udp dpt:53/ {print $1; exit}')"
[[ "${ordinary_count:-0}" -gt 0 ]] || {
    echo "The direct-WAN leak detector did not observe the control packet" >&2
    exit 1
}
ip netns exec "$direct_ns" iptables -t mangle -Z PREROUTING

# Active tunnel: protected DNS succeeds and no packet reaches direct WAN.
if ! ip netns exec "$gateway_ns" python3 "$tmp_dir/query.py" | grep -q DNS_OK; then
    cat "$tmp_dir/proxy.log" >&2 || true
    cat "$tmp_dir/server.log" >&2 || true
    ip -n "$gateway_ns" rule show >&2 || true
    ip -n "$gateway_ns" route show table 51823 >&2 || true
    ip netns exec "$gateway_ns" iptables -t mangle -L OUTPUT -n -v -x >&2 || true
    ip -n "$gateway_ns" route get 1.1.1.1 uid "$nobody_uid" >&2 || true
    ip -n "$gateway_ns" -s link show cham0 >&2 || true
    ip -n "$tunnel_ns" -s link show eth0 >&2 || true
    ip netns exec "$tunnel_ns" iptables -t mangle -L PREROUTING -n -v -x >&2 || true
    ip netns exec "$tunnel_ns" ss -lun >&2 || true
    ip -n "$tunnel_ns" route show >&2 || true
    ip -n "$tunnel_ns" route get 10.252.2.1 >&2 || true
    echo "Protected DNS did not traverse the active tunnel fixture" >&2
    exit 1
fi
sleep 0.1
direct_count="$(ip netns exec "$direct_ns" iptables -t mangle -L PREROUTING -n -v -x \
    | awk '/udp dpt:53/ {print $1; exit}')"
[[ "${direct_count:-0}" -eq 0 ]] || {
    echo "Protected DNS leaked through the direct WAN" >&2
    exit 1
}

# Reproduce a stable-rule installation failure. The production function must
# leave its staging rule active, so the resolver continues through cham0.
if ip netns exec "$gateway_ns" bash -s -- "$stealth_script" "$dns_group" <<'BASH'
source "$1"
DNS_PROXY_USER="nobody"
DNS_PROXY_GROUP="$2"
ip() {
    if [[ "${1:-}" == "rule" && "${2:-}" == "add" \
          && "${*: -1}" == "$DNS_PROXY_PREF" ]]; then
        return 1
    fi
    command ip "$@"
}
install_strict_dns_routing_rules
BASH
then
    echo "Injected stable DNS policy-rule failure unexpectedly succeeded" >&2
    exit 1
fi
ip -n "$gateway_ns" rule show | grep -q "^${DNS_PROXY_STAGING_PREF:-5093}:.*uidrange.*lookup 51823" || {
    echo "Staging DNS policy rule was not retained after replacement failure" >&2
    exit 1
}
if ! ip netns exec "$gateway_ns" python3 "$tmp_dir/query.py" | grep -q DNS_OK; then
    echo "Protected DNS stopped after stable policy-rule replacement failed" >&2
    exit 1
fi

# Even with both uidrange rules absent, the independent owner OUTPUT guard must
# prevent a protected resolver packet from falling back to the ordinary WAN.
ip -n "$gateway_ns" rule del pref 5093 lookup 51823
if ip netns exec "$gateway_ns" python3 "$tmp_dir/query.py" >/dev/null 2>&1; then
    echo "DNS unexpectedly succeeded after all protected policy rules were removed" >&2
    exit 1
fi
direct_count="$(ip netns exec "$direct_ns" iptables -t mangle -L PREROUTING -n -v -x \
    | awk '/udp dpt:53/ {print $1; exit}')"
[[ "${direct_count:-0}" -eq 0 ]] || {
    echo "Owner OUTPUT guard allowed protected DNS onto the direct WAN" >&2
    exit 1
}

# Restore the production rule set for the remaining tunnel-failure scenarios.
ip netns exec "$gateway_ns" bash -s -- "$stealth_script" "$dns_group" <<'BASH'
source "$1"
DNS_PROXY_USER="nobody"
DNS_PROXY_GROUP="$2"
install_strict_dns_routing_rules
BASH

# Failed upstream, missing cham0, and stopped proxy must all fail closed.
kill "$dns_pid"
wait "$dns_pid" >/dev/null 2>&1 || true
dns_pid=""
if ip netns exec "$gateway_ns" python3 "$tmp_dir/query.py" >/dev/null 2>&1; then
    echo "DNS unexpectedly succeeded with an unreachable tunnel upstream" >&2
    exit 1
fi

ip -n "$gateway_ns" link delete cham0
if ip netns exec "$gateway_ns" python3 "$tmp_dir/query.py" >/dev/null 2>&1; then
    echo "DNS unexpectedly succeeded without cham0" >&2
    exit 1
fi

kill "$proxy_pid"
wait "$proxy_pid" >/dev/null 2>&1 || true
proxy_pid=""
if ip netns exec "$gateway_ns" python3 "$tmp_dir/query.py" >/dev/null 2>&1; then
    echo "DNS unexpectedly succeeded after the protected resolver stopped" >&2
    exit 1
fi

direct_count="$(ip netns exec "$direct_ns" iptables -t mangle -L PREROUTING -n -v -x \
    | awk '/udp dpt:53/ {print $1; exit}')"
[[ "${direct_count:-0}" -eq 0 ]] || {
    echo "A failure scenario leaked DNS through the direct WAN" >&2
    exit 1
}

echo "CHAMELEON_STRICT_DNS_REGRESSION=PASS"
