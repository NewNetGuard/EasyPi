#!/usr/bin/env bash
set -euo pipefail

[[ "${EUID}" -eq 0 ]] || {
    echo "This regression test requires root network-namespace privileges" >&2
    exit 77
}

for command_name in ip iptables python3 unshare; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "Missing required command: $command_name" >&2
        exit 77
    }
done

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
stealth_script="$root_dir/scripts/settings/stealth_vpn.sh"

# Active setup temporarily prepends KILL/QUIC while constructing the ruleset,
# then restores PRESTART as the first policy gate. Exercise both production
# functions and the health checker against real iptables state.
unshare -n bash -s -- "$stealth_script" "$root_dir" <<'BASH'
set -uo pipefail
source "$1"
policy_scope='all'
policy_macs=''
read_dns_policy() { printf 'true\n%s\n\n%s\ntrue\n' "$policy_scope" "$policy_macs"; }
ip() {
  [[ "${1:-} ${2:-}" == 'rule del' ]] && return 1
  return 0
}
install_tunnel_forwarding() { return 0; }
install_device_routing() { return 0; }
install_mss_clamp() { return 0; }
clear_startup_dns_guard() { return 0; }
install_prestart_guard all '' '' wan0 || exit 1
apply_manual_routing all '' '' wan0 '' '' true || exit 1
first4="$(iptables -S FORWARD | awk '$1 == "-A" {print; exit}')"
first6="$(ip6tables -S FORWARD | awk '$1 == "-A" {print; exit}')"
[[ "$first4" == '-A FORWARD -j EASYPI_STEALTH_PRESTART' ]]
[[ "$first6" == '-A FORWARD -j EASYPI_STEALTH6_PRESTART' ]]
PYTHONPATH="$2" python3 - <<'PY' || exit 1
from scripts.maintenance import verify_runtime_health as health

failures = []
health.check_forwarding_guards(
    {"version": 1, "enabled": True, "scope": "all", "macs": []}, failures
)
if failures:
    raise SystemExit("; ".join(failures))
PY

# Repeat with three selected identities. This catches loops whose bound shrinks
# while matched MAC entries are removed from the required set.
clear_rules wan0 false
policy_scope='selected'
policy_macs='02:00:00:00:00:21,02:00:00:00:00:22,02:00:00:00:00:23'
install_prestart_guard selected '' "$policy_macs" wan0 || exit 1
apply_manual_routing selected '' "$policy_macs" wan0 '' '' true || exit 1
prestart_guard_matches_policy selected "$policy_macs" || exit 1
PYTHONPATH="$2" python3 - <<'PY' || exit 1
from scripts.maintenance import verify_runtime_health as health

failures = []
health.check_forwarding_guards(
    {
        "version": 1,
        "enabled": True,
        "scope": "selected",
        "macs": [
            "02:00:00:00:00:21",
            "02:00:00:00:00:22",
            "02:00:00:00:00:23",
        ],
    },
    failures,
)
if failures:
    raise SystemExit("; ".join(failures))
PY
BASH

suffix="$$"
client_ns="epcc${suffix}"
gateway_ns="epcg${suffix}"
server_ns="epcs${suffix}"
client_link="epcl${suffix}"
gateway_lan="epgl${suffix}"
gateway_tun="epgt${suffix}"
server_link="epsl${suffix}"
gateway_wan="epgw${suffix}"
server_wan="epsw${suffix}"
tmp_dir="$(mktemp -d)"
server_pid=""

cleanup() {
    if [[ -n "$server_pid" ]]; then
        kill "$server_pid" >/dev/null 2>&1 || true
        wait "$server_pid" >/dev/null 2>&1 || true
    fi
    ip netns delete "$client_ns" >/dev/null 2>&1 || true
    ip netns delete "$gateway_ns" >/dev/null 2>&1 || true
    ip netns delete "$server_ns" >/dev/null 2>&1 || true
    rm -rf -- "$tmp_dir"
}
trap cleanup EXIT

ip netns add "$client_ns"
ip netns add "$gateway_ns"
ip netns add "$server_ns"

ip link add "$client_link" type veth peer name "$gateway_lan"
ip link add "$gateway_tun" type veth peer name "$server_link"
ip link add "$gateway_wan" type veth peer name "$server_wan"
ip link set "$client_link" netns "$client_ns"
ip link set "$gateway_lan" netns "$gateway_ns"
ip link set "$gateway_tun" netns "$gateway_ns"
ip link set "$server_link" netns "$server_ns"
ip link set "$gateway_wan" netns "$gateway_ns"
ip link set "$server_wan" netns "$server_ns"

ip -n "$client_ns" link set "$client_link" name eth0
ip -n "$gateway_ns" link set "$gateway_lan" name lan0
ip -n "$gateway_ns" link set "$gateway_tun" name cham0
ip -n "$server_ns" link set "$server_link" name eth0
ip -n "$gateway_ns" link set "$gateway_wan" name ordinary0
ip -n "$server_ns" link set "$server_wan" name wan0

for namespace in "$client_ns" "$gateway_ns" "$server_ns"; do
    ip -n "$namespace" link set lo up
done
ip -n "$client_ns" address add 10.251.1.2/24 dev eth0
ip -n "$gateway_ns" address add 10.251.1.1/24 dev lan0
ip -n "$gateway_ns" address add 10.251.2.1/24 dev cham0 noprefixroute
ip -n "$server_ns" address add 10.251.2.2/24 dev eth0
ip -n "$gateway_ns" address add 198.18.0.1/24 dev ordinary0
ip -n "$server_ns" address add 198.18.0.2/24 dev wan0
ip -n "$client_ns" link set eth0 up
ip -n "$gateway_ns" link set lan0 up
ip -n "$gateway_ns" link set cham0 mtu 1420 up
ip -n "$gateway_ns" link set ordinary0 mtu 1500 up
ip -n "$server_ns" link set eth0 up
ip -n "$server_ns" link set wan0 up
ip -n "$client_ns" route add default via 10.251.1.1
ip -n "$server_ns" route add default via 10.251.2.1
ip netns exec "$gateway_ns" sysctl -q -w net.ipv4.ip_forward=1
for scope in all default lan0 cham0; do
    ip netns exec "$gateway_ns" sysctl -q -w "net.ipv4.conf.${scope}.rp_filter=0"
done

# Reproduce production policy routing: the unmarked/main lookup sees a normal
# 1500-byte path, while forwarded client packets carry EasyPi's mark and use
# the 1420-byte Chameleon interface through a separate table.
ip -n "$gateway_ns" route add 10.251.2.0/24 dev ordinary0
ip -n "$gateway_ns" route add table 51821 10.251.2.0/24 dev cham0 src 10.251.2.1
ip -n "$gateway_ns" rule add pref 100 fwmark 0x51822/0xffffffff lookup 51821
ip netns exec "$gateway_ns" iptables -t mangle -A PREROUTING -i lan0 \
    -j MARK --set-xmark 0x51822/0xffffffff
ip netns exec "$gateway_ns" ip route get 10.251.2.2 \
    | grep -q 'dev ordinary0'
ip netns exec "$gateway_ns" ip route get 10.251.2.2 mark 0x51822 \
    | grep -q 'dev cham0'

ip netns exec "$gateway_ns" iptables -P FORWARD DROP
ip netns exec "$gateway_ns" iptables -N EASYPI_TEST_BLOCK
ip netns exec "$gateway_ns" iptables -A EASYPI_TEST_BLOCK -s 10.251.1.2 -j DROP
ip netns exec "$gateway_ns" iptables -I FORWARD 1 -j EASYPI_TEST_BLOCK
# Reproduce UFW's misleading late logging hook. Chameleon must suppress this
# log for tunnel traffic without moving its ACCEPT rules ahead of EasyPi's
# existing deny above.
ip netns exec "$gateway_ns" iptables -N ufw-after-logging-forward
ip netns exec "$gateway_ns" iptables -A ufw-after-logging-forward \
    -m limit --limit 3/min --limit-burst 10 -j LOG --log-prefix '[UFW BLOCK] '
ip netns exec "$gateway_ns" iptables -A FORWARD -j ufw-after-logging-forward

ip netns exec "$gateway_ns" bash -s -- "$stealth_script" <<'BASH'
source "$1"
install_tunnel_forwarding
BASH

# Install the old implementation as a negative control. In this topology its
# reverse lookup sees ordinary0 and leaves the SYN-ACK MSS above cham0's limit.
ip netns exec "$gateway_ns" iptables -t mangle -A FORWARD -o cham0 -p tcp \
    --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
ip netns exec "$gateway_ns" iptables -t mangle -A FORWARD -i cham0 -p tcp \
    --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu

cat >"$tmp_dir/server.py" <<'PY'
import pathlib
import socket
import sys

ready_path = pathlib.Path(sys.argv[1])
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("0.0.0.0", 8080))
    listener.listen(1)
    ready_path.write_text("ready", encoding="ascii")
    connection, _ = listener.accept()
    with connection:
        server_mss = connection.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
        received = 0
        while True:
            chunk = connection.recv(65536)
            if not chunk:
                break
            received += len(chunk)
        connection.sendall(f"{server_mss} {received}\n".encode("ascii"))
PY

start_server() {
    local ready_path="$1" log_path="$2"
    rm -f -- "$ready_path"
    ip netns exec "$server_ns" python3 "$tmp_dir/server.py" "$ready_path" \
        >"$log_path" 2>&1 &
    server_pid="$!"
    for _ in $(seq 1 50); do
        [[ -f "$ready_path" ]] && return 0
        sleep 0.05
    done
    return 1
}

start_server "$tmp_dir/legacy-ready" "$tmp_dir/legacy-server.log"

# The pre-existing EasyPi deny must still win after Chameleon installs its
# forwarding rules. A head insertion here would make this connection succeed.
ip netns exec "$client_ns" python3 - <<'PY'
import socket

probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
probe.settimeout(0.5)
try:
    probe.connect(("10.251.2.2", 8080))
except (TimeoutError, OSError):
    raise SystemExit(0)
finally:
    probe.close()
raise SystemExit("blocked client bypassed the EasyPi deny rule")
PY

ip netns exec "$gateway_ns" iptables -D FORWARD -j EASYPI_TEST_BLOCK
ip netns exec "$gateway_ns" iptables -A FORWARD -o ordinary0 -j ACCEPT

# Replacing an active PRESTART policy must be fail-closed. Inject an iptables
# failure while the candidate chain is being built, then prove with a real TCP
# packet that the previously active guard still blocks the public path.
ip netns exec "$gateway_ns" bash -s -- "$stealth_script" <<'BASH'
source "$1"
read_dns_policy() { printf 'true\nall\n\n\ntrue\n'; }
install_prestart_guard all '' '' wan0 || exit 1
real_iptables="$(command -v iptables)"
iptables() {
  if [[ "$*" == *'EP_PRE4_'* && "$*" == *'-d 100.64.0.0/10'* ]]; then
    return 1
  fi
  command "$real_iptables" "$@"
}
if install_prestart_guard all '' '' wan0; then
  echo 'fault-injected PRESTART replacement unexpectedly succeeded' >&2
  exit 1
fi
unset -f iptables
prestart_guard_matches_policy all '' || exit 1

# Fail after both candidate guards are attached but before the IPv4 candidate
# receives the canonical name. Status must still report the live terminal-DROP
# chain so the backend keeps the requested protection enabled and retries it.
iptables() {
  if [[ "${1:-}" == '-E' && "${2:-}" == EP_PRE4_* ]]; then
    return 1
  fi
  command "$real_iptables" "$@"
}
if install_prestart_guard all '' '' wan0; then
  echo 'fault-injected PRESTART rename unexpectedly succeeded' >&2
  exit 1
fi
unset -f iptables
status_json="$(do_status)"
python3 - "$status_json" <<'PY'
import json
import sys

status = json.loads(sys.argv[1])
assert status["killswitch"] is True, status
print("CHAMELEON_PRESTART_RENAME_STATUS=PASS")
PY
BASH

ip netns exec "$client_ns" python3 - <<'PY'
import socket

probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
probe.settimeout(0.5)
try:
    probe.connect(("198.18.0.2", 8080))
except (TimeoutError, OSError):
    print("CHAMELEON_PRESTART_REPLACEMENT_FAILURE=PASS")
    raise SystemExit(0)
finally:
    probe.close()
raise SystemExit("PRESTART replacement failure opened a direct forwarding path")
PY

ip netns exec "$gateway_ns" bash -s -- "$stealth_script" <<'BASH'
source "$1"
clear_prestart_guard
BASH

# Verify that the fixture rejects the implementation being guarded against.
# The server sees the clamped client SYN, while the client sees the oversized
# MSS from the reverse SYN-ACK lookup through ordinary0.
ip netns exec "$client_ns" python3 - 1380 <<'PY'
import socket
import sys

expected_mss = int(sys.argv[1])
with socket.create_connection(("10.251.2.2", 8080), timeout=5) as connection:
    client_mss = connection.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
    connection.sendall(b"x")
    connection.shutdown(socket.SHUT_WR)
    response = connection.recv(128).decode("ascii").strip()

server_mss, received = (int(value) for value in response.split())
assert client_mss > expected_mss, (
    "test topology no longer reproduces legacy reverse-MSS failure",
    client_mss,
    expected_mss,
)
assert 0 < server_mss <= expected_mss, (server_mss, expected_mss)
assert received == 1, received
print(
    f"CHAMELEON_LEGACY_MSS_REPRODUCED "
    f"client_mss={client_mss} server_mss={server_mss}"
)
PY

wait "$server_pid"
server_pid=""

ufw_log_hits="$(
    ip netns exec "$gateway_ns" iptables -L ufw-after-logging-forward \
        -n -v -x | awk '$3 == "LOG" {print $1; exit}'
)"
[[ "$ufw_log_hits" == '0' ]] || {
    echo "Chameleon tunnel traffic reached misleading UFW logging: $ufw_log_hits packets" >&2
    exit 1
}

ip netns exec "$gateway_ns" bash -s -- "$stealth_script" <<'BASH'
source "$1"
install_mss_clamp
BASH

start_server "$tmp_dir/fixed-ready" "$tmp_dir/fixed-server.log"

# Exercise a real multi-megabyte client upload and inspect the negotiated send
# MSS at both endpoints. Both values must honor cham0's 1420-byte MTU.
ip netns exec "$client_ns" python3 - 1380 <<'PY'
import socket
import sys

expected_mss = int(sys.argv[1])
payload_size = 8 * 1024 * 1024
with socket.create_connection(("10.251.2.2", 8080), timeout=5) as connection:
    connection.settimeout(10)
    client_mss = connection.getsockopt(socket.IPPROTO_TCP, socket.TCP_MAXSEG)
    chunk = b"x" * 65536
    remaining = payload_size
    while remaining:
        part = chunk[: min(len(chunk), remaining)]
        connection.sendall(part)
        remaining -= len(part)
    connection.shutdown(socket.SHUT_WR)
    response = connection.recv(128).decode("ascii").strip()

server_mss, received = (int(value) for value in response.split())
assert 0 < client_mss <= expected_mss, (client_mss, expected_mss)
assert 0 < server_mss <= expected_mss, (server_mss, expected_mss)
assert received == payload_size, (received, payload_size)
print(
    f"CHAMELEON_FIREWALL_REGRESSION=PASS "
    f"client_mss={client_mss} server_mss={server_mss} uploaded={received}"
)
PY

wait "$server_pid"
server_pid=""
