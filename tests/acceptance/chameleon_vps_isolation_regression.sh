#!/usr/bin/env bash
# Behaviour of the VPS tunnel isolation in Linux network namespaces.
#
#   chameleon_vps_isolation_regression.sh RENDERED_NETWORK_SETUP_SCRIPT
#
# Builds a model VPS (its own namespace) with an uplink to an "internet"
# namespace, a docker bridge, a WireGuard-like network and a tunnel client,
# installs the isolation functions taken from the rendered
# chameleon-network-setup script and checks real TCP connections: the
# internet and the VPS's public address stay reachable from the tunnel, the
# VPS's internal addresses and the networks behind it do not, and removing
# the isolation restores the previous behaviour.
set -euo pipefail

[[ "${EUID}" -eq 0 ]] || { echo "requires root network-namespace privileges" >&2; exit 77; }
for command_name in ip iptables python3 unshare timeout; do
  command -v "$command_name" >/dev/null 2>&1 || { echo "missing: $command_name" >&2; exit 77; }
done
setup_script="${1:?rendered chameleon-network-setup script}"
functions="$(mktemp)"
trap 'rm -f "$functions"' EXIT
sed -n -e '/^TUN_IN_CHAIN=/p' -e '/^TUN_FWD_CHAIN=/p' -e '/^DENIED_DESTINATIONS=/p' \
  -e '/^remove_tunnel_isolation() {$/,/^}$/p' -e '/^install_tunnel_isolation() {$/,/^}$/p' \
  "$setup_script" > "$functions"
grep -q '^install_tunnel_isolation() {$' "$functions" || { echo "isolation functions not found" >&2; exit 1; }

unshare -n bash -s -- "$functions" <<'MODEL'
set -euo pipefail
source "$1"
TUN=chameleon0
id=$$
cli="cli$id" net="net$id" dock="dock$id" wg="wg$id"
cleanup() {
  kill $(jobs -p) 2>/dev/null || true
  for ns in "$cli" "$net" "$dock" "$wg"; do ip netns del "$ns" 2>/dev/null || true; done
}
trap cleanup EXIT
nsx() { ip netns exec "$@"; }
listen() { # ns address port
  ip netns exec "$1" python3 -c '
import socket, sys
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2]))); s.listen(16)
while True:
    c, _ = s.accept(); c.close()
' "$2" "$3" &
}
link() { # vps-side name, vps address, ns, ns-side address, ns default gateway
  ip link add "$1" type veth peer name peer0 netns "$3"
  ip addr add "$2" dev "$1"; ip link set "$1" up
  nsx "$3" ip link set lo up
  nsx "$3" ip addr add "$4" dev peer0; nsx "$3" ip link set peer0 up
  nsx "$3" ip route add default via "$5"
}
for ns in "$cli" "$net" "$dock" "$wg"; do ip netns add "$ns"; done
ip link set lo up
link "$TUN" 10.10.0.1/24 "$cli" 10.10.0.2/24 10.10.0.1
link up0 45.0.0.1/24 "$net" 45.0.0.2/24 45.0.0.1
link docker0 172.17.0.1/16 "$dock" 172.17.0.2/16 172.17.0.1
link wg0 10.66.66.1/24 "$wg" 10.66.66.2/24 10.66.66.1
nsx "$net" ip addr add 8.8.8.8/32 dev lo
ip route add default via 45.0.0.2
sysctl -qw net.ipv4.ip_forward=1

# The VPS as deployed: SSH on every address, a container port published on
# the public address, docker accepting it ahead of the tunnel rule.
listen "$net" 8.8.8.8 80
listen "$dock" 172.17.0.2 8053
listen "$wg" 10.66.66.2 80
python3 -c '
import socket
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", 2222)); s.listen(16)
while True:
    c, _ = s.accept(); c.close()
' &
sleep 0.5
iptables -t nat -A POSTROUTING -s 10.10.0.0/24 -o up0 -j MASQUERADE
iptables -t nat -A PREROUTING -d 45.0.0.1 -p tcp --dport 5353 -j DNAT --to-destination 172.17.0.2:8053
iptables -P FORWARD DROP
iptables -N DOCKER-USER
iptables -A FORWARD -j DOCKER-USER
iptables -A FORWARD -d 172.17.0.2 ! -i docker0 -o docker0 -p tcp --dport 8053 -j ACCEPT
iptables -A FORWARD -o docker0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i docker0 -j ACCEPT
iptables -A FORWARD -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -A FORWARD -i wg0 -j ACCEPT
iptables -A FORWARD -i "$TUN" -j ACCEPT
iptables -A FORWARD -o "$TUN" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT

reach() { nsx "$cli" timeout 2 bash -c "</dev/tcp/$1/$2" 2>/dev/null; }
failed=0
expect() { # open|closed host port label
  if reach "$2" "$3"; then got=open; else got=closed; fi
  if [[ "$got" == "$1" ]]; then echo "ok    $4: $got"; else echo "FAIL  $4: $got, want $1"; failed=1; fi
}
echo "== without isolation (deployed behaviour)"
expect open 10.10.0.1 2222 "VPS tunnel address"
expect open 172.17.0.2 8053 "container directly"
expect open 10.66.66.2 80 "WireGuard peer"

install_tunnel_isolation up0
echo "== with isolation"
expect open 8.8.8.8 80 "internet"
expect open 45.0.0.1 2222 "VPS public address"
expect open 45.0.0.1 5353 "port published on the public address"
expect closed 10.10.0.1 2222 "VPS tunnel address"
expect closed 172.17.0.1 2222 "VPS docker address"
expect closed 10.66.66.1 2222 "VPS WireGuard address"
expect closed 172.17.0.2 8053 "container directly"
expect closed 10.66.66.2 80 "WireGuard peer"
nsx "$net" timeout 2 bash -c "</dev/tcp/45.0.0.1/2222" 2>/dev/null \
  && echo "ok    internet to VPS: open" || { echo "FAIL  internet to VPS"; failed=1; }

# Docker restarting puts its jumps back on top of FORWARD.
iptables -D FORWARD -j DOCKER-USER
iptables -I FORWARD 1 -j DOCKER-USER
iptables -I FORWARD 2 -d 172.17.0.2 ! -i docker0 -o docker0 -p tcp --dport 8053 -j ACCEPT
expect closed 172.17.0.2 8053 "container directly after docker reorders FORWARD"

install_tunnel_isolation up0
[[ "$(iptables -S INPUT | grep -c CHAMELEON_TUN_IN)" == 1 ]] || { echo "FAIL  reinstall duplicated INPUT jump"; failed=1; }
remove_tunnel_isolation
echo "== after removal"
expect open 10.10.0.1 2222 "VPS tunnel address"
iptables -S | grep -q CHAMELEON_TUN && { echo "FAIL  chains left behind"; failed=1; }
kill $(jobs -p) 2>/dev/null || true
[[ "$failed" == 0 ]] && echo "CHAMELEON_VPS_ISOLATION_REGRESSION=PASS"
exit "$failed"
MODEL
