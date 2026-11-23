#!/bin/sh
# Capture many Chameleon connection openings on an isolated WSL stand.
#
#   client (netns clo-dev) --30 ms round trip--> nginx 10.200.0.1:443 (stand
#   build and config from tools/chameleon-load) -> chameleon-server (nginx mode)
#
# Two captures: next to the client (<out>.client.pcap), where an ISP's DPI
# sits, and next to the server (<out>).
#
# The client test opens OPEN_CONNECTIONS fresh sessions one after another and
# replaces each one's connection OPEN_EPOCHS times, so the capture holds both
# kinds of opening: the first session setup and an epoch change.
#
# usage (root in WSL): run_opening.sh <stand-dir> <out.pcap>
#   <stand-dir> is a directory prepared by tools/chameleon-load/prepare.py
#   (nginx, ngx/, srv/, keys.json). Binaries are rebuilt from this checkout.
# env: OPEN_CONNECTIONS (default 20), OPEN_EPOCHS (default 3)
set -eu
W="$1"; OUT="$2"
HERE=$(cd "$(dirname "$0")" && pwd)
SRC=$(cd "$HERE/../.." && pwd)
GO=${GO:-/usr/local/go/bin/go}
[ -x "$GO" ] || GO=$(command -v go)

cleanup() {
    [ -n "${DUMP:-}" ] && kill "$DUMP" 2>/dev/null || true
    [ -n "${DUMP_CLIENT:-}" ] && kill "$DUMP_CLIENT" 2>/dev/null || true
    "$W/nginx" -p "$W/ngx/" -c conf/nginx.conf -s stop 2>/dev/null || true
    # The stand server is whatever listens on its backend port.
    fuser -k 9080/tcp >/dev/null 2>&1 || true
    sleep 1
    ip netns del clo-dev 2>/dev/null || true
    ip link del clo-vps 2>/dev/null || true
}
trap cleanup EXIT
cleanup

# ---- binaries from this checkout ----
(cd "$SRC" && runuser -u sb -- "$GO" build -o "$W/srv/chameleon-server" ./server)
(cd "$SRC" && runuser -u sb -- "$GO" test -c -o "$W/open.test" ./clientcore)

# ---- network ----
ip netns add clo-dev
ip link add clo-vps type veth peer name clo-devp
ip link set clo-devp netns clo-dev
ip addr add 10.200.0.1/30 dev clo-vps
ip link set clo-vps up
ip -n clo-dev addr add 10.200.0.2/30 dev clo-devp
ip -n clo-dev link set lo up
ip -n clo-dev link set clo-devp up
# No offloads: the capture shows packets as they would be on the wire.
ethtool -K clo-vps tso off gso off gro off >/dev/null 2>&1 || true
ip netns exec clo-dev ethtool -K clo-devp tso off gso off gro off >/dev/null 2>&1 || true
# The whole 30 ms round trip is put on the server's side of the link. tcpdump
# sees outgoing packets only after their qdisc, so a delay on the client's
# interface would move the "client" vantage point into the middle of the path.
tc qdisc add dev clo-vps root netem delay 30ms limit 200000

# ---- stand ----
(cd "$W/srv" && exec runuser -u sb -- ./chameleon-server > "$W/opening-server.log" 2>&1) &
SERVER=$!
"$W/nginx" -p "$W/ngx/" -c conf/nginx.conf
sleep 2
if ! ss -ltn | grep -q '127.0.0.1:9080 ' || ! ss -ltn | grep -q '10.200.0.1:443 '; then
    echo "FATAL: server or nginx did not start"; tail -3 "$W/opening-server.log"; exit 1
fi

# Two vantage points: next to the server (OUT) and next to the client
# (OUT with .client before the extension), where an ISP's DPI would sit.
tcpdump -i clo-vps -s 0 -U -w "$OUT" 'tcp port 443' > "$W/opening-tcpdump.log" 2>&1 &
DUMP=$!
ip netns exec clo-dev tcpdump -i clo-devp -s 0 -U -w "${OUT%.pcap}.client.pcap" 'tcp port 443' \
    > "$W/opening-tcpdump-client.log" 2>&1 &
DUMP_CLIENT=$!
sleep 1
ip netns exec clo-dev runuser -u sb -- env OPEN_KEYS="$W/keys.json" OPEN_SERVER=10.200.0.1:443 \
    OPEN_CONNECTIONS="${OPEN_CONNECTIONS:-20}" OPEN_EPOCHS="${OPEN_EPOCHS:-3}" \
    "$W/open.test" -test.run '^TestOpeningCapture$' -test.timeout 30m -test.v > "$W/opening-client.log" 2>&1 \
    || { echo "client failed"; tail -20 "$W/opening-client.log"; }
sleep 1
kill "$DUMP" "$DUMP_CLIENT"; DUMP=; DUMP_CLIENT=
sleep 1
tail -2 "$W/opening-client.log"
cat "$W/opening-tcpdump.log" | tail -2
