#!/usr/bin/env bash
set -euo pipefail

state_path="/var/lib/easypi/prism/flowgraph.jsonl"
lan_interface="$(awk -F= '$1 == "PRISM_INTERFACE" {print $2}' /etc/default/easypi-prism-flowgraph)"
gateway="$(ip -4 route show default dev "$lan_interface" | awk 'NR == 1 {print $3}')"
test_domain="example.com"
server_ip="$(getent ahostsv4 "$test_domain" | awk 'NR == 1 {print $1}')"
namespace="ep-prism-$$"
test_interface="eppr$$"
test_ip=""

cleanup() {
    ip netns delete "$namespace" >/dev/null 2>&1 || true
    ip link delete "$test_interface" >/dev/null 2>&1 || true
}
trap cleanup EXIT

[[ -r "$state_path" && -n "$lan_interface" && -n "$gateway" && -n "$server_ip" ]]
systemctl is-active --quiet easypi-prism-flowgraph

for final_octet in 250 251 252 253 254; do
    candidate="${gateway%.*}.${final_octet}"
    if [[ "$candidate" != "$gateway" ]] && \
        arping -D -q -I "$lan_interface" -c 2 -w 2 "$candidate" >/dev/null 2>&1; then
        test_ip="$candidate"
        break
    fi
done
[[ -n "$test_ip" ]]

baseline_timestamp="$(date +%s.%N)"
ip netns add "$namespace"
ip link add "$test_interface" link "$lan_interface" type macvlan mode bridge
ip link set "$test_interface" netns "$namespace"
ip netns exec "$namespace" ip link set lo up
ip netns exec "$namespace" ip address add "$test_ip/24" dev "$test_interface"
ip netns exec "$namespace" ip link set "$test_interface" up
ip netns exec "$namespace" ip route add default via "$gateway" dev "$test_interface"

ip netns exec "$namespace" curl \
    --http1.1 \
    --connect-timeout 8 \
    --max-time 20 \
    --silent \
    --show-error \
    --output /dev/null \
    --resolve "$test_domain:443:$server_ip" \
    "https://$test_domain/"

evidence=""
for _ in $(seq 1 40); do
    evidence="$(python3 - "$state_path" "$test_ip" "$test_domain" "$baseline_timestamp" <<'PY'
import json
import sys

path, client_ip, domain, baseline = sys.argv[1], sys.argv[2], sys.argv[3], float(sys.argv[4])
matched = None
with open(path, encoding="utf-8") as handle:
    for raw in handle:
        try:
            row = json.loads(raw)
        except (TypeError, ValueError):
            continue
        if (
            row.get("event") == "flow_assessment"
            and row.get("client_ip") == client_ip
            and row.get("server_name") == domain
            and float(row.get("timestamp", 0)) >= baseline
        ):
            matched = row
if matched:
    print(json.dumps({
        "client_ip": matched.get("client_ip"),
        "confidence": matched.get("confidence"),
        "event": matched.get("event"),
        "server_ip": matched.get("server_ip"),
        "server_name": matched.get("server_name"),
        "verdict": matched.get("verdict"),
    }, sort_keys=True))
PY
)"
    [[ -n "$evidence" ]] && break
    sleep 0.25
done

[[ -n "$evidence" ]]
printf '{"result":"PASS","observation":%s}\n' "$evidence"
