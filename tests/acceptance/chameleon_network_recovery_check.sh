#!/usr/bin/env bash
set -euo pipefail

service_name="easypi-chameleon-client"
status_file="/run/easypi-stealth/status/status.json"
packet_mark="333858"
client_pid="$(systemctl show --property MainPID --value "$service_name")"
server_ip="$(python3 - <<'PY'
import json

with open("/run/easypi-stealth/client.conf", encoding="utf-8") as handle:
    print(json.load(handle)["server_route_ip"])
PY
)"

rule=(-p tcp -d "$server_ip" --dport 443 -j REJECT --reject-with tcp-reset)
blocked="false"
cleanup() {
    if [[ "$blocked" == "true" ]]; then
        iptables -D OUTPUT "${rule[@]}" 2>/dev/null || true
    fi
}
trap cleanup EXIT

iptables -I OUTPUT 1 "${rule[@]}"
blocked="true"
# Close the already-established carrier and inject one packet so the outage is
# observed immediately instead of waiting for the next randomized cover frame.
ss -K dst "$server_ip" dport = 443 >/dev/null 2>&1 || true
ping -c 1 -W 1 -m "$packet_mark" 1.1.1.1 >/dev/null 2>&1 || true

observed_down="false"
for _ in $(seq 1 30); do
    if ! python3 - "$status_file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    status = json.load(handle)
raise SystemExit(0 if status.get("connected") is True else 1)
PY
    then
        observed_down="true"
        break
    fi
    sleep 0.5
done

if [[ "$observed_down" != "true" ]]; then
    echo "Chameleon did not report the forced carrier outage" >&2
    exit 1
fi

iptables -D OUTPUT "${rule[@]}"
blocked="false"
unblocked_ms="$(date +%s%3N)"

recovered="false"
for _ in $(seq 1 90); do
    if python3 - "$status_file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    status = json.load(handle)
raise SystemExit(0 if status.get("connected") is True else 1)
PY
    then
        recovered="true"
        break
    fi
    sleep 0.5
done

if [[ "$recovered" != "true" ]]; then
    cat "$status_file" >&2
    exit 1
fi

current_pid="$(systemctl show --property MainPID --value "$service_name")"
[[ "$current_pid" == "$client_pid" ]]
ip route show table 51821 | grep -q '^default dev cham0'

rx_before="$(cat /sys/class/net/cham0/statistics/rx_bytes)"
tx_before="$(cat /sys/class/net/cham0/statistics/tx_bytes)"
ping -c 1 -W 8 -m "$packet_mark" 1.1.1.1 >/dev/null
rx_after="$(cat /sys/class/net/cham0/statistics/rx_bytes)"
tx_after="$(cat /sys/class/net/cham0/statistics/tx_bytes)"
(( rx_after > rx_before && tx_after > tx_before ))

recovered_ms="$(date +%s%3N)"
python3 - "$client_pid" "$((recovered_ms - unblocked_ms))" \
    "$rx_before" "$rx_after" "$tx_before" "$tx_after" <<'PY'
import json
import sys

print(json.dumps({
    "result": "PASS",
    "same_pid": True,
    "client_pid": int(sys.argv[1]),
    "recovery_ms": int(sys.argv[2]),
    "rx_bytes_before": int(sys.argv[3]),
    "rx_bytes_after": int(sys.argv[4]),
    "tx_bytes_before": int(sys.argv[5]),
    "tx_bytes_after": int(sys.argv[6]),
}, sort_keys=True))
PY
