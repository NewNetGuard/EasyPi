#!/usr/bin/env bash
set -euo pipefail

service_name="easypi-chameleon-client"
status_file="/run/easypi-stealth/status/status.json"
route_table="51821"
packet_mark="333858"

old_pid="$(systemctl show --property MainPID --value "$service_name")"
started_ms="$(date +%s%3N)"

systemctl restart "$service_name"

connected="false"
new_pid="0"
for _ in $(seq 1 60); do
    new_pid="$(systemctl show --property MainPID --value "$service_name")"
    if systemctl is-active --quiet "$service_name" \
        && [[ "$new_pid" != "0" && "$new_pid" != "$old_pid" ]] \
        && [[ -r "$status_file" ]] \
        && python3 - "$status_file" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    status = json.load(handle)
raise SystemExit(0 if status.get("connected") is True else 1)
PY
    then
        if ip link show cham0 >/dev/null 2>&1 \
            && ip route show table "$route_table" | grep -q '^default dev cham0' \
            && ss -Htpn | grep -F "pid=$new_pid" | grep -F ':443' >/dev/null; then
            connected="true"
            break
        fi
    fi
    sleep 0.5
done

if [[ "$connected" != "true" ]]; then
    systemctl status "$service_name" --no-pager >&2 || true
    [[ -r "$status_file" ]] && cat "$status_file" >&2 || true
    exit 1
fi

connected_ms="$(date +%s%3N)"
reconnect_ms="$((connected_ms - started_ms))"
rx_before="$(cat /sys/class/net/cham0/statistics/rx_bytes)"
tx_before="$(cat /sys/class/net/cham0/statistics/tx_bytes)"

ping -c 1 -W 5 -m "$packet_mark" 1.1.1.1 >/dev/null

rx_after="$(cat /sys/class/net/cham0/statistics/rx_bytes)"
tx_after="$(cat /sys/class/net/cham0/statistics/tx_bytes)"

if (( rx_after <= rx_before || tx_after <= tx_before )); then
    printf 'Chameleon counters did not advance: rx=%s->%s tx=%s->%s\n' \
        "$rx_before" "$rx_after" "$tx_before" "$tx_after" >&2
    exit 1
fi

health="$(curl --fail --silent --show-error http://127.0.0.1:8000/health)"

python3 - "$old_pid" "$new_pid" "$reconnect_ms" \
    "$rx_before" "$rx_after" "$tx_before" "$tx_after" "$health" <<'PY'
import json
import sys

print(json.dumps({
    "result": "PASS",
    "old_pid": int(sys.argv[1]),
    "new_pid": int(sys.argv[2]),
    "reconnect_ms": int(sys.argv[3]),
    "rx_bytes_before": int(sys.argv[4]),
    "rx_bytes_after": int(sys.argv[5]),
    "tx_bytes_before": int(sys.argv[6]),
    "tx_bytes_after": int(sys.argv[7]),
    "backend_health": json.loads(sys.argv[8]),
}, sort_keys=True))
PY
