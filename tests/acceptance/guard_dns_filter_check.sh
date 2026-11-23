#!/usr/bin/env bash
set -euo pipefail

data_dir="/opt/EasyPi/data/netprotection"
flow_db="$data_dir/flow_log.db"
blocklist="$data_dir/effective_blocklist.txt"
# Loopback exercises the same verdict pipeline while avoiding the appliance's
# unknown-device admission policy for queries originating from its own LAN IP.
dns_ip="127.0.0.1"
blocked_domain="$(python3 - "$blocklist" <<'PY'
import re
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    for raw in handle:
        domain = raw.strip().lower()
        if domain and not domain.startswith("#") and re.fullmatch(r"[a-z0-9.-]+", domain):
            print(domain)
            break
PY
)"

[[ -n "$dns_ip" && -n "$blocked_domain" ]]
baseline_id="$(python3 - "$flow_db" <<'PY'
import sqlite3
import sys

with sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True) as connection:
    print(connection.execute("SELECT COALESCE(MAX(id), 0) FROM flow_log").fetchone()[0])
PY
)"
blocked_answer="$(dig @"$dns_ip" "$blocked_domain" A +time=2 +tries=1 +noall +comments +answer)"
allowed_answer="$(dig @"$dns_ip" example.com A +time=2 +tries=1 +noall +comments +answer)"

grep -q 'status: NXDOMAIN' <<<"$blocked_answer"
grep -q 'status: NOERROR' <<<"$allowed_answer"
grep -Eq '^example\.com\..*[[:space:]]A[[:space:]]' <<<"$allowed_answer"

evidence=""
for _ in $(seq 1 20); do
    evidence="$(python3 - "$flow_db" "$blocked_domain" "$baseline_id" <<'PY'
import json
import sqlite3
import sys

with sqlite3.connect(f"file:{sys.argv[1]}?mode=ro", uri=True) as connection:
    connection.row_factory = sqlite3.Row
    row = connection.execute(
        "SELECT domain, status, verdict, response_code, matcher_id "
        "FROM flow_log WHERE domain = ? AND id > ? ORDER BY id DESC LIMIT 1",
        (sys.argv[2], int(sys.argv[3])),
    ).fetchone()
if row:
    print(json.dumps(dict(row), sort_keys=True))
PY
)"
    [[ -n "$evidence" ]] && break
    sleep 0.25
done

[[ -n "$evidence" ]]
python3 - "$evidence" <<'PY'
import json
import sys

row = json.loads(sys.argv[1])
if row.get("verdict") != "deny" or row.get("response_code") != "NXDOMAIN":
    raise SystemExit(f"unexpected blocked verdict: {row}")
PY

printf '{"result":"PASS","dns_server":"%s","blocked":%s,"allowed":"example.com"}\n' \
    "$dns_ip" "$evidence"
