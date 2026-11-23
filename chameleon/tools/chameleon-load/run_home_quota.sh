#!/bin/bash
# Reproduces the Mobile Link home-server condition: a direct-mode server on
# 127.0.0.1:9081 with the home tunnel's limits (max_connections 256,
# max_sessions_per_source 8), every device arriving from 127.0.0.1 as through
# the Mobile Link agent. Streams target a denied address on purpose: 503 means
# the session quota refused the device, 403 means the device was admitted.
# usage: run_home_quota.sh <server-binary> <load.test> <devices> <out.json>
# Needs the stand (keys, registry, cert) prepared by prepare.py in $CLB_DIR, ~/clb by default.
set -euo pipefail
SERVER="$1"; LOAD="$2"; N="$3"; OUT="$4"
W="${CLB_DIR:-$HOME/clb}"
H=$W/home
rm -rf "$H"; mkdir -p "$H/site"
cp "$SERVER" "$H/chameleon-server"; chmod +x "$H/chameleon-server"
cp "$W/srv/site/index.html" "$H/site/"
python3 - "$W/srv/server_config.json" "$H/server_config.json" <<'PY'
import json, sys
cfg = json.load(open(sys.argv[1]))
cfg.update({"listen_address": "127.0.0.1", "listen_port": 9081, "bootstrap_port": 9082,
            "frontend_mode": "direct", "max_connections": 256, "max_sessions_per_source": 8,
            "max_requests_per_session": 32, "probe_target": "127.0.0.1:9443"})
json.dump(cfg, open(sys.argv[2], "w"), indent=2)
PY
(cd "$H" && exec ./chameleon-server > "$H/server.log" 2>&1) &
SRV=$!
trap 'kill $SRV 2>/dev/null' EXIT
sleep 2
LOAD_MODE=idle LOAD_DEVICES="$N" LOAD_SERVER=127.0.0.1:9081 LOAD_ORIGIN=127.0.0.1:9 \
LOAD_KEYS="$W/keys.json" LOAD_WARM_S=5 LOAD_MEASURE_S=20 LOAD_OUT="$OUT" \
    "$LOAD" -test.run '^TestChameleonLoad$' -test.timeout 10m > "$H/load.log" 2>&1 || true
python3 - "$OUT" "$H/server.log" <<'PY'
import json, sys
r = json.load(open(sys.argv[1]))
errors = {k[7:]: v for k, v in r.get("counts", {}).items() if k.startswith("error: ")}
refusals = sum(1 for l in open(sys.argv[2]) if "per-source session limit" in l)
print(f"devices={r['devices']} connected={r['connected']} stream errors={errors} "
      f"server per-source refusals logged={refusals}")
PY
