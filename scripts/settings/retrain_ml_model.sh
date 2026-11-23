#!/bin/bash
#
# Retrain the on-device domain LANGUAGE MODEL on THIS network's own data, now.
#
# Invoked via the secure runner (runs as root). It retrains in the LIVE
# NetProtection data dir and then hands the freshly-written model file back to
# that dir's owner, so the running (non-root) DNS engine keeps managing it and
# hot-reloads it on the next request. Nothing leaves the device.
#
# The trainer only REPLACES the model if its false-positive gate passes
# (well-known sites must stay natural), so a retrain can never start blocking
# real sites. Prints the trainer's JSON result on the last line.
#
set -euo pipefail

# Deploy root (…/scripts/settings/retrain_ml_model.sh -> …)
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
cd "$ROOT"
export EASYPI_ROOT="$ROOT"

# Prefer the standard config so we resolve the same data dir the engine uses.
if [[ -z "${NETPROTECTION_CONFIG:-}" && -f "/opt/EasyPi/config/netprotection.toml" ]]; then
    export NETPROTECTION_CONFIG="/opt/EasyPi/config/netprotection.toml"
fi

# Use the app's venv interpreter: the bare `python3` (system) lacks pydantic and
# the engine's other deps. The venv python resolves its own site-packages.
PY="$ROOT/backend/.venv/bin/python3"
[[ -x "$PY" ]] || PY="python3"

RUN=("$PY")
if [[ $EUID -eq 0 ]]; then
    RUN=(
        /usr/sbin/runuser -u easypi --
        /usr/bin/env -i
        "PATH=/usr/bin:/bin"
        "EASYPI_ROOT=$ROOT"
        "NETPROTECTION_CONFIG=${NETPROTECTION_CONFIG:-}"
        "$PY"
    )
fi

"${RUN[@]}" - <<'PY'
import json, os, sys
from pathlib import Path

ROOT = os.environ.get("EASYPI_ROOT", "/opt/EasyPi")
sys.path.insert(0, ROOT)

try:
    from easypi_netprotection.config import get_settings
    from easypi_netprotection.heuristics import ml_trainer
except Exception as exc:  # import/setup failure -> report as JSON, exit clean
    print(json.dumps({"success": False, "error": "import failed: %s" % exc}))
    raise SystemExit(0)

data_dir = Path(get_settings().NETPROTECTION_DATA_DIR)
res = ml_trainer.train_on_device(str(data_dir))

# Return ownership of the just-written model to the data dir's owner (we are root).
try:
    st = data_dir.stat()
    model = data_dir / ml_trainer.MODEL_FILENAME
    if model.exists():
        os.chown(model, st.st_uid, st.st_gid)
except Exception as exc:
    res.setdefault("warn", "chown skipped: %s" % exc)

print(json.dumps(res))
PY
