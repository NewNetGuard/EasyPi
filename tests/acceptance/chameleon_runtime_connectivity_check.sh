#!/usr/bin/env bash
set -euo pipefail

checker="/opt/EasyPi/scripts/maintenance/verify_runtime_health.py"
[[ -f "$checker" && ! -L "$checker" ]] || {
    echo "Installed runtime health checker is missing or unsafe" >&2
    exit 1
}

/usr/bin/python3 "$checker" --require-connectivity
