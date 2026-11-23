#!/bin/bash
# Schedule a restart of the fixed EasyPi service stack outside the backend.

set -euo pipefail

export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
umask 077

SELF="/opt/EasyPi/scripts/maintenance/restart_services.sh"
TRANSIENT_UNIT="easypi-restart-services"

fail() {
    echo "[ERROR] $*" >&2
    exit 1
}

[[ "${EUID}" -eq 0 ]] || fail "This helper must run as root"
[[ "$#" -eq 1 ]] || fail "Usage: restart_services.sh schedule"

case "$1" in
    schedule)
        if systemctl is-active --quiet "${TRANSIENT_UNIT}.timer" \
            || systemctl is-active --quiet "${TRANSIENT_UNIT}.service"; then
            echo "EasyPi service restart is already scheduled"
            exit 0
        fi

        systemctl reset-failed "${TRANSIENT_UNIT}.service" 2>/dev/null || true
        systemd-run \
            --quiet \
            --collect \
            --unit="${TRANSIENT_UNIT}" \
            --on-active=5s \
            --property=Type=oneshot \
            --property=TimeoutStartSec=180 \
            "${SELF}" execute
        echo "EasyPi service restart scheduled"
        ;;
    execute)
        # The execute branch is valid only inside the transient systemd unit.
        # The runner clears INVOCATION_ID, so callers cannot bypass the delay.
        [[ -n "${INVOCATION_ID:-}" ]] || fail "Execute mode requires the scheduled systemd unit"

        systemctl daemon-reload
        for service in easypi-netprotection easypi-taildrop-import nginx easypi-backend; do
            if systemctl cat "${service}.service" >/dev/null 2>&1; then
                systemctl reset-failed "${service}.service" 2>/dev/null || true
                systemctl restart "${service}.service"
            fi
        done
        ;;
    *)
        fail "Unsupported operation"
        ;;
esac
