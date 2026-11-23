#!/bin/bash
set -euo pipefail

export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
unset PYTHONPATH PYTHONHOME BASH_ENV ENV CDPATH GLOBIGNORE
umask 077

[[ $# -eq 0 ]] || {
    echo "usage: tailscale_control.sh (JSON is read from stdin)" >&2
    exit 2
}

exec /usr/bin/python3 /opt/EasyPi/scripts/utils/tailscale_control.py
