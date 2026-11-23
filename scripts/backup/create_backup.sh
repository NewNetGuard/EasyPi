#!/bin/bash
set -euo pipefail

# EasyPi backup creation

PROFILE="${1:-config}"
[[ $# -le 1 ]] || {
  echo "Usage: $0 [config|full]" >&2
  exit 1
}

case "$PROFILE" in
  config)
    exec /opt/EasyPi/scripts/backup/create_config_backup.sh
    ;;
  full)
    exec /opt/EasyPi/scripts/backup/create_full_backup.sh
    ;;
  *)
    echo "ERROR: backup profile must be config or full" >&2
    exit 1
    ;;
esac
