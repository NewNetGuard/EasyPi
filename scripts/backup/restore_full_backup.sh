#!/bin/bash
set -euo pipefail

[[ $# -eq 1 ]] || {
  echo "Usage: $0 <backup_file>" >&2
  exit 1
}

exec /opt/EasyPi/scripts/backup/restore_config_backup.sh "$1"
