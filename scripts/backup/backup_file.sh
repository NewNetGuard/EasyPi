#!/bin/bash
set -euo pipefail

ACTION="${1:-}"
NAME="${2:-}"
BACKUP_DIR="/opt/EasyPi/backups"

[[ $# -eq 2 && "$ACTION" =~ ^(delete|verify)$ ]] || {
  echo "Usage: $0 <delete|verify> <generated-backup-name>" >&2
  exit 1
}
[[ "$NAME" =~ ^(config|full|pre-restore)-[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{2}-[0-9]{2}(-[0-9]{2})?\.(tar\.gz|epibak)$ ]] || {
  echo "ERROR: invalid backup name" >&2
  exit 1
}

path="${BACKUP_DIR}/${NAME}"
[[ -f "$path" && ! -L "$path" ]] || {
  echo "ERROR: backup not found" >&2
  exit 1
}
[[ "$(stat -c '%u' -- "$path")" == "0" ]] || {
  echo "ERROR: backup is not root-owned" >&2
  exit 1
}

case "$ACTION" in
  delete)
    rm -f -- "$path"
    ;;
  verify)
    [[ "$NAME" == *.epibak ]] || {
      echo "ERROR: privileged verification is only required for encrypted backups" >&2
      exit 1
    }
    exec /opt/EasyPi/backend/.venv/bin/python \
      /opt/EasyPi/scripts/utils/backup_crypto.py verify "$path"
    ;;
esac
