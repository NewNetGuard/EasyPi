#!/usr/bin/env bash
set -euo pipefail

export PATH="/usr/sbin:/usr/bin:/sbin:/bin"

[[ "${EUID}" -eq 0 ]] || {
  echo "start_installer_job.sh must run as root" >&2
  exit 1
}

JOB_ID="${1:-}"
MODE="${2:-}"
[[ "${JOB_ID}" =~ ^[0-9a-f]{32}$ ]] || {
  echo "Invalid installer job id" >&2
  exit 1
}
[[ $# -le 2 ]] || {
  echo "Too many arguments" >&2
  exit 1
}
[[ -z "${MODE}" || "${MODE}" == "--no-block" ]] || {
  echo "Invalid installer start mode" >&2
  exit 1
}

UNIT="easypi-installer@${JOB_ID}.service"
if [[ "${MODE}" == "--no-block" ]]; then
  exec /usr/bin/systemctl start --no-block "${UNIT}"
fi
exec /usr/bin/systemctl start "${UNIT}"
