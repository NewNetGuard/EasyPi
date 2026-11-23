#!/bin/bash
set -euo pipefail

ACTION="${1:-}"
CONFIG="/opt/go2rtc/go2rtc.yaml"

die() {
  echo "ERROR: $*" >&2
  exit 1
}

[[ "$ACTION" == "apply" && $# -eq 1 ]] || die "usage: go2rtc_config.sh apply"
[[ -d /opt/go2rtc ]] || die "go2rtc is not installed"
getent group go2rtc >/dev/null 2>&1 || die "go2rtc group is missing"

/usr/bin/python3 /opt/EasyPi/scripts/utils/go2rtc_config.py "$CONFIG"

systemctl restart go2rtc

# systemctl restart returns as soon as the process is launched. Camera cards
# can request their first snapshot immediately after the API creates a camera,
# so wait until both loopback listeners are actually accepting connections.
ready=false
for _attempt in {1..100}; do
  if /usr/bin/ss -H -ltn 'sport = :1984' | /usr/bin/grep -q . \
    && /usr/bin/ss -H -ltn 'sport = :8554' | /usr/bin/grep -q .; then
    ready=true
    break
  fi
  sleep 0.1
done

[[ "$ready" == "true" ]] || die "go2rtc did not open its API and RTSP listeners"
echo '{"success":true}'
