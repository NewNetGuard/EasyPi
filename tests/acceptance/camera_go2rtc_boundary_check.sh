#!/bin/bash
set -euo pipefail

GO2RTC_BIN="/opt/go2rtc/go2rtc"
[[ -x "$GO2RTC_BIN" ]] || { echo "go2rtc binary is unavailable" >&2; exit 1; }

TEST_DIR="$(mktemp -d /tmp/easypi-camera-boundary.XXXXXX)"
PID=""
cleanup() {
  if [[ -n "$PID" ]]; then
    kill "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
  fi
  rm -rf "$TEST_DIR"
}
trap cleanup EXIT

cat > "$TEST_DIR/go2rtc.yaml" <<'EOF'
app:
  modules: [api, ws, rtsp, mp4]
api:
  listen: "127.0.0.1:21984"
  username: "boundary_user"
  password: "boundary_password_12345678901234567890"
  local_auth: true
  allow_paths: [/api, /api/streams, /api/ws]
rtsp:
  listen: "127.0.0.1:28554"
log:
  level: disabled
streams:
  easypi_discovery: "rtsp://127.0.0.1:9/unavailable"
EOF

"$GO2RTC_BIN" -c "$TEST_DIR/go2rtc.yaml" >/dev/null 2>&1 &
PID="$!"
for _ in $(seq 1 40); do
  CODE="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:21984/api || true)"
  [[ "$CODE" != "000" ]] && break
  sleep 0.1
done

UNAUTH="$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:21984/api)"
AUTH="$(curl -s -u boundary_user:boundary_password_12345678901234567890 \
  -o /dev/null -w '%{http_code}' http://127.0.0.1:21984/api)"
PATCH="$(curl -s -u boundary_user:boundary_password_12345678901234567890 \
  -X PATCH \
  'http://127.0.0.1:21984/api/streams?name=easypi_discovery&src=rtsp%3A%2F%2F127.0.0.1%3A9%2Fchanged' \
  -o /dev/null -w '%{http_code}')"

[[ "$UNAUTH" == "401" ]] || { echo "unauthenticated API returned HTTP $UNAUTH" >&2; exit 1; }
[[ "$AUTH" == "200" ]] || { echo "authenticated API returned HTTP $AUTH" >&2; exit 1; }
[[ "$PATCH" == "200" ]] || { echo "temporary stream update returned HTTP $PATCH" >&2; exit 1; }

echo "CAMERA_GO2RTC_BOUNDARY=PASS"
