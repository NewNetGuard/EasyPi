#!/usr/bin/env bash
set -euo pipefail

updater="/opt/EasyPi/scripts/maintenance/apply_update.sh"
sentinel="/opt/EasyPi/backend/main.py"
marker="/opt/EasyPi/.update-in-progress"
work="$(mktemp -d /tmp/easypi-signature-reject.XXXXXX)"
cleanup() {
    rm -rf -- "$work"
}
trap cleanup EXIT

[[ -f "$updater" && ! -L "$updater" && -f "$sentinel" && ! -e "$marker" ]]
archive="$work/release.tar.gz"
signature="$work/release.tar.gz.sig"
printf 'unsigned EasyPi acceptance payload\n' > "$archive"
head -c 256 /dev/zero > "$signature"

hash_before="$(sha256sum "$sentinel" | awk '{print $1}')"
pid_before="$(systemctl show --property MainPID --value easypi-backend)"
set +e
output="$(bash "$updater" --mode archive --archive "$archive" --sig "$signature" 2>&1)"
result=$?
set -e
hash_after="$(sha256sum "$sentinel" | awk '{print $1}')"
pid_after="$(systemctl show --property MainPID --value easypi-backend)"

[[ $result -ne 0 ]]
grep -q 'SIGNATURE VERIFICATION FAILED' <<<"$output"
[[ "$hash_after" == "$hash_before" ]]
[[ "$pid_after" == "$pid_before" ]]
[[ ! -e "$marker" ]]
systemctl is-active --quiet easypi-backend

printf '{"result":"PASS","signature_rejected":true,"code_unchanged":true,"backend_not_restarted":true}\n'
