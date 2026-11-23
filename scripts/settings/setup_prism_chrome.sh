#!/bin/bash
# Opt-in installation; never edits routing, firewall or Chameleon.
set -euo pipefail
umask 077
[[ $EUID == 0 ]] || { echo 'Root installation required' >&2; exit 1; }
root=/opt/EasyPi
binary="$root/backend/bin/easypi-backend"
action="${1:-}"
if [[ "$action" == disable ]]; then
    systemctl disable --now easypi-prism-chrome.service
    echo 'Server observer stopped. Also disable Chrome observation in Mobile to restore browser settings.'
    exit 0
fi
[[ "$action" == install && -f "${2:-}" && ! -L "$2" ]] || {
    echo 'Usage: setup_prism_chrome.sh install ROOT_OWNED_CONFIG | disable' >&2; exit 1;
}
config=$(realpath -- "$2")
# The new binary must recognize the mode before any configuration is replaced.
"$binary" --prism-tls-chrome --config "$config" --check
getent passwd easypi-prism-tls >/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin easypi-prism-tls
getent group easypi >/dev/null
backup="/var/lib/easypi/rollback/chrome-$(date -u +%Y%m%dT%H%M%SZ)"
install -d -m 0700 "$backup"
for path in /etc/easypi/chrome-bridge.json /etc/systemd/system/easypi-prism-chrome.service; do
    if [[ -e "$path" ]]; then cp -a -- "$path" "$backup/$(basename "$path")"; fi
done
systemctl is-enabled easypi-prism-chrome.service > "$backup/enabled-before" 2>/dev/null || true
install -d -m 0750 -o root -g easypi /etc/easypi
install -m 0640 -o root -g easypi "$config" /etc/easypi/chrome-bridge.json
install -m 0644 "$root/templates/systemd/easypi-prism-chrome.service" /etc/systemd/system/easypi-prism-chrome.service
systemctl daemon-reload
systemctl enable --now easypi-prism-chrome.service
systemctl is-active --quiet easypi-prism-chrome.service
echo "Observer installed; configuration backup: $backup"
