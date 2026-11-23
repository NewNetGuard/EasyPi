#!/bin/bash
# Remote lifecycle helper for the standalone Chameleon Mobile Link relay.
# This script is uploaded over host-key-pinned SSH and executed as root.

set -euo pipefail

export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
unset PYTHONPATH PYTHONHOME BASH_ENV ENV CDPATH GLOBIGNORE
umask 077

PREFIX="/opt/easypi-mobile-link"
CONFIG_DIR="/etc/easypi-mobile-link"
STATE_DIR="/var/lib/easypi-mobile-link"
SERVICE="easypi-mobile-link-relay.service"
REFRESH_SERVICE="easypi-mobile-link-cert-refresh.service"
REFRESH_TIMER="easypi-mobile-link-cert-refresh.timer"
SERVICE_USER="easypi-mobile-link"
SERVICE_GROUP="easypi-mobile-link"
CONFIG_FILE="${CONFIG_DIR}/relay.json"
SOURCE_CERT_FILE="${CONFIG_DIR}/certificate-source"
CERT_FILE="${CONFIG_DIR}/tls.crt"
KEY_FILE="${CONFIG_DIR}/tls.key"
SYSCTL_FILE="/etc/sysctl.d/98-easypi-mobile-link.conf"
MODULE_FILE="/etc/modules-load.d/easypi-mobile-link-bbr.conf"

die() { printf 'EASYPI_MOBILE_LINK_ERROR:%s\n' "$1" >&2; exit 1; }

[[ "$EUID" -eq 0 ]] || die "root privileges are required"
[[ $# -ge 1 ]] || die "missing action"
action="$1"
shift

validate_private_input() {
  local path="$1" caller_uid="${SUDO_UID:-0}" uid mode
  [[ -f "$path" && ! -L "$path" ]] || die "deployment input is unsafe"
  uid="$(stat -c '%u' -- "$path")"
  mode="$(stat -c '%a' -- "$path")"
  [[ "$uid" == "0" || "$uid" == "$caller_uid" ]] || die "deployment input owner is invalid"
  (( (8#$mode & 8#022) == 0 )) || die "deployment input permissions are unsafe"
}

copy_certificate() {
  local live_dir cert_source key_source
  [[ -s "$SOURCE_CERT_FILE" && ! -L "$SOURCE_CERT_FILE" ]] || die "certificate source is unavailable"
  live_dir="$(<"$SOURCE_CERT_FILE")"
  [[ "$live_dir" == /etc/letsencrypt/live/* && "$live_dir" != *$'\n'* ]] || die "certificate source is invalid"
  cert_source="${live_dir}/fullchain.pem"
  key_source="${live_dir}/privkey.pem"
  [[ -s "$cert_source" && -s "$key_source" ]] || die "Let's Encrypt certificate was not found on the VPS"
  install -o root -g "$SERVICE_GROUP" -m 0440 "$cert_source" "$CERT_FILE"
  install -o root -g "$SERVICE_GROUP" -m 0440 "$key_source" "$KEY_FILE"
}

tune_tcp_transport() {
  # One Mobile Link connection carries every inner Protection flow. Mobile
  # networks can reorder packets heavily, so loss-based congestion control can
  # collapse the complete tunnel after a single burst. BBR with fq pacing keeps
  # the carrier making progress, while the larger reordering threshold avoids
  # treating a short reordering run as wholesale loss. Immediate ACK handling
  # also keeps Android's upload sender moving when return-path ACKs are reordered.
  cat > "$SYSCTL_FILE" <<'SYSCTL'
net.core.rmem_max = 67108864
net.core.wmem_max = 67108864
net.ipv4.tcp_rmem = 4096 87380 67108864
net.ipv4.tcp_wmem = 4096 65536 67108864
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_reordering = 127
net.ipv4.tcp_recovery = 0
net.ipv4.tcp_backlog_ack_defer = 0
net.ipv4.tcp_comp_sack_delay_ns = 0
SYSCTL
  printf '%s\n' tcp_bbr > "$MODULE_FILE"
  chown root:root "$SYSCTL_FILE" "$MODULE_FILE"
  chmod 0644 "$SYSCTL_FILE" "$MODULE_FILE"
  modprobe tcp_bbr >/dev/null 2>&1 || true
  sysctl -q -p "$SYSCTL_FILE" >/dev/null 2>&1 || true
}

write_units() {
  cat > "/etc/systemd/system/${SERVICE}" <<'UNIT'
[Unit]
Description=EasyPi Chameleon Mobile Link VPS Relay
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=300
StartLimitBurst=10

[Service]
Type=simple
User=easypi-mobile-link
Group=easypi-mobile-link
UMask=0077
ExecStart=/opt/easypi-mobile-link/chameleon-mobile-link-relay -config /etc/easypi-mobile-link/relay.json
Restart=on-failure
RestartSec=5s
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectSystem=strict
ProtectHome=yes
ProtectControlGroups=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectClock=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictSUIDSGID=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_INET AF_INET6
SystemCallArchitectures=native

[Install]
WantedBy=multi-user.target
UNIT
  cat > "/etc/systemd/system/${REFRESH_SERVICE}" <<'UNIT'
[Unit]
Description=Refresh EasyPi Mobile Link TLS certificate copy

[Service]
Type=oneshot
ExecStart=/opt/easypi-mobile-link/chameleon-mobile-link-relay-maintenance refresh-certificate
NoNewPrivileges=yes
PrivateTmp=yes
ProtectHome=yes
UNIT
  cat > "/etc/systemd/system/${REFRESH_TIMER}" <<'UNIT'
[Unit]
Description=Daily EasyPi Mobile Link certificate refresh

[Timer]
OnBootSec=10min
OnUnitActiveSec=1d
RandomizedDelaySec=30min
Persistent=true

[Install]
WantedBy=timers.target
UNIT
  cat > "${PREFIX}/chameleon-mobile-link-relay-maintenance" <<'SCRIPT'
#!/bin/bash
set -euo pipefail
export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
[[ "$EUID" -eq 0 && "${1:-}" == "refresh-certificate" ]] || exit 2
source_file=/etc/easypi-mobile-link/certificate-source
[[ -s "$source_file" && ! -L "$source_file" ]] || exit 1
live_dir="$(<"$source_file")"
[[ "$live_dir" == /etc/letsencrypt/live/* && "$live_dir" != *$'\n'* ]] || exit 1
install -o root -g easypi-mobile-link -m 0440 "$live_dir/fullchain.pem" /etc/easypi-mobile-link/tls.crt
install -o root -g easypi-mobile-link -m 0440 "$live_dir/privkey.pem" /etc/easypi-mobile-link/tls.key
systemctl try-restart easypi-mobile-link-relay.service
SCRIPT
  chown root:root "${PREFIX}/chameleon-mobile-link-relay-maintenance"
  chmod 0755 "${PREFIX}/chameleon-mobile-link-relay-maintenance"
  chown root:root "/etc/systemd/system/${SERVICE}" "/etc/systemd/system/${REFRESH_SERVICE}" "/etc/systemd/system/${REFRESH_TIMER}"
  chmod 0644 "/etc/systemd/system/${SERVICE}" "/etc/systemd/system/${REFRESH_SERVICE}" "/etc/systemd/system/${REFRESH_TIMER}"
}

print_status() {
  local installed=false enabled=false active=false agent_port="" mobile_port="" domain=""
  [[ -x "${PREFIX}/chameleon-mobile-link-relay" && -s "$CONFIG_FILE" ]] && installed=true
  systemctl is-enabled --quiet "$SERVICE" 2>/dev/null && enabled=true || true
  systemctl is-active --quiet "$SERVICE" 2>/dev/null && active=true || true
  if [[ -s "$CONFIG_FILE" && ! -L "$CONFIG_FILE" ]]; then
    readarray -t values < <(/usr/bin/python3 - "$CONFIG_FILE" <<'PY'
import json, sys
from pathlib import Path
d = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(str(d.get("agent_listen", "")).rsplit(":", 1)[-1])
print(str(d.get("mobile_listen", "")).rsplit(":", 1)[-1])
routes = d.get("host_routes", {})
print(next(iter(routes), ""))
PY
)
    agent_port="${values[0]:-}"
    mobile_port="${values[1]:-}"
    domain="${values[2]:-}"
  fi
  printf 'EASYPI_MOBILE_LINK_RESULT installed=%s enabled=%s active=%s agent_port=%q mobile_port=%q domain=%q\n' \
    "$installed" "$enabled" "$active" "$agent_port" "$mobile_port" "$domain"
}

case "$action" in
  deploy)
    [[ $# -eq 2 ]] || die "deploy requires a private JSON configuration and relay binary"
    input_config="$1"
    input_binary="$2"
    validate_private_input "$input_config"
    validate_private_input "$input_binary"
    command -v python3 >/dev/null 2>&1 || die "Python 3 is required"
    command -v systemctl >/dev/null 2>&1 || die "systemd is required"
    mapfile -t validated < <(/usr/bin/python3 - "$input_config" <<'PY'
import ipaddress
import json
import re
import sys
from pathlib import Path

d = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
required = {"domain", "agent_port", "mobile_port", "installation_id", "secret", "tunnel_installation_id", "tunnel_secret"}
if set(d) != required:
    raise SystemExit("invalid deployment configuration")
domain = str(d["domain"]).strip().lower().rstrip(".")
labels = domain.split(".")
if not labels or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", x) for x in labels):
    raise SystemExit("invalid relay domain")
agent_port, mobile_port = int(d["agent_port"]), int(d["mobile_port"])
if agent_port == mobile_port or any(p < 1024 or p > 65535 for p in (agent_port, mobile_port)):
    raise SystemExit("invalid relay ports")
installation_id, secret = str(d["installation_id"]), str(d["secret"])
tunnel_installation_id, tunnel_secret = str(d["tunnel_installation_id"]), str(d["tunnel_secret"])
if (not re.fullmatch(r"[0-9a-f]{32}", installation_id) or not re.fullmatch(r"[0-9a-f]{64}", secret)
        or not re.fullmatch(r"[0-9a-f]{32}", tunnel_installation_id) or not re.fullmatch(r"[0-9a-f]{64}", tunnel_secret)):
    raise SystemExit("invalid relay identity")
print(domain)
print(agent_port)
print(mobile_port)
print(installation_id)
print(secret)
print(tunnel_installation_id)
print(tunnel_secret)
PY
    )
    [[ ${#validated[@]} -eq 7 ]] || die "invalid deployment configuration"
    domain="${validated[0]}"; agent_port="${validated[1]}"; mobile_port="${validated[2]}"
    installation_id="${validated[3]}"; secret="${validated[4]}"
    tunnel_installation_id="${validated[5]}"; tunnel_secret="${validated[6]}"
    cert_dir="/etc/letsencrypt/live/${domain}"
    [[ -s "${cert_dir}/fullchain.pem" && -s "${cert_dir}/privkey.pem" ]] \
      || die "install a Let's Encrypt certificate for the Mobile Link domain first"
    getent group "$SERVICE_GROUP" >/dev/null 2>&1 || groupadd --system "$SERVICE_GROUP"
    id -u "$SERVICE_USER" >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin --gid "$SERVICE_GROUP" "$SERVICE_USER"
    install -d -o root -g root -m 0755 "$PREFIX"
    install -d -o root -g "$SERVICE_GROUP" -m 0750 "$CONFIG_DIR"
    install -d -o root -g root -m 0700 "$STATE_DIR"
    install -o root -g root -m 0755 "$input_binary" "${PREFIX}/chameleon-mobile-link-relay"
    printf '%s\n' "$cert_dir" > "$SOURCE_CERT_FILE"
    chown root:root "$SOURCE_CERT_FILE"; chmod 0600 "$SOURCE_CERT_FILE"
    copy_certificate
    tune_tcp_transport
    temporary="$(mktemp "${CONFIG_DIR}/.relay.XXXXXX")"
    trap 'rm -f -- "${temporary:-}"' EXIT HUP INT TERM
    /usr/bin/python3 - "$temporary" "$agent_port" "$mobile_port" "$domain" "$installation_id" "$secret" "$tunnel_installation_id" "$tunnel_secret" <<'PY'
import json, os, sys
path, agent_port, mobile_port, domain, installation_id, secret, tunnel_installation_id, tunnel_secret = sys.argv[1:]
with open(path, "w", encoding="utf-8") as handle:
    json.dump({
        "agent_listen": f"0.0.0.0:{agent_port}",
        "mobile_listen": f"0.0.0.0:{mobile_port}",
        "base_domain": domain,
        "tls_cert_file": "/etc/easypi-mobile-link/tls.crt",
        "tls_key_file": "/etc/easypi-mobile-link/tls.key",
        "installations": {installation_id: secret},
        "host_routes": {domain: installation_id},
        "tunnel_agent_listen": f"0.0.0.0:{int(agent_port) + 2}",
        "tunnel_mobile_listen": f"0.0.0.0:{int(mobile_port) + 2}",
        "tunnel_installations": {tunnel_installation_id: tunnel_secret},
        "tunnel_host_routes": {domain: tunnel_installation_id},
        "prism_agent_listen": f"0.0.0.0:{int(agent_port) + 3}",
        "prism_mobile_listen": f"0.0.0.0:{int(mobile_port) + 3}",
        "prism_installations": {tunnel_installation_id: tunnel_secret},
    }, handle, separators=(",", ":"))
    handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
PY
    chown root:"$SERVICE_GROUP" "$temporary"; chmod 0440 "$temporary"
    mv -f -- "$temporary" "$CONFIG_FILE"
    trap - EXIT HUP INT TERM
    write_units
    systemctl daemon-reload
    systemctl enable "$SERVICE" >/dev/null
    systemctl restart "$SERVICE"
    systemctl enable --now "$REFRESH_TIMER" >/dev/null
    if command -v ufw >/dev/null 2>&1 && ufw status 2>/dev/null | grep -q '^Status: active'; then
      ufw allow "${agent_port}/tcp" comment 'EasyPi Mobile Link agent' >/dev/null
      ufw allow "${mobile_port}/tcp" comment 'EasyPi Mobile Link mobile' >/dev/null
      ufw allow "$((agent_port + 2))/tcp" comment 'EasyPi Mobile tunnel agent' >/dev/null
      ufw allow "$((mobile_port + 2))/tcp" comment 'EasyPi Mobile tunnel client' >/dev/null
      ufw allow "$((agent_port + 3))/udp" comment 'EasyPi PrismLink agent' >/dev/null
      ufw allow "$((mobile_port + 3))/udp" comment 'EasyPi PrismLink mobile' >/dev/null
      printf '%s/tcp\n%s/tcp\n%s/tcp\n%s/tcp\n%s/udp\n%s/udp\n' "$agent_port" "$mobile_port" "$((agent_port + 2))" "$((mobile_port + 2))" "$((agent_port + 3))" "$((mobile_port + 3))" > "${STATE_DIR}/ufw-ports"
      chown root:root "${STATE_DIR}/ufw-ports"; chmod 0600 "${STATE_DIR}/ufw-ports"
    fi
    sleep 1
    systemctl is-active --quiet "$SERVICE" || die "Mobile Link relay did not start"
    print_status
    ;;
  status)
    [[ $# -eq 0 ]] || die "status accepts no arguments"
    print_status
    ;;
  restart)
    [[ $# -eq 0 ]] || die "restart accepts no arguments"
    systemctl restart "$SERVICE" || die "relay restart failed"
    print_status
    ;;
  disable)
    [[ $# -eq 0 ]] || die "disable accepts no arguments"
    systemctl disable --now "$SERVICE" >/dev/null 2>&1 || true
    print_status
    ;;
  uninstall)
    [[ $# -eq 0 ]] || die "uninstall accepts no arguments"
    systemctl disable --now "$SERVICE" "$REFRESH_TIMER" >/dev/null 2>&1 || true
    if [[ -s "${STATE_DIR}/ufw-ports" && ! -L "${STATE_DIR}/ufw-ports" ]] && command -v ufw >/dev/null 2>&1; then
      while IFS= read -r managed_port; do
        [[ "$managed_port" =~ ^([0-9]{4,5})/(tcp|udp)$ ]] || continue
        (( BASH_REMATCH[1] >= 1024 && BASH_REMATCH[1] <= 65535 )) || continue
        ufw --force delete allow "$managed_port" >/dev/null 2>&1 || true
      done < "${STATE_DIR}/ufw-ports"
    fi
    rm -f -- "/etc/systemd/system/${SERVICE}" "/etc/systemd/system/${REFRESH_SERVICE}" "/etc/systemd/system/${REFRESH_TIMER}" \
      "$SYSCTL_FILE" "$MODULE_FILE"
    rm -rf -- "$PREFIX" "$CONFIG_DIR" "$STATE_DIR"
    systemctl daemon-reload
    print_status
    ;;
  *) die "unsupported action" ;;
esac
