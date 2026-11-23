#!/bin/bash
#
# Narrow privileged helper for EasyPi gateway mode.
# This script is executed through scripts/runner as root and intentionally
# exposes only fixed destination writes needed by gateway management.

set -euo pipefail

ACTION="${1:-}"

die() {
  echo "ERROR: $*" >&2
  exit 1
}

TMP_SOURCE_FD=""

open_tmp_file() {
  local source="$1"
  exec {TMP_SOURCE_FD}<"$source" || die "cannot open source"
  local fd_path="/proc/self/fd/${TMP_SOURCE_FD}"
  local real
  real="$(realpath -- "$fd_path" 2>/dev/null)" || die "cannot resolve source"
  case "$real" in
    /tmp/*) ;;
    *) die "source must be under /tmp" ;;
  esac
  [[ "$(stat -Lc '%F' -- "$fd_path" 2>/dev/null)" == "regular file" ]] ||
    die "source must be a regular file"
}

install_root_file() {
  local source="$1"
  local dest="$2"
  local mode="$3"
  open_tmp_file "$source"
  install -o root -g root -m "$mode" "/proc/self/fd/${TMP_SOURCE_FD}" "$dest"
  exec {TMP_SOURCE_FD}<&-
}

install_gateway_service() {
  local tmp
  tmp="$(mktemp)"
  cat > "$tmp" <<'UNIT'
[Unit]
Description=EasyPi Gateway Loop Fix
After=network-online.target NetworkManager.service
Wants=network-online.target

[Service]
Type=oneshot
ExecStart=/bin/bash /opt/EasyPi/scripts/setup/gateway_fix.sh

[Install]
WantedBy=multi-user.target
UNIT
  install -o root -g root -m 644 "$tmp" /etc/systemd/system/easypi-gateway-fix.service
  rm -f "$tmp"
}

install_gateway_timer() {
  local tmp
  tmp="$(mktemp)"
  cat > "$tmp" <<'UNIT'
[Unit]
Description=EasyPi Gateway Loop Fix Timer
After=network-online.target

[Timer]
OnBootSec=30
OnUnitActiveSec=60
Unit=easypi-gateway-fix.service

[Install]
WantedBy=timers.target
UNIT
  install -o root -g root -m 644 "$tmp" /etc/systemd/system/easypi-gateway-fix.timer
  rm -f "$tmp"
}

case "$ACTION" in
  install-iptables-rules)
    [[ $# -eq 2 ]] || die "usage: gateway_config.sh install-iptables-rules /tmp/source"
    mkdir -p /etc/iptables
    install_root_file "$2" /etc/iptables/rules.v4 644
    ;;

  install-gateway-service)
    [[ $# -eq 1 ]] || die "usage: gateway_config.sh install-gateway-service"
    install_gateway_service
    ;;

  install-gateway-timer)
    [[ $# -eq 1 ]] || die "usage: gateway_config.sh install-gateway-timer"
    install_gateway_timer
    ;;

  chmod-gateway-fix)
    [[ $# -eq 1 ]] || die "usage: gateway_config.sh chmod-gateway-fix"
    chmod 755 /opt/EasyPi/scripts/setup/gateway_fix.sh
    ;;

  persist-ip-forward)
    [[ $# -eq 2 ]] || die "usage: gateway_config.sh persist-ip-forward 0|1"
    case "$2" in
      0) value=0 ;;
      1) value=1 ;;
      *) die "ip_forward value must be 0 or 1" ;;
    esac
    if [[ "$value" == "1" ]]; then
      printf '%s\n' \
        'net.ipv4.ip_forward = 1' \
        'net.ipv4.conf.all.send_redirects = 0' \
        'net.ipv4.conf.default.send_redirects = 0' \
        > /etc/sysctl.d/99-easypi-gateway.conf
    else
      printf 'net.ipv4.ip_forward = 0\n' > /etc/sysctl.d/99-easypi-gateway.conf
    fi
    chown root:root /etc/sysctl.d/99-easypi-gateway.conf
    chmod 644 /etc/sysctl.d/99-easypi-gateway.conf
    ;;

  *)
    die "unknown action: ${ACTION:-missing}"
    ;;
esac
