#!/usr/bin/env bash
set -euo pipefail

# EasyPi NetProtection Native Installer
# This script installs NetProtection as a native systemd service.

info() { echo -e "\033[0;32m==>\033[0m $1"; }
warn() { echo -e "\033[0;33m==>\033[0m $1"; }

EASYPI_PREFIX="${EASYPI_PREFIX:-/opt/EasyPi}"
EASYPI_USER="${EASYPI_USER:-easypi}"
EASYPI_GROUP="${EASYPI_GROUP:-easypi}"
SERVICE_FILE="/etc/systemd/system/easypi-netprotection.service"
SERVICE_TEMPLATE="${EASYPI_PREFIX}/templates/systemd/easypi-netprotection.service"
BACKUP_TS="$(date +%Y%m%d-%H%M%S)"

check_port_53() {
  if ! command -v ss >/dev/null 2>&1; then
    warn "ss not available; skipping port 53 availability check"
    return 0
  fi

  local listeners
  listeners="$(ss -tulpn 2>/dev/null | awk '$5 ~ /:53$/ {print}')"
  if [[ -n "${listeners}" ]]; then
    warn "Port 53 is already in use:"
    echo "${listeners}"
    if echo "${listeners}" | grep -q "systemd-resolved"; then
      warn "systemd-resolved is using port 53. Disable the stub listener and retry:"
      warn "  sudo sed -i 's/^#DNSStubListener=yes/DNSStubListener=no/' /etc/systemd/resolved.conf"
      warn "  sudo systemctl restart systemd-resolved"
      warn "  sudo ln -sf /run/systemd/resolve/resolv.conf /etc/resolv.conf"
    elif echo "${listeners}" | grep -q "unbound"; then
      warn "unbound is using port 53. Move it to 5354 and retry:"
      warn "  sudo /opt/EasyPi/scripts/setup/setup_unbound.sh"
    elif echo "${listeners}" | grep -q "dnsmasq"; then
      warn "dnsmasq is using port 53. Disable it and retry:"
      warn "  sudo systemctl disable --now dnsmasq"
    fi
    warn "After freeing port 53, run: sudo systemctl restart easypi-netprotection"
    return 1
  fi

  return 0
}

info "Installing NetProtection as a systemd service..."

if [[ -f "${SERVICE_FILE}" ]]; then
  cp -a "${SERVICE_FILE}" "${SERVICE_FILE}.bak-${BACKUP_TS}"
  info "Backup created: ${SERVICE_FILE}.bak-${BACKUP_TS}"
fi

if [[ ! -f "${SERVICE_TEMPLATE}" || -L "${SERVICE_TEMPLATE}" ]]; then
  echo "ERROR: hardened NetProtection service template is missing" >&2
  exit 1
fi

# Install the single reviewed hardened unit. Keeping a generated second copy
# caused production installations to silently lose the sandbox directives.
install -o root -g root -m 0644 "${SERVICE_TEMPLATE}" "${SERVICE_FILE}"
sed -i \
  -e "s|/opt/EasyPi|${EASYPI_PREFIX}|g" \
  -e "s|User=easypi|User=${EASYPI_USER}|g" \
  -e "s|Group=easypi|Group=${EASYPI_GROUP}|g" \
  -e "s|easypi:easypi|${EASYPI_USER}:${EASYPI_GROUP}|g" \
  "${SERVICE_FILE}"

systemctl daemon-reload
if ! check_port_53; then
  warn "NetProtection service cannot start due to port 53 conflict."
  systemctl disable easypi-netprotection >/dev/null 2>&1 || true
  exit 1
fi

info "Reloading systemd and starting NetProtection..."
systemctl enable easypi-netprotection
systemctl restart easypi-netprotection
sleep 2
if ! systemctl is-active --quiet easypi-netprotection; then
  warn "NetProtection did not remain active after startup."
  systemctl status easypi-netprotection --no-pager -l || true
  exit 1
fi

info "NetProtection service installed and started."
