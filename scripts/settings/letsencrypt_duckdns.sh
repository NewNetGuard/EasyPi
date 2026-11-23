#!/usr/bin/env bash
#
# Trusted Let's Encrypt certificate for EasyPi encrypted DNS (DoH/DoT) via a free
# DuckDNS domain. Runner-invoked (root). Non-interactive.
#
# Why this exists (vs scripts/setup/letsencrypt.sh, which targets the nginx web UI):
#   * The DNS engine (easypi-netprotection) runs as the NON-root `easypi` user and
#     CANNOT read /etc/letsencrypt (root-only privkey). So we COPY fullchain+privkey
#     into /opt/EasyPi/certs as root:easypi 640/644 — symlinks would break it.
#   * The DoH/DoT SSL context is built once at service start, so after issue/renew we
#     MUST restart easypi-netprotection (a plain nginx reload is not enough).
#   * DuckDNS A-record is kept pointed at the box's PUBLIC IP by a systemd timer, so
#     the domain resolves from anywhere (Android Private DNS over mobile).
#
# Subcommands:
#   issue <fqdn> [email]                   token is read from stdin
#   status                                 JSON: mode/domain/expiry/ddns
#
# Env: LE_STAGING=1 uses the Let's Encrypt staging CA (for testing; not trusted).
#
set -uo pipefail

CERT_DIR="/opt/EasyPi/certs"
EASYPI_GROUP="${EASYPI_GROUP:-easypi}"
ENV_FILE="/etc/easypi/duckdns.env"
AUTH_HOOK="/etc/easypi/duckdns-auth.sh"
CLEAN_HOOK="/etc/easypi/duckdns-cleanup.sh"
DDNS_HOOK="/etc/easypi/duckdns-update.sh"
DEPLOY_HOOK="/etc/letsencrypt/renewal-hooks/deploy/easypi-doh.sh"

json() { printf '%s\n' "$1"; }
jesc() { printf '%s' "${1:-}" | sed 's/\\/\\\\/g; s/"/\\"/g'; }

duckdns_update_ip() {
  local subdomain="$1" token="$2"
  curl --fail --silent --show-error --config - >/dev/null <<EOF
url = "https://www.duckdns.org/update"
get
data-urlencode = "domains=${subdomain}"
data-urlencode = "token=${token}"
data-urlencode = "ip="
EOF
}

# ---- status -------------------------------------------------------------------
cert_status() {
  local mode="none" domain="" expiry="" issuer="" ddns="inactive"
  if [[ -f "$CERT_DIR/cert.pem" ]]; then
    issuer=$(openssl x509 -in "$CERT_DIR/cert.pem" -noout -issuer 2>/dev/null | sed 's/^issuer=//')
    expiry=$(openssl x509 -in "$CERT_DIR/cert.pem" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')
    if echo "$issuer" | grep -qiE "let's encrypt|R1[0-9]|E[0-9]|staging"; then mode="letsencrypt"; else mode="self-signed"; fi
  fi
  [[ -f "$CERT_DIR/.letsencrypt" ]] && domain=$(cat "$CERT_DIR/.letsencrypt" 2>/dev/null)
  systemctl is-active --quiet easypi-duckdns.timer 2>/dev/null && ddns="active"
  json "{\"mode\":\"$(jesc "$mode")\",\"domain\":\"$(jesc "$domain")\",\"expiry\":\"$(jesc "$expiry")\",\"issuer\":\"$(jesc "$issuer")\",\"ddns\":\"$(jesc "$ddns")\"}"
}

# ---- install the copy-to-easypi + restart deploy hook -------------------------
install_deploy_hook() {
  mkdir -p "$(dirname "$DEPLOY_HOOK")"
  cat > "$DEPLOY_HOOK" <<HOOK
#!/bin/bash
# Installed by EasyPi. After any cert renewal, copy the fresh cert into the DNS
# engine's readable cert dir and restart it so DoH/DoT serve the new cert.
set -e
D=\$(cat "$CERT_DIR/.letsencrypt" 2>/dev/null)
[ -n "\$D" ] || exit 0
LE="/etc/letsencrypt/live/\$D"
[ -f "\$LE/fullchain.pem" ] || exit 0
install -o root -g "$EASYPI_GROUP" -m 644 "\$LE/fullchain.pem" "$CERT_DIR/cert.pem"
install -o root -g "$EASYPI_GROUP" -m 640 "\$LE/privkey.pem"  "$CERT_DIR/key.pem"
systemctl reload nginx 2>/dev/null || true
systemctl restart easypi-netprotection 2>/dev/null || true
HOOK
  chmod 755 "$DEPLOY_HOOK"
}

# ---- install DuckDNS manual-challenge hooks -----------------------------------
install_challenge_hooks() {
  mkdir -p /etc/easypi
  cat > "$AUTH_HOOK" <<'HOOK'
#!/bin/bash
set -euo pipefail
source /etc/easypi/duckdns.env
[[ "${CERTBOT_VALIDATION:-}" =~ ^[A-Za-z0-9_-]{1,512}$ ]] || exit 1
curl --fail --silent --show-error --config - >/dev/null <<EOF
url = "https://www.duckdns.org/update"
get
data-urlencode = "domains=${DUCKDNS_SUBDOMAIN}"
data-urlencode = "token=${DUCKDNS_TOKEN}"
data-urlencode = "txt=${CERTBOT_VALIDATION}"
data-urlencode = "verbose=true"
EOF
sleep 45
HOOK
  cat > "$CLEAN_HOOK" <<'HOOK'
#!/bin/bash
set -euo pipefail
source /etc/easypi/duckdns.env
curl --fail --silent --show-error --config - >/dev/null <<EOF
url = "https://www.duckdns.org/update"
get
data-urlencode = "domains=${DUCKDNS_SUBDOMAIN}"
data-urlencode = "token=${DUCKDNS_TOKEN}"
data-urlencode = "txt=removed"
data-urlencode = "clear=true"
EOF
HOOK
  chmod 700 "$AUTH_HOOK" "$CLEAN_HOOK"
}

# ---- install the DDNS updater (keeps A-record on the public IP) ----------------
install_ddns_timer() {
  cat > "$DDNS_HOOK" <<'HOOK'
#!/bin/bash
set -euo pipefail
source /etc/easypi/duckdns.env
curl --fail --silent --show-error --config - >/dev/null <<EOF
url = "https://www.duckdns.org/update"
get
data-urlencode = "domains=${DUCKDNS_SUBDOMAIN}"
data-urlencode = "token=${DUCKDNS_TOKEN}"
data-urlencode = "ip="
EOF
HOOK
  chmod 700 "$DDNS_HOOK"

  cat > /etc/systemd/system/easypi-duckdns.service <<'UNIT'
[Unit]
Description=EasyPi DuckDNS A-record updater
After=network-online.target
Wants=network-online.target
[Service]
Type=oneshot
# Empty ip= makes DuckDNS use the request source IP = this box's public IP.
ExecStart=/etc/easypi/duckdns-update.sh
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
CapabilityBoundingSet=
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
UNIT
  cat > /etc/systemd/system/easypi-duckdns.timer <<'UNIT'
[Unit]
Description=Refresh EasyPi DuckDNS A-record
[Timer]
OnBootSec=60
OnUnitActiveSec=5min
[Install]
WantedBy=timers.target
UNIT
  systemctl daemon-reload
  systemctl enable --now easypi-duckdns.timer >/dev/null 2>&1 || true
}

# ---- issue --------------------------------------------------------------------
issue() {
  local fqdn="${1:-}" email="${2:-}" token="" extra=""
  if ! IFS= read -r token && [[ -z "$token" ]]; then
    json '{"success":false,"error":"DuckDNS token is required on stdin"}'; exit 0
  fi
  if IFS= read -r extra; then
    json '{"success":false,"error":"DuckDNS token must be a single line"}'; exit 0
  fi
  if [[ -z "$fqdn" || -z "$token" ]]; then
    json '{"success":false,"error":"usage: issue <fqdn> [email], token on stdin"}'; exit 0
  fi
  fqdn="${fqdn,,}"
  if [[ ! "$fqdn" =~ ^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.duckdns\.org$ ]]; then
    json '{"success":false,"error":"domain must end with .duckdns.org"}'; exit 0
  fi
  if [[ ! "$token" =~ ^[A-Za-z0-9_-]{16,128}$ ]]; then
    json '{"success":false,"error":"invalid DuckDNS token"}'; exit 0
  fi
  if [[ -n "$email" && ! "$email" =~ ^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}$ ]]; then
    json '{"success":false,"error":"invalid email address"}'; exit 0
  fi
  local sub="${fqdn%.duckdns.org}"; sub="${sub##*.}"

  if ! command -v certbot >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq certbot >/dev/null 2>&1 || {
      json '{"success":false,"error":"could not install certbot"}'; exit 0; }
  fi

  # Persist DuckDNS creds (root-only) for the challenge hooks + DDNS timer.
  mkdir -p /etc/easypi
  umask 077
  {
    printf 'DUCKDNS_SUBDOMAIN=%q\n' "$sub"
    printf 'DUCKDNS_TOKEN=%q\n' "$token"
    printf 'DUCKDNS_FQDN=%q\n' "$fqdn"
  } > "$ENV_FILE"
  chmod 600 "$ENV_FILE"

  install_challenge_hooks
  install_ddns_timer

  # Point the A-record at the public IP up front (so it resolves right away).
  duckdns_update_ip "$sub" "$token"

  local staging=()
  [[ "${LE_STAGING:-0}" == "1" ]] && staging=(--staging)
  local em=(--register-unsafely-without-email)
  [[ -n "$email" ]] && em=(--email "$email")

  local certbot_log certbot_detail
  certbot_log="$(mktemp /run/easypi-certbot.XXXXXX)" || {
    json '{"success":false,"error":"could not create certbot log"}'; exit 0; }
  chmod 600 "$certbot_log"
  if ! certbot certonly --manual --preferred-challenges dns \
        --manual-auth-hook "$AUTH_HOOK" --manual-cleanup-hook "$CLEAN_HOOK" \
        --non-interactive --agree-tos "${em[@]}" "${staging[@]}" \
        -d "$fqdn" >"$certbot_log" 2>&1; then
    certbot_detail="$(tail -3 "$certbot_log")"
    rm -f -- "$certbot_log"
    json "{\"success\":false,\"error\":\"certbot failed\",\"detail\":\"$(jesc "$certbot_detail")\"}"; exit 0
  fi
  rm -f -- "$certbot_log"

  local le="/etc/letsencrypt/live/$fqdn"
  if [[ ! -f "$le/fullchain.pem" ]]; then
    json '{"success":false,"error":"certificate not found after issue"}'; exit 0
  fi

  # Copy into the DNS engine's readable cert dir (NOT symlink — easypi must read it).
  install -o root -g "$EASYPI_GROUP" -m 644 "$le/fullchain.pem" "$CERT_DIR/cert.pem"
  install -o root -g "$EASYPI_GROUP" -m 640 "$le/privkey.pem"  "$CERT_DIR/key.pem"
  echo "$fqdn" > "$CERT_DIR/.letsencrypt"

  install_deploy_hook
  systemctl enable --now certbot.timer >/dev/null 2>&1 || true
  systemctl restart easypi-netprotection 2>/dev/null || true

  local expiry
  expiry=$(openssl x509 -in "$CERT_DIR/cert.pem" -noout -enddate 2>/dev/null | sed 's/^notAfter=//')
  json "{\"success\":true,\"domain\":\"$(jesc "$fqdn")\",\"expiry\":\"$(jesc "$expiry")\",\"staging\":${LE_STAGING:-0}}"
}

case "${1:-status}" in
  issue)  shift; issue "$@" ;;
  status) cert_status ;;
  *) json '{"success":false,"error":"unknown subcommand"}'; exit 0 ;;
esac
