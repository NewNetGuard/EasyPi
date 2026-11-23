#!/bin/bash
# Configure the local Chameleon Mobile Link agent. The transport secret is
# generated locally and never accepted through argv, the environment, or HTTP.

set -euo pipefail

export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
unset PYTHONPATH PYTHONHOME BASH_ENV ENV CDPATH GLOBIGNORE
umask 077

CONFIG_DIR="/etc/easypi-mobile-link"
CONFIG_FILE="${CONFIG_DIR}/agent.json"
SECRET_FILE="${CONFIG_DIR}/agent.secret"
TUNNEL_CONFIG_FILE="${CONFIG_DIR}/tunnel-agent.json"
TUNNEL_SECRET_FILE="${CONFIG_DIR}/tunnel-agent.secret"
SERVICE="easypi-mobile-link-agent.service"
TUNNEL_SERVICE="easypi-mobile-home-tunnel-agent.service"
HOME_SERVICE="easypi-mobile-home-tunnel.service"
HOME_DIR="/etc/easypi-mobile-home"
HOME_CONFIG="${HOME_DIR}/server_config.json"
SERVICE_USER="easypi-mobile-link"
SERVICE_GROUP="easypi-mobile-link"
LOCAL_ADDRESS="127.0.0.1:9445"
TUNNEL_LOCAL_ADDRESS="127.0.0.1:9081"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)"
EASYPI_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
NGINX_TEMPLATE="${EASYPI_ROOT}/templates/nginx/easypi-mobile-link.conf"
NGINX_AVAILABLE="/etc/nginx/sites-available/easypi-mobile-link"
NGINX_ENABLED="/etc/nginx/sites-enabled/easypi-mobile-link"

die() { echo "$1" >&2; exit 1; }

[[ "$EUID" -eq 0 ]] || die "root required"
[[ $# -ge 1 ]] || die "usage: mobile_link_agent.sh <configure|enable|disable|status|rotate-secret|registration|ensure-endpoint|ensure-home|home-profile>"
action="$1"
shift

validate_endpoint() {
  /usr/bin/python3 - "$1" "$2" <<'PY'
import ipaddress
import re
import sys

endpoint, server_name = sys.argv[1:]
if any(ch.isspace() for ch in endpoint + server_name) or len(endpoint) > 320 or len(server_name) > 253:
    raise SystemExit("invalid Mobile Link relay address")
host, sep, port_text = endpoint.rpartition(":")
if not sep or not host or not port_text.isdigit() or not 1 <= int(port_text) <= 65535:
    raise SystemExit("relay address must be HOST:PORT")
try:
    ipaddress.ip_address(host.strip("[]"))
except ValueError:
    labels = host.rstrip(".").split(".")
    if not labels or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in labels):
        raise SystemExit("invalid relay host")
labels = server_name.rstrip(".").split(".")
if not labels or any(not re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label) for label in labels):
    raise SystemExit("invalid TLS server name")
print(endpoint)
print(server_name.rstrip("."))
PY
}

ensure_secret() {
  install -d -o root -g "$SERVICE_GROUP" -m 0750 "$CONFIG_DIR"
  [[ ! -L "$SECRET_FILE" ]] || die "secret path must not be a symlink"
  if [[ ! -s "$SECRET_FILE" ]]; then
    temporary="$(mktemp "${CONFIG_DIR}/.agent-secret.XXXXXX")"
    trap 'rm -f -- "${temporary:-}"' EXIT HUP INT TERM
    /usr/bin/openssl rand -hex 32 > "$temporary"
    chown root:"$SERVICE_GROUP" "$temporary"
    chmod 0440 "$temporary"
    mv -f -- "$temporary" "$SECRET_FILE"
    trap - EXIT HUP INT TERM
  fi
  chown root:"$SERVICE_GROUP" "$SECRET_FILE"
  chmod 0440 "$SECRET_FILE"
  temporary="$(mktemp "${CONFIG_DIR}/.tunnel-secret.XXXXXX")"
  /usr/bin/python3 - "$SECRET_FILE" "$temporary" <<'PY'
import hashlib, hmac, os, sys
from pathlib import Path
source = bytes.fromhex(Path(sys.argv[1]).read_text(encoding="ascii").strip())
derived = hmac.new(source, b"easypi-mobile-home-tunnel-relay-v1", hashlib.sha256).hexdigest()
with open(sys.argv[2], "w", encoding="ascii") as handle:
    handle.write(derived + "\n"); handle.flush(); os.fsync(handle.fileno())
PY
  chown root:"$SERVICE_GROUP" "$temporary"; chmod 0440 "$temporary"
  mv -f -- "$temporary" "$TUNNEL_SECRET_FILE"
}

installation_id() {
  /usr/bin/python3 - "$SECRET_FILE" <<'PY'
import hashlib
import hmac
import sys
from pathlib import Path

secret = bytes.fromhex(Path(sys.argv[1]).read_text(encoding="ascii").strip())
if len(secret) != 32:
    raise SystemExit("invalid Mobile Link secret")
print(hmac.new(secret, b"easypi-mobile-link-installation-v1", hashlib.sha256).hexdigest()[:32])
PY
}

write_config() {
  local relay_address="$1" server_name="$2" temporary
  temporary="$(mktemp "${CONFIG_DIR}/.agent-config.XXXXXX")"
  trap 'rm -f -- "${temporary:-}"' EXIT HUP INT TERM
  /usr/bin/python3 - "$temporary" "$relay_address" "$server_name" "$LOCAL_ADDRESS" "$SECRET_FILE" <<'PY'
import json
import os
import sys

path, relay, server_name, local, secret = sys.argv[1:]
with open(path, "w", encoding="utf-8") as handle:
    json.dump({
        "relay_address": relay,
        "server_name": server_name,
        "local_address": local,
        "secret_file": secret,
    }, handle, separators=(",", ":"))
    handle.write("\n")
    handle.flush()
    os.fsync(handle.fileno())
PY
  chown root:"$SERVICE_GROUP" "$temporary"
  chmod 0440 "$temporary"
  mv -f -- "$temporary" "$CONFIG_FILE"
  local host="${relay_address%:*}" port="${relay_address##*:}" tunnel_relay prism_relay
  tunnel_relay="${host}:$((port + 2))"
  prism_relay="${host}:$((port + 3))"
  temporary="$(mktemp "${CONFIG_DIR}/.tunnel-agent-config.XXXXXX")"
  /usr/bin/python3 - "$temporary" "$tunnel_relay" "$server_name" "$TUNNEL_LOCAL_ADDRESS" "$TUNNEL_SECRET_FILE" "$prism_relay" <<'PY'
import json, os, sys
path, relay, server_name, local, secret, prism_relay = sys.argv[1:]
with open(path, "w", encoding="utf-8") as handle:
    json.dump({"relay_address": relay, "server_name": server_name, "local_address": local, "secret_file": secret,
               "prism_relay_address": prism_relay, "prism_local_address": "127.0.0.1:9083"}, handle, separators=(",", ":"))
    handle.write("\n"); handle.flush(); os.fsync(handle.fileno())
PY
  chown root:"$SERVICE_GROUP" "$temporary"; chmod 0440 "$temporary"
  mv -f -- "$temporary" "$TUNNEL_CONFIG_FILE"
  trap - EXIT HUP INT TERM
}

ensure_private_endpoint() {
  local rendered="" backup="" old_target="" changed=false had_available=false had_enabled=false
  command -v nginx >/dev/null 2>&1 || die "nginx is not installed"
  [[ -f "$NGINX_TEMPLATE" && ! -L "$NGINX_TEMPLATE" ]] || die "Mobile Link nginx template is unavailable"
  install -d -o root -g root -m 0755 /etc/nginx/sites-available /etc/nginx/sites-enabled
  [[ ! -e "$NGINX_AVAILABLE" || ( -f "$NGINX_AVAILABLE" && ! -L "$NGINX_AVAILABLE" ) ]] \
    || die "Mobile Link nginx configuration path is unsafe"
  [[ ! -e "$NGINX_ENABLED" || -L "$NGINX_ENABLED" ]] \
    || die "Mobile Link nginx enabled path is unsafe"

  rendered="$(mktemp /etc/nginx/sites-available/.easypi-mobile-link.XXXXXX)"
  backup="$(mktemp /etc/nginx/sites-available/.easypi-mobile-link-backup.XXXXXX)"
  trap 'rm -f -- "${rendered:-}" "${backup:-}"' EXIT HUP INT TERM
  install -o root -g root -m 0644 "$NGINX_TEMPLATE" "$rendered"
  sed -i "s|/opt/EasyPi|${EASYPI_ROOT}|g" "$rendered"

  if [[ -f "$NGINX_AVAILABLE" ]]; then
    had_available=true
    cp -a -- "$NGINX_AVAILABLE" "$backup"
  fi
  if [[ -L "$NGINX_ENABLED" ]]; then
    had_enabled=true
    old_target="$(readlink -- "$NGINX_ENABLED")"
  fi
  if [[ ! -f "$NGINX_AVAILABLE" ]] || ! cmp -s -- "$rendered" "$NGINX_AVAILABLE"; then
    install -o root -g root -m 0644 "$rendered" "$NGINX_AVAILABLE"
    changed=true
  fi
  if [[ ! -L "$NGINX_ENABLED" || "$(readlink -f -- "$NGINX_ENABLED")" != "$NGINX_AVAILABLE" ]]; then
    ln -sfn -- "$NGINX_AVAILABLE" "$NGINX_ENABLED"
    changed=true
  fi

  if ! nginx -t >/dev/null 2>&1; then
    if [[ "$had_available" == true ]]; then
      install -o root -g root -m 0644 "$backup" "$NGINX_AVAILABLE"
    else
      rm -f -- "$NGINX_AVAILABLE"
    fi
    if [[ "$had_enabled" == true ]]; then
      ln -sfn -- "$old_target" "$NGINX_ENABLED"
    else
      rm -f -- "$NGINX_ENABLED"
    fi
    die "Mobile Link nginx configuration validation failed"
  fi
  if [[ "$changed" == true ]]; then
    systemctl reload nginx >/dev/null 2>&1 || systemctl restart nginx >/dev/null 2>&1 \
      || die "nginx could not load the Mobile Link endpoint"
  fi
  rm -f -- "$rendered" "$backup"
  trap - EXIT HUP INT TERM
}

print_status() {
  local configured=false enabled=false active=false id="" relay="" server_name=""
  [[ -s "$CONFIG_FILE" && -s "$SECRET_FILE" ]] && configured=true
  systemctl is-enabled --quiet "$SERVICE" 2>/dev/null && enabled=true || true
  systemctl is-active --quiet "$SERVICE" 2>/dev/null && active=true || true
  if [[ "$configured" == true ]]; then
    id="$(installation_id)"
    readarray -t fields < <(/usr/bin/python3 - "$CONFIG_FILE" <<'PY'
import json
import sys
from pathlib import Path
data = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
print(data.get("relay_address", ""))
print(data.get("server_name", ""))
PY
)
    relay="${fields[0]:-}"
    server_name="${fields[1]:-}"
  fi
  /usr/bin/python3 - "$configured" "$enabled" "$active" "$id" "$relay" "$server_name" <<'PY'
import json, sys
configured, enabled, active = (item == "true" for item in sys.argv[1:4])
print(json.dumps({
    "configured": configured,
    "enabled": enabled,
    "active": active,
    "installation_id": sys.argv[4] or None,
    "relay_address": sys.argv[5] or None,
    "server_name": sys.argv[6] or None,
}, separators=(",", ":")))
PY
}

ensure_home_server() {
  local temporary
  systemctl is-enabled --quiet "$SERVICE" || die "Enable Mobile Link before starting the home tunnel"
  [[ -s "$TUNNEL_CONFIG_FILE" && -s "$TUNNEL_SECRET_FILE" ]] || die "Configure the Mobile Link relay before starting the home tunnel"
  [[ -x "${EASYPI_ROOT}/bin/chameleon-server-home" ]] || die "home tunnel server binary is unavailable"
  [[ -s "${EASYPI_ROOT}/certs/cert.pem" && -s "${EASYPI_ROOT}/certs/key.pem" ]] || die "EasyPi TLS certificate is unavailable"
  install -d -o root -g "$SERVICE_GROUP" -m 0750 "$HOME_DIR"
  if [[ ! -s "$HOME_CONFIG" ]]; then
    temporary="$(mktemp "${HOME_DIR}/.home-server.XXXXXX")"
    /usr/bin/python3 - "$temporary" "${EASYPI_ROOT}" <<'PY'
import json, os, secrets, sys
path, root = sys.argv[1:]
payload = {
 "listen_address":"127.0.0.1", "listen_port":9081, "bootstrap_port":9082,
 "frontend_mode":"direct", "backend_address":"127.0.0.1:9081",
 "psk_key":secrets.token_hex(32), "client_auth_key":secrets.token_hex(32),
 "mobile_clients_file":f"{root}/data/netprotection/mobile-home-tunnel-peers.json",
 "max_connections":256, "max_requests_per_session":32, "max_sessions_per_source":8,
 "max_pre_auth_connections":128, "max_pre_auth_per_ip":32, "log_level":"info",
 "tls_cert":f"{root}/certs/cert.pem", "tls_key":f"{root}/certs/key.pem", "site_dir":f"{root}/chameleon/site",
 "domain":"", "upstream_dns":"127.0.0.1:53", "reality_public_key":secrets.token_hex(32),
 "shield_domain":"", "shield_preset":"ip", "probe_mode":"local", "probe_target":"127.0.0.1:9443",
 "block_quic_udp443":False, "quic_datagram_port":0, "tunnel_name":"easypi-mobile0", "tunnel_cidr":"10.77.0.1/24",
 "tunnel_mtu":1200, "prism_link_listen":"127.0.0.1:9083"
}
with open(path,"w",encoding="utf-8") as f:
 json.dump(payload,f,separators=(",",":")); f.write("\n"); f.flush(); os.fsync(f.fileno())
PY
    chown root:"$SERVICE_GROUP" "$temporary"; chmod 0440 "$temporary"; mv -f -- "$temporary" "$HOME_CONFIG"
  else
    [[ -f "$HOME_CONFIG" && ! -L "$HOME_CONFIG" ]] || die "home tunnel configuration path is unsafe"
    temporary="$(mktemp "${HOME_DIR}/.home-server-migrate.XXXXXX")"
    /usr/bin/python3 - "$HOME_CONFIG" "$temporary" <<'PY'
import json, os, sys
from pathlib import Path
source, target = sys.argv[1:]
payload = json.loads(Path(source).read_text(encoding="utf-8"))
payload["tunnel_mtu"] = 1200
payload["prism_link_listen"] = "127.0.0.1:9083"
with open(target,"w",encoding="utf-8") as f:
 json.dump(payload,f,separators=(",",":")); f.write("\n"); f.flush(); os.fsync(f.fileno())
PY
    chown root:"$SERVICE_GROUP" "$temporary"; chmod 0440 "$temporary"; mv -f -- "$temporary" "$HOME_CONFIG"
  fi
  [[ -f "$TUNNEL_CONFIG_FILE" && ! -L "$TUNNEL_CONFIG_FILE" ]] || die "home tunnel relay configuration path is unsafe"
  temporary="$(mktemp "${CONFIG_DIR}/.tunnel-agent-migrate.XXXXXX")"
  /usr/bin/python3 - "$TUNNEL_CONFIG_FILE" "$temporary" <<'PY'
import json, os, sys
from pathlib import Path
source, target = sys.argv[1:]
payload = json.loads(Path(source).read_text(encoding="utf-8"))
host, port = payload["relay_address"].rsplit(":", 1)
payload["prism_relay_address"] = f"{host}:{int(port) + 1}"
payload["prism_local_address"] = "127.0.0.1:9083"
with open(target,"w",encoding="utf-8") as f:
 json.dump(payload,f,separators=(",",":")); f.write("\n"); f.flush(); os.fsync(f.fileno())
PY
  chown root:"$SERVICE_GROUP" "$temporary"; chmod 0440 "$temporary"; mv -f -- "$temporary" "$TUNNEL_CONFIG_FILE"
  systemctl daemon-reload
  systemctl enable --now "$HOME_SERVICE" "$TUNNEL_SERVICE" >/dev/null
  systemctl is-active --quiet "$HOME_SERVICE" || die "Mobile home tunnel server is unavailable"
  systemctl is-active --quiet "$TUNNEL_SERVICE" || die "Mobile home tunnel relay agent is unavailable"
}

home_profile() {
  [[ $# -eq 4 ]] || die "home-profile requires DEVICE_ID ADDRESS SERVER PORT"
  ensure_home_server
  /usr/bin/python3 - "$HOME_CONFIG" "$TUNNEL_SECRET_FILE" "$1" "$2" "$3" "$4" <<'PY'
import hashlib,hmac,ipaddress,json,re,sys,uuid
from pathlib import Path
cfg=json.loads(Path(sys.argv[1]).read_text(encoding="utf-8")); relay_secret=bytes.fromhex(Path(sys.argv[2]).read_text(encoding="ascii").strip())
device=str(uuid.UUID(sys.argv[3])); address=ipaddress.ip_interface(sys.argv[4]); server=sys.argv[5].strip().lower(); port=int(sys.argv[6])
if address.version!=4 or address.network.prefixlen!=32 or address.ip not in ipaddress.ip_network("10.77.0.0/24"): raise SystemExit("invalid address")
if not re.fullmatch(r"[a-z0-9.-]{1,253}",server) or not 1024<=port<=65535: raise SystemExit("invalid endpoint")
master=bytes.fromhex(cfg["client_auth_key"]); psk=hmac.new(master,("easypi/mobile-auth/v1/"+device).encode("ascii"),hashlib.sha256).hexdigest()
relay_id=hmac.new(relay_secret,b"easypi-mobile-link-installation-v1",hashlib.sha256).hexdigest()[:32]
# Per-phone relay route key: prismlink.MobileRouteKey(installation secret,
# shared.ClientIDForPSK(psk)). The relay derives the same key itself.
client_id=hmac.new(bytes.fromhex(psk),b"chameleon-client-identity-v1",hashlib.sha256).digest()[:16]
route_key=hmac.new(relay_secret,b"easypi/prismlink/mobile-route-key/v1\x00"+client_id,hashlib.sha256).hexdigest()
print(json.dumps({"address":str(address),"server_address":f"{server}:{port}","server_dial_address":"","psk_key":psk,
 "transport_key":cfg["psk_key"],"reality_server_public_key":cfg["reality_public_key"],"buffer_size":1000,"reconnect_interval":5,"mtu":1200,
 "prism_link_relay_address":f"{server}:{port+1}","prism_link_relay_installation_id":relay_id,"prism_link_relay_route_key":route_key,
 "prism_link_direct_address":""},separators=(",",":")))
PY
}

case "$action" in
  configure)
    [[ $# -eq 2 ]] || die "usage: mobile_link_agent.sh configure HOST:PORT TLS_SERVER_NAME"
    readarray -t validated < <(validate_endpoint "$1" "$2")
    [[ ${#validated[@]} -eq 2 ]] || die "invalid Mobile Link endpoint"
    ensure_secret
    write_config "${validated[0]}" "${validated[1]}"
    systemctl daemon-reload
    if systemctl is-active --quiet "$SERVICE"; then systemctl restart "$SERVICE"; fi
    if systemctl is-active --quiet "$TUNNEL_SERVICE"; then systemctl restart "$TUNNEL_SERVICE"; fi
    print_status
    ;;
  enable)
    [[ $# -eq 0 ]] || die "enable accepts no arguments"
    [[ -s "$CONFIG_FILE" && -s "$SECRET_FILE" ]] || die "configure Mobile Link first"
    systemctl enable --now "$SERVICE" "$TUNNEL_SERVICE" >/dev/null
    print_status
    ;;
  disable)
    [[ $# -eq 0 ]] || die "disable accepts no arguments"
    systemctl disable --now "$SERVICE" "$TUNNEL_SERVICE" >/dev/null 2>&1 || true
    print_status
    ;;
  rotate-secret)
    [[ $# -eq 0 ]] || die "rotate-secret accepts no arguments"
    [[ -s "$CONFIG_FILE" ]] || die "configure Mobile Link first"
    systemctl stop "$SERVICE" 2>/dev/null || true
    rm -f -- "$SECRET_FILE"
    ensure_secret
    print_status
    ;;
  registration)
    [[ $# -eq 0 ]] || die "registration accepts no arguments"
    [[ -s "$SECRET_FILE" ]] || die "configure Mobile Link first"
    id="$(installation_id)"
    secret="$(tr -d '[:space:]' < "$SECRET_FILE")"
    tunnel_secret="$(tr -d '[:space:]' < "$TUNNEL_SECRET_FILE")"
    [[ "$secret" =~ ^[0-9a-f]{64}$ && "$tunnel_secret" =~ ^[0-9a-f]{64}$ ]] || die "invalid Mobile Link secret"
    /usr/bin/python3 - "$id" "$secret" "$tunnel_secret" <<'PY'
import json, sys
import hashlib, hmac
tunnel = bytes.fromhex(sys.argv[3])
tunnel_id = hmac.new(tunnel, b"easypi-mobile-link-installation-v1", hashlib.sha256).hexdigest()[:32]
print(json.dumps({"installation_id": sys.argv[1], "secret": sys.argv[2], "tunnel_installation_id": tunnel_id, "tunnel_secret": sys.argv[3]}, separators=(",", ":")))
PY
    ;;
  ensure-endpoint)
    [[ $# -eq 0 ]] || die "ensure-endpoint accepts no arguments"
    ensure_private_endpoint
    print_status
    ;;
  ensure-home)
    [[ $# -eq 0 ]] || die "ensure-home accepts no arguments"
    ensure_home_server
    print_status
    ;;
  home-profile)
    home_profile "$@"
    ;;
  status)
    [[ $# -eq 0 ]] || die "status accepts no arguments"
    print_status
    ;;
  *) die "unsupported action" ;;
esac
