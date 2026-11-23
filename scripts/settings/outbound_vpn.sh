#!/usr/bin/env bash
#
# Outbound VPN client (Privacy -> Internet Encryption). Runner-invoked (root).
#
# EasyPi as a VPN CLIENT (WireGuard, OpenVPN, or Outline) to a provider, routing
# either the WHOLE network or SELECTED devices out through the tunnel, so the home
# ISP sees only one encrypted tunnel — not the sites behind it.
#
# NOTE: distinct from setup_vpn_blocking.sh / the EASYPI_VPN_* chains, which do the
# OPPOSITE (detect/block LAN clients bypassing the DNS filter via a VPN). This is
# the BOX's own uplink.
#
# Subcommands:
#   up <src_conf> <engine> <scope> [csv_ips] [csv_macs]
#   reconcile <csv_ips> <csv_macs>              re-apply selected-device rules
#   down                                       tear tunnel + routing + kill-switch down
#   status                                     JSON
#
set -uo pipefail

WG_IF="wg-out"
OVPN_IF="easypi-ovpn"
WG_CONF="/etc/wireguard/${WG_IF}.conf"
OVPN_CONF="/etc/openvpn/${OVPN_IF}.conf"
OVPN_PID="/run/easypi-ovpn.pid"
OVPN_LOG="/var/log/easypi/ovpn.log"
RUNTIME_DIR="/run/easypi-outbound-vpn"
SAFE_SOURCE="$RUNTIME_DIR/source.conf"
OVPN_AUTH="$RUNTIME_DIR/openvpn.auth"
OUTLINE_CONF="$RUNTIME_DIR/outline.json"
OUTLINE_PID="$RUNTIME_DIR/outline.pid"
OUTLINE_PORT="12345"
OUTLINE_ACTIVE="/run/easypi-outbound-vpn.active"
OUTLINE_USER="easypi-outline"
LOCK_FILE="$RUNTIME_DIR/operation.lock"
OVPN_SECRET_BROKER="/opt/EasyPi/scripts/settings/outbound_vpn_secrets.sh"
STATE="$RUNTIME_DIR/state.env"
RT_TABLE="51820"
KILL_CHAIN="EASYPI_VPNOUT"
DEVICE_CHAIN="EASYPI_VPNOUT_DEVICE"
FORWARD_CHAIN="EASYPI_VPNOUT_FORWARD"
RULE_PREF="5000"
MGMT_PREF="4990"  # keep LAN, VPN Server and Tailscale control paths in main
TAILSCALE_PREF="4989"
PROBE_PREF="4988"
OUTLINE_PREF="4987"
DEVICE_MARK="0x51820"
DEVICE_MARK_MASK="0xffffffff"
OUTLINE_TABLE="51821"
OUTLINE_MARK="0x51821"
OUTLINE_NAT_CHAIN="EASYPI_OUTLINE_TCP"
OUTLINE_MANGLE_CHAIN="EASYPI_OUTLINE_PROXY"
OUTLINE_RX_CHAIN="EASYPI_OUTLINE_RX"
OUTLINE_TX_CHAIN="EASYPI_OUTLINE_TX"
OUTLINE6_CHAIN="EASYPI_OUTLINE6"
SOURCE_CONF="/opt/EasyPi/data/netprotection/outbound_vpn.conf"

init_runtime() {
  install -d -o root -g root -m 0700 "$RUNTIME_DIR"
  install -d -o root -g easypi -m 0750 "$(dirname "$OVPN_LOG")"
  [[ ! -L "$OVPN_LOG" ]] || { echo "Refusing symlink log file: $OVPN_LOG" >&2; exit 1; }
  touch "$OVPN_LOG"
  chown root:easypi "$OVPN_LOG"
  chmod 0640 "$OVPN_LOG"
}

json() { printf '%s\n' "$1"; }
jesc() { printf '%s' "${1:-}" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
err()  { json "{\"success\":false,\"error\":\"$(jesc "$1")\"}"; exit 0; }

wan_iface() {
  ip -4 route show table main default 2>/dev/null | awk -v wg="$WG_IF" -v ovpn="$OVPN_IF" '
    {
      dev=""
      for (i=1; i<=NF; i++) if ($i=="dev") dev=$(i+1)
      if (dev != "" && dev != wg && dev != ovpn) { print dev; exit }
    }
  '
}
wan_gw() {
  local wanted="${1:-}"
  ip -4 route show table main default 2>/dev/null | awk -v wanted="$wanted" -v wg="$WG_IF" -v ovpn="$OVPN_IF" '
    {
      dev=""; via=""
      for (i=1; i<=NF; i++) {
        if ($i=="dev") dev=$(i+1)
        if ($i=="via") via=$(i+1)
      }
      if (via != "" && dev != wg && dev != ovpn && (wanted == "" || dev == wanted)) {
        print via; exit
      }
    }
  '
}
lan_cidr()  { local w="$1"; ip route show dev "$w" proto kernel scope link 2>/dev/null | awk '{print $1; exit}'; }

# ── routing / kill-switch (interface-agnostic) ─────────────────────────────────
clear_rules() {
  # Remove any ip rules we added (by preference) + our table + kill-switch.
  local wan; wan="$1"
  while ip rule del pref "$RULE_PREF" 2>/dev/null; do :; done
  while ip rule del pref "$MGMT_PREF" 2>/dev/null; do :; done
  while ip rule del pref "$TAILSCALE_PREF" 2>/dev/null; do :; done
  while ip rule del pref "$PROBE_PREF" 2>/dev/null; do :; done
  ip route flush table "$RT_TABLE" 2>/dev/null
  if [[ -n "$wan" ]]; then
    while iptables -t mangle -D PREROUTING -i "$wan" -j "$DEVICE_CHAIN" 2>/dev/null; do :; done
  fi
  # Remove the legacy hook used before interface-scoped marking was introduced.
  while iptables -t mangle -D PREROUTING -j "$DEVICE_CHAIN" 2>/dev/null; do :; done
  iptables -t mangle -F "$DEVICE_CHAIN" 2>/dev/null
  iptables -t mangle -X "$DEVICE_CHAIN" 2>/dev/null
  while iptables -D FORWARD -j "$FORWARD_CHAIN" 2>/dev/null; do :; done
  iptables -F "$FORWARD_CHAIN" 2>/dev/null
  iptables -X "$FORWARD_CHAIN" 2>/dev/null
  if [[ -n "$wan" ]]; then
    while iptables  -D FORWARD -o "$wan" -j "$KILL_CHAIN" 2>/dev/null; do :; done
    while ip6tables -D FORWARD -o "$wan" -j "$KILL_CHAIN" 2>/dev/null; do :; done
  fi
  iptables  -F "$KILL_CHAIN" 2>/dev/null; iptables  -X "$KILL_CHAIN" 2>/dev/null
  ip6tables -F "$KILL_CHAIN" 2>/dev/null; ip6tables -X "$KILL_CHAIN" 2>/dev/null
}

install_management_rules() {
  # Preserve every EasyPi management plane before installing a default-route
  # policy. This includes off-subnet RFC1918 administrators, VPN Server peers,
  # and Tailscale peers whose routes live in table 52.
  local net
  while ip rule del pref "$MGMT_PREF" 2>/dev/null; do :; done
  while ip rule del pref "$TAILSCALE_PREF" 2>/dev/null; do :; done
  ip rule add to 100.64.0.0/10 lookup 52 pref "$TAILSCALE_PREF" || return 1
  for net in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16; do
    ip rule add to "$net" lookup main pref "$MGMT_PREF" || return 1
  done
}

apply_manual_routing() {
  # $1=IF $2=scope $3=csv_macs $4=wan $5=gw $6=lancidr $7=server_ip(optional)
  local IF="$1" scope="$2" macs="$3" wan="$4" gw="$5" lan="$6" srv="${7:-}"
  ip route replace default dev "$IF" table "$RT_TABLE" || return 1
  [[ -n "$lan" ]] && ip route replace "$lan" dev "$wan" table "$RT_TABLE" || true
  # Keep the box's own tunnel packets off the tunnel (avoid a loop) for whole-net.
  [[ -n "$srv" && -n "$gw" ]] && ip route replace "$srv" via "$gw" dev "$wan" table "$RT_TABLE"

  # Do not hijack EasyPi management, WireGuard Server clients, or Tailscale
  # peers. These more-specific destinations remain in the main table while
  # internet traffic still follows the selected outbound tunnel.
  install_management_rules || return 1

  iptables  -N "$KILL_CHAIN" 2>/dev/null || true
  iptables  -F "$KILL_CHAIN" || return 1
  iptables  -A "$KILL_CHAIN" -j DROP || return 1
  ip6tables -N "$KILL_CHAIN" 2>/dev/null; ip6tables -F "$KILL_CHAIN" 2>/dev/null; ip6tables -A "$KILL_CHAIN" -j DROP 2>/dev/null

  # Route only packets forwarded from client devices. EasyPi's own traffic stays
  # in the main table, so enabling Internet Encryption cannot take down its web
  # panel, SSH, DNS services, package downloads, or the OpenVPN control socket.
  while iptables -t mangle -D PREROUTING -j "$DEVICE_CHAIN" 2>/dev/null; do :; done
  iptables -t mangle -N "$DEVICE_CHAIN" 2>/dev/null || true
  iptables -t mangle -F "$DEVICE_CHAIN" || return 1
  iptables -t mangle -A PREROUTING -i "$wan" -j "$DEVICE_CHAIN" || return 1
  iptables -t mangle -A "$DEVICE_CHAIN" -m addrtype --dst-type LOCAL -j RETURN || return 1

  if [[ "$scope" == "all" ]]; then
    iptables -t mangle -A "$DEVICE_CHAIN" -j MARK \
      --set-xmark "$DEVICE_MARK/$DEVICE_MARK_MASK" || return 1
    ip rule add fwmark "$DEVICE_MARK/$DEVICE_MARK_MASK" lookup "$RT_TABLE" pref "$RULE_PREF" || return 1
    # IPv6 has no configured provider tunnel here, so keep it fail-closed.
    ip6tables -I FORWARD 1 -o "$wan" -j "$KILL_CHAIN" 2>/dev/null
  else
    local mac
    IFS=',' read -ra arr <<< "$macs"
    for mac in "${arr[@]}"; do
      [[ -z "$mac" ]] && continue
      iptables -t mangle -A "$DEVICE_CHAIN" -m mac --mac-source "$mac" \
        -j MARK --set-xmark "$DEVICE_MARK/$DEVICE_MARK_MASK" || return 1
      ip6tables -I FORWARD 1 -m mac --mac-source "$mac" -o "$wan" -j "$KILL_CHAIN" 2>/dev/null || true
    done
    ip rule add fwmark "$DEVICE_MARK/$DEVICE_MARK_MASK" lookup "$RT_TABLE" pref "$RULE_PREF" || return 1
  fi

  # UFW and the rest of EasyPi's firewall remain authoritative for unrelated
  # traffic. This narrow chain allows only marked clients into the tunnel and
  # established replies back to the LAN. If policy routing falls back to the
  # physical WAN, the marked packet is dropped instead of leaking.
  while iptables -D FORWARD -j "$FORWARD_CHAIN" 2>/dev/null; do :; done
  iptables -N "$FORWARD_CHAIN" 2>/dev/null || true
  iptables -F "$FORWARD_CHAIN" || return 1
  iptables -A "$FORWARD_CHAIN" -i "$wan" -o "$IF" \
    -m mark --mark "$DEVICE_MARK/$DEVICE_MARK_MASK" -j ACCEPT || return 1
  iptables -A "$FORWARD_CHAIN" -i "$IF" -o "$wan" \
    -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT || return 1
  iptables -A "$FORWARD_CHAIN" -m mark --mark "$DEVICE_MARK/$DEVICE_MARK_MASK" \
    -o "$wan" -j "$KILL_CHAIN" || return 1
  iptables -I FORWARD 1 -j "$FORWARD_CHAIN" || return 1
}

verify_routing_invariants() {
  # $1=tunnel IF, $2=physical WAN, $3=original gateway
  local IF="$1" wan="$2" gw="$3" route
  route="$(ip -4 route get 1.1.1.1 2>/dev/null)" || return 1
  grep -Eq "(^|[[:space:]])dev[[:space:]]+$wan([[:space:]]|$)" <<< "$route" || return 1
  route="$(ip -4 route get 1.1.1.1 mark "$DEVICE_MARK" 2>/dev/null)" || return 1
  grep -Eq "(^|[[:space:]])dev[[:space:]]+$IF([[:space:]]|$)" <<< "$route" || return 1
  ip -4 route show table main default | grep -Fq "via $gw dev $wan" || return 1
}

rollback_incomplete_activation() {
  local rc=$?
  trap - EXIT HUP INT TERM
  do_down >/dev/null 2>&1 || true
  exit "$rc"
}

# ── engine bring-up ────────────────────────────────────────────────────────────
ensure_wg()   { command -v wg-quick >/dev/null 2>&1 || { apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq wireguard-tools >/dev/null 2>&1; }; command -v wg-quick >/dev/null 2>&1; }
ensure_ovpn() { command -v openvpn  >/dev/null 2>&1 || { apt-get update -qq >/dev/null 2>&1; apt-get install -y -qq openvpn >/dev/null 2>&1; }; command -v openvpn >/dev/null 2>&1; }
ensure_outline() {
  if ! command -v ss-redir >/dev/null 2>&1; then
    # Debian's package also ships a public ss-server unit and tries to start it
    # on first install. EasyPi needs only the client-side ss-redir binary, so
    # block maintainer-script service starts for this transaction. Never replace
    # an administrator-supplied policy-rc.d file.
    (
      local policy="/usr/sbin/policy-rc.d" policy_created="false"
      local runtime_mask="/run/systemd/system/shadowsocks-libev.service" mask_created="false"
      cleanup_outline_policy() {
        if [[ "$policy_created" == "true" ]] &&
           grep -Fqx '# EasyPi temporary no-service-start policy' "$policy" 2>/dev/null; then
          rm -f -- "$policy"
        fi
        if [[ "$mask_created" == "true" && -L "$runtime_mask" &&
              "$(readlink -f "$runtime_mask" 2>/dev/null || true)" == "/dev/null" ]]; then
          rm -f -- "$runtime_mask"
          systemctl daemon-reload >/dev/null 2>&1 || true
        fi
      }
      trap cleanup_outline_policy EXIT
      trap 'cleanup_outline_policy; exit 1' HUP INT TERM
      if [[ ! -e "$policy" && ! -L "$policy" ]] && (
        set -o noclobber
        printf '%s\n' '#!/bin/sh' '# EasyPi temporary no-service-start policy' 'exit 101' > "$policy"
      ) 2>/dev/null; then
        policy_created="true"
        chmod 0755 "$policy" || exit 1
      fi
      # A runtime systemd mask is the second, independent barrier. Debian's
      # maintainer scripts may unmask /etc links, but they cannot bypass this
      # /run mask during the package transaction.
      install -d -o root -g root -m 0755 /run/systemd/system || exit 1
      if [[ ! -e "$runtime_mask" && ! -L "$runtime_mask" ]]; then
        ln -s /dev/null "$runtime_mask" || exit 1
        mask_created="true"
      fi
      [[ -L "$runtime_mask" && "$(readlink -f "$runtime_mask" 2>/dev/null || true)" == "/dev/null" ]] || exit 1
      systemctl daemon-reload >/dev/null 2>&1 || exit 1
      apt-get update -qq >/dev/null 2>&1 || exit 1
      DEBIAN_FRONTEND=noninteractive apt-get install -y -qq shadowsocks-libev >/dev/null 2>&1 || exit 1
      systemctl disable --now shadowsocks-libev.service >/dev/null 2>&1 || true
    ) || return 1
  fi
  # Do not expose the package's default Shadowsocks server. EasyPi launches
  # only a per-session, unprivileged ss-redir client with a root-owned config.
  systemctl disable --now shadowsocks-libev.service >/dev/null 2>&1 || true
  command -v ss-redir >/dev/null 2>&1 || return 1
  if ! getent passwd "$OUTLINE_USER" >/dev/null 2>&1; then
    useradd --system --user-group --no-create-home --home-dir /nonexistent \
      --shell /usr/sbin/nologin "$OUTLINE_USER" >/dev/null 2>&1 || return 1
  fi
  local account_name account_uid account_gid account_home account_shell
  IFS=: read -r account_name _ account_uid account_gid _ account_home account_shell \
    < <(getent passwd "$OUTLINE_USER")
  [[ "$account_name" == "$OUTLINE_USER" && "$account_uid" =~ ^[0-9]+$ &&
     "$account_gid" =~ ^[0-9]+$ && "$account_uid" -gt 0 &&
     "$account_home" == "/nonexistent" && "$account_shell" == "/usr/sbin/nologin" ]] || return 1
  [[ "$(getent group "$account_gid" | cut -d: -f1)" == "$OUTLINE_USER" ]] || return 1
  [[ "$(id -G "$OUTLINE_USER")" == "$account_gid" ]] || return 1
  passwd -S "$OUTLINE_USER" 2>/dev/null | awk '$2 == "L" { found=1 } END { exit !found }'
}

resolve_host_ip() { # host (name OR literal IP) -> IPv4
  local h="${1:-}"; [[ -z "$h" ]] && return
  # getent doesn't echo back a raw IP, so pass literal IPs through unchanged.
  if [[ "$h" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then printf '%s' "$h"; return; fi
  getent ahostsv4 "$h" 2>/dev/null | awk '{print $1; exit}'
}
wg_server_ip() { # resolve Endpoint host -> IP from a wg conf
  local host; host=$(grep -iE '^\s*Endpoint' "$1" | head -1 | sed -E 's/.*=\s*//; s/:[0-9]+\s*$//')
  resolve_host_ip "$host"
}
ovpn_server_ip() { # resolve first `remote host port`
  local host; host=$(openvpn_option_lines "$1" | awk '$1 == "remote" && !found { print $2; found=1 }')
  resolve_host_ip "$host"
}

validate_ip_csv() {
  /usr/bin/python3 - "$1" <<'PY'
import ipaddress
import sys

value = sys.argv[1]
if not value:
    raise SystemExit(0)
items = value.split(",")
if len(items) > 256:
    raise SystemExit(1)
for item in items:
    address = ipaddress.ip_address(item)
    if address.version != 4 or address.is_unspecified or address.is_multicast:
        raise SystemExit(1)
PY
}

validate_mac_csv() {
  /usr/bin/python3 - "$1" <<'PY'
import re
import sys

value = sys.argv[1]
if not value:
    raise SystemExit(0)
items = value.split(",")
if len(items) > 256 or any(not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", item) for item in items):
    raise SystemExit(1)
PY
}

copy_source_config() {
  SOURCE_CONFIG="$1" SAFE_SOURCE="$SAFE_SOURCE" /usr/bin/python3 - <<'PY'
import os
import stat
import tempfile

source = os.environ["SOURCE_CONFIG"]
destination = os.environ["SAFE_SOURCE"]
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(source, flags)
try:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_size > 1024 * 1024:
        raise ValueError("invalid VPN source config")
    temp_fd, temp_name = tempfile.mkstemp(prefix=".source.", dir=os.path.dirname(destination))
    try:
        with os.fdopen(temp_fd, "wb") as output:
            while True:
                chunk = os.read(fd, 128 * 1024)
                if not chunk:
                    break
                output.write(chunk)
            output.flush()
            os.fsync(output.fileno())
        os.chmod(temp_name, 0o600)
        os.replace(temp_name, destination)
    finally:
        try:
            os.unlink(temp_name)
        except FileNotFoundError:
            pass
finally:
    os.close(fd)
PY
}

validate_openvpn_config() {
  local conf="$1" rewritten
  rewritten="$(mktemp "${RUNTIME_DIR}/.openvpn-validated.XXXXXX")" || err "cannot validate OpenVPN config"
  chmod 0600 "$rewritten"
  # Repeat import validation inside the root boundary, using only trusted code
  # and isolated system Python. The canonical result also closes parser gaps in
  # the downstream endpoint, routing and credential handlers.
  /usr/bin/python3 -I - "$conf" > "$rewritten" <<'PY'
import os
import runpy
import stat
import sys
from pathlib import Path

validator = Path("/opt/EasyPi/backend/app/core/openvpn_config.py")
try:
    for path in (validator, *validator.parents):
        details = path.lstat()
        expected = stat.S_ISREG if path == validator else stat.S_ISDIR
        if not expected(details.st_mode) or details.st_uid != 0 or details.st_mode & 0o022:
            raise ValueError("OpenVPN validator has unsafe ownership or permissions")
except (OSError, ValueError):
    raise SystemExit("ERROR: trusted OpenVPN validator is unavailable")
sys.argv = [str(validator), sys.argv[1]]
runpy.run_path(str(validator), run_name="__main__")
PY
  if [[ $? -ne 0 ]]; then
    rm -f -- "$rewritten"
    err "OpenVPN profile rejected by the directive allowlist"
  fi
  install -o root -g root -m 0600 "$rewritten" "$conf" || {
    rm -f -- "$rewritten"
    err "cannot install validated OpenVPN profile"
  }
  rm -f -- "$rewritten"
}

openvpn_option_lines() {
  # Input has already been canonicalized. Inline credentials/PEM comments must
  # never be interpreted as endpoint, routing or credential directives.
  awk '
    /^<[^\/][^>]*>$/ { in_inline=1; next }
    /^<\/[^>]+>$/ { in_inline=0; next }
    !in_inline { print }
  ' "$1"
}

openvpn_requires_credentials() {
  openvpn_option_lines "$1" | awk '
    /^auth-user-pass$/ { found=1 }
    END { exit !found }
  '
}

prepare_openvpn_credentials() {
  local conf="$1" broker_uid broker_mode rewritten
  openvpn_requires_credentials "$conf" || return 0
  [[ -f "$OVPN_SECRET_BROKER" && ! -L "$OVPN_SECRET_BROKER" ]] ||
    err "secure OpenVPN credential broker is unavailable"
  broker_uid="$(stat -c '%u' -- "$OVPN_SECRET_BROKER" 2>/dev/null || echo -1)"
  broker_mode="$(stat -c '%a' -- "$OVPN_SECRET_BROKER" 2>/dev/null || echo 777)"
  [[ "$broker_uid" == "0" && $((8#$broker_mode & 8#022)) -eq 0 ]] ||
    err "secure OpenVPN credential broker has unsafe permissions"
  "$OVPN_SECRET_BROKER" exists | grep -qx 'true' ||
    err "OpenVPN username and password are required; save them in Internet Encryption first"
  "$OVPN_SECRET_BROKER" read > "$OVPN_AUTH" || {
    rm -f -- "$OVPN_AUTH"
    err "stored OpenVPN credentials could not be decrypted"
  }
  chmod 0600 "$OVPN_AUTH"
  rewritten="$(mktemp "${RUNTIME_DIR}/.openvpn-conf.XXXXXX")" || err "cannot prepare OpenVPN config"
  chmod 0600 "$rewritten"
  awk -v auth="$OVPN_AUTH" '
    BEGIN { IGNORECASE=1 }
    /^<[^\/][^>]*>$/ { in_inline=1 }
    in_inline { print; if ($0 ~ /^<\/[^>]+>$/) in_inline=0; next }
    /^[[:space:]]*auth-user-pass([[:space:]]*([#;].*)?)?$/ { print "auth-user-pass " auth; next }
    { print }
  ' "$conf" > "$rewritten"
  install -o root -g root -m 0600 "$rewritten" "$conf"
  rm -f -- "$rewritten"
}

cleanup_openvpn_runtime() {
  local pid="" i
  if [[ -f "$OVPN_PID" ]]; then pid="$(cat "$OVPN_PID" 2>/dev/null || true)"; fi
  if [[ ! "$pid" =~ ^[0-9]+$ || ! -d "/proc/$pid" ]]; then
    pid="$(python3 - "$OVPN_CONF" "$OVPN_IF" <<'PY'
import os
import sys
from pathlib import Path

config, interface = sys.argv[1:]
for proc in Path("/proc").iterdir():
    if not proc.name.isdigit():
        continue
    try:
        argv = (proc / "cmdline").read_bytes().split(b"\0")
        args = [item.decode("utf-8", errors="ignore") for item in argv if item]
    except OSError:
        continue
    if not args or os.path.basename(args[0]) not in {"openvpn", "easypi-ovpn"}:
        continue
    pairs = set(zip(args, args[1:]))
    if ("--config", config) in pairs and ("--dev", interface) in pairs:
        print(proc.name)
        break
PY
)"
  fi
  if [[ "$pid" =~ ^[0-9]+$ && -d "/proc/$pid" ]]; then
    kill "$pid" 2>/dev/null || true
    for i in $(seq 1 40); do
      [[ ! -d "/proc/$pid" ]] && break
      sleep 0.25
    done
    [[ -d "/proc/$pid" ]] && kill -KILL "$pid" 2>/dev/null || true
  fi
  ip link delete "$OVPN_IF" 2>/dev/null || true
  rm -f -- "$OVPN_PID" "$OVPN_CONF" "$OVPN_AUTH"
}

prepare_outline_config() {
  local src="$1"
  /usr/bin/python3 - "$src" "$OUTLINE_CONF" "$OUTLINE_PORT" <<'PY'
import base64
import json
import os
import re
import sys
import tempfile
from urllib.parse import unquote, urlsplit

source, destination, local_port = sys.argv[1:]
key = open(source, encoding="utf-8").read().strip()
if len(key) > 8192 or not key.lower().startswith("ss://"):
    raise SystemExit(1)

def decode(value):
    try:
        return base64.urlsafe_b64decode((value + "=" * (-len(value) % 4)).encode("ascii")).decode("utf-8")
    except (ValueError, UnicodeDecodeError):
        raise SystemExit(1)

parsed = urlsplit(key)
userinfo = unquote(parsed.username or "")
host = parsed.hostname or ""
try:
    port = parsed.port
except ValueError:
    raise SystemExit(1)
if host and port:
    credentials = userinfo if ":" in userinfo else decode(userinfo)
else:
    payload = key[5:].split("#", 1)[0].split("?", 1)[0].rstrip("/")
    legacy = urlsplit("ss://" + decode(payload))
    if legacy.username is None or legacy.password is None:
        raise SystemExit(1)
    credentials = unquote(legacy.username) + ":" + unquote(legacy.password)
    host = legacy.hostname or ""
    try:
        port = legacy.port
    except ValueError:
        raise SystemExit(1)
if ":" not in credentials:
    raise SystemExit(1)
method, password = credentials.split(":", 1)
method = method.lower().strip()
allowed = {"aes-128-gcm", "aes-192-gcm", "aes-256-gcm", "chacha20-ietf-poly1305", "xchacha20-ietf-poly1305"}
if method not in allowed or not password or len(password) > 512:
    raise SystemExit(1)
if any(ord(char) < 32 for char in password):
    raise SystemExit(1)
if not host or not port or not 1 <= port <= 65535 or len(host) > 253 or not re.fullmatch(r"[A-Za-z0-9.-]+", host):
    raise SystemExit(1)
config = {
    "server": host,
    "server_port": port,
    "local_address": "0.0.0.0",
    "local_port": int(local_port),
    "password": password,
    "method": method,
    "timeout": 60,
    "mode": "tcp_and_udp",
}
fd, temp_name = tempfile.mkstemp(prefix=".outline.", dir=os.path.dirname(destination))
try:
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        json.dump(config, output, separators=(",", ":"))
        output.flush()
        os.fsync(output.fileno())
    os.chmod(temp_name, 0o600)
    os.replace(temp_name, destination)
finally:
    try:
        os.unlink(temp_name)
    except FileNotFoundError:
        pass
PY
}

outline_server_host() {
  /usr/bin/python3 - "$OUTLINE_CONF" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    print(json.load(handle)["server"])
PY
}

outline_server_port() {
  /usr/bin/python3 - "$OUTLINE_CONF" <<'PY'
import json, sys
with open(sys.argv[1], encoding="utf-8") as handle:
    print(int(json.load(handle)["server_port"]))
PY
}

outline_chain_bytes() {
  local chain="$1"
  iptables -t mangle -L "$chain" -n -v -x 2>/dev/null |
    awk 'NR > 2 && $1 ~ /^[0-9]+$/ { total += $2 } END { printf "%.0f", total + 0 }'
}

clear_outline_rules() {
  local wan="${1:-}"
  if [[ -n "$wan" ]]; then
    while iptables -t mangle -D PREROUTING -i "$wan" -j "$OUTLINE_MANGLE_CHAIN" 2>/dev/null; do :; done
    while iptables -t nat -D PREROUTING -i "$wan" -p tcp -j "$OUTLINE_NAT_CHAIN" 2>/dev/null; do :; done
    while iptables -D INPUT -i "$wan" -m mark --mark "$OUTLINE_MARK/$DEVICE_MARK_MASK" -p tcp --dport "$OUTLINE_PORT" -j ACCEPT 2>/dev/null; do :; done
    while iptables -D INPUT -i "$wan" -p tcp --dport "$OUTLINE_PORT" -m conntrack --ctstate DNAT -j ACCEPT 2>/dev/null; do :; done
    while iptables -D INPUT -i "$wan" -m mark --mark "$OUTLINE_MARK/$DEVICE_MARK_MASK" -p udp --dport "$OUTLINE_PORT" -j ACCEPT 2>/dev/null; do :; done
    while iptables -D INPUT -i "$wan" -m mark --mark "$OUTLINE_MARK/$DEVICE_MARK_MASK" -p udp -j ACCEPT 2>/dev/null; do :; done
    while ip6tables -D FORWARD -i "$wan" -j "$OUTLINE6_CHAIN" 2>/dev/null; do :; done
  fi
  iptables -t mangle -S INPUT 2>/dev/null | grep -- "-j $OUTLINE_RX_CHAIN" |
    sed 's/^-A/-D/' | while read -r rule; do iptables -t mangle $rule 2>/dev/null || true; done || true
  iptables -t mangle -S OUTPUT 2>/dev/null | grep -- "-j $OUTLINE_TX_CHAIN" |
    sed 's/^-A/-D/' | while read -r rule; do iptables -t mangle $rule 2>/dev/null || true; done || true
  while iptables -D INPUT -p tcp --dport "$OUTLINE_PORT" -j DROP 2>/dev/null; do :; done
  while iptables -D INPUT -p udp --dport "$OUTLINE_PORT" -j DROP 2>/dev/null; do :; done
  iptables -t mangle -F "$OUTLINE_MANGLE_CHAIN" 2>/dev/null || true
  iptables -t mangle -X "$OUTLINE_MANGLE_CHAIN" 2>/dev/null || true
  iptables -t nat -F "$OUTLINE_NAT_CHAIN" 2>/dev/null || true
  iptables -t nat -X "$OUTLINE_NAT_CHAIN" 2>/dev/null || true
  iptables -t mangle -F "$OUTLINE_RX_CHAIN" 2>/dev/null || true
  iptables -t mangle -X "$OUTLINE_RX_CHAIN" 2>/dev/null || true
  iptables -t mangle -F "$OUTLINE_TX_CHAIN" 2>/dev/null || true
  iptables -t mangle -X "$OUTLINE_TX_CHAIN" 2>/dev/null || true
  ip6tables -F "$OUTLINE6_CHAIN" 2>/dev/null || true
  ip6tables -X "$OUTLINE6_CHAIN" 2>/dev/null || true
  while ip rule del pref "$OUTLINE_PREF" 2>/dev/null; do :; done
  ip route flush table "$OUTLINE_TABLE" 2>/dev/null || true
}

cleanup_outline_runtime() {
  local wan="${1:-}" pid=""
  if [[ -f "$OUTLINE_PID" ]]; then pid="$(cat "$OUTLINE_PID" 2>/dev/null || true)"; fi
  if [[ "$pid" =~ ^[0-9]+$ && -d "/proc/$pid" ]]; then
    local exe cmdline
    exe="$(basename "$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)")"
    cmdline="$(tr '\0' '\n' < "/proc/$pid/cmdline" 2>/dev/null || true)"
    if [[ "$exe" == "ss-redir" ]] && grep -Fxq "$OUTLINE_CONF" <<< "$cmdline"; then
      kill "$pid" 2>/dev/null || true
      for _ in $(seq 1 20); do [[ ! -d "/proc/$pid" ]] && break; sleep 0.25; done
      [[ -d "/proc/$pid" ]] && kill -KILL "$pid" 2>/dev/null || true
    fi
  fi
  clear_outline_rules "$wan"
  rm -f -- "$OUTLINE_PID" "$OUTLINE_CONF"
  rm -f -- "$OUTLINE_ACTIVE"
}

outline_process_running() {
  local pid="" exe="" cmdline=""
  [[ -f "$OUTLINE_PID" ]] || return 1
  pid="$(cat "$OUTLINE_PID" 2>/dev/null || true)"
  [[ "$pid" =~ ^[0-9]+$ && -d "/proc/$pid" ]] || return 1
  exe="$(basename "$(readlink -f "/proc/$pid/exe" 2>/dev/null || true)")"
  cmdline="$(tr '\0' '\n' < "/proc/$pid/cmdline" 2>/dev/null || true)"
  [[ "$exe" == "ss-redir" ]] && grep -Fxq "$OUTLINE_CONF" <<< "$cmdline"
}

apply_outline_proxy() {
  # $1=scope $2=csv_macs $3=physical WAN $4=server IPv4 $5=server port
  local scope="$1" macs="$2" wan="$3" srv="$4" srv_port="$5" net mac outline_uid
  [[ "$srv_port" =~ ^[0-9]+$ && "$srv_port" -ge 1 && "$srv_port" -le 65535 ]] || return 1
  outline_uid="$(getent passwd "$OUTLINE_USER" | cut -d: -f3)"
  [[ "$outline_uid" =~ ^[0-9]+$ ]] || return 1
  clear_outline_rules "$wan"
  iptables -t mangle -N "$OUTLINE_MANGLE_CHAIN" || return 1
  iptables -t nat -N "$OUTLINE_NAT_CHAIN" || return 1
  iptables -t mangle -N "$OUTLINE_RX_CHAIN" || return 1
  iptables -t mangle -N "$OUTLINE_TX_CHAIN" || return 1
  ip6tables -N "$OUTLINE6_CHAIN" 2>/dev/null || true
  # Account encrypted provider traffic. The dedicated service UID prevents
  # unrelated host processes from inflating the upload counter.
  iptables -t mangle -A "$OUTLINE_RX_CHAIN" -j RETURN || return 1
  iptables -t mangle -A "$OUTLINE_TX_CHAIN" -j RETURN || return 1
  iptables -t mangle -I INPUT 1 -i "$wan" -s "$srv" -p tcp --sport "$srv_port" -j "$OUTLINE_RX_CHAIN" || return 1
  iptables -t mangle -I INPUT 1 -i "$wan" -s "$srv" -p udp --sport "$srv_port" -j "$OUTLINE_RX_CHAIN" || return 1
  iptables -t mangle -I OUTPUT 1 -m owner --uid-owner "$outline_uid" -d "$srv" -p tcp --dport "$srv_port" -j "$OUTLINE_TX_CHAIN" || return 1
  iptables -t mangle -I OUTPUT 1 -m owner --uid-owner "$outline_uid" -d "$srv" -p udp --dport "$srv_port" -j "$OUTLINE_TX_CHAIN" || return 1
  if [[ -n "$srv" ]]; then
    iptables -t mangle -A "$OUTLINE_MANGLE_CHAIN" -d "$srv" -j RETURN || return 1
    iptables -t nat -A "$OUTLINE_NAT_CHAIN" -d "$srv" -j RETURN || return 1
  fi
  for net in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 224.0.0.0/4 240.0.0.0/4; do
    iptables -t mangle -A "$OUTLINE_MANGLE_CHAIN" -d "$net" -j RETURN || return 1
    iptables -t nat -A "$OUTLINE_NAT_CHAIN" -d "$net" -j RETURN || return 1
  done
  if [[ "$scope" == "all" ]]; then
    iptables -t nat -A "$OUTLINE_NAT_CHAIN" -p tcp -j REDIRECT --to-ports "$OUTLINE_PORT" || return 1
    iptables -t mangle -A "$OUTLINE_MANGLE_CHAIN" -p udp -j TPROXY --on-port "$OUTLINE_PORT" --tproxy-mark "$OUTLINE_MARK/$DEVICE_MARK_MASK" || return 1
    ip6tables -A "$OUTLINE6_CHAIN" -j DROP 2>/dev/null || true
  else
    IFS=',' read -ra arr <<< "$macs"
    for mac in "${arr[@]}"; do
      [[ -z "$mac" ]] && continue
      iptables -t nat -A "$OUTLINE_NAT_CHAIN" -m mac --mac-source "$mac" -p tcp -j REDIRECT --to-ports "$OUTLINE_PORT" || return 1
      iptables -t mangle -A "$OUTLINE_MANGLE_CHAIN" -m mac --mac-source "$mac" -p udp -j TPROXY --on-port "$OUTLINE_PORT" --tproxy-mark "$OUTLINE_MARK/$DEVICE_MARK_MASK" || return 1
      ip6tables -A "$OUTLINE6_CHAIN" -m mac --mac-source "$mac" -j DROP 2>/dev/null || true
    done
  fi
  iptables -t mangle -A PREROUTING -i "$wan" -j "$OUTLINE_MANGLE_CHAIN" || return 1
  iptables -t nat -A PREROUTING -i "$wan" -p tcp -j "$OUTLINE_NAT_CHAIN" || return 1
  # TCP REDIRECT is intentionally unmarked, following ss-redir's documented
  # transparent-proxy path. Accept only connections carrying DNAT state so a
  # LAN client cannot connect directly to the private listener.
  iptables -I INPUT 1 -i "$wan" -p tcp --dport "$OUTLINE_PORT" -m conntrack --ctstate DNAT -j ACCEPT || return 1
  # TPROXY preserves the packet's original UDP destination port. The kernel-only
  # mark identifies packets selected by the preceding TPROXY rule.
  iptables -I INPUT 1 -i "$wan" -m mark --mark "$OUTLINE_MARK/$DEVICE_MARK_MASK" -p udp -j ACCEPT || return 1
  # ss-redir must bind 0.0.0.0 for transparent REDIRECT. Deny every direct
  # connection to that listener regardless of broader UFW/LAN allow rules.
  iptables -I INPUT 3 -p tcp --dport "$OUTLINE_PORT" -j DROP || return 1
  iptables -I INPUT 4 -p udp --dport "$OUTLINE_PORT" -j DROP || return 1
  ip6tables -I FORWARD 1 -i "$wan" -j "$OUTLINE6_CHAIN" 2>/dev/null || true
  ip route replace local default dev lo table "$OUTLINE_TABLE" || return 1
  ip rule add fwmark "$OUTLINE_MARK/$DEVICE_MARK_MASK" lookup "$OUTLINE_TABLE" pref "$OUTLINE_PREF" || return 1
}

sanitize_openvpn_routing() {
  # The imported profile may contain redirect-gateway/route directives that
  # mutate the main table independently of EasyPi. Keep the provider's crypto
  # and transport settings, but make EasyPi the sole routing authority.
  local conf="$1" rewritten
  rewritten="$(mktemp "${RUNTIME_DIR}/.openvpn-routing.XXXXXX")" || return 1
  chmod 0600 "$rewritten"
  awk '
    BEGIN { IGNORECASE=1 }
    /^<[^\/][^>]*>$/ { in_inline=1 }
    in_inline { print; if ($0 ~ /^<\/[^>]+>$/) in_inline=0; next }
    /^[[:space:]]*(route|route-ipv6|redirect-gateway|redirect-private|route-gateway|route-metric|route-delay|route-method|route-noexec|route-nopull|pull-filter)([[:space:]]|$)/ { next }
    { print }
  ' "$conf" > "$rewritten"
  install -o root -g root -m 0600 "$rewritten" "$conf"
  rm -f -- "$rewritten"
}

restore_wan_default_route() {
  local wan="$1" gw="$2"
  [[ "$wan" =~ ^[A-Za-z0-9_.:-]{1,32}$ ]] || return 1
  ip link show "$wan" >/dev/null 2>&1 || return 1
  python3 - "$gw" <<'PY' || return 1
import ipaddress
import sys
ipaddress.IPv4Address(sys.argv[1])
PY
  # Remove a provider-created main-table default, then restore the gateway that
  # was captured before tunnel startup. This is also a recovery belt for legacy
  # profiles activated before --route-noexec was enforced.
  while ip route del default dev "$OVPN_IF" 2>/dev/null; do :; done
  if ! ip -4 route show table main default | grep -Fq "via $gw dev $wan"; then
    ip route replace default via "$gw" dev "$wan"
  fi
}

validate_wireguard_routing() {
  # Internet Encryption is a full internet tunnel. Reject a provider profile
  # that cannot carry every IPv4 destination before it can alter any routes.
  /usr/bin/python3 - "$1" <<'PY'
import ipaddress
import sys

networks = []
section = ""
with open(sys.argv[1], encoding="utf-8") as handle:
    for raw in handle:
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1].strip().lower()
            continue
        if section != "peer" or "=" not in line:
            continue
        key, value = (part.strip() for part in line.split("=", 1))
        if key.lower() != "allowedips":
            continue
        for item in value.split(","):
            network = ipaddress.ip_network(item.strip(), strict=False)
            if network.version == 4:
                networks.append(network)

collapsed = list(ipaddress.collapse_addresses(networks))
if ipaddress.ip_network("0.0.0.0/0") not in collapsed:
    raise SystemExit(1)
PY
}

wait_for_wireguard_handshake() {
  # Bring-up is transactional: Table=off keeps the current management route
  # intact while this probe forces and verifies the authenticated WG handshake.
  local i latest ready="false"
  # A narrow temporary rule stimulates the peer without changing the system's
  # default route. It is removed on both success and failure.
  ip route replace 1.1.1.1/32 dev "$WG_IF" table "$RT_TABLE" || return 1
  while ip rule del pref "$PROBE_PREF" 2>/dev/null; do :; done
  ip rule add to 1.1.1.1/32 lookup "$RT_TABLE" pref "$PROBE_PREF" || {
    ip route del 1.1.1.1/32 table "$RT_TABLE" 2>/dev/null || true
    return 1
  }
  ping -c 1 -W 1 1.1.1.1 >/dev/null 2>&1 || true
  for i in $(seq 1 20); do
    latest="$(wg show "$WG_IF" latest-handshakes 2>/dev/null | awk '$2 > 0 {print $2; exit}')"
    if [[ -n "$latest" ]]; then
      ready="true"
      break
    fi
    sleep 0.5
  done
  while ip rule del pref "$PROBE_PREF" 2>/dev/null; do :; done
  ip route del 1.1.1.1/32 table "$RT_TABLE" 2>/dev/null || true
  [[ "$ready" == "true" ]]
}

# ── up ──────────────────────────────────────────────────────────────────────────
do_up() {
  local src="${1:-}" engine="${2:-wireguard}" scope="${3:-all}" ips="${4:-}" macs="${5:-}"
  [[ -n "$src" ]] || err "usage: up <src_conf> <engine> <scope> [csv_ips] [csv_macs]"
  [[ "$src" == "$SOURCE_CONF" ]] || err "config path is not allowed"
  [[ "$(realpath -e -- "$src" 2>/dev/null)" == "$SOURCE_CONF" ]] ||
    err "config path is not canonical"
  [[ "$engine" == "wireguard" || "$engine" == "openvpn" || "$engine" == "outline" ]] || err "invalid VPN engine"
  [[ "$scope" == "all" || "$scope" == "selected" ]] || err "invalid routing scope"
  validate_ip_csv "$ips" || err "invalid selected-device IP list"
  validate_mac_csv "$macs" || err "invalid selected-device MAC list"
  [[ "$scope" == "selected" || -z "$ips" ]] || err "IP list is only valid for selected scope"
  [[ "$scope" == "selected" || -z "$macs" ]] || err "MAC list is only valid for selected scope"
  [[ "$scope" != "selected" || -n "$macs" ]] || err "selected scope requires at least one MAC address"
  # Tear any prior instance down first (idempotent).
  do_down >/dev/null 2>&1
  copy_source_config "$src" || err "invalid VPN source configuration"
  src="$SAFE_SOURCE"

  local wan gw lan; wan="$(wan_iface)"; gw="$(wan_gw "$wan")"; lan="$(lan_cidr "$wan")"
  [[ -n "$wan" ]] || err "cannot determine WAN interface (no default route)"
  [[ -n "$gw" ]] || err "cannot determine the original WAN gateway"
  sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1

  local IF="" srv=""
  if [[ "$engine" == "openvpn" ]]; then
    IF="$OVPN_IF"
  elif [[ "$engine" == "outline" ]]; then
    IF="outline-redir"
  else
    IF="$WG_IF"
  fi
  # Persist recovery information before either VPN engine starts. A crash or an
  # interrupted request can therefore always restore the physical WAN route.
  printf 'PHASE=preparing\nENGINE=%s\nIF=%s\nSCOPE=%s\nIPS=%s\nMACS=%s\nWAN=%s\nGW=%s\nUP_TS=%s\n' \
    "$engine" "$IF" "$scope" "$ips" "$macs" "$wan" "$gw" "$(date +%s)" > "$STATE"
  chmod 0600 "$STATE"
  trap rollback_incomplete_activation EXIT
  trap 'exit 1' HUP INT TERM

  if [[ "$engine" == "openvpn" ]]; then
    ensure_ovpn || err "openvpn not available"
    mkdir -p /etc/openvpn
    validate_openvpn_config "$src"
    grep -qiE '^\s*remote\s+' "$src" || err "not an OpenVPN config (no remote)"
    # Any exit before the interface is authenticated must leave no credentials,
    # provider config, daemon, route or kill-switch behind.
    install -o root -g root -m 600 "$src" "$OVPN_CONF"
    sanitize_openvpn_routing "$OVPN_CONF" || err "cannot sanitize OpenVPN routing directives"
    prepare_openvpn_credentials "$OVPN_CONF"
    srv="$(ovpn_server_ip "$OVPN_CONF")"
    # Named tun, no wg-style DNS push handling; NetProtection owns :53.
    openvpn --config "$OVPN_CONF" --dev-type tun --dev "$OVPN_IF" \
            --script-security 0 --user nobody --group nogroup \
            --remote-cert-tls server \
            --route-nopull --route-noexec --daemon easypi-ovpn --writepid "$OVPN_PID" \
            --log "$OVPN_LOG" 9>&- >/dev/null 2>&1
    local i
    for i in $(seq 1 120); do
      ip link show "$OVPN_IF" >/dev/null 2>&1 && break
      if [[ -s "$OVPN_PID" ]]; then
        local ovpn_pid
        ovpn_pid="$(cat "$OVPN_PID" 2>/dev/null || true)"
        [[ "$ovpn_pid" =~ ^[0-9]+$ ]] && kill -0 "$ovpn_pid" 2>/dev/null || break
      fi
      sleep 0.5
    done
    ip link show "$OVPN_IF" >/dev/null 2>&1 || err "openvpn interface did not appear: $(tail -6 "$OVPN_LOG" 2>/dev/null | tr '\n' ' ')"
    ip link set "$OVPN_IF" up 2>/dev/null
    # Provider profiles must never be able to replace EasyPi's main default
    # route, even when a future OpenVPN option bypasses the config sanitizer.
    ip -4 route show table main default | grep -Fq "via $gw dev $wan" ||
      err "OpenVPN changed the EasyPi management route; activation was rolled back"
  elif [[ "$engine" == "wireguard" ]]; then
    ensure_wg || err "wireguard-tools not available"
    mkdir -p /etc/wireguard
    # Strip provider hooks and routing directives. Table=off makes activation
    # transactional: validate the encrypted peer first, then add our own audited
    # routing and management exceptions for both scopes.
    grep -viE '^\s*(DNS|Table|PreUp|PostUp|PreDown|PostDown|SaveConfig)\s*=' "$src" > "$WG_CONF"
    grep -qiE '^\s*PrivateKey' "$WG_CONF" || err "not a WireGuard config (no PrivateKey)"
    grep -qiE '^\s*Endpoint' "$WG_CONF" || err "not a WireGuard config (no Endpoint)"
    validate_wireguard_routing "$WG_CONF" || err "WireGuard config must route all IPv4 traffic (AllowedIPs 0.0.0.0/0)"
    sed -i '/^\[Interface\]/a Table = off' "$WG_CONF"
    chmod 600 "$WG_CONF"
    local wg_log wg_error
    wg_log="$(mktemp /run/easypi-wgout.XXXXXX)" || err "cannot create WireGuard log"
    chmod 600 "$wg_log"
    if ! wg-quick up "$WG_IF" >"$wg_log" 2>&1; then
      wg_error="$(tail -2 "$wg_log" | tr '\n' ' ')"
      rm -f -- "$wg_log"
      err "wg-quick up failed: $wg_error"
    fi
    rm -f -- "$wg_log"
    srv="$(wg_server_ip "$WG_CONF")"
    if ! wait_for_wireguard_handshake; then
      wg-quick down "$WG_IF" >/dev/null 2>&1 || true
      rm -f "$WG_CONF"
      err "WireGuard peer did not complete a handshake; routing was not changed"
    fi
  else
    ensure_outline || err "Outline runtime is not available"
    prepare_outline_config "$src" || err "invalid static Outline access key"
    srv="$(resolve_host_ip "$(outline_server_host 2>/dev/null || true)")"
    [[ -n "$srv" ]] || err "Outline server hostname did not resolve to IPv4"

    # The access-key secret exists only in a root-owned 0600 JSON file and is
    # never placed in argv or logs. ss-redir drops privileges after binding.
    # The daemon must not inherit the operation lock. Otherwise its lifetime
    # holds the flock and every later Disable request times out as "busy".
    ss-redir -u -c "$OUTLINE_CONF" -a "$OUTLINE_USER" -f "$OUTLINE_PID" 9>&- >/dev/null 2>&1 ||
      err "Outline client failed to start"
    local outline_ready="false"
    for _ in $(seq 1 20); do
      if outline_process_running; then outline_ready="true"; break; fi
      sleep 0.25
    done
    [[ "$outline_ready" == "true" ]] || err "Outline client stopped during startup"
    local outline_srv_port
    outline_srv_port="$(outline_server_port 2>/dev/null || true)"
    if ! apply_outline_proxy "$scope" "$macs" "$wan" "$srv" "$outline_srv_port"; then
      err "failed to install fail-closed Outline routing"
    fi
    ip -4 route get 1.1.1.1 mark "$OUTLINE_MARK" 2>/dev/null | grep -Eq '(^|[[:space:]])dev[[:space:]]+lo([[:space:]]|$)' ||
      err "Outline routing safety check failed; activation was rolled back"
    install -o root -g root -m 0644 /dev/null "$OUTLINE_ACTIVE"
    printf 'outline\n' > "$OUTLINE_ACTIVE"
  fi

  if [[ "$engine" != "outline" ]]; then
    # NAT LAN -> tunnel.
    iptables -t nat -C POSTROUTING -o "$IF" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o "$IF" -j MASQUERADE

    if ! apply_manual_routing "$IF" "$scope" "$macs" "$wan" "$gw" "$lan" "$srv"; then
      err "failed to install fail-closed outbound VPN routing"
    fi

    verify_routing_invariants "$IF" "$wan" "$gw" ||
      err "routing safety check failed; activation was rolled back"
  fi

  sed -i 's/^PHASE=.*/PHASE=active/' "$STATE"
  trap - EXIT HUP INT TERM
  do_status
}

# ── reconcile (DHCP follow for selected scope) ─────────────────────────────────
do_reconcile() {
  local ips="${1:-}" macs="${2:-}"
  validate_ip_csv "$ips" || err "invalid selected-device IP list"
  validate_mac_csv "$macs" || err "invalid selected-device MAC list"
  [[ -n "$macs" ]] || err "selected scope requires at least one MAC address"
  [[ -f "$STATE" ]] || err "not running"
  local engine scope wan IF
  engine=$(sed -n 's/^ENGINE=//p' "$STATE"); scope=$(sed -n 's/^SCOPE=//p' "$STATE")
  wan=$(sed -n 's/^WAN=//p' "$STATE"); IF=$(sed -n 's/^IF=//p' "$STATE")
  [[ "$scope" == "selected" ]] || err "reconcile only applies to selected scope"
  if [[ "$engine" == "outline" ]]; then
    outline_process_running || err "Outline client is not running"
    # Outline targets are MAC-based, so DHCP/IP reconciliation never requires
    # firewall mutation. Explicit UI target changes use a full transactional up.
    [[ "$(sed -n 's/^MACS=//p' "$STATE")" == "$macs" ]] ||
      err "Outline target changes require a transactional re-enable"
  else
    local gw lan; gw="$(wan_gw "$wan")"; lan="$(lan_cidr "$wan")"
    # Rebuild per-device MAC rules. IPs remain status metadata only.
    while ip rule del pref "$RULE_PREF" 2>/dev/null; do :; done
    while iptables -D FORWARD -o "$wan" -j "$KILL_CHAIN" 2>/dev/null; do :; done
    # (per-source kill rules are removed below by flushing the chain refs)
    iptables -S FORWARD 2>/dev/null | grep -- "-j $KILL_CHAIN" | sed 's/^-A/-D/' | while read -r line; do iptables $line 2>/dev/null; done
    apply_manual_routing "$IF" "selected" "$macs" "$wan" "$gw" "$lan" "" ||
      err "failed to update selected-device routing"
  fi
  sed -i "s/^IPS=.*/IPS=$ips/" "$STATE"
  if grep -q '^MACS=' "$STATE"; then
    sed -i "s/^MACS=.*/MACS=$macs/" "$STATE"
  else
    printf 'MACS=%s\n' "$macs" >> "$STATE"
  fi
  do_status
}

# ── down ────────────────────────────────────────────────────────────────────────
do_down() {
  local wan="" gw="" IF="" engine=""
  if [[ -f "$STATE" ]]; then
    wan=$(sed -n 's/^WAN=//p' "$STATE"); gw=$(sed -n 's/^GW=//p' "$STATE")
    IF=$(sed -n 's/^IF=//p' "$STATE"); engine=$(sed -n 's/^ENGINE=//p' "$STATE")
  fi
  [[ -n "$wan" ]] || wan="$(wan_iface)"

  # Stop the engine while management exceptions and the kill-switch still
  # exist. Restore the original WAN default before removing those safeguards.
  wg-quick down "$WG_IF" >/dev/null 2>&1; rm -f "$WG_CONF"
  cleanup_openvpn_runtime
  cleanup_outline_runtime "$wan"
  [[ -n "$gw" ]] && restore_wan_default_route "$wan" "$gw" || true
  [[ -n "$IF" ]] && iptables -t nat -D POSTROUTING -o "$IF" -j MASQUERADE 2>/dev/null
  iptables -t nat -D POSTROUTING -o "$WG_IF" -j MASQUERADE 2>/dev/null
  iptables -t nat -D POSTROUTING -o "$OVPN_IF" -j MASQUERADE 2>/dev/null

  # Remove any per-source kill rules referencing our chain, plus the whole-net one.
  iptables -S FORWARD 2>/dev/null | grep -- "-j $KILL_CHAIN" | sed 's/^-A/-D/' | while read -r line; do iptables $line 2>/dev/null; done
  ip6tables -S FORWARD 2>/dev/null | grep -- "-j $KILL_CHAIN" | sed 's/^-A/-D/' | while read -r line; do ip6tables $line 2>/dev/null; done
  clear_rules "$wan"
  rm -f -- "$STATE" "$SAFE_SOURCE" "$OUTLINE_ACTIVE"
  do_status
}

# ── status ──────────────────────────────────────────────────────────────────────
do_status() {
  local engine="" scope="all" running="false" endpoint="" handshake="0" rx="0" tx="0"
  local killswitch="false" wan="" IF="" ndev="0" ips="" macs=""
  if [[ -f "$STATE" ]]; then
    engine=$(sed -n 's/^ENGINE=//p' "$STATE"); scope=$(sed -n 's/^SCOPE=//p' "$STATE")
    wan=$(sed -n 's/^WAN=//p' "$STATE"); IF=$(sed -n 's/^IF=//p' "$STATE"); ips=$(sed -n 's/^IPS=//p' "$STATE"); macs=$(sed -n 's/^MACS=//p' "$STATE")
  fi
  [[ -n "$macs" ]] && ndev=$(printf '%s' "$macs" | awk -F',' '{print NF}')
  if [[ "$engine" == "outline" ]] && outline_process_running; then
    running="true"
  elif [[ -n "$IF" ]] && ip link show "$IF" >/dev/null 2>&1; then
    running="true"
    if [[ "$engine" == "wireguard" ]]; then
      local peer; peer="$(wg show "$WG_IF" dump 2>/dev/null | sed -n '2p')"
      if [[ -n "$peer" ]]; then
        endpoint="$(printf '%s' "$peer" | cut -f3)"; handshake="$(printf '%s' "$peer" | cut -f5)"
        rx="$(printf '%s' "$peer" | cut -f6)"; tx="$(printf '%s' "$peer" | cut -f7)"
      fi
    fi
  fi
  if [[ "$running" == "true" && "$engine" != "outline" && -n "$IF" ]]; then
    [[ -r "/sys/class/net/$IF/statistics/rx_bytes" ]] &&
      rx="$(cat "/sys/class/net/$IF/statistics/rx_bytes" 2>/dev/null || printf '0')"
    [[ -r "/sys/class/net/$IF/statistics/tx_bytes" ]] &&
      tx="$(cat "/sys/class/net/$IF/statistics/tx_bytes" 2>/dev/null || printf '0')"
  elif [[ "$engine" == "outline" ]]; then
    rx="$(outline_chain_bytes "$OUTLINE_RX_CHAIN")"
    tx="$(outline_chain_bytes "$OUTLINE_TX_CHAIN")"
  fi
  if [[ "$engine" == "outline" && -n "$wan" ]] &&
     iptables -t mangle -C PREROUTING -i "$wan" -j "$OUTLINE_MANGLE_CHAIN" 2>/dev/null &&
     iptables -t nat -C PREROUTING -i "$wan" -p tcp -j "$OUTLINE_NAT_CHAIN" 2>/dev/null; then
    killswitch="true"
  elif [[ -n "$wan" ]] && { iptables -C FORWARD -o "$wan" -j "$KILL_CHAIN" 2>/dev/null || iptables -S FORWARD 2>/dev/null | grep -q -- "-j $KILL_CHAIN"; }; then
    killswitch="true"
  fi
  local configured="false"; { [[ -f "$WG_CONF" ]] || [[ -f "$OVPN_CONF" ]] || [[ -f "$OUTLINE_CONF" ]]; } && configured="true"
  json "{\"success\":true,\"configured\":$configured,\"running\":$running,\"engine\":\"$(jesc "$engine")\",\"scope\":\"$(jesc "$scope")\",\"devices\":${ndev:-0},\"endpoint\":\"$(jesc "$endpoint")\",\"latest_handshake\":${handshake:-0},\"rx_bytes\":${rx:-0},\"tx_bytes\":${tx:-0},\"killswitch\":$killswitch}"
}

main() {
  init_runtime
  case "${1:-status}" in
    up|reconcile|down)
      local action="$1"
      shift
      exec 9>"$LOCK_FILE"
      chmod 0600 "$LOCK_FILE"
      flock -w 10 9 || err "another Internet Encryption operation is already running"
      case "$action" in
        up) do_up "$@" ;;
        reconcile) do_reconcile "$@" ;;
        down) do_down ;;
      esac
      ;;
    status)    do_status ;;
    *) err "unknown subcommand" ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
