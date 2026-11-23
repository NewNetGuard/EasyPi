#!/usr/bin/env bash
#
# Stealth VPN (Privacy -> Stealth, anti-DPI). Runner-invoked (root).
#
# EasyPi as a Chameleon CLIENT: routes the whole network or selected devices out
# through a DPI/ТСПУ-resistant stealth tunnel (REALITY + uTLS, masquerades as a
# browser) to a Chameleon server. The headless client daemon (chameleon-client)
# owns the cham0 TUN; this script runs it and wires the policy routing + kill-switch.
#
# Uses its OWN routing table (51821) + kill-switch chain (EASYPI_STEALTH), distinct
# from the Internet Encryption outbound VPN (51820 / EASYPI_VPNOUT), so the two can
# coexist per-device (some devices via Stealth, others via WireGuard/OpenVPN).
#
# Subcommands:
#   up <src_conf> <scope> [csv_ips] [block_quic]   scope=all|selected
#   reconcile <csv_ips>               re-apply per-device rules (DHCP follow)
#   guard                             install persisted fail-closed rules early
#   resume                            restore a persisted strict session at boot
#   down                              stop daemon + tear routing/kill-switch down
#   status                            JSON
#
set -uo pipefail

IF="cham0"
# TCP streams: covered devices' TCP leaves through this veth into a local
# namespace where TPROXY hands it to a listener systemd passes to the
# Chameleon client, which carries each connection as its own stream. The
# client installs the route into that namespace only while the server offers
# streams; without it the same TCP takes the packet tunnel (cham0). Nothing
# is routed onward from that namespace, so the guard may let it pass.
TCP_STREAM_IF="chtcp0"
TCP_STREAM_NS="easypi-chtcp"
TCP_STREAM_NS_IF="chtcp1"
TCP_STREAM_HOST_IP="169.254.77.1"
TCP_STREAM_NS_IP="169.254.77.2"
TCP_STREAM_PORT="15080"
TCP_STREAM_TABLE="51824"
TCP_STREAM_SOCKET="easypi-chameleon-tcp.socket"
CHAM_BIN="/opt/EasyPi/bin/chameleon-client"
SOURCE_CONF="/opt/EasyPi/data/netprotection/stealth_client.conf"
RUNTIME_DIR="/run/easypi-stealth"
SAFE_CONF="$RUNTIME_DIR/client.conf"
STATE="$RUNTIME_DIR/state.env"
STATUS_DIR="$RUNTIME_DIR/status"
STATUS_FILE="$STATUS_DIR/status.json"
PROFILE_DIR="/var/lib/easypi/stealth"
PROFILE_FILE="$PROFILE_DIR/profile.json"
POLICY_DIR="/var/lib/easypi/stealth-policy"
DNS_POLICY_FILE="$POLICY_DIR/dns-policy.json"
LOG="/var/log/easypi/stealth.log"
CHAM_SERVICE="easypi-chameleon-client.service"
CHAM_UNIT="/run/systemd/system/$CHAM_SERVICE"
TCP_STREAM_SOCKET_UNIT="/run/systemd/system/$TCP_STREAM_SOCKET"
STEALTH_SCRIPT="/opt/EasyPi/scripts/settings/stealth_vpn.sh"
CHAM_USER="easypi-chameleon"
CHAM_GROUP="easypi-chameleon"
DNS_PROXY_USER="easypi-stealth-dns"
DNS_PROXY_GROUP="easypi-stealth-dns"
DNS_PROXY_SERVICE="easypi-stealth-dns.service"
STRICT_UNIT_TEMPLATE_DIR="/opt/EasyPi/templates/systemd"
UPDATE_MARKER="/opt/EasyPi/.update-in-progress"
UPDATE_LOCK_FILE="/run/lock/easypi-update.lock"
RT_TABLE="51821"
DNS_RT_TABLE="51823"
KILL_CHAIN="EASYPI_STEALTH"
QUIC_CHAIN="EASYPI_STEALTH_QUIC"
DNS_CHAIN="EASYPI_STEALTH_DNS"
DNS6_CHAIN="EASYPI_STEALTH_DNS6"
DNS_BOOT_CHAIN="EASYPI_STEALTH_DNS_BOOT"
DNS6_BOOT_CHAIN="EASYPI_STEALTH_DNS6_BOOT"
DEVICE_CHAIN="EASYPI_STEALTH_DEVICE"
MSS_CHAIN="EASYPI_STEALTH_MSS"
PRE_CHAIN="EASYPI_STEALTH_PRESTART"
PRE6_CHAIN="EASYPI_STEALTH6_PRESTART"
PRE_DNS_CHAIN="EASYPI_STEALTH_DNS_PRE"
PRE_DNS6_CHAIN="EASYPI_STEALTH_DNS6_PRE"
DEVICE_MARK="0x51822"
DEVICE_MARK_MASK="0xffffffff"
DNS_PROXY_CHAIN="EASYPI_STEALTH_DNS_PROXY"
DNS_EGRESS_CHAIN="EASYPI_STEALTH_DNS_EGRESS"
RULE_PREF="5100" # legacy whole-host rule; retained only for upgrade cleanup
MGMT_PREF="5090"   # higher priority than RULE_PREF: LAN/management always direct
TAILSCALE_PREF="5089" # Tailscale routes live in its policy table, not main
LEGACY_DNS_PREF="5095" # old releases routed EasyPi's own resolver through Stealth
DEVICE_PREF="5096" # selected-device packets are marked by source MAC in PREROUTING
DNS_PROXY_PREF="5094" # dedicated resolver egress; blackholes when cham0 is absent
DNS_PROXY_STAGING_PREF="5093" # protects rule replacement without a routing gap
TCP_STREAM_VPS_PREF="5091" # device TCP to the Chameleon server stays on cham0
TCP_STREAM_PREF="5092" # device TCP to the stream table; empty table falls through to DEVICE_PREF

initialize_runtime_paths() {
  if getent group "$CHAM_GROUP" >/dev/null 2>&1; then
    install -d -o root -g "$CHAM_GROUP" -m 0750 "$RUNTIME_DIR"
  else
    install -d -o root -g root -m 0700 "$RUNTIME_DIR"
  fi
  if id -u "$CHAM_USER" >/dev/null 2>&1; then
    install -d -o "$CHAM_USER" -g easypi -m 0750 "$PROFILE_DIR"
  else
    install -d -o root -g easypi -m 0750 "$PROFILE_DIR"
  fi
  install -d -o root -g easypi -m 0750 "$(dirname "$LOG")"
  [[ ! -L "$POLICY_DIR" ]] || { echo "Refusing symlink policy directory: $POLICY_DIR" >&2; return 1; }
  install -d -o root -g easypi -m 0750 "$POLICY_DIR" || return 1
  [[ ! -L "$LOG" ]] || { echo "Refusing symlink log file: $LOG" >&2; return 1; }
  touch "$LOG" || return 1
  chown root:easypi "$LOG" || return 1
  chmod 0640 "$LOG" || return 1

  # Safe Update copies product files without rerunning the full installer. Once
  # its rollback marker is gone, provision the strict product-owned units from
  # the signed, root-owned tree. Deferring while the marker exists prevents a
  # failed first update from leaving host integration behind after code rollback.
  # Lifecycle cleanup must never provision or enable services. In particular,
  # uninstall calls `down` after taking the operation locks; allowing this
  # initializer to repair units there would recreate the services being removed.
  if [[ "${EASYPI_LIFECYCLE_MODE:-runtime}" == "runtime" \
      && ! -e "$UPDATE_MARKER" && "${1:-status}" != "guard" ]]; then
    ensure_strict_service_units || return 1
    migrate_running_policy_if_needed || return 1
  fi
}

json() { printf '%s\n' "$1"; }
jesc() { printf '%s' "${1:-}" | sed 's/\\/\\\\/g; s/"/\\"/g'; }
err()  { json "{\"success\":false,\"error\":\"$(jesc "$1")\"}"; exit 1; }
temporary_err() {
  json "{\"success\":false,\"failure_code\":\"server_unavailable\",\"error\":\"$(jesc "$1")\"}"
  exit 75
}

tune_tcp_transport() {
  # Chameleon carries all selected devices over one long-lived TCP connection.
  # Large autotuning ceilings avoid starving that carrier, while BBR prevents
  # one loss/reordering event from collapsing throughput for every inner flow.
  # Every setting is best-effort so an older kernel can still run Chameleon.
  sysctl -q -w net.core.rmem_max=67108864 >/dev/null 2>&1 || true
  sysctl -q -w net.core.wmem_max=67108864 >/dev/null 2>&1 || true
  sysctl -q -w 'net.ipv4.tcp_rmem=4096 87380 67108864' >/dev/null 2>&1 || true
  sysctl -q -w 'net.ipv4.tcp_wmem=4096 65536 67108864' >/dev/null 2>&1 || true
  if modprobe tcp_bbr >/dev/null 2>&1; then
    sysctl -q -w net.core.default_qdisc=fq >/dev/null 2>&1 || true
    sysctl -q -w net.ipv4.tcp_congestion_control=bbr >/dev/null 2>&1 || true
  fi
}

update_lock_is_held() {
  # Safe Update keeps its root-owned lock for the complete apply, validation
  # and rollback transaction. A boot with only a stale marker has no holder and
  # must remain blocked until the recovery unit acquires the lock.
  [[ -f "$UPDATE_LOCK_FILE" && ! -L "$UPDATE_LOCK_FILE" ]] || return 1
  local owner mode lock_fd
  owner="$(stat -c '%u' -- "$UPDATE_LOCK_FILE" 2>/dev/null)" || return 1
  mode="$(stat -c '%a' -- "$UPDATE_LOCK_FILE" 2>/dev/null)" || return 1
  [[ "$owner" == "0" && $((8#$mode & 8#022)) -eq 0 ]] || return 1
  exec {lock_fd}<>"$UPDATE_LOCK_FILE" || return 1
  if flock -n "$lock_fd"; then
    flock -u "$lock_fd" 2>/dev/null || true
    exec {lock_fd}>&-
    return 1
  fi
  exec {lock_fd}>&-
  return 0
}

first_append_rule_is() {
  local command_name="$1" builtin_chain="$2" expected="${3,,}" first
  first="$("$command_name" -S "$builtin_chain" 2>/dev/null \
    | awk '$1 == "-A" {print; exit}')" || return 1
  [[ "${first,,}" == "$expected" ]]
}

selected_guards_are_leading() {
  local command_name="$1" builtin_chain="$2" target_chain="$3" mac_csv="$4"
  local mac line index=0 required_count=0
  local -a macs=() rules=()
  local -A required=()
  IFS=',' read -ra macs <<< "$mac_csv"
  for mac in "${macs[@]}"; do
    [[ -n "$mac" ]] || continue
    required["-a ${builtin_chain,,} -m mac --mac-source ${mac,,} -j ${target_chain,,}"]=1
  done
  [[ "${#required[@]}" -gt 0 ]] || return 1
  required_count="${#required[@]}"
  mapfile -t rules < <("$command_name" -S "$builtin_chain" 2>/dev/null \
    | awk '$1 == "-A"')
  [[ "${#rules[@]}" -ge "$required_count" ]] || return 1
  for ((index = 0; index < required_count; index++)); do
    line="${rules[$index],,}"
    [[ -n "${required[$line]:-}" ]] || return 1
    unset "required[$line]"
  done
  [[ "${#required[@]}" -eq 0 ]]
}

wan_iface() { ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="dev"){print $(i+1); exit}}' | grep -vE "^${IF}$" | head -n1; }
wan_gw()    { ip route show default 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="via"){print $(i+1); exit}}' | head -n1; }
lan_cidr()  { local w="$1"; ip route show dev "$w" proto kernel scope link 2>/dev/null | awk '{print $1; exit}'; }

resolve_host_ip() { # host (name OR literal IP) -> IPv4
  local h="${1:-}"; [[ -z "$h" ]] && return
  if [[ "$h" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then printf '%s' "$h"; return; fi
  getent ahostsv4 "$h" 2>/dev/null | awk '{print $1; exit}'
}
cham_server_ip() { # parse "server_address":"host:port" from the JSON config
  local host route_ip
  route_ip=$(grep -oE '"server_route_ip"[[:space:]]*:[[:space:]]*"[0-9.]+"' "$1" | head -1 \
    | sed -E 's/.*:[[:space:]]*"([0-9.]+)".*/\1/')
  if [[ "$route_ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
    printf '%s' "$route_ip"
    return
  fi
  host=$(grep -oE '"server_address"[[:space:]]*:[[:space:]]*"[^"]*"' "$1" | head -1 \
    | sed -E 's/.*:[[:space:]]*"([^"]*)".*/\1/; s/:[0-9]+$//')
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
if len(items) > 256 or len(set(items)) != len(items):
    raise SystemExit(1)
pattern = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")
if any(not pattern.fullmatch(item) for item in items):
    raise SystemExit(1)
PY
}

write_dns_policy() {
  # $1=true|false $2=scope $3=csv_ips $4=csv_macs $5=block_quic
  local enabled="$1" scope="$2" ips="$3" macs="$4" block_quic="$5"
  [[ ! -L "$POLICY_DIR" && ! -L "$DNS_POLICY_FILE" ]] || return 1
  install -d -o root -g easypi -m 0750 "$POLICY_DIR" || return 1
  POLICY_DIR="$POLICY_DIR" DNS_POLICY_FILE="$DNS_POLICY_FILE" \
    /usr/bin/python3 - "$enabled" "$scope" "$ips" "$macs" "$block_quic" <<'PY'
import grp
import json
import os
import tempfile

enabled, scope, ips, macs, block_quic = os.sys.argv[1:]
payload = {
    "version": 1,
    "enabled": enabled == "true",
    "scope": scope,
    "ips": [value for value in ips.split(",") if value],
    "macs": [value for value in macs.split(",") if value],
    "block_quic": block_quic == "true",
}
directory = os.environ["POLICY_DIR"]
destination = os.environ["DNS_POLICY_FILE"]
group_id = grp.getgrnam("easypi").gr_gid
fd, temporary = tempfile.mkstemp(prefix=".dns-policy.", dir=directory)
try:
    os.fchmod(fd, 0o640)
    os.fchown(fd, 0, group_id)
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        fd = -1
        json.dump(payload, handle, separators=(",", ":"), sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, destination)
    directory_fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(directory_fd)
    finally:
        os.close(directory_fd)
finally:
    if fd >= 0:
        os.close(fd)
    try:
        os.unlink(temporary)
    except FileNotFoundError:
        pass
PY
}

read_dns_policy() {
  DNS_POLICY_FILE="$DNS_POLICY_FILE" POLICY_DIR="$POLICY_DIR" /usr/bin/python3 - <<'PY'
import ipaddress
import json
import os
import re
import stat

path = os.environ["DNS_POLICY_FILE"]
directory = os.environ["POLICY_DIR"]


def fail_closed():
    print("true")
    print("all")
    print("")
    print("")
    print("true")


try:
    parent = os.stat(directory, follow_symlinks=False)
    if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
        raise ValueError("unsafe policy directory")
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
except FileNotFoundError:
    print("false\nall\n\n\ntrue")
    raise SystemExit(0)
except (OSError, ValueError):
    fail_closed()
    raise SystemExit(0)

try:
    info = os.fstat(fd)
    if (
        not stat.S_ISREG(info.st_mode)
        or info.st_uid != 0
        or info.st_mode & 0o022
        or info.st_size > 64 * 1024
    ):
        raise ValueError("unsafe policy file")
    with os.fdopen(fd, "r", encoding="utf-8") as handle:
        fd = -1
        value = json.load(handle)
    if (
        not isinstance(value, dict)
        or value.get("version") != 1
        or not isinstance(value.get("enabled"), bool)
    ):
        raise ValueError("invalid policy")
    scope = value.get("scope")
    if scope not in {"all", "selected"}:
        raise ValueError("invalid scope")
    ips = value.get("ips", [])
    macs = value.get("macs", [])
    if not isinstance(ips, list) or not isinstance(macs, list) or len(ips) > 256 or len(macs) > 256:
        raise ValueError("invalid device list")
    normalized_ips = []
    for item in ips:
        address = ipaddress.ip_address(str(item))
        if address.version != 4 or address.is_unspecified or address.is_multicast:
            raise ValueError("invalid address")
        normalized_ips.append(str(address))
    pattern = re.compile(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}")
    normalized_macs = [str(item).lower() for item in macs]
    if any(not pattern.fullmatch(item) for item in normalized_macs):
        raise ValueError("invalid MAC")
    if scope == "selected" and not normalized_macs:
        raise ValueError("empty selected policy")
    print("true" if value["enabled"] else "false")
    print(scope)
    print(",".join(normalized_ips))
    print(",".join(normalized_macs))
    print("true" if value.get("block_quic", True) else "false")
except (OSError, ValueError, TypeError, json.JSONDecodeError):
    fail_closed()
finally:
    if fd >= 0:
        os.close(fd)
PY
}

migrate_running_policy_if_needed() {
  # A Safe Update can introduce strict mode while an older Chameleon session is
  # already running. Convert its trusted root runtime state only after the
  # update marker has been cleared, so a failed update cannot leave new firewall
  # state behind after rollback.
  [[ ! -e "$DNS_POLICY_FILE" && -f "$STATE" && ! -L "$STATE" ]] || return 0
  # /run survives some reinstall/update sequences and is not persistent intent.
  # Migrate an old running session only when its canonical persistent client
  # configuration still exists. A stale runtime file alone must never enable a
  # fresh installation's fail-closed policy.
  [[ -f "$SOURCE_CONF" && ! -L "$SOURCE_CONF" ]] || return 0
  [[ "$(realpath -e -- "$SOURCE_CONF" 2>/dev/null)" == "$SOURCE_CONF" ]] || return 1
  local source_mode
  source_mode="$(stat -c '%a' -- "$SOURCE_CONF" 2>/dev/null)" || return 1
  [[ $((8#$source_mode & 8#022)) -eq 0 ]] || return 1
  local state_uid state_mode scope ips macs block_quic wan
  state_uid="$(stat -c '%u' -- "$STATE" 2>/dev/null)" || return 1
  state_mode="$(stat -c '%a' -- "$STATE" 2>/dev/null)" || return 1
  [[ "$state_uid" == "0" && $((8#$state_mode & 8#022)) -eq 0 ]] || return 1
  scope="$(sed -n 's/^SCOPE=//p' "$STATE")"
  ips="$(sed -n 's/^IPS=//p' "$STATE")"
  macs="$(sed -n 's/^MACS=//p' "$STATE")"
  block_quic="$(sed -n 's/^BLOCK_QUIC=//p' "$STATE")"
  [[ "$scope" == "all" || "$scope" == "selected" ]] || return 1
  [[ "$block_quic" == "false" ]] || block_quic="true"
  validate_ip_csv "$ips" || return 1
  validate_mac_csv "$macs" || return 1
  [[ "$scope" != "selected" || -n "$macs" ]] || return 1
  wan="$(wan_iface)"
  install_prestart_guard "$scope" "$ips" "$macs" "$wan" || return 1
  activate_strict_dns_policy "$scope" "$ips" "$macs" "$block_quic" || return 1
}

ensure_dns_proxy_identity() {
  if ! getent group "$DNS_PROXY_GROUP" >/dev/null 2>&1; then
    groupadd --system "$DNS_PROXY_GROUP" || return 1
  fi
  if id -u "$DNS_PROXY_USER" >/dev/null 2>&1; then
    [[ "$(id -gn "$DNS_PROXY_USER" 2>/dev/null)" == "$DNS_PROXY_GROUP" ]] || return 1
    [[ "$(id -nG "$DNS_PROXY_USER" 2>/dev/null)" == "$DNS_PROXY_GROUP" ]] || return 1
    local account_shell
    account_shell="$(getent passwd "$DNS_PROXY_USER" | cut -d: -f7)"
    [[ "$account_shell" == "/usr/sbin/nologin" || "$account_shell" == "/sbin/nologin" ]] \
      || return 1
  else
    useradd --system --gid "$DNS_PROXY_GROUP" --home-dir /nonexistent --no-create-home \
      --shell /usr/sbin/nologin "$DNS_PROXY_USER" || return 1
  fi
}

ensure_strict_service_units() {
  local unit source target source_uid source_mode changed="false"
  ensure_dns_proxy_identity || return 1
  for unit in easypi-netprotection.service easypi-stealth-guard.service \
      easypi-stealth-dns.service easypi-stealth-resume.service; do
    source="$STRICT_UNIT_TEMPLATE_DIR/$unit"
    target="/etc/systemd/system/$unit"
    [[ -f "$source" && ! -L "$source" ]] || return 1
    [[ "$(realpath -e -- "$source" 2>/dev/null)" == "$source" ]] || return 1
    source_uid="$(stat -c '%u' -- "$source" 2>/dev/null)" || return 1
    source_mode="$(stat -c '%a' -- "$source" 2>/dev/null)" || return 1
    [[ "$source_uid" == "0" && $((8#$source_mode & 8#022)) -eq 0 ]] || return 1
    if [[ -e "$target" || -L "$target" ]]; then
      [[ -f "$target" && ! -L "$target" ]] || return 1
    fi
    if ! cmp -s -- "$source" "$target" 2>/dev/null; then
      install -o root -g root -m 0644 "$source" "$target" || return 1
      changed="true"
    fi
  done
  if [[ "$changed" == "true" ]]; then
    systemctl daemon-reload >/dev/null 2>&1 || return 1
  fi
  systemctl enable easypi-netprotection.service easypi-stealth-guard.service \
    easypi-stealth-dns.service easypi-stealth-resume.service \
    >/dev/null 2>&1 || return 1
}

install_dns_egress_guard() {
  local dns_uid="$1"
  iptables -N "$DNS_EGRESS_CHAIN" 2>/dev/null || true
  # Build monotonically: install the deny rule before exposing the chain, then
  # insert narrow allows ahead of it. Never flush a live chain and create a gap.
  iptables -C "$DNS_EGRESS_CHAIN" -m owner --uid-owner "$dns_uid" \
    -j REJECT --reject-with icmp-port-unreachable 2>/dev/null \
    || iptables -A "$DNS_EGRESS_CHAIN" -m owner --uid-owner "$dns_uid" \
      -j REJECT --reject-with icmp-port-unreachable || return 1
  iptables -C OUTPUT -j "$DNS_EGRESS_CHAIN" 2>/dev/null \
    || iptables -I OUTPUT 1 -j "$DNS_EGRESS_CHAIN" || return 1
  iptables -C "$DNS_EGRESS_CHAIN" -m owner --uid-owner "$dns_uid" -o lo -j ACCEPT \
    2>/dev/null || iptables -I "$DNS_EGRESS_CHAIN" 1 -m owner \
      --uid-owner "$dns_uid" -o lo -j ACCEPT || return 1
  iptables -C "$DNS_EGRESS_CHAIN" -m owner --uid-owner "$dns_uid" -o "$IF" \
    -p udp --dport 53 -j ACCEPT 2>/dev/null \
    || iptables -I "$DNS_EGRESS_CHAIN" 1 -m owner --uid-owner "$dns_uid" \
      -o "$IF" -p udp --dport 53 -j ACCEPT || return 1
  iptables -C "$DNS_EGRESS_CHAIN" -m owner --uid-owner "$dns_uid" -o "$IF" \
    -p tcp --dport 53 -j ACCEPT 2>/dev/null \
    || iptables -I "$DNS_EGRESS_CHAIN" 1 -m owner --uid-owner "$dns_uid" \
      -o "$IF" -p tcp --dport 53 -j ACCEPT || return 1
}

clear_dns_egress_guard() {
  while iptables -D OUTPUT -j "$DNS_EGRESS_CHAIN" 2>/dev/null; do :; done
  iptables -F "$DNS_EGRESS_CHAIN" 2>/dev/null || true
  iptables -X "$DNS_EGRESS_CHAIN" 2>/dev/null || true
}

install_strict_dns_routing_rules() {
  ensure_dns_proxy_identity || return 1
  local dns_uid
  dns_uid="$(id -u "$DNS_PROXY_USER")" || return 1
  # Independent of policy routing: any later failure can stop DNS, but cannot
  # send this process through the ordinary WAN route.
  install_dns_egress_guard "$dns_uid" || return 1
  ip route replace blackhole default metric 42760 table "$DNS_RT_TABLE" || return 1
  if ip link show "$IF" >/dev/null 2>&1; then
    ip route replace default dev "$IF" metric 10 table "$DNS_RT_TABLE" || return 1
  fi
  # Keep a higher-priority staging rule while the stable rule is replaced. If
  # the stable add fails, staging and the OUTPUT guard remain fail-closed.
  while ip rule del pref "$DNS_PROXY_STAGING_PREF" lookup "$DNS_RT_TABLE" 2>/dev/null; do :; done
  ip rule add uidrange "$dns_uid-$dns_uid" lookup "$DNS_RT_TABLE" \
    pref "$DNS_PROXY_STAGING_PREF" || return 1
  while ip rule del pref "$DNS_PROXY_PREF" lookup "$DNS_RT_TABLE" 2>/dev/null; do :; done
  if ! ip rule add uidrange "$dns_uid-$dns_uid" lookup "$DNS_RT_TABLE" \
      pref "$DNS_PROXY_PREF"; then
    return 1
  fi
  while ip rule del pref "$DNS_PROXY_STAGING_PREF" lookup "$DNS_RT_TABLE" 2>/dev/null; do :; done

  # Remove the late OUTPUT-mark implementation used by development builds.
  # uidrange participates in the initial route lookup, so Linux also chooses
  # the correct cham0 source address instead of retaining the WAN address.
  while iptables -t mangle -D OUTPUT -j "$DNS_PROXY_CHAIN" 2>/dev/null; do :; done
  iptables -t mangle -F "$DNS_PROXY_CHAIN" 2>/dev/null || true
  iptables -t mangle -X "$DNS_PROXY_CHAIN" 2>/dev/null || true
}

install_strict_dns_routing() {
  install_strict_dns_routing_rules || return 1
  systemctl start "$DNS_PROXY_SERVICE" >/dev/null 2>&1 || return 1
}

strict_dns_guard_active() {
  local dns_uid accepts rule_count last_rule
  dns_uid="$(id -u "$DNS_PROXY_USER" 2>/dev/null)" || return 1
  ip rule show 2>/dev/null \
    | grep -E "^[[:space:]]*${DNS_PROXY_PREF}:.*uidrange ${dns_uid}-${dns_uid}.*lookup ${DNS_RT_TABLE}([[:space:]]|$)" >/dev/null \
    || return 1
  ip route show table "$DNS_RT_TABLE" 2>/dev/null | grep '^blackhole default' >/dev/null \
    || return 1
  first_append_rule_is iptables OUTPUT \
    "-A OUTPUT -j $DNS_EGRESS_CHAIN" || return 1
  iptables -C "$DNS_EGRESS_CHAIN" -m owner --uid-owner "$dns_uid" -o lo \
    -j ACCEPT 2>/dev/null || return 1
  iptables -C "$DNS_EGRESS_CHAIN" -m owner --uid-owner "$dns_uid" -o "$IF" \
    -p udp --dport 53 -j ACCEPT 2>/dev/null || return 1
  iptables -C "$DNS_EGRESS_CHAIN" -m owner --uid-owner "$dns_uid" -o "$IF" \
    -p tcp --dport 53 -j ACCEPT 2>/dev/null || return 1
  iptables -C "$DNS_EGRESS_CHAIN" -m owner --uid-owner "$dns_uid" \
    -j REJECT --reject-with icmp-port-unreachable 2>/dev/null || return 1
  accepts="$(iptables -S "$DNS_EGRESS_CHAIN" 2>/dev/null | grep -c -- '-j ACCEPT$')" \
    || true
  [[ "$accepts" == "3" ]] || return 1
  rule_count="$(iptables -S "$DNS_EGRESS_CHAIN" 2>/dev/null | grep -c -- '^-A ')" \
    || true
  [[ "$rule_count" == "4" ]] || return 1
  last_rule="$(iptables -S "$DNS_EGRESS_CHAIN" 2>/dev/null | tail -n1)"
  [[ "$last_rule" == *"--uid-owner $dns_uid"* \
     && "$last_rule" == *"-j REJECT --reject-with icmp-port-unreachable" ]]
}

activate_strict_dns_policy() {
  local scope="$1" ips="$2" macs="$3" block_quic="$4"
  # Install the independent egress guard before publishing strict intent. Then
  # publish before systemd starts the resolver and its guard dependency, so the
  # dependency can never mistake this activation for a disabled policy.
  install_strict_dns_routing_rules || return 1
  write_dns_policy true "$scope" "$ips" "$macs" "$block_quic" || return 1
  systemctl start "$DNS_PROXY_SERVICE" >/dev/null 2>&1 || return 1
}

clear_strict_dns_routing() {
  while ip rule del pref "$DNS_PROXY_STAGING_PREF" lookup "$DNS_RT_TABLE" 2>/dev/null; do :; done
  while ip rule del pref "$DNS_PROXY_PREF" lookup "$DNS_RT_TABLE" 2>/dev/null; do :; done
  ip route flush table "$DNS_RT_TABLE" 2>/dev/null || true
  clear_dns_egress_guard
  while iptables -t mangle -D OUTPUT -j "$DNS_PROXY_CHAIN" 2>/dev/null; do :; done
  iptables -t mangle -F "$DNS_PROXY_CHAIN" 2>/dev/null || true
  iptables -t mangle -X "$DNS_PROXY_CHAIN" 2>/dev/null || true
}

prepare_client_config() {
  SOURCE_CONF="$1" SAFE_CONF="$SAFE_CONF" PROFILE_FILE="$PROFILE_FILE" \
    STATUS_FILE="$STATUS_FILE" CHAM_GROUP="$CHAM_GROUP" \
    TCP_STREAM_TABLE="$TCP_STREAM_TABLE" TCP_STREAM_NS_IP="$TCP_STREAM_NS_IP" \
    TCP_STREAM_IF="$TCP_STREAM_IF" \
    /usr/bin/python3 - <<'PY'
import grp
import ipaddress
import json
import os
import re
import socket
import stat
import tempfile
import urllib.parse

source = os.environ["SOURCE_CONF"]
destination = os.environ["SAFE_CONF"]
profile_file = os.environ["PROFILE_FILE"]
status_file = os.environ["STATUS_FILE"]


def valid_host(value):
    if not value or len(value) > 253 or any(ord(char) < 33 for char in value):
        return False
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        pass
    try:
        ascii_host = value.encode("idna").decode("ascii")
    except UnicodeError:
        return False
    labels = ascii_host.rstrip(".").split(".")
    return bool(labels) and all(
        re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
        for label in labels
    )


def endpoint(value):
    if not isinstance(value, str) or len(value) > 320:
        raise ValueError("invalid endpoint")
    parsed = urllib.parse.urlsplit("//" + value)
    if parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment:
        raise ValueError("invalid endpoint")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid endpoint port") from exc
    if not valid_host(parsed.hostname or "") or port is None or not 1 <= port <= 65535:
        raise ValueError("invalid endpoint")
    host = parsed.hostname
    if ":" in host:
        host = f"[{host}]"
    return f"{host}:{port}"


def validated_ipv4_endpoint(value, route_value=None):
    normalized = endpoint(value)
    parsed = urllib.parse.urlsplit("//" + normalized)
    host, port = parsed.hostname, parsed.port
    if port != 443:
        raise ValueError("IP Shield endpoint must use port 443")
    route_address = None
    if route_value not in (None, ""):
        try:
            route_address = ipaddress.ip_address(str(route_value).strip())
        except ValueError as exc:
            raise ValueError("invalid server route address") from exc
        if route_address.version != 4 or not route_address.is_global:
            raise ValueError("server route must be a public IPv4 address")
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if route_address is not None:
            address = route_address
        else:
            answers = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
            if not answers:
                raise ValueError("cannot resolve server endpoint")
            address = ipaddress.ip_address(answers[0][4][0])
    if address.version != 4 or not address.is_global:
        raise ValueError("server endpoint must resolve to a public IPv4 address")
    if route_address is not None and address != route_address:
        raise ValueError("server route does not match the endpoint address")
    return normalized, str(address)


flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(source, flags)
try:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_size > 64 * 1024:
        raise ValueError("invalid source config")
    with os.fdopen(fd, "r", encoding="utf-8") as handle:
        fd = -1
        raw = json.load(handle)
finally:
    if fd >= 0:
        os.close(fd)

if not isinstance(raw, dict):
    raise ValueError("config must be a JSON object")

hex_key = re.compile(r"[0-9a-fA-F]{64}")
psk = str(raw.get("psk_key", ""))
transport_key = str(raw.get("transport_key", psk))
reality_public = str(raw.get("reality_server_public_key", ""))
if not hex_key.fullmatch(psk) or not hex_key.fullmatch(reality_public) or not hex_key.fullmatch(transport_key):
    raise ValueError("invalid tunnel key")

shield = str(raw.get("reality_shield_preset") or "").strip()
if shield != "ip":
    raise ValueError("only IP Shield is supported")
if raw.get("verify_server_certificate") is not True:
    raise ValueError("IP Shield requires server certificate verification")

doh_domain = str(raw.get("doh_domain") or "").strip()
if doh_domain and not valid_host(doh_domain):
    raise ValueError("invalid DoH domain")

buffer_size = int(raw.get("buffer_size", 1000))
reconnect_interval = int(raw.get("reconnect_interval", 5))
fingerprint_mode = str(raw.get("fingerprint_mode") or "auto").strip().lower()
if not 64 <= buffer_size <= 65535:
    raise ValueError("invalid buffer size")
if not 1 <= reconnect_interval <= 300:
    raise ValueError("invalid reconnect interval")
if fingerprint_mode not in {"auto", "mobile", "desktop"}:
    raise ValueError("invalid fingerprint mode")

server_endpoint, server_route_ip = validated_ipv4_endpoint(
    raw.get("server_address"), raw.get("server_route_ip")
)

clean = {
    # Preserve a DNS endpoint for TLS identity/SNI, but pin its resolved route
    # separately before the startup DNS guard is installed. The daemon verifies
    # the domain certificate while routing setup never needs an unprotected lookup.
    "server_address": server_endpoint,
    "server_route_ip": server_route_ip,
    "server_dial_address": f"{server_route_ip}:443",
    "psk_key": psk.lower(),
    "transport_key": transport_key.lower(),
    "protocol": "http2",
    "reality_server_public_key": reality_public.lower(),
    "reality_shield_preset": shield,
    "verify_server_certificate": True,
    "doh_domain": doh_domain,
    "buffer_size": buffer_size,
    "reconnect_interval": reconnect_interval,
    "fingerprint_mode": fingerprint_mode,
    "tun_name": "cham0",
    "tun_addr": "10.10.0.2/32",
    "mtu": 1420,
    "configure_tun": True,
    "status_file": status_file,
    "profile_path": profile_file,
    # Used only when EasyPi passes the stream listener: the client keeps this
    # route while the server offers TCP streams.
    "tcp_stream_route": {
        "table": int(os.environ["TCP_STREAM_TABLE"]),
        "via": os.environ["TCP_STREAM_NS_IP"],
        "dev": os.environ["TCP_STREAM_IF"],
    },
}

directory = os.path.dirname(destination)
chameleon_gid = grp.getgrnam(os.environ["CHAM_GROUP"]).gr_gid
fd, temp_name = tempfile.mkstemp(prefix=".client.", dir=directory)
try:
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        json.dump(clean, handle, separators=(",", ":"))
        handle.flush()
        os.fchown(handle.fileno(), 0, chameleon_gid)
        os.fchmod(handle.fileno(), 0o640)
        os.fsync(handle.fileno())
    os.replace(temp_name, destination)
finally:
    try:
        os.unlink(temp_name)
    except FileNotFoundError:
        pass
PY
}

ensure_chameleon_identity() {
  if ! getent group "$CHAM_GROUP" >/dev/null 2>&1; then
    groupadd --system "$CHAM_GROUP" || return 1
  fi
  if id -u "$CHAM_USER" >/dev/null 2>&1; then
    [[ "$(id -gn "$CHAM_USER" 2>/dev/null)" == "$CHAM_GROUP" ]] || return 1
    [[ "$(id -nG "$CHAM_USER" 2>/dev/null)" == "$CHAM_GROUP" ]] || return 1
    local account_shell
    account_shell="$(getent passwd "$CHAM_USER" | cut -d: -f7)"
    [[ "$account_shell" == "/usr/sbin/nologin" || "$account_shell" == "/sbin/nologin" ]] || return 1
  else
    useradd --system --gid "$CHAM_GROUP" --home-dir /nonexistent --no-create-home \
      --shell /usr/sbin/nologin "$CHAM_USER" || return 1
  fi

  install -d -o root -g "$CHAM_GROUP" -m 0750 "$RUNTIME_DIR" || return 1
  install -d -o "$CHAM_USER" -g "$CHAM_GROUP" -m 0700 "$STATUS_DIR" || return 1
  install -d -o "$CHAM_USER" -g easypi -m 0750 "$PROFILE_DIR" || return 1
}

write_chameleon_unit() {
  # $1=true when the TCP stream listener is prepared for the client.
  local tcp_streams="${1:-false}" unit_tmp stream_unit="" stream_service=""
  if [[ "$tcp_streams" == "true" ]]; then
    stream_unit="Wants=$TCP_STREAM_SOCKET
After=$TCP_STREAM_SOCKET"
    stream_service="Sockets=$TCP_STREAM_SOCKET"
  fi
  unit_tmp="$(mktemp "${CHAM_UNIT}.tmp.XXXXXX")" || return 1
  cat > "$unit_tmp" <<EOF
[Unit]
Description=EasyPi Chameleon stealth client
After=network-online.target
$stream_unit

[Service]
Type=simple
$stream_service
User=$CHAM_USER
Group=$CHAM_GROUP
ExecStart=$CHAM_BIN -config $SAFE_CONF -status $STATUS_FILE
# The TUN device is recreated when systemd restarts the client. Linux removes
# routes bound to the old device, so restore the policy-table default after the
# new cham0 appears. The less-preferred blackhole remains the fail-closed path.
ExecStartPost=+/bin/bash $STEALTH_SCRIPT restore-route
Restart=on-failure
RestartSec=2s
TimeoutStopSec=5s
KillMode=control-group
UMask=0077
Environment=PATH=/usr/sbin:/usr/bin:/sbin:/bin
AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=yes
PrivateTmp=yes
DevicePolicy=closed
DeviceAllow=/dev/net/tun rw
ProtectSystem=strict
ProtectHome=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
ReadWritePaths=$STATUS_DIR $PROFILE_DIR
MemoryMax=256M
TasksMax=128
LimitNOFILE=4096
StandardOutput=append:$LOG
StandardError=append:$LOG
EOF
  chown root:root "$unit_tmp" || { rm -f -- "$unit_tmp"; return 1; }
  chmod 0644 "$unit_tmp" || { rm -f -- "$unit_tmp"; return 1; }
  mv -f -- "$unit_tmp" "$CHAM_UNIT" || { rm -f -- "$unit_tmp"; return 1; }
}

daemon_alive() {
  systemctl is-active --quiet "$CHAM_SERVICE" 2>/dev/null || pgrep -f "$CHAM_BIN" >/dev/null 2>&1
}

report_tunnel_start_failure() {
  local message="$1" failure_code=""
  [[ -f "$STATUS_FILE" && ! -L "$STATUS_FILE" ]] \
    && failure_code="$(jval "$STATUS_FILE" failure_code)"
  do_down true >/dev/null 2>&1
  case "$failure_code" in
    server_unavailable|server_timeout) temporary_err "$message" ;;
    *) err "$message" ;;
  esac
}

install_runtime_routes() {
  ip route replace blackhole default metric 42760 table "$RT_TABLE" || return 1
  ip route replace default dev "$IF" metric 10 table "$RT_TABLE" || return 1
  if ip rule show 2>/dev/null | grep "lookup $DNS_RT_TABLE" >/dev/null; then
    ip route replace blackhole default metric 42760 table "$DNS_RT_TABLE" || return 1
    ip route replace default dev "$IF" metric 10 table "$DNS_RT_TABLE" || return 1
  fi
}

restore_runtime_route() {
  # ExecStartPost runs as soon as the client process starts. The client creates
  # cham0 first and brings it up a moment later; a route through a link that is
  # not up yet is rejected ("Device for nexthop is not up"). Wait for the UP
  # flag, not mere existence, and keep retrying within the same time budget.
  # The link line is captured first: an early-exiting grep in a pipeline would
  # trip pipefail even when the flag is present.
  local i link up_flag='[<,]UP[,>]'
  for i in $(seq 1 30); do
    link="$(ip -o link show "$IF" 2>/dev/null)" || link=""
    if [[ $link =~ $up_flag ]]; then
      install_runtime_routes 2>/dev/null && return 0
    fi
    sleep 0.5
  done
  install_runtime_routes
}

clear_mss_clamp() {
  # Remove both the current dedicated chain and direct rules left by releases
  # which used route-derived PMTU clamping.
  while iptables -t mangle -D FORWARD -j "$MSS_CHAIN" 2>/dev/null; do :; done
  iptables -t mangle -F "$MSS_CHAIN" 2>/dev/null
  iptables -t mangle -X "$MSS_CHAIN" 2>/dev/null
  while iptables -t mangle -D FORWARD -o "$IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; do :; done
  while iptables -t mangle -D FORWARD -i "$IF" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu 2>/dev/null; do :; done
}

# ── routing / kill-switch ──────────────────────────────────────────────────────
clear_rules() {
  local preserve_prestart="${2:-false}"
  while ip rule del pref "$RULE_PREF" 2>/dev/null; do :; done
  while ip rule del pref "$MGMT_PREF" 2>/dev/null; do :; done
  while ip rule del pref "$TAILSCALE_PREF" 2>/dev/null; do :; done
  while ip rule del pref "$LEGACY_DNS_PREF" 2>/dev/null; do :; done
  while ip rule del pref "$DEVICE_PREF" 2>/dev/null; do :; done
  ip route flush table "$RT_TABLE" 2>/dev/null
  local wan="$1"
  if [[ -n "$wan" ]]; then
    while iptables  -D FORWARD -o "$wan" -j "$KILL_CHAIN" 2>/dev/null; do :; done
    while ip6tables -D FORWARD -o "$wan" -j "$KILL_CHAIN" 2>/dev/null; do :; done
  fi
  iptables  -F "$KILL_CHAIN" 2>/dev/null; iptables  -X "$KILL_CHAIN" 2>/dev/null
  ip6tables -F "$KILL_CHAIN" 2>/dev/null; ip6tables -X "$KILL_CHAIN" 2>/dev/null
  iptables -t mangle -S PREROUTING 2>/dev/null | grep -E -- "-j ${DEVICE_CHAIN}$" | sed 's/^-A/-D/' | while read -r line; do iptables -t mangle $line 2>/dev/null; done
  iptables -t mangle -F "$DEVICE_CHAIN" 2>/dev/null
  iptables -t mangle -X "$DEVICE_CHAIN" 2>/dev/null
  clear_mss_clamp
  clear_ufw_tunnel_log_exclusions
  while iptables -D FORWARD -o "$IF" -m conntrack --ctstate INVALID -j DROP 2>/dev/null; do :; done
  while iptables -D FORWARD -o "$IF" -j ACCEPT 2>/dev/null; do :; done
  while iptables -D FORWARD -i "$IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; do :; done
  while iptables -D FORWARD -j "$QUIC_CHAIN" 2>/dev/null; do :; done
  iptables -F "$QUIC_CHAIN" 2>/dev/null; iptables -X "$QUIC_CHAIN" 2>/dev/null
  while iptables -t mangle -D OUTPUT -j "$DNS_CHAIN" 2>/dev/null; do :; done
  iptables -t mangle -F "$DNS_CHAIN" 2>/dev/null
  iptables -t mangle -X "$DNS_CHAIN" 2>/dev/null
  while ip6tables -D OUTPUT -j "$DNS6_CHAIN" 2>/dev/null; do :; done
  ip6tables -F "$DNS6_CHAIN" 2>/dev/null; ip6tables -X "$DNS6_CHAIN" 2>/dev/null
  while iptables -D OUTPUT -j "$DNS_BOOT_CHAIN" 2>/dev/null; do :; done
  iptables -F "$DNS_BOOT_CHAIN" 2>/dev/null; iptables -X "$DNS_BOOT_CHAIN" 2>/dev/null
  while ip6tables -D OUTPUT -j "$DNS6_BOOT_CHAIN" 2>/dev/null; do :; done
  ip6tables -F "$DNS6_BOOT_CHAIN" 2>/dev/null; ip6tables -X "$DNS6_BOOT_CHAIN" 2>/dev/null
  [[ "$preserve_prestart" == "true" ]] || clear_prestart_guard
}

install_mss_clamp() {
  # Route-derived clamping is wrong for SYN-ACK packets arriving from cham0:
  # their normal output route is the 1500-byte LAN, so Linux can advertise 1460
  # even though the tunnel MTU is smaller. Derive the IPv4 MSS from cham0 itself
  # and apply the same upper bound to both sides of the handshake.
  local mtu mss
  mtu="$(cat "/sys/class/net/$IF/mtu" 2>/dev/null)" || return 1
  [[ "$mtu" =~ ^[0-9]+$ ]] || return 1
  (( mtu >= 576 && mtu <= 65535 )) || return 1
  mss=$((mtu - 40))

  clear_mss_clamp
  iptables -t mangle -N "$MSS_CHAIN" 2>/dev/null || return 1
  iptables -t mangle -A "$MSS_CHAIN" -o "$IF" -p tcp --tcp-flags SYN,RST SYN \
    -j TCPMSS --set-mss "$mss" || return 1
  iptables -t mangle -A "$MSS_CHAIN" -i "$IF" -p tcp --tcp-flags SYN,RST SYN \
    -j TCPMSS --set-mss "$mss" || return 1
  iptables -t mangle -I FORWARD 1 -j "$MSS_CHAIN" || return 1
}

install_tunnel_forwarding() {
  # The host FORWARD policy is deliberately DROP. Append these terminal allows
  # after EasyPi admission, schedule, parental and anti-bypass chains so a
  # Chameleon restart cannot jump ahead of an existing device block. New EasyPi
  # policy hooks are inserted at the head and therefore remain authoritative.
  while iptables -D FORWARD -o "$IF" -m conntrack --ctstate INVALID -j DROP 2>/dev/null; do :; done
  while iptables -D FORWARD -o "$IF" -j ACCEPT 2>/dev/null; do :; done
  while iptables -D FORWARD -i "$IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; do :; done
  # Conntrack forgets flows that were masqueraded through cham0 when the tunnel
  # interface goes away. After Stealth is re-enabled, later packets of those
  # flows are INVALID, skip MASQUERADE and would enter the tunnel with the LAN
  # device's own address, which the server rejects. Drop them here; the device
  # retransmits or reconnects and the new flow is translated normally.
  iptables -A FORWARD -o "$IF" -m conntrack --ctstate INVALID -j DROP || return 1
  iptables -A FORWARD -o "$IF" -j ACCEPT || return 1
  iptables -A FORWARD -i "$IF" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT || return 1
  # UFW logs unmatched forwarded packets before these deliberately late
  # terminal allows. Skip only that misleading log entry for traffic which the
  # Chameleon rules below will accept; keep every UFW and EasyPi verdict in the
  # parent FORWARD chain authoritative. UFW is optional, so logging cleanup is
  # best-effort and must never prevent the tunnel from starting.
  install_ufw_tunnel_log_exclusions || true
}

clear_ufw_tunnel_log_exclusions() {
  iptables -S ufw-after-logging-forward >/dev/null 2>&1 || return 0
  while iptables -D ufw-after-logging-forward -o "$IF" -j RETURN 2>/dev/null; do :; done
  while iptables -D ufw-after-logging-forward -i "$IF" -m conntrack \
    --ctstate RELATED,ESTABLISHED -j RETURN 2>/dev/null; do :; done
}

install_ufw_tunnel_log_exclusions() {
  iptables -S ufw-after-logging-forward >/dev/null 2>&1 || return 0
  clear_ufw_tunnel_log_exclusions
  iptables -I ufw-after-logging-forward 1 -o "$IF" -j RETURN || return 1
  if ! iptables -I ufw-after-logging-forward 1 -i "$IF" -m conntrack \
    --ctstate RELATED,ESTABLISHED -j RETURN; then
    clear_ufw_tunnel_log_exclusions
    return 1
  fi
}

remove_forward_chain_references() {
  local tool="$1" chain="$2" line
  local -a rule=()
  while IFS= read -r line; do
    [[ -n "$line" ]] || continue
    read -r -a rule <<< "${line/#-A /-D }"
    "$tool" "${rule[@]}" || return 1
  done < <("$tool" -S FORWARD 2>/dev/null | grep -E -- "-j ${chain}$" || true)
}

clear_forward_guard_chain() {
  local tool="$1" chain="$2"
  remove_forward_chain_references "$tool" "$chain" || return 1
  if "$tool" -S "$chain" >/dev/null 2>&1; then
    "$tool" -F "$chain" || return 1
    "$tool" -X "$chain" || return 1
  fi
}

clear_stale_prestart_chains() {
  local tool="$1" prefix="$2" chain
  while IFS= read -r chain; do
    [[ -n "$chain" ]] || continue
    clear_forward_guard_chain "$tool" "$chain" || return 1
  done < <("$tool" -S 2>/dev/null | awk -v prefix="$prefix" '$1 == "-N" && index($2, prefix) == 1 {print $2}')
}

temporary_prestart_guard_active() {
  local chain
  while IFS= read -r chain; do
    [[ -n "$chain" ]] || continue
    if iptables -S "$chain" 2>/dev/null \
        | grep -Fx -- "-A $chain -j DROP" >/dev/null; then
      return 0
    fi
  done < <(iptables -S FORWARD 2>/dev/null \
    | awk '$1 == "-A" && $(NF - 1) == "-j" && $NF ~ /^EP_PRE4_[0-9]+_[0-9]+$/ {print $NF}')
  return 1
}

clear_prestart_guard() {
  clear_forward_guard_chain iptables "$PRE_CHAIN" 2>/dev/null || true
  clear_forward_guard_chain ip6tables "$PRE6_CHAIN" 2>/dev/null || true
  clear_stale_prestart_chains iptables "EP_PRE4_" 2>/dev/null || true
  clear_stale_prestart_chains ip6tables "EP_PRE6_" 2>/dev/null || true
  while iptables -D OUTPUT -j "$PRE_DNS_CHAIN" 2>/dev/null; do :; done
  iptables -F "$PRE_DNS_CHAIN" 2>/dev/null; iptables -X "$PRE_DNS_CHAIN" 2>/dev/null
  while ip6tables -D OUTPUT -j "$PRE_DNS6_CHAIN" 2>/dev/null; do :; done
  ip6tables -F "$PRE_DNS6_CHAIN" 2>/dev/null; ip6tables -X "$PRE_DNS6_CHAIN" 2>/dev/null
  return 0
}

prestart_guard_matches_policy() {
  local expected_scope="$1" expected_macs="$2" policy_text
  local -a policy=()
  local -a arr=()
  local -a chain4=()
  local -a expected4=(
    "-N $PRE_CHAIN"
    "-A $PRE_CHAIN -o $IF -j RETURN"
    "-A $PRE_CHAIN -o $TCP_STREAM_IF -j RETURN"
    "-A $PRE_CHAIN -d 10.0.0.0/8 -j RETURN"
    "-A $PRE_CHAIN -d 100.64.0.0/10 -j RETURN"
    "-A $PRE_CHAIN -d 172.16.0.0/12 -j RETURN"
    "-A $PRE_CHAIN -d 192.168.0.0/16 -j RETURN"
    "-A $PRE_CHAIN -d 169.254.0.0/16 -j RETURN"
    "-A $PRE_CHAIN -j DROP"
  )
  policy_text="$(read_dns_policy)" || return 1
  mapfile -t policy <<< "$policy_text"
  [[ "${policy[0]:-false}" == "true" \
     && "${policy[1]:-}" == "$expected_scope" \
     && "${policy[3]:-}" == "$expected_macs" ]] || return 1
  mapfile -t chain4 < <(iptables -S "$PRE_CHAIN" 2>/dev/null) || return 1
  [[ "${#chain4[@]}" -eq "${#expected4[@]}" ]] || return 1
  local index
  for index in "${!expected4[@]}"; do
    [[ "${chain4[$index]}" == "${expected4[$index]}" ]] || return 1
  done
  mapfile -t arr < <(ip6tables -S "$PRE6_CHAIN" 2>/dev/null) || return 1
  [[ "${#arr[@]}" -eq 2 \
     && "${arr[0]}" == "-N $PRE6_CHAIN" \
     && "${arr[1]}" == "-A $PRE6_CHAIN -j DROP" ]] || return 1
  if [[ "$expected_scope" == "all" ]]; then
    first_append_rule_is iptables FORWARD "-A FORWARD -j $PRE_CHAIN" \
      && first_append_rule_is ip6tables FORWARD \
        "-A FORWARD -j $PRE6_CHAIN"
    return
  fi
  selected_guards_are_leading iptables FORWARD "$PRE_CHAIN" "$expected_macs" \
    && selected_guards_are_leading ip6tables FORWARD "$PRE6_CHAIN" "$expected_macs"
}

ensure_prestart_guard() {
  local scope="$1" ips="$2" macs="$3" wan="$4"
  prestart_guard_matches_policy "$scope" "$macs" \
    || install_prestart_guard "$scope" "$ips" "$macs" "$wan"
}

install_prestart_guard() {
  # This independent guard remains installed for the whole strict session. It
  # allows private destinations and cham0, but drops every public direct path,
  # including a replacement WAN interface after a network reconnect.
  # $1=scope $2=csv_ips $3=csv_macs $4=wan
  local scope="$1" ips="$2" macs="$3" wan="$4" net mac
  local next4="EP_PRE4_${BASHPID}_${RANDOM}"
  local next6="EP_PRE6_${BASHPID}_${RANDOM}"

  # Build complete replacement chains while the current guard remains attached.
  # A command failure before both replacements are active therefore cannot open
  # a direct forwarding path.
  iptables -N "$next4" || return 1
  iptables -A "$next4" -o "$IF" -j RETURN || return 1
  iptables -A "$next4" -o "$TCP_STREAM_IF" -j RETURN || return 1
  for net in 10.0.0.0/8 100.64.0.0/10 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16; do
    iptables -A "$next4" -d "$net" -j RETURN || return 1
  done
  iptables -A "$next4" -j DROP || return 1

  ip6tables -N "$next6" 2>/dev/null || return 1
  ip6tables -A "$next6" -j DROP 2>/dev/null || return 1

  if [[ "$scope" == "all" ]]; then
    iptables -I FORWARD 1 -j "$next4" || return 1
    ip6tables -I FORWARD 1 -j "$next6" 2>/dev/null || return 1
  else
    IFS=',' read -ra arr <<< "$macs"
    for mac in "${arr[@]}"; do
      [[ -z "$mac" ]] && continue
      iptables -I FORWARD 1 -m mac --mac-source "$mac" -j "$next4" || return 1
      ip6tables -I FORWARD 1 -m mac --mac-source "$mac" -j "$next6" 2>/dev/null || return 1
    done
  fi

  # Both candidate guards now protect traffic. Replace the canonical chains;
  # renaming preserves the live FORWARD references without a policy gap.
  clear_forward_guard_chain iptables "$PRE_CHAIN" || return 1
  clear_forward_guard_chain ip6tables "$PRE6_CHAIN" || return 1
  iptables -E "$next4" "$PRE_CHAIN" || return 1
  ip6tables -E "$next6" "$PRE6_CHAIN" 2>/dev/null || return 1

  # A previously interrupted replacement may have left an extra fail-closed
  # temporary chain. The canonical guards are active before these are removed.
  clear_stale_prestart_chains iptables "EP_PRE4_" || return 1
  clear_stale_prestart_chains ip6tables "EP_PRE6_" || return 1

  # Preserve the upgrade cleanup performed by the former clear-then-build path.
  # These legacy OUTPUT chains are unrelated to the live forwarding guard.
  while iptables -D OUTPUT -j "$PRE_DNS_CHAIN" 2>/dev/null; do :; done
  iptables -F "$PRE_DNS_CHAIN" 2>/dev/null || true
  iptables -X "$PRE_DNS_CHAIN" 2>/dev/null || true
  while ip6tables -D OUTPUT -j "$PRE_DNS6_CHAIN" 2>/dev/null; do :; done
  ip6tables -F "$PRE_DNS6_CHAIN" 2>/dev/null || true
  ip6tables -X "$PRE_DNS6_CHAIN" 2>/dev/null || true
}

clear_startup_dns_guard() {
  while iptables -D OUTPUT -j "$DNS_BOOT_CHAIN" 2>/dev/null; do :; done
  iptables -F "$DNS_BOOT_CHAIN" 2>/dev/null; iptables -X "$DNS_BOOT_CHAIN" 2>/dev/null
  while ip6tables -D OUTPUT -j "$DNS6_BOOT_CHAIN" 2>/dev/null; do :; done
  ip6tables -F "$DNS6_BOOT_CHAIN" 2>/dev/null; ip6tables -X "$DNS6_BOOT_CHAIN" 2>/dev/null
  # Cleanup is idempotent: an already absent chain is the desired end state.
  return 0
}

install_startup_guard() {
  # $1=scope $2=csv_ips $3=csv_macs $4=wan $5=lancidr
  local scope="$1" ips="$2" macs="$3" wan="$4" lan="$5"
  local net mac

  ip route replace blackhole default metric 42760 table "$RT_TABLE" || return 1
  [[ -n "$lan" ]] && ip route replace "$lan" dev "$wan" table "$RT_TABLE"
  for net in 10.0.0.0/8 100.64.0.0/10 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16; do
    ip rule add to "$net" lookup main pref "$MGMT_PREF" 2>/dev/null || return 1
  done
  ip rule add to 100.64.0.0/10 lookup 52 pref "$TAILSCALE_PREF" 2>/dev/null || return 1

  iptables -N "$KILL_CHAIN" 2>/dev/null || true
  iptables -F "$KILL_CHAIN" || return 1
  for net in 10.0.0.0/8 100.64.0.0/10 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16; do
    iptables -A "$KILL_CHAIN" -d "$net" -j RETURN || return 1
  done
  iptables -A "$KILL_CHAIN" -j DROP || return 1
  ip6tables -N "$KILL_CHAIN" 2>/dev/null || true
  ip6tables -F "$KILL_CHAIN" 2>/dev/null || return 1
  ip6tables -A "$KILL_CHAIN" -j DROP 2>/dev/null || return 1

  install_device_routing "$scope" "$macs" "$wan" || return 1
  if [[ "$scope" == "all" ]]; then
    iptables -I FORWARD 1 -o "$wan" -j "$KILL_CHAIN" || return 1
    ip6tables -I FORWARD 1 -o "$wan" -j "$KILL_CHAIN" 2>/dev/null || return 1
  else
    IFS=',' read -ra arr <<< "$macs"
    for mac in "${arr[@]}"; do
      [[ -z "$mac" ]] && continue
      iptables -I FORWARD 1 -m mac --mac-source "$mac" -o "$wan" -j "$KILL_CHAIN" || return 1
      ip6tables -I FORWARD 1 -m mac --mac-source "$mac" -o "$wan" -j "$KILL_CHAIN" 2>/dev/null || return 1
    done
  fi
}

install_device_routing() {
  # Route only forwarded client traffic through Stealth. EasyPi's own control
  # plane (Chameleon, local DNS recursion, updates and management) stays on the
  # main WAN table and therefore cannot loop through cham0.
  # $1=scope $2=csv_macs $3=wan
  local scope="$1" macs="$2" wan="$3" mac
  while ip rule del pref "$RULE_PREF" 2>/dev/null; do :; done
  while ip rule del pref "$LEGACY_DNS_PREF" 2>/dev/null; do :; done
  while ip rule del pref "$DEVICE_PREF" 2>/dev/null; do :; done
  iptables -t mangle -S PREROUTING 2>/dev/null | grep -E -- "-j ${DEVICE_CHAIN}$" | sed 's/^-A/-D/' | while read -r line; do iptables -t mangle $line 2>/dev/null; done
  iptables -t mangle -N "$DEVICE_CHAIN" 2>/dev/null || true
  iptables -t mangle -F "$DEVICE_CHAIN" || return 1
  iptables -t mangle -A "$DEVICE_CHAIN" -m addrtype --dst-type LOCAL -j RETURN || return 1
  if [[ "$scope" == "all" ]]; then
    iptables -t mangle -A "$DEVICE_CHAIN" -j MARK --set-xmark "$DEVICE_MARK/$DEVICE_MARK_MASK" || return 1
  else
    IFS=',' read -ra arr <<< "$macs"
    for mac in "${arr[@]}"; do
      [[ -z "$mac" ]] && continue
      iptables -t mangle -A "$DEVICE_CHAIN" -m mac --mac-source "$mac" \
        -j MARK --set-xmark "$DEVICE_MARK/$DEVICE_MARK_MASK" || return 1
    done
  fi
  iptables -t mangle -I PREROUTING 1 -i "$wan" -j "$DEVICE_CHAIN" || return 1
  ip rule add fwmark "$DEVICE_MARK/$DEVICE_MARK_MASK" lookup "$RT_TABLE" pref "$DEVICE_PREF" || return 1
}

tcp_stream_forward_rules() {
  # Device TCP towards the stream namespace, after every other FORWARD policy.
  local action="$1" rule
  local rules=(
    "-o $TCP_STREAM_IF -m conntrack --ctstate INVALID -j DROP"
    "-o $TCP_STREAM_IF -j ACCEPT"
    "-i $TCP_STREAM_IF -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT"
  )
  for rule in "${rules[@]}"; do
    # shellcheck disable=SC2086
    while iptables -D FORWARD $rule 2>/dev/null; do :; done
    if [[ "$action" == "add" ]]; then
      # shellcheck disable=SC2086
      iptables -A FORWARD $rule || return 1
    fi
  done
  return 0
}

clear_tcp_streams() {
  systemctl stop "$TCP_STREAM_SOCKET" >/dev/null 2>&1 || true
  rm -f -- "$TCP_STREAM_SOCKET_UNIT"
  while ip rule del pref "$TCP_STREAM_VPS_PREF" 2>/dev/null; do :; done
  while ip rule del pref "$TCP_STREAM_PREF" 2>/dev/null; do :; done
  ip route flush table "$TCP_STREAM_TABLE" 2>/dev/null
  tcp_stream_forward_rules remove
  ip link del "$TCP_STREAM_IF" 2>/dev/null
  ip netns del "$TCP_STREAM_NS" 2>/dev/null
  return 0
}

# The stream namespace is a bind mount under /run/netns that systemd has to
# see to open the listener inside it (NetworkNamespacePath=). The backend runs
# this script in its own mount namespace (PrivateTmp=), where that mount stays
# invisible to systemd, so the listener never started when Stealth was turned
# on from the panel. Namespace work therefore runs in a transient systemd unit,
# which always lives in the host's mount namespace.
tcp_streams_in_host_ns() { # install <server-ipv4> | clear
  if [[ "${EASYPI_STEALTH_HOST_NS:-}" == "1" ]]; then
    case "$1" in
      install) install_tcp_streams "$2" ;;
      clear) clear_tcp_streams ;;
    esac
    return
  fi
  systemd-run --quiet --wait --collect --pipe --service-type=oneshot \
    --setenv=EASYPI_STEALTH_HOST_NS=1 -p TimeoutStartSec=20s \
    /bin/bash "$STEALTH_SCRIPT" tcp-streams "$@"
}

do_tcp_streams() {
  # Internal: only tcp_streams_in_host_ns calls this, inside its transient unit.
  [[ "${EASYPI_STEALTH_HOST_NS:-}" == "1" ]] || err "internal subcommand"
  case "${1:-}" in
    install)
      [[ "${2:-}" =~ ^[0-9]{1,3}(\.[0-9]{1,3}){3}$ ]] && validate_ip_csv "$2" ||
        err "invalid server address"
      install_tcp_streams "$2" ;;
    clear) clear_tcp_streams ;;
    *) err "unknown tcp-streams action" ;;
  esac
}

install_tcp_streams() {
  # $1=Chameleon server IPv4. Prepares the stream path; the client adds the
  # route into it once the server offers streams.
  local srv="$1" unit_tmp
  clear_tcp_streams
  modprobe xt_TPROXY 2>/dev/null || return 1
  ip netns add "$TCP_STREAM_NS" || return 1
  ip link add "$TCP_STREAM_IF" type veth peer name "$TCP_STREAM_NS_IF" || return 1
  ip link set "$TCP_STREAM_NS_IF" netns "$TCP_STREAM_NS" || return 1
  ip addr add "$TCP_STREAM_HOST_IP/30" dev "$TCP_STREAM_IF" || return 1
  ip link set "$TCP_STREAM_IF" up || return 1
  # Replies leave the namespace with the site's address as their source.
  sysctl -qw "net.ipv4.conf.$TCP_STREAM_IF.rp_filter=0" || return 1
  # The namespace inherits src_valid_mark=1, which makes the reverse-path check
  # use the TPROXY mark, hit the local route below and drop every SYN.
  ip netns exec "$TCP_STREAM_NS" /bin/bash -euo pipefail -c "
    ip link set lo up
    ip addr add $TCP_STREAM_NS_IP/30 dev $TCP_STREAM_NS_IF
    ip link set $TCP_STREAM_NS_IF up
    ip route add default via $TCP_STREAM_HOST_IP dev $TCP_STREAM_NS_IF
    sysctl -qw net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.$TCP_STREAM_NS_IF.rp_filter=0
    sysctl -qw net.ipv4.conf.all.src_valid_mark=0
    ip rule add fwmark 0x1/0x1 lookup 100
    ip route add local 0.0.0.0/0 dev lo table 100
    iptables -t mangle -A PREROUTING -i $TCP_STREAM_NS_IF -p tcp -j TPROXY --on-port $TCP_STREAM_PORT --tproxy-mark 0x1/0x1
  " || return 1
  # The stream server never dials its own address; TCP to it keeps cham0.
  ip rule add pref "$TCP_STREAM_VPS_PREF" fwmark "$DEVICE_MARK/$DEVICE_MARK_MASK" to "$srv/32" lookup "$RT_TABLE" || return 1
  ip rule add pref "$TCP_STREAM_PREF" fwmark "$DEVICE_MARK/$DEVICE_MARK_MASK" ipproto tcp lookup "$TCP_STREAM_TABLE" || return 1
  tcp_stream_forward_rules add || return 1
  unit_tmp="$(mktemp "${TCP_STREAM_SOCKET_UNIT}.tmp.XXXXXX")" || return 1
  cat > "$unit_tmp" <<EOF
[Unit]
Description=EasyPi Chameleon TCP stream listener

[Socket]
ListenStream=0.0.0.0:$TCP_STREAM_PORT
Transparent=yes
FreeBind=yes
Backlog=1024
NetworkNamespacePath=/run/netns/$TCP_STREAM_NS
Service=$CHAM_SERVICE
EOF
  chmod 0644 "$unit_tmp" || { rm -f -- "$unit_tmp"; return 1; }
  mv -f -- "$unit_tmp" "$TCP_STREAM_SOCKET_UNIT" || { rm -f -- "$unit_tmp"; return 1; }
}

install_quic_guard() {
  # $1=scope $2=csv_macs $3=true|false
  local scope="$1" macs="$2" enabled="$3"
  while iptables -D FORWARD -j "$QUIC_CHAIN" 2>/dev/null; do :; done
  iptables -F "$QUIC_CHAIN" 2>/dev/null
  iptables -X "$QUIC_CHAIN" 2>/dev/null
  [[ "$enabled" == "true" ]] || return 0
  iptables -N "$QUIC_CHAIN" 2>/dev/null || true
  iptables -F "$QUIC_CHAIN" || return 1
  if [[ "$scope" == "all" ]]; then
    iptables -A "$QUIC_CHAIN" -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable || return 1
  else
    local mac
    IFS=',' read -ra arr <<< "$macs"
    for mac in "${arr[@]}"; do
      [[ -z "$mac" ]] && continue
      iptables -A "$QUIC_CHAIN" -m mac --mac-source "$mac" -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable || return 1
    done
  fi
  iptables -I FORWARD 1 -j "$QUIC_CHAIN" || return 1
}

apply_manual_routing() {
  # $1=scope $2=csv_ips $3=csv_macs $4=wan $5=lancidr $6=server_ip $7=block_quic
  local scope="$1" ips="$2" macs="$3" wan="$4" lan="$5" srv="${6:-}" block_quic="${7:-true}"
  iptables -S FORWARD 2>/dev/null | grep -E -- "-j ${KILL_CHAIN}$" | sed 's/^-A/-D/' | while read -r line; do iptables $line 2>/dev/null; done
  ip6tables -S FORWARD 2>/dev/null | grep -E -- "-j ${KILL_CHAIN}$" | sed 's/^-A/-D/' | while read -r line; do ip6tables $line 2>/dev/null; done
  while ip rule del pref "$RULE_PREF" 2>/dev/null; do :; done
  while ip rule del pref "$DEVICE_PREF" 2>/dev/null; do :; done
  iptables -t mangle -S PREROUTING 2>/dev/null | grep -E -- "-j ${DEVICE_CHAIN}$" | sed 's/^-A/-D/' | while read -r line; do iptables -t mangle $line 2>/dev/null; done
  iptables -t mangle -F "$DEVICE_CHAIN" 2>/dev/null
  iptables -t mangle -X "$DEVICE_CHAIN" 2>/dev/null
  # Keep a less-preferred blackhole default in the policy table. If cham0
  # disappears, marked DNS and selected-device traffic remain fail-closed.
  ip route replace blackhole default metric 42760 table "$RT_TABLE" || return 1
  ip route replace default dev "$IF" metric 10 table "$RT_TABLE" || return 1
  [[ -n "$lan" ]] && ip route replace "$lan" dev "$wan" table "$RT_TABLE"
  # Remove the broad endpoint bypass installed by older releases. The local
  # Chameleon process now stays on main because only forwarded clients are marked.
  [[ -n "$srv" ]] && ip route del "$srv" table "$RT_TABLE" 2>/dev/null || true

  # LAN / private / link-local destinations must NEVER go through the tunnel — resolve
  # them via the main table. Keeps ALL local management reachable (SSH/panel from ANY
  # private subnet, not just the box's own /24 — an off-subnet admin host used to get
  # locked out) and is correct for a "route my internet out" feature. Source-agnostic,
  # so it protects both the box's own traffic (whole-network) and forwarded clients.
  local net
  while ip rule del pref "$MGMT_PREF" 2>/dev/null; do :; done
  while ip rule del pref "$TAILSCALE_PREF" 2>/dev/null; do :; done
  for net in 10.0.0.0/8 100.64.0.0/10 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16; do
    ip rule add to "$net" lookup main pref "$MGMT_PREF" 2>/dev/null || return 1
  done
  ip rule add to 100.64.0.0/10 lookup 52 pref "$TAILSCALE_PREF" 2>/dev/null || return 1

  # Install tunnel accepts first. install_quic_guard inserts its jump at the
  # head afterwards, so blocked UDP/443 can never bypass the QUIC policy.
  install_tunnel_forwarding || return 1
  install_quic_guard "$scope" "$macs" "$block_quic" || return 1
  install_device_routing "$scope" "$macs" "$wan" || return 1
  install_mss_clamp || return 1

  # Kill-switch chain: drop leaked internet traffic (fail-closed if the tunnel drops),
  # but RETURN (never drop) traffic to private ranges — LAN is not "internet".
  iptables  -N "$KILL_CHAIN" 2>/dev/null; iptables  -F "$KILL_CHAIN"
  for net in 10.0.0.0/8 100.64.0.0/10 172.16.0.0/12 192.168.0.0/16 169.254.0.0/16; do
    iptables -A "$KILL_CHAIN" -d "$net" -j RETURN
  done
  iptables  -A "$KILL_CHAIN" -j DROP
  ip6tables -N "$KILL_CHAIN" 2>/dev/null; ip6tables -F "$KILL_CHAIN" 2>/dev/null; ip6tables -A "$KILL_CHAIN" -j DROP 2>/dev/null

  if [[ "$scope" == "all" ]]; then
    iptables -I FORWARD 1 -o "$wan" -j "$KILL_CHAIN"
    ip6tables -I FORWARD 1 -o "$wan" -j "$KILL_CHAIN" 2>/dev/null
  else
    local mac
    IFS=',' read -ra arr <<< "$macs"
    for mac in "${arr[@]}"; do
      [[ -z "$mac" ]] && continue
      iptables -I FORWARD 1 -m mac --mac-source "$mac" -o "$wan" -j "$KILL_CHAIN" || return 1
      ip6tables -I FORWARD 1 -m mac --mac-source "$mac" -o "$wan" -j "$KILL_CHAIN" 2>/dev/null || return 1
    done
  fi
  # KILL and QUIC are inserted at the head while the active route is built.
  # Re-attach the independent PRESTART guard last so it remains the first
  # policy gate in both active and disconnected states. Its RETURN rules then
  # continue into KILL/QUIC; its terminal DROP prevents every direct public path.
  ensure_prestart_guard "$scope" "$ips" "$macs" "$wan" || return 1
  clear_startup_dns_guard
}

# ── up ──────────────────────────────────────────────────────────────────────────
do_up() {
  local src="${1:-}" scope="${2:-all}" ips="${3:-}" block_quic="${4:-true}" macs="${5:-}"
  [[ -n "$src" ]] || err "usage: up <src_conf> <scope> [csv_ips] [block_quic] [csv_macs]"
  [[ "$src" == "$SOURCE_CONF" ]] || err "config path is not allowed"
  [[ "$scope" == "all" || "$scope" == "selected" ]] || err "invalid routing scope"
  validate_ip_csv "$ips" || err "invalid selected-device IP list"
  validate_mac_csv "$macs" || err "invalid selected-device MAC list"
  [[ "$scope" == "selected" || -z "$ips" ]] || err "IP list is only valid for selected scope"
  [[ "$scope" == "selected" || -z "$macs" ]] || err "MAC list is only valid for selected scope"
  [[ "$scope" != "selected" || -n "$macs" ]] || err "selected scope requires at least one MAC address"
  [[ "$block_quic" == "true" || "$block_quic" == "false" ]] || err "invalid block_quic value"

  # Establish the persistent forwarding guard first. DNS activation then
  # installs its independent egress guard, publishes policy, and only after
  # that starts the resolver and its systemd guard dependency.
  local wan lan srv
  wan="$(wan_iface)"
  ensure_prestart_guard "$scope" "$ips" "$macs" "$wan" ||
    err "failed to install persistent Chameleon guard"
  activate_strict_dns_policy "$scope" "$ips" "$macs" "$block_quic" ||
    err "failed to activate fail-closed DNS routing"

  [[ "$(realpath -e -- "$src" 2>/dev/null)" == "$SOURCE_CONF" ]] ||
    err "config path is not canonical"
  ensure_chameleon_identity || err "cannot create the restricted stealth service account"
  prepare_client_config "$src" || err "invalid stealth client configuration"
  chown root:"$CHAM_GROUP" "$SAFE_CONF" || err "cannot protect the runtime stealth configuration"
  chmod 0640 "$SAFE_CONF" || err "cannot protect the runtime stealth configuration"
  [[ -x "$CHAM_BIN" ]] || err "chameleon-client binary not installed at $CHAM_BIN"
  [[ "$(stat -c '%u' -- "$CHAM_BIN" 2>/dev/null)" == "0" ]] ||
    err "chameleon-client must be root-owned"
  local bin_mode
  bin_mode="$(stat -c '%a' -- "$CHAM_BIN")"
  [[ $((8#$bin_mode & 8#022)) -eq 0 ]] ||
    err "chameleon-client must not be writable outside root"

  lan="$(lan_cidr "$wan")"; srv="$(cham_server_ip "$SAFE_CONF")"
  [[ -n "$wan" ]] || temporary_err "cannot determine WAN interface (no default route)"
  [[ -n "$srv" ]] || err "cannot resolve stealth server before fail-closed startup"
  do_down true >/dev/null 2>&1
  if ! install_startup_guard "$scope" "$ips" "$macs" "$wan" "$lan"; then
    do_down true >/dev/null 2>&1
    err "failed to install stealth startup guard"
  fi
  sysctl -w net.ipv4.ip_forward=1 >/dev/null 2>&1
  tune_tcp_transport
  # Device TCP is carried as streams when this host can run the transparent
  # listener; otherwise, and whenever the server does not offer streams, it
  # stays on the packet tunnel.
  local tcp_streams=false
  if tcp_streams_in_host_ns install "$srv" >/dev/null 2>&1; then
    tcp_streams=true
  else
    tcp_streams_in_host_ns clear >/dev/null 2>&1
  fi
  # Run the client under a dedicated account with only CAP_NET_ADMIN. The
  # service owns its status directory but cannot modify its configuration or
  # the installed executable.
  write_chameleon_unit "$tcp_streams" || { do_down true >/dev/null 2>&1; err "failed to create restricted stealth service"; }
  install -o "$CHAM_USER" -g "$CHAM_GROUP" -m 0600 /dev/null "$STATUS_FILE" || {
    do_down true >/dev/null 2>&1
    err "failed to prepare stealth status file"
  }
  systemctl daemon-reload >/dev/null 2>&1 || { do_down true >/dev/null 2>&1; err "failed to reload systemd"; }
  if [[ "$tcp_streams" == "true" ]] && ! systemctl start "$TCP_STREAM_SOCKET" >/dev/null 2>&1; then
    tcp_streams_in_host_ns clear >/dev/null 2>&1
    write_chameleon_unit false || { do_down true >/dev/null 2>&1; err "failed to create restricted stealth service"; }
    systemctl daemon-reload >/dev/null 2>&1 || { do_down true >/dev/null 2>&1; err "failed to reload systemd"; }
  fi
  systemctl start "$CHAM_SERVICE" >/dev/null 2>&1 \
    || report_tunnel_start_failure "failed to start restricted stealth service"

  local i
  for i in $(seq 1 30); do ip link show "$IF" >/dev/null 2>&1 && break; sleep 0.5; done
  if ! ip link show "$IF" >/dev/null 2>&1; then
    report_tunnel_start_failure "stealth client did not create the tunnel interface"
  fi

  iptables -t nat -C POSTROUTING -o "$IF" -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -o "$IF" -j MASQUERADE
  if ! apply_manual_routing "$scope" "$ips" "$macs" "$wan" "$lan" "$srv" "$block_quic"; then
    do_down true >/dev/null 2>&1
    err "failed to install fail-closed stealth routing"
  fi
  install_strict_dns_routing || {
    do_down true >/dev/null 2>&1
    err "failed to attach protected DNS to Chameleon"
  }

  printf 'IF=%s\nSCOPE=%s\nIPS=%s\nMACS=%s\nWAN=%s\nBLOCK_QUIC=%s\nUP_TS=%s\n' "$IF" "$scope" "$ips" "$macs" "$wan" "$block_quic" "$(date +%s)" > "$STATE"
  # Return a meaningful first result instead of reporting "started" while the
  # daemon is already failing its initial server handshake.
  local ready failure i
  for i in $(seq 1 20); do
    if [[ -f "$STATUS_FILE" ]]; then
      ready=$(jval "$STATUS_FILE" connected)
      failure=$(jval "$STATUS_FILE" failure_code)
      [[ "$ready" == "true" || -n "$failure" ]] && break
    fi
    daemon_alive || break
    sleep 0.5
  done
  do_status
}

# ── reconcile ────────────────────────────────────────────────────────────────────
do_reconcile() {
  local ips="${1:-}" macs="${2:-}"
  validate_ip_csv "$ips" || err "invalid selected-device IP list"
  validate_mac_csv "$macs" || err "invalid selected-device MAC list"
  [[ -f "$STATE" ]] || err "not running"
  local scope wan block_quic; scope=$(sed -n 's/^SCOPE=//p' "$STATE"); wan=$(sed -n 's/^WAN=//p' "$STATE")
  block_quic=$(sed -n 's/^BLOCK_QUIC=//p' "$STATE"); [[ "$block_quic" == "false" ]] || block_quic="true"
  [[ "$scope" == "selected" ]] || err "reconcile only applies to selected scope"
  [[ -n "$macs" ]] || macs=$(sed -n 's/^MACS=//p' "$STATE")
  [[ -n "$macs" ]] || err "selected scope requires at least one MAC address"
  local lan srv; lan="$(lan_cidr "$wan")"; srv="$(cham_server_ip "$SAFE_CONF")"
  ensure_prestart_guard "selected" "$ips" "$macs" "$wan" ||
    err "failed to refresh persistent Chameleon guard"
  activate_strict_dns_policy "selected" "$ips" "$macs" "$block_quic" ||
    err "failed to activate reconciled fail-closed DNS routing"
  while ip rule del pref "$RULE_PREF" 2>/dev/null; do :; done
  iptables -S FORWARD 2>/dev/null | grep -E -- "-j ${KILL_CHAIN}$" | sed 's/^-A/-D/' | while read -r line; do iptables $line 2>/dev/null; done
  if ! apply_manual_routing "selected" "$ips" "$macs" "$wan" "$lan" "$srv" "$block_quic"; then
    do_down true >/dev/null 2>&1
    err "failed to reconcile fail-closed stealth routing"
  fi
  sed -i "s/^IPS=.*/IPS=$ips/" "$STATE"
  if grep -q '^MACS=' "$STATE"; then
    sed -i "s/^MACS=.*/MACS=$macs/" "$STATE"
  else
    printf 'MACS=%s\n' "$macs" >> "$STATE"
  fi
  do_status
}

# ── down ──────────────────────────────────────────────────────────────────────────
do_down() {
  local preserve_strict="${1:-false}"
  local wan=""
  [[ -f "$STATE" ]] && wan=$(sed -n 's/^WAN=//p' "$STATE")
  [[ -n "$wan" ]] || wan="$(wan_iface)"

  iptables -S FORWARD 2>/dev/null | grep -E -- "-j ${KILL_CHAIN}$" | sed 's/^-A/-D/' | while read -r line; do iptables $line 2>/dev/null; done
  ip6tables -S FORWARD 2>/dev/null | grep -E -- "-j ${KILL_CHAIN}$" | sed 's/^-A/-D/' | while read -r line; do ip6tables $line 2>/dev/null; done
  # Keep the independent strict guard in place until the daemon and all live
  # routes are gone. Internal restart/error paths leave it installed.
  clear_rules "$wan" true

  # The listener goes first: a connection on it would start the client again.
  systemctl stop "$TCP_STREAM_SOCKET" >/dev/null 2>&1 || true
  systemctl stop "$CHAM_SERVICE" >/dev/null 2>&1 || true
  tcp_streams_in_host_ns clear >/dev/null 2>&1
  # Kill a detached root daemon left by an older EasyPi release.
  pkill -TERM -f "$CHAM_BIN" 2>/dev/null; sleep 0.3; pkill -KILL -f "$CHAM_BIN" 2>/dev/null
  rm -f -- "$CHAM_UNIT"
  systemctl daemon-reload >/dev/null 2>&1 || true
  iptables -t nat -D POSTROUTING -o "$IF" -j MASQUERADE 2>/dev/null
  rm -f "$STATE" "$STATUS_FILE"
  if [[ "$preserve_strict" != "true" ]]; then
    write_dns_policy false "all" "" "" "true" ||
      err "tunnel stopped, but strict policy could not be disabled safely"
    clear_strict_dns_routing
    clear_prestart_guard
  fi
  do_status
}

do_resume() {
  local -a policy=()
  local policy_text=""
  if policy_text="$(read_dns_policy)"; then
    mapfile -t policy <<< "$policy_text"
  fi
  # A reader/runtime failure is different from a missing policy (which the
  # reader reports explicitly as disabled). Unknown persistent state blocks all.
  if [[ "${#policy[@]}" -lt 5 ]]; then
    policy=("true" "all" "" "" "true")
  fi
  local enabled="${policy[0]:-false}" scope="${policy[1]:-all}"
  local ips="${policy[2]:-}" macs="${policy[3]:-}" block_quic="${policy[4]:-true}"
  if [[ "$enabled" != "true" ]]; then
    clear_strict_dns_routing
    clear_prestart_guard
    do_status
    return 0
  fi

  local wan
  wan="$(wan_iface)"
  if ! ensure_prestart_guard "$scope" "$ips" "$macs" "$wan"; then
    json '{"success":false,"error":"failed to restore persistent Chameleon guard"}'
    return 1
  fi
  if ! install_strict_dns_routing; then
    json '{"success":false,"error":"failed to restore fail-closed DNS routing"}'
    return 1
  fi

  # Persistent protection intent exists, so failures must remain fail-closed.
  # Report a real service failure while retaining both guards; do not let a
  # missing/replaced client config look like a successful boot resume.
  if [[ ! -f "$SOURCE_CONF" || -L "$SOURCE_CONF" \
      || "$(realpath -e -- "$SOURCE_CONF" 2>/dev/null)" != "$SOURCE_CONF" ]]; then
    json '{"success":false,"error":"strict Chameleon policy is enabled, but its client configuration is missing or unsafe"}'
    return 1
  fi

  # Run startup in a subshell because `err` exits on a genuine interactive/API
  # failure. For boot/update resume, an unavailable VPS is a degraded but safe
  # state when both independent guards remain complete. Return success to
  # systemd in that case so NetProtection can still start; unsafe guard failures
  # remain service failures.
  local output rc=0
  output="$(do_up "$SOURCE_CONF" "$scope" "$ips" "$block_quic" "$macs")" || rc=$?
  printf '%s\n' "$output"
  if (( rc == 75 )); then
    prestart_guard_matches_policy "$scope" "$macs" \
      && strict_dns_guard_active \
      && return 0
  fi
  return "$rc"
}

do_guard() {
  local -a policy=()
  local policy_text=""
  if policy_text="$(read_dns_policy)"; then
    mapfile -t policy <<< "$policy_text"
  fi
  # A damaged or unreadable persistent policy is treated as protect-all.
  if [[ "${#policy[@]}" -lt 5 ]]; then
    policy=("true" "all" "" "" "true")
  fi
  local enabled="${policy[0]:-false}" scope="${policy[1]:-all}"
  local ips="${policy[2]:-}" macs="${policy[3]:-}"
  if [[ "$enabled" != "true" ]]; then
    clear_strict_dns_routing
    clear_prestart_guard
    return 0
  fi

  # Runs before network-pre.target. No WAN or tunnel is needed: forwarding is
  # blocked and resolver egress is blackholed until the late resume connects.
  install_prestart_guard "$scope" "$ips" "$macs" "$(wan_iface)" || return 1
  install_strict_dns_routing_rules || return 1
}

# ── status ────────────────────────────────────────────────────────────────────────
jval() {
  /usr/bin/python3 - "$1" "$2" <<'PY'
import json
import os
import stat
import sys

path, key = sys.argv[1:]
try:
    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > 64 * 1024:
            raise ValueError("invalid status file")
        with os.fdopen(fd, "r", encoding="utf-8") as handle:
            fd = -1
            value = json.load(handle).get(key, "")
    finally:
        if fd >= 0:
            os.close(fd)
except (OSError, ValueError, TypeError, json.JSONDecodeError):
    value = ""
if isinstance(value, bool):
    print("true" if value else "false")
elif isinstance(value, (str, int, float)):
    print(value)
PY
}

do_status() {
  local scope="all" running="false" connected="false" killswitch="false" dns_protected="false" quic_blocked="false"
  local policy_active="false"
  local wan="" ndev="0" ips="" macs="" server="" fp="" behavior="" sent="0" recv="0" shield=""
  local failure_code="" health_error="" failed_at=""
  if [[ -f "$STATE" ]]; then
    scope=$(sed -n 's/^SCOPE=//p' "$STATE"); wan=$(sed -n 's/^WAN=//p' "$STATE"); ips=$(sed -n 's/^IPS=//p' "$STATE"); macs=$(sed -n 's/^MACS=//p' "$STATE")
  else
    local -a policy=()
    mapfile -t policy < <(read_dns_policy)
    if [[ "${policy[0]:-false}" == "true" ]]; then
      policy_active="true"
      scope="${policy[1]:-all}"; ips="${policy[2]:-}"; macs="${policy[3]:-}"
    fi
  fi
  [[ -n "$macs" ]] && ndev=$(printf '%s' "$macs" | awk -F',' '{print NF}')
  if daemon_alive && ip link show "$IF" >/dev/null 2>&1; then running="true"; fi
  if [[ -f "$STATUS_FILE" ]]; then
    connected=$(jval "$STATUS_FILE" connected); [[ "$connected" == "true" ]] || connected="false"
    server=$(jval "$STATUS_FILE" server_addr); fp=$(jval "$STATUS_FILE" fingerprint)
    behavior=$(jval "$STATUS_FILE" behavior); sent=$(jval "$STATUS_FILE" bytes_sent); recv=$(jval "$STATUS_FILE" bytes_recv)
    shield=$(jval "$STATUS_FILE" shield_domain)
    failure_code=$(jval "$STATUS_FILE" failure_code); health_error=$(jval "$STATUS_FILE" health_error)
    failed_at=$(jval "$STATUS_FILE" failed_at)
  elif [[ "$running" != "true" ]] \
      && { [[ -f "$STATE" ]] || [[ "$policy_active" == "true" ]]; }; then
    failure_code="client_stopped"
    health_error="Strict protection is active, but the Stealth client is not connected"
  fi
  if iptables -S FORWARD 2>/dev/null \
      | grep -E -- "-j (${KILL_CHAIN}|${PRE_CHAIN})$" >/dev/null \
      || temporary_prestart_guard_active; then
    killswitch="true"
  fi
  if ip rule show 2>/dev/null | grep "uidrange .* lookup $DNS_RT_TABLE" >/dev/null \
      && ip route show table "$DNS_RT_TABLE" 2>/dev/null | grep '^blackhole default' >/dev/null \
      && iptables -C OUTPUT -j "$DNS_EGRESS_CHAIN" 2>/dev/null; then
    dns_protected="true"
  fi
  iptables -C FORWARD -j "$QUIC_CHAIN" 2>/dev/null && quic_blocked="true"
  # The client keeps this route only while device TCP is carried as streams.
  local tcp_streams="false"
  ip route show table "$TCP_STREAM_TABLE" 2>/dev/null | grep '^default' >/dev/null && tcp_streams="true"
  json "{\"success\":true,\"running\":$running,\"connected\":$connected,\"scope\":\"$(jesc "$scope")\",\"devices\":${ndev:-0},\"server\":\"$(jesc "$server")\",\"fingerprint\":\"$(jesc "$fp")\",\"behavior\":\"$(jesc "$behavior")\",\"shield\":\"$(jesc "$shield")\",\"bytes_sent\":${sent:-0},\"bytes_recv\":${recv:-0},\"killswitch\":$killswitch,\"dns_protected\":$dns_protected,\"quic_blocked\":$quic_blocked,\"tcp_streams\":$tcp_streams,\"failure_code\":\"$(jesc "$failure_code")\",\"health_error\":\"$(jesc "$health_error")\",\"failed_at\":\"$(jesc "$failed_at")\"}"
}

main() {
  case "${1:-status}" in
    up|reconcile)
      [[ ! -e "$UPDATE_MARKER" ]] || err "signed update is still in progress"
      ;;
    resume)
      if [[ -e "$UPDATE_MARKER" ]] && ! update_lock_is_held; then
        err "signed update is awaiting rollback or recovery"
      fi
      ;;
  esac
  case "${1:-status}" in
    up)        shift; do_up "$@" ;;
    reconcile) shift; do_reconcile "$@" ;;
    guard)     do_guard ;;
    resume)    do_resume ;;
    restore-route) restore_runtime_route ;;
    tcp-streams) shift; do_tcp_streams "$@" ;;
    down)      do_down ;;
    status)    do_status ;;
    *) err "unknown subcommand" ;;
  esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  # The internal namespace helper must not provision or migrate anything.
  if [[ "${1:-}" != "tcp-streams" ]]; then
    initialize_runtime_paths "${1:-status}" || exit 1
  fi
  main "$@"
fi
