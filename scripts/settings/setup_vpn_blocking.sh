#!/bin/bash
#
# VPN/Tor/DoH/Proxy/SmartDNS blocking management
# Called by NetProtection service via runner to setup/remove iptables rules
#
# Usage: setup_vpn_blocking.sh <action> <client_ip> [channels]
# Actions: add, remove, clear-runtime, quarantine, unquarantine,
#          hold-admission, release-admission, list-quarantine, sync,
#          update-tor-list
#

set -e

ACTION="${1:-}"
CLIENT_IP="${2:-}"
CLIENT_CHANNELS="${3:-}"
CLIENT_MAC="$(printf '%s' "${4:-}" | tr '[:upper:]' '[:lower:]')"

TOR_IPSET="easypi_tor_nodes"
TOR_LIST_FILE="/var/lib/easypi-security/tor/current/tor_ipv4.txt"
DOH_IPSET="easypi_doh_providers"
DOH_LIST_FILE="/opt/EasyPi/data/netprotection/doh_provider_ips.txt"
SMARTDNS_IPSET="easypi_smartdns_providers"
SMARTDNS_STAGING_IPSET="easypi_smartdns_stage"
SMARTDNS_LIST_FILE="/opt/EasyPi/data/netprotection/smartdns_provider_ips.txt"
PROXY_IPSET="easypi_proxy_endpoints"
PROXY_LIST_FILE="/opt/EasyPi/data/netprotection/proxy_endpoint_ips.txt"
STATE_DIR="/var/lib/easypi/netprotection"
STATE_GROUP="easypi"
FAIL_CLOSED_FILE="$STATE_DIR/fail_closed_devices.json"
ADMISSION_HOLD_FILE="$STATE_DIR/admission_holds.json"
ADMISSION_HOLD_CHAIN="EASYPI_ADMISSION_HOLD"
ADMISSION_HOLD_STAGING="EASYPI_ADMISSION_HOLD_NEXT"
ADMISSION_BLOCK_FILE="$STATE_DIR/admission_blocked_macs.json"
ADMISSION_BLOCK_CHAIN="EASYPI_ADMISSION_BLOCK"
ADMISSION_BLOCK_STAGING="EASYPI_ADMISSION_BLOCK_NEXT"
TOR_FEED_UPDATER="/opt/EasyPi/scripts/settings/update_tor_list.sh"
RUNTIME_DIR="/run/easypi-vpn-blocking"
DATA_WRITER="/opt/EasyPi/scripts/utils/write_easypi_data.py"
DNS_REDIRECT_COMMENT="easypi_dns_redirect"
install -d -o root -g root -m 700 "$RUNTIME_DIR"
install -d -o root -g "$STATE_GROUP" -m 0750 "$STATE_DIR"

publish_data_file() {
    [[ -f "$DATA_WRITER" && ! -L "$DATA_WRITER" ]] || {
        echo "ERROR: secure data writer is missing" >&2
        return 1
    }
    /usr/bin/python3 "$DATA_WRITER" "$1" "$2"
}

# Channel-specific port groups
DOH_PORTS=(
    "udp:443"   # QUIC (browser DoH / encrypted DNS channel)
    "tcp:853"   # DNS-over-TLS
    "udp:853"
)

VPN_PORTS=(
    "udp:1194"  # OpenVPN
    "tcp:1194"
    "udp:1195"
    "udp:500"   # IPSec/IKEv2
    "udp:4500"
    "tcp:1723"  # PPTP
    "udp:1701"  # L2TP
    "tcp:8388"  # Shadowsocks
    "udp:8388"
)

PROXY_PORTS=(
    "tcp:1080"  # SOCKS
    "tcp:1081"
    "tcp:8080"  # HTTP proxy
    "tcp:3128"
    "tcp:8118"  # Privoxy
)

TOR_PORTS=(
    "tcp:9001"
    "tcp:9030"
    "tcp:9050"
    "tcp:9051"
    "tcp:9150"
)

# Known DoH/DoT resolver IPs
DOH_PROVIDER_IPS=(
    "1.1.1.1" "1.0.0.1"
    "1.1.1.2" "1.0.0.2"
    "1.1.1.3" "1.0.0.3"
    "104.16.248.249" "104.16.249.249"
    "8.8.8.8" "8.8.4.4"
    "9.9.9.9" "149.112.112.112"
    "9.9.9.10" "149.112.112.10"
    "94.140.14.14" "94.140.15.15"
    "94.140.14.15" "94.140.15.16"
    "45.90.28.0" "45.90.30.0"
    "208.67.222.222" "208.67.220.220"
    "208.67.222.123" "208.67.220.123"
    "185.228.168.9" "185.228.169.9"
    "185.228.168.10" "185.228.169.10"
    "185.228.168.168" "185.228.169.168"
    "194.242.2.2" "194.242.2.3"
    "194.242.2.4" "194.242.2.5"
    "76.76.2.0" "76.76.10.0"
    "76.76.2.2" "76.76.10.2"
    # Verisign / Yandex / DNS.SB / He.net / LibreDNS / Comodo / Neustar / Alternate / Level3
    "64.6.64.6" "64.6.65.6"
    "77.88.8.8" "77.88.8.1"
    "185.222.222.222" "45.11.45.11"
    "74.82.42.42" "116.202.176.26"
    "8.26.56.26" "8.20.247.20"
    "156.154.70.1" "156.154.71.1"
    "76.76.19.19" "209.244.0.3" "209.244.0.4"
    "130.59.31.248" "185.95.218.42" "185.95.218.43"
)

# Well-known DoH/DoT resolver hostnames, resolved dynamically to catch current
# anycast IPs beyond the static list above (best-effort, cached to DOH_LIST_FILE).
DOH_DOMAINS=(
    "dns.google" "dns64.dns.google"
    "cloudflare-dns.com" "mozilla.cloudflare-dns.com" "one.one.one.one"
    "dns.quad9.net" "dns9.quad9.net" "dns10.quad9.net" "dns11.quad9.net"
    "dns.adguard-dns.com" "unfiltered.adguard-dns.com" "family.adguard-dns.com"
    "doh.opendns.com" "doh.familyshield.opendns.com"
    "dns.nextdns.io" "doh.mullvad.net" "doh.cleanbrowsing.org"
    "dns.controld.com" "freedns.controld.com" "doh.dns.sb"
    "dns.switch.ch" "dns.digitale-gesellschaft.ch"
    "doh.libredns.gr" "ordns.he.net" "doh.360.cn"
)

# Opera built-in VPN (SurfEasy) + popular web-proxy endpoints. Resolved to IPs so
# even a hardcoded-IP bootstrap is blocked for protected devices (DNS-level block
# alone is not enough because Opera VPN can bootstrap without our DNS).
PROXY_ENDPOINT_DOMAINS=(
    "opera-proxy.net"
    "de0.opera-proxy.net" "de1.opera-proxy.net"
    "eu0.opera-proxy.net" "eu1.opera-proxy.net" "eu2.opera-proxy.net"
    "us0.opera-proxy.net" "us1.opera-proxy.net"
    "asia0.opera-proxy.net" "asia1.opera-proxy.net"
    "api.sec-tunnel.com" "api2.sec-tunnel.com"
    "surfeasy.com" "www.surfeasy.com"
    "croxyproxy.com" "www.croxyproxy.com"
    "proxysite.com" "www.proxysite.com"
    "hide.me" "www.hide.me"
    "4everproxy.com" "www.4everproxy.com"
)

SMARTDNS_DOMAINS=(
    "unlocator.com"
    "getflix.com.au"
    "smartdnsproxy.com"
    "unotelly.com"
    "overplay.net"
    "unblock-us.com"
    "ironsocket.com"
    "smartdns.com"
)

get_chain_name() {
    local identity="$1"
    if is_valid_mac "$identity"; then
        echo "EASYPI_VPNM_${identity//:/}"
    else
        echo "EASYPI_VPN_${identity//./_}"
    fi
}

is_valid_ipv4() {
    local ip_value="$1"
    [[ "$ip_value" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

is_valid_mac() {
    [[ "${1:-}" =~ ^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$ ]]
}

MOBILE_TUNNEL_IFACE="easypi-mobile0"

# Routed EasyPi Mobile home-tunnel peers (10.77.0.0/24) have no Ethernet MAC.
is_mobile_tunnel_ip() {
    [[ "${1:-}" =~ ^10\.77\.0\.([0-9]{1,3})$ ]] && (( BASH_REMATCH[1] >= 2 && BASH_REMATCH[1] <= 254 ))
}

chain_exists() {
    local chain_name="$1"
    iptables -L "$chain_name" -n >/dev/null 2>&1
}

ipset_exists_name() {
    local set_name="$1"
    ipset list "$set_name" >/dev/null 2>&1
}

ip_in_array() {
    local needle="$1"
    shift
    local item
    for item in "$@"; do
        if [[ "$item" == "$needle" ]]; then
            return 0
        fi
    done
    return 1
}

mac_in_array() {
    local needle="${1,,}"
    shift
    local item
    for item in "$@"; do
        if [[ "${item,,}" == "$needle" ]]; then
            return 0
        fi
    done
    return 1
}

remove_chain_references() {
    local chain_name="$1"
    local rule_no

    while true; do
        rule_no=$(iptables -L OUTPUT --line-numbers -n | awk -v c="$chain_name" '$2==c {print $1; exit}')
        [[ -z "$rule_no" ]] && break
        iptables -D OUTPUT "$rule_no" >/dev/null 2>&1 || break
    done

    while true; do
        rule_no=$(iptables -L FORWARD --line-numbers -n | awk -v c="$chain_name" '$2==c {print $1; exit}')
        [[ -z "$rule_no" ]] && break
        iptables -D FORWARD "$rule_no" >/dev/null 2>&1 || break
    done
}

fail_closed_state_cmd() {
    local cmd="$1"
    local ip_value="${2:-}"
    local mac_value="${3:-}"
    FAIL_CLOSED_FILE="$FAIL_CLOSED_FILE" FAIL_CLOSED_CMD="$cmd" \
        FAIL_CLOSED_IP="$ip_value" FAIL_CLOSED_MAC="$mac_value" python3 - <<'PY'
import ipaddress
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path

path = Path(os.environ["FAIL_CLOSED_FILE"])
cmd = os.environ.get("FAIL_CLOSED_CMD", "").strip().lower()
target = os.environ.get("FAIL_CLOSED_IP", "").strip()
target_mac = os.environ.get("FAIL_CLOSED_MAC", "").strip().lower()


def normalize_ip(value: str) -> str | None:
    try:
        ip_obj = ipaddress.ip_address(value)
    except ValueError:
        return None
    if ip_obj.version != 4:
        return None
    return str(ip_obj)


def normalize_mac(value: str) -> str | None:
    value = value.strip().lower()
    return value if re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", value) else None


def arp_by_mac() -> dict[str, str]:
    result: dict[str, str] = {}
    try:
        lines = Path("/proc/net/arp").read_text().splitlines()[1:]
    except Exception:
        return result
    for line in lines:
        parts = line.split()
        if len(parts) < 4 or parts[2] == "0x0":
            continue
        ip = normalize_ip(parts[0])
        mac = normalize_mac(parts[3])
        if ip and mac:
            result[mac] = ip
    return result


def load_state() -> dict:
    if not path.exists():
        return {"version": 2, "updated_at": None, "ips": [], "devices": []}
    try:
        data = json.loads(path.read_text())
    except Exception:
        data = {}
    raw_ips = data.get("ips", [])
    if not isinstance(raw_ips, list):
        raw_ips = []
    normalized: list[str] = []
    seen: set[str] = set()
    for raw in raw_ips:
        ip = normalize_ip(str(raw).strip())
        if ip and ip not in seen:
            seen.add(ip)
            normalized.append(ip)
    devices: list[dict[str, str]] = []
    seen_macs: set[str] = set()
    for raw in data.get("devices", []):
        if not isinstance(raw, dict):
            continue
        mac = normalize_mac(str(raw.get("mac", "")))
        last_ip = normalize_ip(str(raw.get("last_ip", "")))
        if mac and mac not in seen_macs:
            seen_macs.add(mac)
            devices.append({"mac": mac, "last_ip": last_ip or ""})
    return {"version": 2, "updated_at": data.get("updated_at"), "ips": normalized, "devices": devices}


def save_state(state: dict) -> None:
    import tempfile

    state["updated_at"] = datetime.now(timezone.utc).isoformat()
    fd, tmp_name = tempfile.mkstemp(prefix=".fail-closed.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, 0o640)
        os.replace(tmp_name, path)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


state = load_state()
target_ip = normalize_ip(target)
target_mac = normalize_mac(target_mac)
live_by_mac = arp_by_mac()
live_mac_by_ip = {ip: mac for mac, ip in live_by_mac.items()}
device_macs = {item["mac"] for item in state["devices"]}

if cmd == "contains":
    observed_mac = target_mac or (live_mac_by_ip.get(target_ip) if target_ip else None)
    active = bool((target_ip and target_ip in state["ips"]) or (observed_mac and observed_mac in device_macs))
    print("1" if active else "0")
    raise SystemExit(0)

if cmd == "list":
    resolved = list(state["ips"])
    for item in state["devices"]:
        ip = live_by_mac.get(item["mac"])
        if ip and ip not in resolved:
            resolved.append(ip)
    for ip in resolved:
        print(ip)
    raise SystemExit(0)

if cmd == "add":
    if target_mac:
        if target_mac not in device_macs:
            state["devices"].append({"mac": target_mac, "last_ip": target_ip or ""})
            if target_ip in state["ips"]:
                state["ips"].remove(target_ip)
            save_state(state)
            print("1")
        else:
            print("0")
        raise SystemExit(0)
    if not target_ip:
        raise SystemExit(2)
    if target_ip not in state["ips"]:
        state["ips"].append(target_ip)
        save_state(state)
        print("1")
    else:
        print("0")
    raise SystemExit(0)

if cmd == "remove":
    observed_mac = target_mac or (live_mac_by_ip.get(target_ip) if target_ip else None)
    if not target_ip and not observed_mac:
        raise SystemExit(2)
    before = (len(state["ips"]), len(state["devices"]))
    if target_ip:
        state["ips"] = [x for x in state["ips"] if x != target_ip]
    if observed_mac:
        state["devices"] = [item for item in state["devices"] if item["mac"] != observed_mac]
    if before != (len(state["ips"]), len(state["devices"])):
        save_state(state)
        print("1")
    else:
        print("0")
    raise SystemExit(0)

raise SystemExit(2)
PY
}

is_fail_closed_ip() {
    local ip_value="$1"
    local mac_value="${2:-}"
    [[ "$(fail_closed_state_cmd contains "$ip_value" "$mac_value" 2>/dev/null || echo "0")" == "1" ]]
}

add_fail_closed_ip() {
    local ip_value="$1"
    local mac_value="${2:-}"
    fail_closed_state_cmd add "$ip_value" "$mac_value" >/dev/null
}

remove_fail_closed_ip() {
    local ip_value="$1"
    local mac_value="${2:-}"
    fail_closed_state_cmd remove "$ip_value" "$mac_value" >/dev/null 2>&1 || true
}

list_fail_closed_ips() {
    fail_closed_state_cmd list 2>/dev/null || true
}

admission_hold_state_cmd() {
    local cmd="$1"
    local ip_value="${2:-}"
    local mac_value="${3:-}"
    ADMISSION_HOLD_FILE="$ADMISSION_HOLD_FILE" ADMISSION_HOLD_CMD="$cmd" \
        ADMISSION_HOLD_IP="$ip_value" ADMISSION_HOLD_MAC="$mac_value" python3 - <<'PY'
import ipaddress
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

path = Path(os.environ["ADMISSION_HOLD_FILE"])
cmd = os.environ.get("ADMISSION_HOLD_CMD", "").strip().lower()
raw_ip = os.environ.get("ADMISSION_HOLD_IP", "").strip()
raw_mac = os.environ.get("ADMISSION_HOLD_MAC", "").strip().lower()


def normalize_pair(ip_value: str, mac_value: str) -> tuple[str, str]:
    try:
        ip_obj = ipaddress.IPv4Address(ip_value)
    except ipaddress.AddressValueError as exc:
        raise SystemExit(2) from exc
    if not any(ip_obj in network for network in (
        ipaddress.IPv4Network("10.0.0.0/8"),
        ipaddress.IPv4Network("172.16.0.0/12"),
        ipaddress.IPv4Network("192.168.0.0/16"),
    )):
        raise SystemExit(2)
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac_value):
        raise SystemExit(2)
    return str(ip_obj), mac_value


def load_state() -> dict:
    if not path.exists():
        return {"version": 1, "updated_at": None, "holds": []}
    if path.is_symlink() or path.stat().st_size > 1024 * 1024:
        raise SystemExit(3)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        raise SystemExit(3) from exc
    if payload.get("version") != 1 or not isinstance(payload.get("holds"), list):
        raise SystemExit(3)
    holds: list[dict[str, str]] = []
    seen: set[str] = set()
    for item in payload["holds"]:
        if not isinstance(item, dict):
            raise SystemExit(3)
        ip, mac = normalize_pair(str(item.get("ip", "")), str(item.get("mac", "")))
        if mac in seen:
            raise SystemExit(3)
        seen.add(mac)
        holds.append({"ip": ip, "mac": mac})
    return {"version": 1, "updated_at": payload.get("updated_at"), "holds": holds}


def save_state(state: dict) -> None:
    state["updated_at"] = datetime.now(timezone.utc).isoformat()
    fd, tmp_name = tempfile.mkstemp(prefix=".admission-holds.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, path)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


state = load_state()
if cmd == "list":
    for item in state["holds"]:
        print(f"{item['ip']}|{item['mac']}")
    raise SystemExit(0)

target_ip, target_mac = normalize_pair(raw_ip, raw_mac)
if cmd == "add":
    state["holds"] = [item for item in state["holds"] if item["mac"] != target_mac]
    state["holds"].append({"ip": target_ip, "mac": target_mac})
elif cmd == "remove":
    state["holds"] = [item for item in state["holds"] if item["mac"] != target_mac]
else:
    raise SystemExit(2)
save_state(state)
PY
}

sync_admission_holds() {
    local chain="$ADMISSION_HOLD_CHAIN"
    local staging="$ADMISSION_HOLD_STAGING"
    local excluded_mac="${1:-}"
    local state_dump
    state_dump="$(mktemp "$RUNTIME_DIR/admission-holds.XXXXXX")"
    if ! admission_hold_state_cmd list > "$state_dump"; then
        rm -f "$state_dump"
        echo "ERROR: Cannot load admission hold state; preserving active deny chain" >&2
        return 1
    fi

    if chain_exists "$staging"; then
        if iptables -C FORWARD -j "$staging" 2>/dev/null; then
            remove_chain_references "$chain"
            if chain_exists "$chain"; then
                iptables -F "$chain"
                iptables -X "$chain"
            fi
            iptables -E "$staging" "$chain"
        else
            iptables -F "$staging"
            iptables -X "$staging"
        fi
    fi

    iptables -N "$staging"
    local hold_ip hold_mac
    while IFS='|' read -r hold_ip hold_mac; do
        [[ -n "$hold_ip" && -n "$hold_mac" ]] || continue
        [[ -n "$excluded_mac" && "$hold_mac" == "$excluded_mac" ]] && continue
        is_valid_ipv4 "$hold_ip" || { rm -f "$state_dump"; return 1; }
        is_valid_mac "$hold_mac" || { rm -f "$state_dump"; return 1; }
        # A routed tunnel packet carries no MAC, so a MAC hold cannot match it.
        # Unapproved tunnel peers are denied by the admission chain instead.
        [[ "$hold_ip" == 10.77.0.* ]] && continue
        iptables -A "$staging" -s "$hold_ip" -m mac --mac-source "$hold_mac" \
            -j REJECT --reject-with icmp-admin-prohibited
    done < "$state_dump"
    rm -f "$state_dump"
    iptables -A "$staging" -j RETURN

    # Attach the complete replacement before removing the old chain. If any
    # command above fails, the previous deny remains the active boundary.
    iptables -I FORWARD 1 -j "$staging"
    remove_chain_references "$chain"
    if chain_exists "$chain"; then
        iptables -F "$chain"
        iptables -X "$chain"
    fi
    iptables -E "$staging" "$chain"
}

admission_block_state_cmd() {
    local cmd="$1"
    local mac_value="${2:-}"
    ADMISSION_BLOCK_FILE="$ADMISSION_BLOCK_FILE" ADMISSION_BLOCK_CMD="$cmd" \
        ADMISSION_BLOCK_MAC="$mac_value" python3 - <<'PY'
import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path

path = Path(os.environ["ADMISSION_BLOCK_FILE"])
cmd = os.environ.get("ADMISSION_BLOCK_CMD", "").strip().lower()
raw_mac = os.environ.get("ADMISSION_BLOCK_MAC", "").strip().lower()


def normalize_mac(value: str) -> str:
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", value):
        raise SystemExit(2)
    return value


def load_state() -> dict:
    if not path.exists():
        return {"version": 1, "updated_at": None, "macs": []}
    if path.is_symlink() or path.stat().st_size > 1024 * 1024:
        raise SystemExit(3)
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError) as exc:
        raise SystemExit(3) from exc
    if payload.get("version") != 1 or not isinstance(payload.get("macs"), list):
        raise SystemExit(3)
    macs = [normalize_mac(str(value).strip().lower()) for value in payload["macs"]]
    if len(macs) != len(set(macs)):
        raise SystemExit(3)
    return {"version": 1, "updated_at": payload.get("updated_at"), "macs": macs}


def save_state(state: dict) -> None:
    state["updated_at"] = datetime.now(timezone.utc).isoformat()
    fd, tmp_name = tempfile.mkstemp(prefix=".admission-blocks.", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(state, handle, indent=2)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, path)
    finally:
        try:
            os.unlink(tmp_name)
        except FileNotFoundError:
            pass


state = load_state()
if cmd == "list":
    for mac in state["macs"]:
        print(mac)
    raise SystemExit(0)
if cmd == "init":
    save_state(state)
    raise SystemExit(0)

target_mac = normalize_mac(raw_mac)
if cmd == "add":
    if target_mac not in state["macs"]:
        state["macs"].append(target_mac)
elif cmd == "remove":
    state["macs"] = [mac for mac in state["macs"] if mac != target_mac]
else:
    raise SystemExit(2)
save_state(state)
PY
}

migrate_legacy_admission_blocks() {
    [[ -e "$ADMISSION_BLOCK_FILE" || -L "$ADMISSION_BLOCK_FILE" ]] && return 0
    local legacy_state="/opt/EasyPi/data/netprotection/unknown_device_admission.json"
    local state_dump
    state_dump="$(mktemp "$RUNTIME_DIR/legacy-admission-blocks.XXXXXX")"
    if ! /usr/bin/python3 - "$legacy_state" > "$state_dump" <<'PY'
import json
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1])
if not path.exists():
    raise SystemExit(0)
if path.is_symlink() or path.stat().st_size > 2 * 1024 * 1024:
    raise SystemExit(3)
try:
    payload = json.loads(path.read_text(encoding="utf-8"))
except (OSError, ValueError, TypeError) as exc:
    raise SystemExit(3) from exc
if payload.get("version") != 1 or not isinstance(payload.get("devices"), list):
    raise SystemExit(3)
seen: set[str] = set()
for item in payload["devices"]:
    if not isinstance(item, dict) or item.get("status") != "blocked":
        continue
    mac = str(item.get("mac") or "").strip().lower()
    if not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
        raise SystemExit(3)
    if mac not in seen:
        seen.add(mac)
        print(mac)
PY
    then
        rm -f "$state_dump"
        echo "ERROR: Cannot migrate legacy admission blocks" >&2
        return 1
    fi

    local blocked_mac
    while IFS= read -r blocked_mac; do
        [[ -n "$blocked_mac" ]] || continue
        admission_block_state_cmd add "$blocked_mac" || {
            rm -f "$state_dump"
            return 1
        }
    done < "$state_dump"
    rm -f "$state_dump"
    # Record that migration completed even when there were no legacy blocks.
    admission_block_state_cmd init
}

sync_admission_blocks() {
    local chain="$ADMISSION_BLOCK_CHAIN"
    local staging="$ADMISSION_BLOCK_STAGING"
    local excluded_mac="${1:-}"
    migrate_legacy_admission_blocks
    local state_dump
    state_dump="$(mktemp "$RUNTIME_DIR/admission-blocks.XXXXXX")"
    if ! admission_block_state_cmd list > "$state_dump"; then
        rm -f "$state_dump"
        echo "ERROR: Cannot load persistent admission blocks; preserving active deny chain" >&2
        return 1
    fi

    if chain_exists "$staging"; then
        if iptables -C FORWARD -j "$staging" 2>/dev/null; then
            remove_chain_references "$chain"
            if chain_exists "$chain"; then
                iptables -F "$chain"
                iptables -X "$chain"
            fi
            iptables -E "$staging" "$chain"
        else
            iptables -F "$staging"
            iptables -X "$staging"
        fi
    fi

    iptables -N "$staging"
    local blocked_mac
    while IFS= read -r blocked_mac; do
        [[ -n "$blocked_mac" ]] || continue
        [[ -n "$excluded_mac" && "$blocked_mac" == "$excluded_mac" ]] && continue
        is_valid_mac "$blocked_mac" || { rm -f "$state_dump"; return 1; }
        iptables -A "$staging" -m mac --mac-source "$blocked_mac" \
            -j REJECT --reject-with icmp-admin-prohibited
    done < "$state_dump"
    rm -f "$state_dump"
    iptables -A "$staging" -j RETURN

    iptables -I FORWARD 1 -j "$staging"
    remove_chain_references "$chain"
    if chain_exists "$chain"; then
        iptables -F "$chain"
        iptables -X "$chain"
    fi
    iptables -E "$staging" "$chain"
}

ensure_tor_ipset() {
    if ! ipset_exists_name "$TOR_IPSET"; then
        ipset create "$TOR_IPSET" hash:ip hashsize 4096 maxelem 65536
        echo "✓ Created Tor IP set: $TOR_IPSET"
    fi
}

update_tor_list() {
    echo "Refreshing Tor policy from the authenticated feed..."
    if [[ -x "$TOR_FEED_UPDATER" ]]; then
        "$TOR_FEED_UPDATER" update || \
            echo "⚠ Signed Tor feed unavailable or rejected; keeping cached policy"
    else
        echo "⚠ Signed Tor feed updater is unavailable; keeping cached policy"
    fi

    [[ -f "$TOR_LIST_FILE" && ! -L "$TOR_LIST_FILE" ]] || {
        echo "⚠ No authenticated Tor policy is available"
        return 0
    }

    local staged_set="easypi_tor_stage"
    ipset destroy "$staged_set" 2>/dev/null || true
    ipset create "$staged_set" hash:ip hashsize 4096 maxelem 65536 || return 1
    local count=0
    local node_ip
    while IFS= read -r node_ip; do
        if [[ $node_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            ipset add "$staged_set" "$node_ip" 2>/dev/null && ((count++)) || true
        fi
    done < "$TOR_LIST_FILE"
    if (( count < 1000 )); then
        ipset destroy "$staged_set" 2>/dev/null || true
        echo "ERROR: authenticated Tor policy is unexpectedly small; active ipset unchanged" >&2
        return 1
    fi

    ensure_tor_ipset
    ipset swap "$staged_set" "$TOR_IPSET" || {
        ipset destroy "$staged_set" 2>/dev/null || true
        echo "ERROR: failed to activate staged Tor policy" >&2
        return 1
    }
    ipset destroy "$staged_set" 2>/dev/null || true
    echo "✓ Atomically loaded $count authenticated Tor relay nodes"
}

resolve_domains_to_stdout() {
    # Resolve a comma-separated domain list to unique global IPv4 addresses.
    DOMAINS_CSV="$1" python3 - <<'PY'
import ipaddress, os, socket
domains = [d for d in os.environ.get("DOMAINS_CSV", "").split(",") if d]
ips = set()
for d in domains:
    try:
        infos = socket.getaddrinfo(d, None, family=socket.AF_INET)
    except Exception:
        continue
    for info in infos:
        ip = info[4][0]
        try:
            obj = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if obj.version == 4 and obj.is_global:
            ips.add(str(obj))
for ip in sorted(ips):
    print(ip)
PY
}

_ipset_add_from_file() {
    local set_name="$1" file_path="$2" line_ip count=0
    [[ -s "$file_path" ]] || { echo 0; return 0; }
    while IFS= read -r line_ip; do
        if [[ $line_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            ipset add "$set_name" "$line_ip" 2>/dev/null && ((count++)) || true
        fi
    done < "$file_path"
    echo "$count"
}

update_doh_dynamic() {
    if ! ipset_exists_name "$DOH_IPSET"; then
        ipset create "$DOH_IPSET" hash:ip hashsize 1024 maxelem 65536
    fi
    local csv tmp
    csv="$(IFS=,; echo "${DOH_DOMAINS[*]}")"
    tmp="$(mktemp "$RUNTIME_DIR/doh-dynamic.XXXXXX")"
    resolve_domains_to_stdout "$csv" > "$tmp" 2>/dev/null || true
    if [[ -s "$tmp" ]]; then
        _ipset_add_from_file "$DOH_IPSET" "$tmp" >/dev/null
        publish_data_file "$tmp" "$DOH_LIST_FILE"
        rm -f "$tmp"
        echo "✓ DoH provider IP set refreshed from ${#DOH_DOMAINS[@]} hostnames"
    elif [[ -f "$DOH_LIST_FILE" ]]; then
        _ipset_add_from_file "$DOH_IPSET" "$DOH_LIST_FILE" >/dev/null
    fi
}

ensure_doh_ipset() {
    if ! ipset_exists_name "$DOH_IPSET"; then
        ipset create "$DOH_IPSET" hash:ip hashsize 1024 maxelem 65536
        echo "✓ Created DoH IP set: $DOH_IPSET"
    fi

    local provider_ip
    for provider_ip in "${DOH_PROVIDER_IPS[@]}"; do
        ipset add "$DOH_IPSET" "$provider_ip" 2>/dev/null || true
    done

    # Load cached dynamic resolutions, refresh when stale (>1 day) or missing.
    if [[ -f "$DOH_LIST_FILE" ]] && [[ -z "$(find "$DOH_LIST_FILE" -mtime +1 2>/dev/null)" ]]; then
        _ipset_add_from_file "$DOH_IPSET" "$DOH_LIST_FILE" >/dev/null
    else
        update_doh_dynamic
    fi
}

update_proxy_ipset() {
    if ! ipset_exists_name "$PROXY_IPSET"; then
        ipset create "$PROXY_IPSET" hash:ip hashsize 1024 maxelem 65536
    fi
    local csv tmp
    csv="$(IFS=,; echo "${PROXY_ENDPOINT_DOMAINS[*]}")"
    tmp="$(mktemp "$RUNTIME_DIR/proxy-endpoints.XXXXXX")"
    resolve_domains_to_stdout "$csv" > "$tmp" 2>/dev/null || true
    if [[ -s "$tmp" ]]; then
        _ipset_add_from_file "$PROXY_IPSET" "$tmp" >/dev/null
        publish_data_file "$tmp" "$PROXY_LIST_FILE"
        rm -f "$tmp"
        echo "✓ Proxy endpoint IP set refreshed (${#PROXY_ENDPOINT_DOMAINS[@]} hostnames)"
    elif [[ -f "$PROXY_LIST_FILE" ]]; then
        _ipset_add_from_file "$PROXY_IPSET" "$PROXY_LIST_FILE" >/dev/null
    fi
}

ensure_proxy_ipset() {
    if [[ ! -f "$PROXY_LIST_FILE" ]] || [[ -n "$(find "$PROXY_LIST_FILE" -mtime +1 2>/dev/null)" ]]; then
        update_proxy_ipset
    elif ! ipset_exists_name "$PROXY_IPSET"; then
        update_proxy_ipset
    else
        _ipset_add_from_file "$PROXY_IPSET" "$PROXY_LIST_FILE" >/dev/null
    fi
}

# Transparent DNS interception: force ALL port-53 traffic from a protected device
# to EasyPi's local resolver, so it cannot use a rogue plaintext DNS server that
# is not in our block sets. Combined with the DoH/DoT/QUIC blocks, this forces the
# device through the filter regardless of which resolver it is configured to use.
add_dns_redirect() {
    local client_ip="$1" client_mac="${2:-}" proto
    is_valid_ipv4 "$client_ip" || return 0
    for proto in udp tcp; do
        if is_mobile_tunnel_ip "$client_ip"; then
            # A routed tunnel packet carries no MAC. The tunnel server binds
            # this source address to one authenticated phone.
            iptables -t nat -C PREROUTING -i "$MOBILE_TUNNEL_IFACE" -s "$client_ip" -p "$proto" --dport 53 \
                -m comment --comment "$DNS_REDIRECT_COMMENT" -j REDIRECT --to-ports 53 2>/dev/null \
                || iptables -t nat -A PREROUTING -i "$MOBILE_TUNNEL_IFACE" -s "$client_ip" -p "$proto" --dport 53 \
                    -m comment --comment "$DNS_REDIRECT_COMMENT" -j REDIRECT --to-ports 53
        elif is_valid_mac "$client_mac"; then
            # Migrate the pre-1.1 untagged rule to an ownership-tagged rule so
            # uninstall can remove it without guessing at third-party policy.
            while iptables -t nat -C PREROUTING -m mac --mac-source "$client_mac" -p "$proto" --dport 53 -j REDIRECT --to-ports 53 2>/dev/null; do
                iptables -t nat -D PREROUTING -m mac --mac-source "$client_mac" -p "$proto" --dport 53 -j REDIRECT --to-ports 53 2>/dev/null || break
            done
            iptables -t nat -C PREROUTING -m mac --mac-source "$client_mac" -p "$proto" --dport 53 \
                -m comment --comment "$DNS_REDIRECT_COMMENT" -j REDIRECT --to-ports 53 2>/dev/null \
                || iptables -t nat -A PREROUTING -m mac --mac-source "$client_mac" -p "$proto" --dport 53 \
                    -m comment --comment "$DNS_REDIRECT_COMMENT" -j REDIRECT --to-ports 53
        else
            while iptables -t nat -C PREROUTING -s "$client_ip" -p "$proto" --dport 53 -j REDIRECT --to-ports 53 2>/dev/null; do
                iptables -t nat -D PREROUTING -s "$client_ip" -p "$proto" --dport 53 -j REDIRECT --to-ports 53 2>/dev/null || break
            done
            iptables -t nat -C PREROUTING -s "$client_ip" -p "$proto" --dport 53 \
                -m comment --comment "$DNS_REDIRECT_COMMENT" -j REDIRECT --to-ports 53 2>/dev/null \
                || iptables -t nat -A PREROUTING -s "$client_ip" -p "$proto" --dport 53 \
                    -m comment --comment "$DNS_REDIRECT_COMMENT" -j REDIRECT --to-ports 53
        fi
    done
}

delete_dns_redirect_rule() {
    local rule="$1" delete_rule
    local -a delete_args=()
    delete_rule="${rule/#-A /-D }"
    read -r -a delete_args <<< "$delete_rule"
    if ! iptables -t nat "${delete_args[@]}" 2>/dev/null; then
        echo "ERROR: Failed to remove DNS redirect rule: $rule" >&2
        return 1
    fi
}

remove_dns_redirect() {
    local client_ip="$1" client_mac="${2:-}"
    local valid_ip=false valid_mac=false
    local rules_output rule rule_mac rule_ip
    is_valid_ipv4 "$client_ip" && valid_ip=true
    is_valid_mac "$client_mac" && valid_mac=true
    [[ "$valid_ip" == "true" || "$valid_mac" == "true" ]] || return 0

    if ! rules_output="$(iptables -t nat -S PREROUTING 2>&1)"; then
        echo "ERROR: Failed to read DNS redirect rules: $rules_output" >&2
        return 1
    fi
    while IFS= read -r rule; do
        [[ " $rule " == *" --dport 53 "* ]] || continue
        [[ " $rule " == *" -j REDIRECT "* ]] || continue
        [[ " $rule " == *" --to-ports 53 "* ]] || continue
        [[ " $rule " == *" -p udp "* || " $rule " == *" -p tcp "* ]] || continue

        rule_mac="$(awk '{for (i=1; i<=NF; i++) if ($i == "--mac-source") {print $(i+1); exit}}' <<< "$rule")"
        rule_ip="$(awk '{for (i=1; i<=NF; i++) if ($i == "-s") {print $(i+1); exit}}' <<< "$rule")"
        rule_ip="${rule_ip%/32}"
        if [[ "$valid_mac" == "true" && "${rule_mac,,}" == "${client_mac,,}" ]] \
            || [[ "$valid_ip" == "true" && "$rule_ip" == "$client_ip" ]]; then
            delete_dns_redirect_rule "$rule" || return 1
        fi
    done <<< "$rules_output"
}

reconcile_dns_redirects() {
    local -a desired=("$@")
    local rules_output rule rule_mac rule_ip

    if ! rules_output="$(iptables -t nat -S PREROUTING 2>&1)"; then
        echo "ERROR: Failed to read DNS redirect rules: $rules_output" >&2
        return 1
    fi

    while IFS= read -r rule; do
        [[ -n "$rule" ]] || continue
        [[ "$rule" == *"--comment $DNS_REDIRECT_COMMENT"* ]] || continue
        rule_mac="$(awk '{for (i=1; i<=NF; i++) if ($i == "--mac-source") {print $(i+1); exit}}' <<< "$rule")"
        rule_ip="$(awk '{for (i=1; i<=NF; i++) if ($i == "-s") {print $(i+1); exit}}' <<< "$rule")"
        rule_ip="${rule_ip%/32}"

        if is_valid_mac "$rule_mac"; then
            ip_in_array "mac:${rule_mac,,}" "${desired[@]}" && continue
        elif is_valid_ipv4 "$rule_ip"; then
            ip_in_array "ip:$rule_ip" "${desired[@]}" && continue
        else
            echo "ERROR: Refusing unrecognized owned DNS redirect rule: $rule" >&2
            return 1
        fi

        delete_dns_redirect_rule "$rule" || return 1
    done <<< "$rules_output"
}

remove_tagged_rules() {
    local table="$1"
    local parent="$2"
    local pattern="$3"
    local rule del_rule

    while IFS= read -r rule; do
        [[ -n "$rule" ]] || continue
        del_rule="${rule/-A /-D }"
        # The rule came from iptables itself, not from user-controlled state.
        # shellcheck disable=SC2086
        iptables -t "$table" $del_rule 2>/dev/null || true
    done < <(iptables -t "$table" -S "$parent" 2>/dev/null | grep -E -- "$pattern" || true)
}

clear_runtime_rules() {
    local chain set_name
    local -a chains=()

    command -v iptables >/dev/null 2>&1 || return 0

    # Clear ownership-tagged direct rules first.  Legacy untagged DNS rules are
    # migrated the next time policy is applied and remain deliberately
    # untouched here because they cannot be distinguished from administrator
    # rules without the original device identity.
    remove_tagged_rules nat PREROUTING "--comment ${DNS_REDIRECT_COMMENT}( |$)"
    remove_tagged_rules filter OUTPUT "--comment easypi_sched_(cat|quic)( |$)"
    remove_tagged_rules filter FORWARD "--comment easypi_sched_(cat|quic)( |$)"

    while IFS= read -r chain; do
        [[ "$chain" =~ ^EASYPI_(VPN_.*|VPNM_[0-9a-f]{12}|ADMISSION($|_.*)|BYPASS_MON|SCHEDULE)$ ]] || continue
        chains+=("$chain")
    done < <(iptables -S 2>/dev/null | awk '$1 == "-N" {print $2}' || true)

    for chain in "${chains[@]}"; do
        remove_chain_references "$chain"
    done
    # Flush every owned chain before deleting any of them: per-device chains
    # may jump to EASYPI_BYPASS_MON.
    for chain in "${chains[@]}"; do
        iptables -F "$chain" 2>/dev/null || true
    done
    for chain in "${chains[@]}"; do
        iptables -X "$chain" 2>/dev/null || true
    done

    # Once every referencing rule is gone, remove product-owned kernel sets.
    # The allowlist is explicit enough not to capture an administrator's
    # unrelated set merely because it happens to contain a common word.
    if command -v ipset >/dev/null 2>&1; then
        while IFS= read -r set_name; do
            [[ "$set_name" =~ ^easypi_(app_[a-z0-9_]+|cat_[a-z0-9_]+|tor_(nodes|stage)|doh_providers|smartdns_(providers|stage)|proxy_endpoints|wa_quic|fb_quic|messenger_quic)$ ]] || continue
            ipset destroy "$set_name" 2>/dev/null || true
        done < <(ipset list -name 2>/dev/null || true)
    fi

    echo "✓ EasyPi anti-bypass runtime rules cleared"
}

update_smartdns_ipset() {
    local temp_file
    temp_file="$(mktemp "$RUNTIME_DIR/smartdns-nodes.XXXXXX")"
    if python3 - <<'PY' > "$temp_file" 2>/dev/null; then
import ipaddress
import socket

domains = [
    "unlocator.com",
    "getflix.com.au",
    "smartdnsproxy.com",
    "unotelly.com",
    "overplay.net",
    "unblock-us.com",
    "ironsocket.com",
    "smartdns.com",
]

ips = set()
for domain in domains:
    try:
        infos = socket.getaddrinfo(domain, None, family=socket.AF_INET)
    except Exception:
        continue
    for info in infos:
        ip = info[4][0]
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if ip_obj.version == 4 and ip_obj.is_global:
            ips.add(str(ip_obj))

for ip in sorted(ips):
    print(ip)
PY
        :
    fi

    if [[ -s "$temp_file" ]]; then
        # Never destroy the live set: iptables may still reference it. Build a
        # complete replacement and swap it atomically so filtering has no gap.
        ipset destroy "$SMARTDNS_STAGING_IPSET" 2>/dev/null || true
        if ! ipset create "$SMARTDNS_STAGING_IPSET" hash:ip hashsize 1024 maxelem 65536; then
            rm -f "$temp_file"
            echo "ERROR: Could not create staged SmartDNS IP set" >&2
            return 1
        fi

        local count=0
        local smartdns_ip
        while IFS= read -r smartdns_ip; do
            if [[ $smartdns_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                ipset add "$SMARTDNS_STAGING_IPSET" "$smartdns_ip" 2>/dev/null && ((count++)) || true
            fi
        done < "$temp_file"

        if ! ipset_exists_name "$SMARTDNS_IPSET"; then
            ipset create "$SMARTDNS_IPSET" hash:ip hashsize 1024 maxelem 65536
        fi
        if ! ipset swap "$SMARTDNS_STAGING_IPSET" "$SMARTDNS_IPSET"; then
            ipset destroy "$SMARTDNS_STAGING_IPSET" 2>/dev/null || true
            rm -f "$temp_file"
            echo "ERROR: Could not activate staged SmartDNS IP set" >&2
            return 1
        fi
        ipset destroy "$SMARTDNS_STAGING_IPSET" 2>/dev/null || true
        publish_data_file "$temp_file" "$SMARTDNS_LIST_FILE"
        rm -f "$temp_file"

        echo "✓ Loaded $count SmartDNS provider IPs"
    elif [[ -f "$SMARTDNS_LIST_FILE" ]]; then
        if ! ipset_exists_name "$SMARTDNS_IPSET"; then
            ipset create "$SMARTDNS_IPSET" hash:ip hashsize 1024 maxelem 65536
        fi

        local cached_ip
        while IFS= read -r cached_ip; do
            if [[ $cached_ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
                ipset add "$SMARTDNS_IPSET" "$cached_ip" 2>/dev/null || true
            fi
        done < "$SMARTDNS_LIST_FILE"
    else
        echo "⚠ SmartDNS IP set update failed and no cache found"
    fi
}

ensure_smartdns_ipset() {
    if [[ ! -f "$SMARTDNS_LIST_FILE" ]] || [[ $(find "$SMARTDNS_LIST_FILE" -mtime +1 2>/dev/null) ]]; then
        update_smartdns_ipset
    elif ! ipset_exists_name "$SMARTDNS_IPSET"; then
        update_smartdns_ipset
    fi
}

# Empty chain used purely as an accounting target: packets matching a bypass signature
# jump here, get counted, then RETURN — the traffic is NOT blocked. This is what lets the
# banner fire for a channel the admin has not ticked (VPN connects, traffic is seen,
# admin decides from the banner).
BYPASS_MON_CHAIN="EASYPI_BYPASS_MON"

ensure_conntrack_acct() {
    # DNS-shadow detection reads per-flow byte counters from conntrack. nf_conntrack_acct
    # is OFF by default in many kernels; without it conntrack emits no bytes= and detection
    # silently does nothing. Enable it here (runs as root on every sync) so existing installs
    # self-heal; install.sh also persists it across reboots via sysctl.d.
    modprobe nf_conntrack 2>/dev/null || true
    if [[ "$(sysctl -n net.netfilter.nf_conntrack_acct 2>/dev/null || echo 0)" != "1" ]]; then
        sysctl -w net.netfilter.nf_conntrack_acct=1 >/dev/null 2>&1 || true
    fi
}

ensure_monitor_chain() {
    if ! chain_exists "$BYPASS_MON_CHAIN"; then
        iptables -N "$BYPASS_MON_CHAIN" 2>/dev/null || true
    fi
}

add_port_monitor_rules() {
    local chain_name="$1"
    local array_name="$2"
    local array_ref="${array_name}[@]"
    local port_spec
    local proto
    local port

    for port_spec in "${!array_ref}"; do
        proto="${port_spec%%:*}"
        port="${port_spec##*:}"
        # Never monitor plain udp/443: ordinary HTTP/3 lands there and would be pure noise.
        [[ "$proto" == "udp" && "$port" == "443" ]] && continue
        iptables -A "$chain_name" -p "$proto" --dport "$port" -j "$BYPASS_MON_CHAIN"
    done
}

add_port_block_rules() {
    local chain_name="$1"
    local array_name="$2"
    local array_ref="${array_name}[@]"
    local port_spec
    local proto
    local port

    for port_spec in "${!array_ref}"; do
        proto="${port_spec%%:*}"
        port="${port_spec##*:}"
        iptables -A "$chain_name" -p "$proto" --dport "$port" -j REJECT --reject-with icmp-port-unreachable
    done
}

setup_vpn_blocking() {
    local client_ip="$1"
    local channels_csv="${2:-all}"
    local client_mac="${3:-}"
    local identity="$client_ip"
    [[ -n "$client_mac" ]] && identity="$client_mac"
    local chain_name
    chain_name=$(get_chain_name "$identity")

    if ! is_valid_ipv4 "$client_ip"; then
        echo "ERROR: Invalid IP address '$client_ip'" >&2
        return 1
    fi
    if [[ -n "$client_mac" ]] && ! is_valid_mac "$client_mac"; then
        echo "ERROR: Invalid MAC address '$client_mac'" >&2
        return 1
    fi

    local enable_vpn=false
    local enable_doh=false
    local enable_proxy=false
    local enable_tor=false
    local enable_smartdns=false

    if [[ "$channels_csv" == "all" ]]; then
        enable_vpn=true
        enable_doh=true
        enable_proxy=true
        enable_tor=true
        enable_smartdns=true
    elif [[ -n "$channels_csv" && "$channels_csv" != "__monitor__" ]]; then
        local csv=",${channels_csv},"
        [[ "$csv" == *",bypass,"* || "$csv" == *",strict_parental,"* ]] && {
            enable_vpn=true
            enable_doh=true
            enable_proxy=true
            enable_tor=true
            enable_smartdns=true
        }
        [[ "$csv" == *",vpn,"* ]] && enable_vpn=true
        [[ "$csv" == *",doh,"* ]] && enable_doh=true
        [[ "$csv" == *",proxy,"* ]] && enable_proxy=true
        [[ "$csv" == *",tor,"* ]] && enable_tor=true
        [[ "$csv" == *",smartdns,"* ]] && enable_smartdns=true
    fi

    local quarantine_only=false
    if is_fail_closed_ip "$client_ip" "$client_mac"; then
        quarantine_only=true
    fi

    # NOTE: a device with no ticked channels is NOT skipped any more. It still gets a chain
    # containing monitor-only counting rules, because detection reads those counters — with
    # no chain at all a VPN connects and nothing is ever noticed. Devices that opt out
    # entirely (bypass_mode=log_only) are filtered out by sync_from_devices before this.

    if chain_exists "$chain_name"; then
        remove_chain_references "$chain_name"
        iptables -F "$chain_name" 2>/dev/null || true
    else
        iptables -N "$chain_name" || {
            echo "ERROR: Failed to create chain $chain_name" >&2
            return 1
        }
    fi

    if [[ "$enable_tor" == "true" ]]; then
        ensure_tor_ipset
        if [[ ! -f "$TOR_LIST_FILE" ]] || [[ $(find "$TOR_LIST_FILE" -mtime +1 2>/dev/null) ]]; then
            update_tor_list
        fi
        local tor_count
        tor_count=$(ipset list "$TOR_IPSET" 2>/dev/null | grep -c "^[0-9]" || echo "0")
        if [[ "$tor_count" -gt 0 ]]; then
            iptables -A "$chain_name" -m set --match-set "$TOR_IPSET" dst -j REJECT --reject-with icmp-host-unreachable
        fi
        add_port_block_rules "$chain_name" TOR_PORTS
    fi

    if [[ "$enable_doh" == "true" ]]; then
        ensure_doh_ipset
        iptables -A "$chain_name" -m set --match-set "$DOH_IPSET" dst -j REJECT --reject-with icmp-host-unreachable
        add_port_block_rules "$chain_name" DOH_PORTS
    fi

    if [[ "$enable_vpn" == "true" ]]; then
        add_port_block_rules "$chain_name" VPN_PORTS
    fi

    if [[ "$enable_proxy" == "true" ]]; then
        add_port_block_rules "$chain_name" PROXY_PORTS
        # Block Opera VPN (SurfEasy) + web-proxy endpoints by IP (hardcoded bootstrap).
        ensure_proxy_ipset
        if ipset_exists_name "$PROXY_IPSET"; then
            iptables -A "$chain_name" -m set --match-set "$PROXY_IPSET" dst -j REJECT --reject-with icmp-host-unreachable
        fi
    fi

    if [[ "$enable_smartdns" == "true" ]]; then
        ensure_smartdns_ipset
        if ipset_exists_name "$SMARTDNS_IPSET"; then
            iptables -A "$chain_name" -m set --match-set "$SMARTDNS_IPSET" dst -j REJECT --reject-with icmp-host-unreachable
        fi
    fi

    # Monitor (count, do NOT block) every bypass channel the admin did not tick, so that a
    # VPN/proxy/Tor connection still raises the banner and the admin can decide from it.
    # Only the signals the detector treats as reliable are monitored.
    ensure_monitor_chain

    if [[ "$enable_tor" != "true" ]]; then
        ensure_tor_ipset
        if ipset_exists_name "$TOR_IPSET"; then
            iptables -A "$chain_name" -m set --match-set "$TOR_IPSET" dst -j "$BYPASS_MON_CHAIN"
        fi
        add_port_monitor_rules "$chain_name" TOR_PORTS
    fi

    if [[ "$enable_doh" != "true" ]]; then
        ensure_doh_ipset
        iptables -A "$chain_name" -m set --match-set "$DOH_IPSET" dst -j "$BYPASS_MON_CHAIN"
        # DoT only (853). udp/443 is deliberately skipped by add_port_monitor_rules.
        add_port_monitor_rules "$chain_name" DOH_PORTS
    fi

    if [[ "$enable_vpn" != "true" ]]; then
        add_port_monitor_rules "$chain_name" VPN_PORTS
    fi

    if [[ "$enable_proxy" != "true" ]]; then
        add_port_monitor_rules "$chain_name" PROXY_PORTS
        ensure_proxy_ipset
        if ipset_exists_name "$PROXY_IPSET"; then
            iptables -A "$chain_name" -m set --match-set "$PROXY_IPSET" dst -j "$BYPASS_MON_CHAIN"
        fi
    fi

    if [[ "$enable_smartdns" != "true" ]]; then
        ensure_smartdns_ipset
        if ipset_exists_name "$SMARTDNS_IPSET"; then
            iptables -A "$chain_name" -m set --match-set "$SMARTDNS_IPSET" dst -j "$BYPASS_MON_CHAIN"
        fi
    fi

    if [[ "$quarantine_only" == "true" ]]; then
        iptables -A "$chain_name" -j REJECT --reject-with icmp-host-unreachable
    fi

    # Force ALL plaintext DNS (to any resolver) transparently back through EasyPi for EVERY
    # managed device, not just those blocking DoH. This is visibility, not blocking: the
    # device's DNS becomes visible in flow_log and filtering still follows its profile. It
    # also closes the DNS-shadow evasion where a device emits a decoy plaintext query to a
    # foreign resolver to masquerade as "resolving elsewhere" while tunnelling everything
    # else. log_only devices get no chain here, so they keep their own resolver untouched.
    add_dns_redirect "$client_ip" "$client_mac"

    remove_chain_references "$chain_name"
    if is_mobile_tunnel_ip "$client_ip"; then
        iptables -I FORWARD 1 -i "$MOBILE_TUNNEL_IFACE" -s "$client_ip" -j "$chain_name"
    elif is_valid_mac "$client_mac"; then
        iptables -I FORWARD 1 -m mac --mac-source "$client_mac" -j "$chain_name"
    else
        iptables -I OUTPUT 1 -s "$client_ip" -j "$chain_name"
        iptables -I FORWARD 1 -s "$client_ip" -j "$chain_name"
    fi

    local enabled_summary
    if [[ "$channels_csv" == "__monitor__" || -z "$channels_csv" ]]; then
        enabled_summary="monitor-only: nothing blocked, bypass is detected and reported"
    else
        enabled_summary="blocked: $channels_csv"
    fi
    [[ "$quarantine_only" == "true" ]] && enabled_summary="$enabled_summary + quarantine"
    echo "✓ Anti-bypass rules applied for $client_ip ($chain_name) [$enabled_summary]"
}

remove_vpn_blocking() {
    local client_ip="$1"
    local client_mac="${2:-}"
    local identity="$client_ip"
    [[ -n "$client_mac" ]] && identity="$client_mac"
    local chain_name
    chain_name=$(get_chain_name "$identity")

    if ! is_valid_ipv4 "$client_ip"; then
        echo "ERROR: Invalid IP address '$client_ip'" >&2
        return 1
    fi

    remove_chain_references "$chain_name"

    if chain_exists "$chain_name"; then
        iptables -F "$chain_name" 2>/dev/null || true
        iptables -X "$chain_name" 2>/dev/null || true
    fi

    remove_dns_redirect "$client_ip" "$client_mac"
    remove_fail_closed_ip "$client_ip" "$client_mac"
    echo "✓ VPN/Tor blocking removed for $client_ip"
}

sync_unknown_device_admission() {
    local chain="EASYPI_ADMISSION"
    local staging="EASYPI_ADMISSION_NEXT"
    local settings_file="/opt/EasyPi/data/netprotection/settings.json"
    local profiles_file="/opt/EasyPi/data/netprotection/profiles.json"
    local bindings_file="/opt/EasyPi/data/netprotection/bindings.json"
    local tunnel_registry_file="/opt/EasyPi/data/netprotection/mobile-home-tunnel-peers.json"
    local mode
    mode="$(/usr/bin/python3 - "$settings_file" <<'PY'
import json
import pathlib
import sys

path = pathlib.Path(sys.argv[1])
if not path.exists():
    print("block")
else:
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
        section = payload.get("unknown_devices")
        raw_mode = section.get("mode") if isinstance(section, dict) else None
        print("default" if raw_mode == "default" else "block")
    except Exception:
        print("block")
PY
)"

    local subnet

    remove_admission_hooks() {
        local target="$1"
        for subnet in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
            while iptables -C FORWARD -s "$subnet" -j "$target" 2>/dev/null; do
                iptables -D FORWARD -s "$subnet" -j "$target"
            done
        done
    }

    # Recover a staging policy left active by interruption after the switch.
    # Renaming a user chain also updates its references atomically in iptables.
    if chain_exists "$staging"; then
        local staging_live=0
        for subnet in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
            if iptables -C FORWARD -s "$subnet" -j "$staging" 2>/dev/null; then
                staging_live=1
                break
            fi
        done
        if [[ "$staging_live" == "1" ]]; then
            remove_admission_hooks "$chain"
            if chain_exists "$chain"; then
                iptables -F "$chain"
                iptables -X "$chain"
            fi
            iptables -E "$staging" "$chain"
        else
            iptables -F "$staging"
            iptables -X "$staging"
        fi
    fi

    if [[ "$mode" == "default" ]]; then
        remove_admission_hooks "$chain"
        if chain_exists "$chain"; then
            iptables -F "$chain"
            iptables -X "$chain"
        fi
        return 0
    fi

    # Build off-path. Until every allow/reject rule exists, the currently
    # attached policy remains untouched.
    iptables -N "$staging"
    # Do not interfere with container or explicit tunnel ingress.
    iptables -A "$staging" -i tailscale0 -j RETURN 2>/dev/null || true
    iptables -A "$staging" -i 'wg+' -j RETURN 2>/dev/null || true
    iptables -A "$staging" -i 'tun+' -j RETURN 2>/dev/null || true
    iptables -A "$staging" -i 'docker+' -j RETURN 2>/dev/null || true
    iptables -A "$staging" -i 'br-+' -j RETURN 2>/dev/null || true

    # Mobile home-tunnel peers have no Ethernet MAC. Their address is bound to
    # an authenticated phone by the tunnel server, so an approval for a tunnel
    # address is honoured only while the live peer registry still assigns that
    # address to the same phone identity. A stale approval left by a former
    # phone therefore never admits a new phone which reuses the address.
    local -A tunnel_pairs=()
    local tunnel_pair tmp_tunnel_pairs
    tmp_tunnel_pairs="$(mktemp "$RUNTIME_DIR/admission-tunnel.XXXXXX")"
    if ! /usr/bin/python3 - "$tunnel_registry_file" > "$tmp_tunnel_pairs" <<'PY'
import hashlib
import ipaddress
import json
import pathlib
import sys
import uuid

# Same identifier as UnknownDeviceAdmissionService.mobile_tunnel_mac().
path = pathlib.Path(sys.argv[1])
if not path.is_file() or path.is_symlink() or path.stat().st_size > 64 * 1024:
    raise SystemExit(0)
payload = json.loads(path.read_text(encoding="utf-8"))
if payload.get("version") != 1 or not isinstance(payload.get("devices"), list):
    raise SystemExit(0)
network = ipaddress.IPv4Network("10.77.0.0/24")
for item in payload["devices"]:
    identity = str(uuid.UUID(str(item["id"])))
    address = ipaddress.IPv4Address(str(item["address"]))
    if address not in network:
        continue
    digest = hashlib.sha256(
        ("easypi/mobile-tunnel-identity/v1/" + identity).encode("ascii")
    ).digest()
    mac = ":".join(f"{byte:02x}" for byte in bytes([0x02]) + digest[:5])
    print(f"{mac}|{address}")
PY
    then
        # An unreadable registry admits no tunnel peer; LAN admission is unaffected.
        echo "WARNING: Mobile tunnel registry is invalid; no tunnel peer is admitted" >&2
        : > "$tmp_tunnel_pairs"
    fi
    while IFS= read -r tunnel_pair; do
        [[ -n "$tunnel_pair" ]] && tunnel_pairs["$tunnel_pair"]=1
    done < "$tmp_tunnel_pairs"
    rm -f "$tmp_tunnel_pairs"

    local known_mac known_ip
    for known_mac in "${managed_macs[@]}"; do
        is_valid_mac "$known_mac" || continue
        known_ip="${mac_ips[$known_mac]:-}"
        if is_valid_ipv4 "$known_ip"; then
            if [[ "$known_ip" == 10.77.0.* ]]; then
                [[ -n "${tunnel_pairs["${known_mac,,}|$known_ip"]:-}" ]] || continue
                iptables -A "$staging" -i easypi-mobile0 -s "$known_ip" -j RETURN
            else
                iptables -A "$staging" -s "$known_ip" -m mac --mac-source "$known_mac" -j RETURN
            fi
        fi
    done

    # Profiles are the authoritative source for per-device DNS policy. Mirror
    # their active bindings here so the network admission layer cannot reject a
    # device which the profile engine already recognises.
    local tmp_bindings
    tmp_bindings="$(mktemp "$RUNTIME_DIR/admission-bindings.XXXXXX")"
    if ! /usr/bin/python3 - "$profiles_file" "$bindings_file" > "$tmp_bindings" <<'PY'
import ipaddress
import json
import pathlib
import re
import sys
from collections import defaultdict

profiles_path = pathlib.Path(sys.argv[1])
bindings_path = pathlib.Path(sys.argv[2])


def load_items(path: pathlib.Path, key: str) -> list[dict]:
    if not path.exists():
        return []
    payload = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(payload, list):
        return [item for item in payload if isinstance(item, dict)]
    if isinstance(payload, dict) and isinstance(payload.get(key), list):
        return [item for item in payload[key] if isinstance(item, dict)]
    return []


try:
    profiles = load_items(profiles_path, "profiles")
    bindings = load_items(bindings_path, "bindings")
except (OSError, ValueError, TypeError) as exc:
    sys.stderr.write(f"Cannot load profile admission policy: {exc}\n")
    raise SystemExit(1)

active_profiles = {
    str(profile.get("id") or "")
    for profile in profiles
    if profile.get("enabled", True) and str(profile.get("id") or "")
}

groups: dict[tuple[str, str], dict[str, list[str]]] = defaultdict(
    lambda: {"mac": [], "network": []}
)

for binding in bindings:
    if not binding.get("enabled", True):
        continue
    if str(binding.get("profile_id") or "") not in active_profiles:
        continue
    kind = str(binding.get("binding_type") or "").strip().lower()
    value = str(binding.get("value") or "").strip().lower()
    profile_id = str(binding.get("profile_id") or "")
    name = str(binding.get("name") or "").strip().casefold()
    key = (profile_id, name)
    try:
        if kind == "mac" and re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", value):
            groups[key]["mac"].append(value)
        elif kind == "ip":
            address = ipaddress.ip_address(value)
            if address.version == 4:
                groups[key]["network"].append(str(address))
        elif kind == "range":
            network = ipaddress.ip_network(value, strict=False)
            if network.version == 4 and network.prefixlen >= 16:
                groups[key]["network"].append(str(network))
    except ValueError:
        continue

for (_profile_id, name), identity in sorted(groups.items()):
    macs = sorted(set(identity["mac"]))
    networks = sorted(set(identity["network"]))
    # A device name scopes the pair, but duplicate names are not an identity.
    # Accept only an unambiguous one-MAC/one-network pair in every group.
    if len(macs) != 1 or len(networks) != 1:
        continue
    for mac in macs:
        for network in networks:
            print(f"PAIR|{mac}|{network}")
PY
    then
        rm -f "$tmp_bindings"
        echo "ERROR: Active profile bindings could not be loaded; refusing partial admission policy" >&2
        return 1
    fi

    local binding_type binding_mac binding_network
    while IFS='|' read -r binding_type binding_mac binding_network; do
        case "$binding_type" in
            PAIR)
                if is_valid_mac "$binding_mac" \
                    && { is_valid_ipv4 "$binding_network" \
                        || [[ "$binding_network" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/([1-2][0-9]|3[0-2])$ ]]; }; then
                    if [[ "$binding_network" == 10.77.0.* ]]; then
                        [[ -n "${tunnel_pairs["${binding_mac,,}|$binding_network"]:-}" ]] || continue
                        iptables -A "$staging" -i easypi-mobile0 -s "$binding_network" -j RETURN
                    else
                        iptables -A "$staging" -s "$binding_network" -m mac --mac-source "$binding_mac" -j RETURN
                    fi
                fi
                ;;
        esac
    done < "$tmp_bindings"
    rm -f "$tmp_bindings"

    iptables -A "$staging" -j REJECT --reject-with icmp-admin-prohibited

    # Attach the complete chain before detaching the previous policy, then
    # promote it to the stable name. At least one complete policy is active at
    # every point in the transition.
    for subnet in 10.0.0.0/8 172.16.0.0/12 192.168.0.0/16; do
        iptables -I FORWARD 1 -s "$subnet" -j "$staging"
    done
    remove_admission_hooks "$chain"
    if chain_exists "$chain"; then
        iptables -F "$chain"
        iptables -X "$chain"
    fi
    iptables -E "$staging" "$chain"
}

sync_from_devices() {
    local devices_file="/opt/EasyPi/data/netprotection/devices.json"

    # Persistent administrator blocks and transaction holds are restored before
    # any allow policy is rebuilt. This keeps restarts fail-closed.
    sync_admission_blocks
    sync_admission_holds

    # Keep conntrack byte accounting on so the DNS-shadow detector has data to work with.
    ensure_conntrack_acct

    local tmp_configs
    tmp_configs="$(mktemp "$RUNTIME_DIR/device-configs.XXXXXX")"

    if [[ ! -f "$devices_file" ]]; then
        : > "$tmp_configs"
    elif ! /usr/sbin/runuser -u easypi -- /usr/bin/python3 - "$devices_file" <<'PY' > "$tmp_configs"; then
import ipaddress
import json
import re
import sys

devices_file = sys.argv[1]

SERVICE_ALIASES = {
    "vpn": {"vpn", "vpn_services"},
    "doh": {"doh", "dns_over_https", "dot", "dns_over_tls"},
    "proxy": {"proxy", "web_proxy", "web_proxies"},
    "tor": {"tor"},
    "smartdns": {"smartdns", "smart_dns"},
}


def iter_devices(payload):
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and isinstance(payload.get("devices"), list):
        return payload.get("devices")
    return []


def valid_ipv4(value: str) -> bool:
    try:
        obj = ipaddress.ip_address(value)
    except ValueError:
        return False
    return obj.version == 4


try:
    with open(devices_file) as f:
        payload = json.load(f)
except Exception as exc:
    sys.stderr.write(f"Error: {exc}\n")
    raise SystemExit(1)

for device in iter_devices(payload):
    if not isinstance(device, dict):
        continue
    if not device.get("enabled", True):
        continue

    device_ip = str(device.get("ip") or "").strip()
    device_mac = str(device.get("mac") or "").strip().lower()
    if not valid_ipv4(device_ip) or not re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", device_mac):
        continue

    bypass_mode = str(device.get("bypass_mode") or "warn").strip().lower()
    blocked_services = device.get("blocked_services", []) or []
    if not isinstance(blocked_services, list):
        blocked_services = []

    normalized_services = {
        str(service).strip().lower()
        for service in blocked_services
        if isinstance(service, str) and str(service).strip()
    }

    channels: set[str] = set()

    if bypass_mode != "log_only":
        # Blocking is opt-in: only the channels the admin ticked in Parental Controls are
        # REJECTed. Channels that are NOT ticked are still *monitored* (counting rules, see
        # setup_vpn_blocking) so a VPN/proxy/Tor connection raises the banner without being
        # blocked — the admin then decides from the banner.
        if "bypass" in normalized_services or "strict_parental" in normalized_services:
            channels.update({"vpn", "doh", "proxy", "tor", "smartdns"})
        for channel, aliases in SERVICE_ALIASES.items():
            if normalized_services.intersection(aliases):
                channels.add(channel)

    if bypass_mode == "log_only":
        # Explicit opt-out: no rules at all for this device, not even monitoring.
        print(f"M|{device_ip}|{device_mac}|__none__")
    else:
        # Empty channel list is legitimate: the device gets monitor-only rules.
        print(f"M|{device_ip}|{device_mac}|{','.join(sorted(channels))}")
PY
        local err
        err="$(cat "$tmp_configs" 2>/dev/null || true)"
        rm -f "$tmp_configs"
        echo "ERROR: Failed to read devices.json. ${err}" >&2
        return 1
    fi

    local managed_macs=()
    local macs_to_block=()
    declare -A mac_channels mac_ips

    local rec_type
    local rec_ip
    local rec_mac
    local rec_channels
    while IFS='|' read -r rec_type rec_ip rec_mac rec_channels; do
        [[ "$rec_type" != "M" ]] && continue
        if ! is_valid_ipv4 "$rec_ip" || ! is_valid_mac "$rec_mac"; then
            continue
        fi

        if ! mac_in_array "$rec_mac" "${managed_macs[@]}"; then
            managed_macs+=("$rec_mac")
        fi
        mac_ips["$rec_mac"]="$rec_ip"

        # '__none__' = log_only opt-out (no rules). An empty channel list still gets a
        # chain, built with monitor-only counting rules so bypass is detected, not blocked.
        if [[ "$rec_channels" != "__none__" ]]; then
            if ! mac_in_array "$rec_mac" "${macs_to_block[@]}"; then
                macs_to_block+=("$rec_mac")
            fi
            mac_channels["$rec_mac"]="$rec_channels"
        fi
    done < "$tmp_configs"
    rm -f "$tmp_configs"

    sync_unknown_device_admission

    local fail_ip
    while IFS= read -r fail_ip; do
        [[ -z "$fail_ip" ]] && continue
        if ! is_valid_ipv4 "$fail_ip"; then
            continue
        fi

        local fail_mac=""
        local candidate_mac
        for candidate_mac in "${managed_macs[@]}"; do
            [[ "${mac_ips[$candidate_mac]:-}" == "$fail_ip" ]] && { fail_mac="$candidate_mac"; break; }
        done
        if [[ -n "$fail_mac" ]]; then
            if ! mac_in_array "$fail_mac" "${macs_to_block[@]}"; then
                macs_to_block+=("$fail_mac")
            fi
            : "${mac_channels[$fail_mac]:=""}"
        else
            remove_fail_closed_ip "$fail_ip"
        fi
    done < <(list_fail_closed_ips)

    local chain_name
    while IFS= read -r chain_name; do
        if [[ $chain_name =~ ^EASYPI_VPN_ ]]; then
            remove_chain_references "$chain_name"
            iptables -F "$chain_name" 2>/dev/null || true
            iptables -X "$chain_name" 2>/dev/null || true
        elif [[ $chain_name =~ ^EASYPI_VPNM_([0-9a-f]{12})$ ]]; then
            local raw_mac="${BASH_REMATCH[1]}"
            local chain_mac="${raw_mac:0:2}:${raw_mac:2:2}:${raw_mac:4:2}:${raw_mac:6:2}:${raw_mac:8:2}:${raw_mac:10:2}"
            if ! mac_in_array "$chain_mac" "${macs_to_block[@]}"; then
                remove_chain_references "$chain_name"
                iptables -F "$chain_name" 2>/dev/null || true
                iptables -X "$chain_name" 2>/dev/null || true
            fi
        fi
    done < <(iptables -L -n | awk '/^Chain EASYPI_VPN/ {print $2}')

    local -a desired_dns_redirects=()
    local desired_mac
    for desired_mac in "${macs_to_block[@]}"; do
        if is_mobile_tunnel_ip "${mac_ips[$desired_mac]:-}"; then
            desired_dns_redirects+=("ip:${mac_ips[$desired_mac]}")
        else
            desired_dns_redirects+=("mac:${desired_mac,,}")
        fi
    done
    reconcile_dns_redirects "${desired_dns_redirects[@]}" || return 1

    local block_mac block_ip
    local channels
    for block_mac in "${macs_to_block[@]}"; do
        block_ip="${mac_ips[$block_mac]}"
        channels="${mac_channels[$block_mac]:-}"
        # Guard: setup_vpn_blocking defaults an EMPTY arg to "all" (${2:-all}), which would
        # block every channel. Pass an explicit sentinel for the monitor-only case.
        [[ -z "$channels" ]] && channels="__monitor__"
        setup_vpn_blocking "$block_ip" "$channels" "$block_mac"
    done

    if [[ ${#macs_to_block[@]} -gt 0 ]]; then
        local quarantined=0
        for block_mac in "${macs_to_block[@]}"; do
            block_ip="${mac_ips[$block_mac]}"
            if is_fail_closed_ip "$block_ip" "$block_mac"; then
                ((quarantined++)) || true
            fi
        done
        echo "VPN blocking active for ${#macs_to_block[@]} device(s) (fail-closed: $quarantined)"
    else
        echo "No devices require VPN blocking"
    fi
}

# Serialize invocations so concurrent runs (service auto-sync + manual/API calls)
# cannot interleave and produce duplicate iptables rules.
if ! command -v flock >/dev/null 2>&1; then
    echo "ERROR: flock is required to serialize firewall updates" >&2
    exit 69
fi
exec 9>/run/easypi-vpn-blocking.lock
if ! flock -w 30 9; then
    echo "ERROR: Timed out waiting for the firewall update lock" >&2
    exit 75
fi

case "$ACTION" in
    add)
        if [[ -z "$CLIENT_IP" ]]; then
            echo "ERROR: IP address required for 'add' action" >&2
            exit 1
        fi
        setup_vpn_blocking "$CLIENT_IP" "${CLIENT_CHANNELS:-all}" "$CLIENT_MAC"
        ;;
    remove)
        if [[ -z "$CLIENT_IP" ]]; then
            echo "ERROR: IP address required for 'remove' action" >&2
            exit 1
        fi
        remove_vpn_blocking "$CLIENT_IP" "$CLIENT_MAC"
        ;;
    clear-runtime)
        clear_runtime_rules
        ;;
    quarantine)
        if [[ -z "$CLIENT_IP" ]]; then
            echo "ERROR: IP address required for 'quarantine' action" >&2
            exit 1
        fi
        if ! is_valid_ipv4 "$CLIENT_IP"; then
            echo "ERROR: Invalid IP address '$CLIENT_IP'" >&2
            exit 1
        fi
        add_fail_closed_ip "$CLIENT_IP" "$CLIENT_MAC"
        setup_vpn_blocking "$CLIENT_IP" "${CLIENT_CHANNELS:-}" "$CLIENT_MAC"
        echo "✓ Fail-closed quarantine enabled for $CLIENT_IP"
        ;;
    unquarantine)
        if [[ -z "$CLIENT_IP" ]]; then
            echo "ERROR: IP address required for 'unquarantine' action" >&2
            exit 1
        fi
        if ! is_valid_ipv4 "$CLIENT_IP"; then
            echo "ERROR: Invalid IP address '$CLIENT_IP'" >&2
            exit 1
        fi
        remove_fail_closed_ip "$CLIENT_IP" "$CLIENT_MAC"
        sync_from_devices
        echo "✓ Fail-closed quarantine removed for $CLIENT_IP"
        ;;
    hold-admission)
        if [[ -z "$CLIENT_IP" || -z "$CLIENT_MAC" ]]; then
            echo "ERROR: IP and MAC are required for 'hold-admission'" >&2
            exit 1
        fi
        admission_hold_state_cmd add "$CLIENT_IP" "$CLIENT_MAC"
        sync_admission_holds
        echo "✓ Admission hold enabled for $CLIENT_IP"
        ;;
    release-admission)
        if [[ -z "$CLIENT_IP" || -z "$CLIENT_MAC" ]]; then
            echo "ERROR: IP and MAC are required for 'release-admission'" >&2
            exit 1
        fi
        # Keep the durable hold recorded until the replacement chain without
        # this pair is fully active. A failed swap therefore leaves the old
        # deny in force. State cleanup after a successful swap is best-effort:
        # stale state may re-block later, but can never create unintended access.
        sync_admission_holds "$CLIENT_MAC"
        if ! admission_hold_state_cmd remove "$CLIENT_IP" "$CLIENT_MAC"; then
            echo "WARNING: admission hold released but stale state could not be removed" >&2
        fi
        echo "✓ Admission hold released for $CLIENT_IP"
        ;;
    block-admission)
        if [[ -z "$CLIENT_MAC" ]] || ! is_valid_mac "$CLIENT_MAC"; then
            echo "ERROR: A valid MAC is required for 'block-admission'" >&2
            exit 1
        fi
        admission_block_state_cmd add "$CLIENT_MAC"
        sync_admission_blocks
        echo "✓ Persistent admission block enabled for $CLIENT_MAC"
        ;;
    unblock-admission)
        if [[ -z "$CLIENT_MAC" ]] || ! is_valid_mac "$CLIENT_MAC"; then
            echo "ERROR: A valid MAC is required for 'unblock-admission'" >&2
            exit 1
        fi
        # First publish a complete replacement without this MAC. If durable
        # state cleanup fails, restore the active deny from the unchanged file.
        sync_admission_blocks "$CLIENT_MAC"
        if ! admission_block_state_cmd remove "$CLIENT_MAC"; then
            sync_admission_blocks || true
            echo "ERROR: Persistent admission block state could not be cleared" >&2
            exit 1
        fi
        echo "✓ Persistent admission block removed for $CLIENT_MAC"
        ;;
    list-quarantine)
        list_fail_closed_ips
        ;;
    sync)
        sync_from_devices
        ;;
    update-tor-list)
        update_tor_list
        ;;
    update-doh-list)
        update_doh_dynamic
        ;;
    update-proxy-list)
        update_proxy_ipset
        ;;
    *)
        echo "Usage: $0 {add|remove|clear-runtime|quarantine|unquarantine|hold-admission|release-admission|block-admission|unblock-admission|list-quarantine|sync|update-tor-list} [client_ip] [channels] [client_mac]" >&2
        echo "  add <ip> [channels] - Enable blocking for IP (default channels: all)" >&2
        echo "  remove <ip>         - Disable blocking for IP" >&2
        echo "  clear-runtime       - Remove all EasyPi anti-bypass runtime rules" >&2
        echo "  quarantine <ip>     - Enable fail-closed (full internet block) for IP" >&2
        echo "  unquarantine <ip>   - Disable fail-closed for IP and resync base rules" >&2
        echo "  list-quarantine     - List fail-closed IPs" >&2
        echo "  sync                - Sync per-device blocking from devices.json" >&2
        echo "  update-tor-list     - Update Tor exit nodes list" >&2
        echo "  update-doh-list     - Refresh DoH provider IPs (resolve known DoH hosts)" >&2
        echo "  update-proxy-list   - Refresh Opera VPN / web-proxy endpoint IPs" >&2
        exit 1
        ;;
esac
