#!/bin/bash
#
# App IP Blocking Management (Telegram, WhatsApp, Signal, etc.)
# Called by NetProtection service via runner to setup/remove iptables rules
# for apps that bypass DNS resolution.
#
# Usage: setup_app_blocking.sh <action> <client_ip> [apps]
# Actions: add, remove, clear-runtime, sync, status, update-lists,
#          learn-whatsapp, set-whatsapp-mode, get-whatsapp-mode
#
# This script blocks apps at IP level using:
# 1. ipset - for fast IP range matching
# 2. iptables - for port-based blocking
# 3. ASN blocking - for provider networks (optional)
#

set -e

ACTION="${1:-}"
CLIENT_IP="${2:-}"
APPS="${3:-all}"
CLIENT_MAC="$(printf '%s' "${4:-}" | tr '[:upper:]' '[:lower:]')"

DATA_DIR="/opt/EasyPi/data/netprotection"
STATE_DIR="/var/lib/easypi/netprotection"
IPSET_PREFIX="easypi_app"
WHATSAPP_EXTRA_IPS_FILE="$DATA_DIR/whatsapp_extra_ips.txt"
WHATSAPP_INCLUDE_META_FILE="$STATE_DIR/whatsapp_include_meta"
WHATSAPP_MODE_FILE="$STATE_DIR/whatsapp_block_mode"
WHATSAPP_STALE_CONNMARK="0x45500000"
WHATSAPP_STALE_CONNMARK_MASK="0xffff0000"
FACEBOOK_STALE_CONNMARK="0x45510000"
FACEBOOK_STALE_CONNMARK_MASK="0xffff0000"
TELEGRAM_DYNAMIC_IPS_FILE="$DATA_DIR/telegram_dynamic_ips.txt"
TELEGRAM_DYNAMIC_IPS_V6_FILE="$DATA_DIR/telegram_dynamic_ips_v6.txt"
WHATSAPP_DYNAMIC_IPS_FILE="$DATA_DIR/whatsapp_dynamic_ips.txt"
WHATSAPP_DYNAMIC_IPS_V6_FILE="$DATA_DIR/whatsapp_dynamic_ips_v6.txt"

# Tor relay list (shared with VPN blocker)
TOR_IPSET="easypi_tor_nodes"
TOR_LIST_FILE="/var/lib/easypi-security/tor/current/tor_ipv4.txt"
TOR_FEED_UPDATER="/opt/EasyPi/scripts/settings/update_tor_list.sh"
RUNTIME_DIR="/run/easypi-app-blocking"
DATA_WRITER="/opt/EasyPi/scripts/utils/write_easypi_data.py"
install -d -o root -g root -m 700 "$RUNTIME_DIR"
install -d -o root -g easypi -m 0750 "$STATE_DIR"

publish_data_file() {
    [[ -f "$DATA_WRITER" && ! -L "$DATA_WRITER" ]] || {
        log_error "Secure data writer is missing"
        return 1
    }
    /usr/bin/python3 "$DATA_WRITER" "$1" "$2"
}

# ═══════════════════════════════════════════════════════════════════════════════
# APP DEFINITIONS - IP Ranges and Ports
# ═══════════════════════════════════════════════════════════════════════════════

# Release-pinned Telegram IP ranges. Updates arrive only in signed EasyPi releases.
declare -a TELEGRAM_IPS=(
    "91.108.4.0/22"
    "91.108.8.0/22"
    "91.108.12.0/22"
    "91.108.16.0/22"
    "91.108.20.0/22"
    "91.108.56.0/22"
    "149.154.160.0/20"
    "185.76.151.0/24"
)

declare -a TELEGRAM_IPS_V6=(
    "2001:67c:4e8::/48"
    "2001:b28:f23c::/48"
    "2001:b28:f23d::/48"
    "2001:b28:f23f::/48"
    "2a0a:f280::/32"
)

# WhatsApp IP ranges (strict list to avoid blocking Instagram/Facebook)
declare -a WHATSAPP_IPS=(
    # WhatsApp-specific (IBM/SoftLayer + edge)
    "158.85.0.0/16"
    "158.85.5.0/24"
    "158.85.46.0/24"
    "158.85.48.0/24"
    "158.85.58.0/24"
    "158.85.61.0/24"
    "158.85.224.0/24"
    "158.85.233.0/24"
    "50.22.198.0/24"
    "50.22.210.0/24"
    "50.22.225.0/24"
    "50.22.235.0/24"
    "50.22.240.0/24"
    "169.44.82.0/24"
    "169.45.71.0/24"
    "169.45.87.0/24"
    "169.53.29.0/24"
    "169.53.81.0/24"
    "169.54.2.0/24"
    "169.54.51.0/24"
    "169.55.74.0/24"
    "169.55.126.0/24"
    "169.55.210.0/24"
    "173.192.231.0/24"
    "174.37.243.0/24"
    "184.173.136.0/24"
    "184.173.147.0/24"
    # Observed WhatsApp endpoints (Meta, /32)
    "157.240.253.13/32"
    "157.240.253.60/32"
    "157.240.253.61/32"
    # WhatsApp-owned allocation (AS32934 sub-block, not shared with FB/IG)
    "160.79.104.0/24"
)

# Optional Meta ranges (broad; will block Instagram/Facebook if enabled)
declare -a WHATSAPP_META_IPS=(
    "31.13.24.0/21"
    "31.13.64.0/18"
    "57.144.0.0/14"      # newer Meta allocation - hosts whatsapp-chatd-edge (the chat/messaging channel)
    "66.220.144.0/20"
    "69.63.176.0/20"
    "69.171.224.0/19"
    "74.119.76.0/22"
    "102.132.96.0/20"
    "129.134.0.0/17"
    "157.240.0.0/16"
    "163.70.128.0/17"
    "173.252.64.0/18"
    "179.60.192.0/22"
    "185.60.216.0/22"
    "185.89.218.0/23"
    "204.15.20.0/22"
)

declare -a WHATSAPP_IPS_V6=()
declare -a WHATSAPP_META_IPS_V6=(
    "2620:0:1c00::/40"
    "2a03:2880::/32"
)

is_valid_ipv4() {
    local ip="$1"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]
}

is_valid_mac() {
    [[ "${1:-}" =~ ^([0-9a-f]{2}:){5}[0-9a-f]{2}$ ]]
}

is_known_app() {
    local app="$1"
    [[ " telegram whatsapp signal tor messenger facebook snapchat wechat viber imessage discord line " =~ " $app " ]]
}

# Signal IP ranges (limited, uses shared infrastructure)
declare -a SIGNAL_IPS=(
    "13.248.212.0/24"
    "76.223.92.0/24"
)

# Facebook Messenger (Meta ranges - may affect Facebook/Instagram)
declare -a MESSENGER_IPS=(
    "157.240.0.0/16"
    "31.13.0.0/16"
    "129.134.0.0/16"
    "179.60.192.0/22"
    "185.60.216.0/22"
    "66.220.144.0/20"
    "69.63.176.0/20"
    "69.171.224.0/19"
    "74.119.76.0/22"
    "102.132.96.0/20"
)

# Facebook shares every Meta edge range with other apps. Keep this empty so
# TCP enforcement remains hostname-specific instead of blocking all of Meta.
declare -a FACEBOOK_IPS=()

# Snapchat (uses Google infrastructure)
declare -a SNAPCHAT_IPS=(
    "64.233.160.0/19"
    "216.58.192.0/19"
)

# WeChat (Tencent)
declare -a WECHAT_IPS=(
    "101.32.0.0/16"
    "109.244.0.0/16"
    "203.205.0.0/16"
)

# Viber (AWS)
declare -a VIBER_IPS=(
    "54.72.0.0/13"
)

# iMessage (no reliable IP ranges; use ports only)
declare -a IMESSAGE_IPS=()

# Discord (limited ranges; may require extra IPs)
declare -a DISCORD_IPS=(
    "66.22.196.0/22"
)

# Line (LINE Corp)
declare -a LINE_IPS=(
    "147.92.0.0/16"
    "203.104.128.0/19"
)

declare -a MESSENGER_IPS_V6=()
declare -a FACEBOOK_IPS_V6=()
declare -a SNAPCHAT_IPS_V6=()
declare -a WECHAT_IPS_V6=()
declare -a VIBER_IPS_V6=()
declare -a IMESSAGE_IPS_V6=()
declare -a DISCORD_IPS_V6=()
declare -a LINE_IPS_V6=()

# Ports per app (proto:port)
declare -A APP_PORTS=(
    ["telegram"]="tcp:443 tcp:80 tcp:5222 udp:443"
    ["whatsapp"]="tcp:443 tcp:5222 tcp:5223 udp:3478 udp:19302"
    ["signal"]="tcp:443 udp:3478 udp:10000"
    ["tor"]="tcp:9001 tcp:9030 tcp:9050 tcp:9051 tcp:9150"
    ["imessage"]="tcp:5223 tcp:5228 tcp:5229 tcp:5230"
)

# SNI domains for TLS-based blocking (more precise than IP blocking)
# This allows blocking WhatsApp without affecting Facebook/Instagram
declare -A APP_SNI_DOMAINS=(
    ["whatsapp"]="whatsapp.net whatsapp.com wa.me"
    ["telegram"]="telegram.org t.me telegram.me"
    ["signal"]="signal.org whispersystems.org"
    ["messenger"]="messenger.com"
    ["facebook"]="facebook.com facebook.net fbcdn.net fbsbx.com fb.com fb.me messenger.com graph.fbpigeon.com"
    ["discord"]="discord.com discord.gg discordapp.com"
    ["snapchat"]="snapchat.com snap.com"
)

# ═══════════════════════════════════════════════════════════════════════════════
# HELPER FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

log_info() {
    echo "[INFO] $*"
}

log_error() {
    echo "[ERROR] $*" >&2
}

log_warn() {
    echo "[WARN] $*" >&2
}

normalize_whatsapp_mode() {
    local mode="${1:-}"
    mode="$(echo "$mode" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
    case "$mode" in
        balanced|aggressive)
            echo "$mode"
            return 0
            ;;
        *)
            return 1
            ;;
    esac
}

get_whatsapp_mode() {
    local mode=""

    if [[ -f "$WHATSAPP_MODE_FILE" ]]; then
        mode="$(head -n 1 "$WHATSAPP_MODE_FILE" 2>/dev/null || true)"
    elif [[ -f "$WHATSAPP_INCLUDE_META_FILE" ]]; then
        # Legacy compatibility: previous builds used this marker to enable Meta ranges.
        mode="aggressive"
    fi

    mode="$(echo "$mode" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')"
    if [[ "$mode" != "balanced" && "$mode" != "aggressive" ]]; then
        mode="balanced"
    fi

    echo "$mode"
}

is_whatsapp_aggressive() {
    [[ "$(get_whatsapp_mode)" == "aggressive" ]]
}

set_whatsapp_mode() {
    local requested_raw="${1:-}"
    local requested=""
    requested="$(normalize_whatsapp_mode "$requested_raw")" || {
        log_error "Invalid WhatsApp mode: '$requested_raw' (expected: balanced|aggressive)"
        return 1
    }

    local mode_tmp
    mode_tmp="$(mktemp "$STATE_DIR/.whatsapp-mode.XXXXXX")"
    printf '%s\n' "$requested" > "$mode_tmp"
    chown root:easypi "$mode_tmp"
    chmod 0640 "$mode_tmp"
    mv -T "$mode_tmp" "$WHATSAPP_MODE_FILE"

    # Keep legacy marker in sync for backward compatibility with older scripts.
    if [[ "$requested" == "aggressive" ]]; then
        install -o root -g easypi -m 0640 /dev/null "$WHATSAPP_INCLUDE_META_FILE"
    else
        rm -f "$WHATSAPP_INCLUDE_META_FILE"
    fi

    log_info "WhatsApp block mode set to: $requested"
}

get_chain_name() {
    # MAC-backed names survive DHCP changes. Keep the legacy IP form for
    # explicit maintenance commands and migration of old installations.
    local identity="$1"
    local app="$2"
    
    # Abbreviate app names
    local app_short
    case "$app" in
        telegram) app_short="tg" ;;
        whatsapp) app_short="wa" ;;
        signal)   app_short="sig" ;;
        tor)      app_short="tor" ;;
        messenger) app_short="msg" ;;
        facebook) app_short="fb" ;;
        snapchat) app_short="snap" ;;
        wechat)   app_short="wc" ;;
        viber)    app_short="vbr" ;;
        imessage) app_short="imsg" ;;
        discord)  app_short="disc" ;;
        line)     app_short="line" ;;
        *)        app_short="${app:0:3}" ;;
    esac
    
    if is_valid_mac "$identity"; then
        echo "EPM_${identity//:/}_${app_short}"
    else
        local ip_short
        ip_short=$(echo "$identity" | awk -F. '{print $3"_"$4}')
        echo "EP_${ip_short}_${app_short}"
    fi
}

# Learn WhatsApp IPs by observing traffic for a short window.
# This only records IPs that fall into known WhatsApp/Meta ranges
# to avoid adding unrelated endpoints (e.g., Google push).
learn_whatsapp_ips() {
    local ip="$1"
    local seconds="${2:-20}"
    if [[ "$seconds" == "all" ]]; then
        seconds=20
    fi
    local extra_file="$DATA_DIR/whatsapp_extra_ips.txt"
    local since
    local log_lines

    if [[ -z "$ip" ]]; then
        log_error "IP address required for 'learn-whatsapp'"
        return 1
    fi

    since=$(date -Is 2>/dev/null || date)

    # Add temporary LOG rules
    for p in 443 5222 5223; do
        iptables -I FORWARD 1 -s "$ip" -p tcp --dport "$p" -m limit --limit 20/min --limit-burst 20 -j LOG --log-prefix "WAIP-TCP$p " 2>/dev/null || true
    done
    for p in 443 3478 19302; do
        iptables -I FORWARD 1 -s "$ip" -p udp --dport "$p" -m limit --limit 20/min --limit-burst 20 -j LOG --log-prefix "WAIP-UDP$p " 2>/dev/null || true
    done

    log_info "Learning WhatsApp IPs for $ip (sleep ${seconds}s)..."
    sleep "$seconds"

    # Collect kernel logs
    if command -v journalctl &>/dev/null; then
        log_lines=$(journalctl -k --since "$since" --no-pager | grep "WAIP-" || true)
    else
        log_lines=$(dmesg | tail -n 500 | grep "WAIP-" || true)
    fi

    # Remove temporary LOG rules
    for p in 443 5222 5223; do
        iptables -D FORWARD -s "$ip" -p tcp --dport "$p" -m limit --limit 20/min --limit-burst 20 -j LOG --log-prefix "WAIP-TCP$p " 2>/dev/null || true
    done
    for p in 443 3478 19302; do
        iptables -D FORWARD -s "$ip" -p udp --dport "$p" -m limit --limit 20/min --limit-burst 20 -j LOG --log-prefix "WAIP-UDP$p " 2>/dev/null || true
    done

    if [[ -z "$log_lines" ]]; then
        log_warn "No WhatsApp traffic captured in logs"
        return 0
    fi

    # Build ranges list for filtering captured IPs.
    # Aggressive mode includes shared Meta ranges; balanced keeps strict ranges.
    local ranges_csv
    if is_whatsapp_aggressive; then
        ranges_csv=$(IFS=,; echo "${WHATSAPP_IPS[*]},${WHATSAPP_META_IPS[*]}")
    else
        ranges_csv=$(IFS=,; echo "${WHATSAPP_IPS[*]}")
    fi

    # Extract DST IPs, filter by known ranges, append /32s
    local learned
    learned=$(RANGES="$ranges_csv" python3 - <<'PY'
import os
import re
import ipaddress
import sys

ranges = [r for r in os.environ.get("RANGES","").split(",") if r]
nets = [ipaddress.ip_network(r, strict=False) for r in ranges]
ips = set()
for line in sys.stdin:
    m = re.search(r"\\bDST=([0-9.]+)\\b", line)
    if not m:
        continue
    ip = ipaddress.ip_address(m.group(1))
    if any(ip in n for n in nets):
        ips.add(str(ip))
for ip in sorted(ips):
    print(ip)
PY
    <<< "$log_lines")

    if [[ -z "$learned" ]]; then
        if is_whatsapp_aggressive; then
            log_warn "No WhatsApp/Meta IPs detected in captured traffic"
        else
            log_warn "No WhatsApp IPs detected in captured traffic"
        fi
        return 0
    fi

    touch "$extra_file"
    local added=0
    while IFS= read -r ip_line; do
        [[ -z "$ip_line" ]] && continue
        local entry="${ip_line}/32"
        if ! grep -qF "$entry" "$extra_file"; then
            echo "$entry" >> "$extra_file"
            ((added++)) || true
        fi
    done <<< "$learned"

    log_info "Learned $added new WhatsApp IPs (saved to $extra_file)"
}

get_ipset_name() {
    local app="$1"
    echo "${IPSET_PREFIX}_${app}"
}

chain_exists() {
    local chain="$1"
    iptables -L "$chain" -n >/dev/null 2>&1
}

chain_exists_v6() {
    local chain="$1"
    ip6tables -L "$chain" -n >/dev/null 2>&1
}

chain_has_rules() {
    local chain="$1"
    iptables -S "$chain" 2>/dev/null | grep -q "^-A "
}

ipset_exists() {
    local name="$1"
    ipset list "$name" >/dev/null 2>&1
}

create_chain_if_needed() {
    local chain="$1"
    if iptables -N "$chain" 2>/dev/null; then
        return 0
    fi
    if chain_exists "$chain"; then
        return 0
    fi
    return 1
}

create_chain_if_needed_v6() {
    local chain="$1"
    if ip6tables -N "$chain" 2>/dev/null; then
        return 0
    fi
    if chain_exists_v6 "$chain"; then
        return 0
    fi
    return 1
}

remove_chain_references() {
    local bin="$1"   # iptables | ip6tables
    local chain="$2"
    local src="${3:-}"
    local table_arg=()

    # Find and delete all OUTPUT/FORWARD jumps to chain (including duplicates)
    for parent in OUTPUT FORWARD; do
        while IFS= read -r rule; do
            [[ -z "$rule" ]] && continue
            # Convert "-A ..." to "-D ..."
            local del_rule
            del_rule="${rule/-A /-D }"
            # shellcheck disable=SC2086
            $bin ${table_arg[*]} $del_rule 2>/dev/null || true
        done < <(
            if [[ -n "$src" ]]; then
                # Middle part is optional: app jumps are simple "-s IP/32 -j CHAIN"
                # (no match conditions), so ".* " alone would never match them.
                $bin -S "$parent" 2>/dev/null | grep -E -- "^-A $parent -s ${src}/32( .*)? -j ${chain}$" || true
            else
                $bin -S "$parent" 2>/dev/null | grep -E -- "-j ${chain}$" || true
            fi
        )
    done
}

ensure_jump_unique() {
    local bin="$1"      # iptables | ip6tables
    local parent="$2"   # OUTPUT | FORWARD
    local src="$3"
    local chain="$4"
    local mac="${5:-}"

    if [[ -n "$mac" ]]; then
        is_valid_mac "$mac" || {
            log_warn "Skipping jump rule with invalid MAC '$mac'"
            return 0
        }
        # Source MAC is available only on forwarded LAN frames, not OUTPUT.
        [[ "$parent" == "FORWARD" ]] || return 0
        while $bin -D "$parent" -m mac --mac-source "$mac" -j "$chain" 2>/dev/null; do :; done
        $bin -I "$parent" 1 -m mac --mac-source "$mac" -j "$chain" 2>/dev/null || {
            log_warn "Failed to insert MAC jump ($bin $parent $mac -> $chain)"
        }
        return 0
    fi

    # Guard against malformed source values from data files.
    if [[ -z "$src" ]]; then
        log_warn "Skipping jump rule with empty source ($bin $parent -> $chain)"
        return 0
    fi
    if [[ "$bin" == "iptables" ]]; then
        if ! is_valid_ipv4 "$src"; then
            log_warn "Skipping invalid IPv4 source '$src' ($bin $parent -> $chain)"
            return 0
        fi
    elif [[ "$src" != *:* ]]; then
        log_warn "Skipping invalid IPv6 source '$src' ($bin $parent -> $chain)"
        return 0
    fi

    # Remove all duplicates first
    while $bin -D "$parent" -s "$src" -j "$chain" 2>/dev/null; do :; done
    # Insert one deterministic rule at top
    $bin -I "$parent" 1 -s "$src" -j "$chain" 2>/dev/null || {
        log_warn "Failed to insert jump ($bin $parent -s $src -j $chain)"
        return 0
    }
}

ensure_tor_ipset() {
    if ! ipset_exists "$TOR_IPSET"; then
        ipset create "$TOR_IPSET" hash:ip hashsize 4096 maxelem 65536
        log_info "Created Tor IP set: $TOR_IPSET"
    fi
}

update_tor_list() {
    log_info "Refreshing Tor policy from the authenticated feed..."
    if [[ -x "$TOR_FEED_UPDATER" ]]; then
        "$TOR_FEED_UPDATER" update || log_warn \
            "Signed Tor feed unavailable or rejected; keeping the last known-good policy"
    else
        log_warn "Signed Tor feed updater is unavailable; keeping cached policy"
    fi

    [[ -f "$TOR_LIST_FILE" && ! -L "$TOR_LIST_FILE" ]] || {
        log_warn "No authenticated Tor policy is available"
        return 0
    }

    local staged_set="easypi_tor_stage"
    ipset destroy "$staged_set" 2>/dev/null || true
    ipset create "$staged_set" hash:ip hashsize 4096 maxelem 65536 || return 1
    local count=0
    local ip
    while IFS= read -r ip; do
        if [[ $ip =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
            ipset add "$staged_set" "$ip" 2>/dev/null && ((count++)) || true
        fi
    done < "$TOR_LIST_FILE"
    if (( count < 1000 )); then
        ipset destroy "$staged_set" 2>/dev/null || true
        log_error "Authenticated Tor policy is unexpectedly small; active ipset unchanged"
        return 1
    fi

    ensure_tor_ipset
    ipset swap "$staged_set" "$TOR_IPSET" || {
        ipset destroy "$staged_set" 2>/dev/null || true
        log_error "Failed to activate staged Tor policy"
        return 1
    }
    ipset destroy "$staged_set" 2>/dev/null || true
    log_info "Atomically loaded $count authenticated Tor relay nodes"
}

# ═══════════════════════════════════════════════════════════════════════════════
# IPSET MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════════

ensure_ipset() {
    local app="$1"
    local force_refresh="${2:-0}"
    local ipset_name
    local ip  # local so the populate read-loops below do not clobber the caller's client IP
    ipset_name=$(get_ipset_name "$app")
    
    if ipset_exists "$ipset_name"; then
        local existing_count
        existing_count=$(ipset list "$ipset_name" 2>/dev/null | grep -c "^[0-9]" || echo "0")
        if [[ "$existing_count" -gt 0 && "$force_refresh" != "1" ]]; then
            return 0
        fi
        ipset flush "$ipset_name" 2>/dev/null || true
    else
        # Create ipset for IPv4
        ipset create "$ipset_name" hash:net hashsize 1024 maxelem 8192
        log_info "Created ipset: $ipset_name"
    fi
    
    # Populate based on app
    local -n ip_array="${app^^}_IPS"
    for ip_range in "${ip_array[@]}"; do
        ipset add "$ipset_name" "$ip_range" 2>/dev/null || true
    done

    if [[ "$app" == "whatsapp" ]]; then
        if is_whatsapp_aggressive; then
            for ip_range in "${WHATSAPP_META_IPS[@]}"; do
                ipset add "$ipset_name" "$ip_range" 2>/dev/null || true
            done
        fi
        if [[ -f "$WHATSAPP_EXTRA_IPS_FILE" ]]; then
            while IFS= read -r ip; do
                ip=$(echo "$ip" | tr -d '[:space:]')
                [[ -z "$ip" || "$ip" =~ ^# ]] && continue
                if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
                    ipset add "$ipset_name" "$ip" 2>/dev/null || true
                fi
            done < "$WHATSAPP_EXTRA_IPS_FILE"
        fi
    fi

    local extra_file="$DATA_DIR/${app}_extra_ips.txt"
    if [[ -f "$extra_file" ]]; then
        while IFS= read -r ip; do
            ip=$(echo "$ip" | tr -d '[:space:]')
            [[ -z "$ip" || "$ip" =~ ^# ]] && continue
            if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
                ipset add "$ipset_name" "$ip" 2>/dev/null || true
            fi
        done < "$extra_file"
    fi

    local dynamic_file="$DATA_DIR/${app}_dynamic_ips.txt"
    if [[ -f "$dynamic_file" ]]; then
        while IFS= read -r ip; do
            ip=$(echo "$ip" | tr -d '[:space:]')
            [[ -z "$ip" || "$ip" =~ ^# ]] && continue
            if [[ "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(/[0-9]+)?$ ]]; then
                ipset add "$ipset_name" "$ip" 2>/dev/null || true
            fi
        done < "$dynamic_file"
    fi
    
    local count
    count=$(ipset list "$ipset_name" 2>/dev/null | grep -c "^[0-9]" || echo "0")
    log_info "Populated $ipset_name with $count entries"
}

ensure_ipset_v6() {
    local app="$1"
    local force_refresh="${2:-0}"
    local ipset_name
    local ip  # local so the populate read-loops below do not clobber the caller's client IP
    ipset_name=$(get_ipset_name "${app}_v6")
    
    if ipset_exists "$ipset_name"; then
        if [[ "$force_refresh" != "1" ]]; then
            return 0
        fi
        ipset flush "$ipset_name" 2>/dev/null || true
    else
        # Create ipset for IPv6
        ipset create "$ipset_name" hash:net family inet6 hashsize 1024 maxelem 8192
    fi
    
    # Populate based on app
    local -n ip_array="${app^^}_IPS_V6"
    for ip_range in "${ip_array[@]}"; do
        ipset add "$ipset_name" "$ip_range" 2>/dev/null || true
    done

    if [[ "$app" == "whatsapp" ]]; then
        if is_whatsapp_aggressive; then
            for ip_range in "${WHATSAPP_META_IPS_V6[@]}"; do
                ipset add "$ipset_name" "$ip_range" 2>/dev/null || true
            done
        fi
        if [[ -f "$WHATSAPP_EXTRA_IPS_FILE" ]]; then
            while IFS= read -r ip; do
                ip=$(echo "$ip" | tr -d '[:space:]')
                [[ -z "$ip" || "$ip" =~ ^# ]] && continue
                if [[ "$ip" =~ : ]]; then
                    ipset add "$ipset_name" "$ip" 2>/dev/null || true
                fi
            done < "$WHATSAPP_EXTRA_IPS_FILE"
        fi
    fi

    local extra_file="$DATA_DIR/${app}_extra_ips.txt"
    if [[ -f "$extra_file" ]]; then
        while IFS= read -r ip; do
            ip=$(echo "$ip" | tr -d '[:space:]')
            [[ -z "$ip" || "$ip" =~ ^# ]] && continue
            if [[ "$ip" =~ : ]]; then
                ipset add "$ipset_name" "$ip" 2>/dev/null || true
            fi
        done < "$extra_file"
    fi

    local dynamic_file="$DATA_DIR/${app}_dynamic_ips_v6.txt"
    if [[ -f "$dynamic_file" ]]; then
        while IFS= read -r ip; do
            ip=$(echo "$ip" | tr -d '[:space:]')
            [[ -z "$ip" || "$ip" =~ ^# ]] && continue
            if [[ "$ip" =~ : ]]; then
                ipset add "$ipset_name" "$ip" 2>/dev/null || true
            fi
        done < "$dynamic_file"
    fi
}

update_whatsapp_dynamic_lists() {
    log_info "Updating WhatsApp dynamic IPs via DNS resolution..."

    local hosts_file="$DATA_DIR/whatsapp_hosts.txt"
    if [[ ! -f "$hosts_file" ]]; then
        local default_hosts
        default_hosts="$(mktemp "$RUNTIME_DIR/whatsapp-hosts.XXXXXX")"
        cat > "$default_hosts" <<'HOSTS'
web.whatsapp.com
whatsapp.com
mmg.whatsapp.net
media.whatsapp.net
cdn.whatsapp.net
HOSTS
        publish_data_file "$default_hosts" "$hosts_file"
        rm -f "$default_hosts"
    fi

    local out4_tmp out6_tmp
    out4_tmp="$(mktemp "$RUNTIME_DIR/whatsapp-v4.XXXXXX")"
    out6_tmp="$(mktemp "$RUNTIME_DIR/whatsapp-v6.XXXXXX")"

    if ! python3 - "$hosts_file" "$out4_tmp" "$out6_tmp" <<'PY'; then
import ipaddress
import re
import socket
import sys
from pathlib import Path

hosts_path = Path(sys.argv[1])
out4 = Path(sys.argv[2])
out6 = Path(sys.argv[3])

hosts = []
for line in hosts_path.read_text(encoding='utf-8').splitlines():
    line = line.strip()
    if not line or line.startswith('#'):
        continue
    if len(hosts) >= 32:
        break
    if len(line) > 253 or not re.fullmatch(
        r"(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?",
        line,
    ):
        continue
    hosts.append(line)

ips4 = set()
ips6 = set()
for host in hosts:
    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    except OSError:
        continue
    for info in infos:
        ip = info[4][0]
        try:
            addr = ipaddress.ip_address(ip)
        except ValueError:
            continue
        if not addr.is_global or len(ips4) + len(ips6) >= 512:
            continue
        if addr.version == 4:
            ips4.add(f"{addr}/32")
        else:
            ips6.add(f"{addr}/128")

out4.write_text("\n".join(sorted(ips4)) + ("\n" if ips4 else ""), encoding='utf-8')
out6.write_text("\n".join(sorted(ips6)) + ("\n" if ips6 else ""), encoding='utf-8')
PY
        log_warn "WhatsApp DNS refresh failed, keeping previous dynamic lists"
        rm -f "$out4_tmp" "$out6_tmp"
        return 1
    fi

    publish_data_file "$out4_tmp" "$WHATSAPP_DYNAMIC_IPS_FILE"
    publish_data_file "$out6_tmp" "$WHATSAPP_DYNAMIC_IPS_V6_FILE"
    rm -f "$out4_tmp" "$out6_tmp"

    local c4 c6
    c4=$(grep -c "^[0-9]" "$WHATSAPP_DYNAMIC_IPS_FILE" 2>/dev/null || echo 0)
    c6=$(grep -c ":" "$WHATSAPP_DYNAMIC_IPS_V6_FILE" 2>/dev/null || echo 0)
    log_info "Updated WhatsApp dynamic IPs: IPv4=$c4 IPv6=$c6"
}

# ═══════════════════════════════════════════════════════════════════════════════
# SNI-BASED BLOCKING (TLS domain filtering)
# ═══════════════════════════════════════════════════════════════════════════════

# Add SNI-based blocking rules for an app
# This blocks TLS connections based on Server Name Indication (domain name)
# More precise than IP blocking - won't affect other services on same IP
add_sni_blocking() {
    local chain="$1"
    local app="$2"
    
    local sni_domains="${APP_SNI_DOMAINS[$app]}"
    if [[ -z "$sni_domains" ]]; then
        return 0
    fi
    
    local count=0
    for domain in $sni_domains; do
        # Block TLS connections with this domain in SNI
        # Using string match on raw packet - matches SNI in TLS ClientHello
        iptables -A "$chain" -p tcp --dport 443 -m string --string "$domain" --algo bm -j REJECT --reject-with icmp-port-unreachable 2>/dev/null && ((count++)) || true
        
        # Also block QUIC (UDP 443) with same domain
        iptables -A "$chain" -p udp --dport 443 -m string --string "$domain" --algo bm -j REJECT --reject-with icmp-port-unreachable 2>/dev/null || true
    done
    
    if [[ $count -gt 0 ]]; then
        log_info "Added SNI blocking for $app ($count domains: $sni_domains)"
    fi
}

# Prism DPI: inline in-kernel drop of an app's first-packet signature.
# Enforcement is a firewall rule, not a process — Prism emits the u32 match from
# its signature registry and the kernel drops the app's first packet before it is
# forwarded. No-op for apps without a signature. See /opt/EasyPi/prism_dpi/README.md.
add_prism_signature_block() {
    local chain="$1" app="$2"
    local prism_out matcher port arg1 arg2 count=0
    modprobe xt_u32 2>/dev/null || true
    prism_out=$(cd /opt/EasyPi 2>/dev/null && PYTHONPATH=/opt/EasyPi python3 -m prism_dpi.rule "$app" 2>/dev/null) || return 0
    [[ -z "$prism_out" ]] && return 0
    while IFS=$'\t' read -r matcher port arg1 arg2; do
        [[ "$port" =~ ^[0-9]{1,5}$ ]] || continue
        case "$matcher" in
            u32)
                [[ -n "$arg1" ]] || continue
                if iptables -I "$chain" 1 -p tcp --dport "$port" -m u32 --u32 "$arg1" -j DROP 2>/dev/null; then
                    ((count++)) || true
                fi
                ;;
            strings)
                [[ -n "$arg1" && -n "$arg2" ]] || continue
                if iptables -I "$chain" 1 -p tcp --dport "$port" \
                    -m string --string "$arg1" --algo bm \
                    -m string --string "$arg2" --algo bm -j DROP 2>/dev/null; then
                    ((count++)) || true
                fi
                ;;
        esac
    done <<< "$prism_out"
    [[ $count -gt 0 ]] && log_info "Prism: inline signature drop for $app ($count rule(s))"
    return 0
}

# Check if SNI blocking should be used instead of IP blocking.
# - balanced: precise SNI for WhatsApp/Messenger (lower collateral impact)
# - aggressive: full IP blocking for WhatsApp (includes shared Meta ranges)
use_sni_blocking() {
    local app="$1"
    
    # Use SNI blocking for apps that share infrastructure with others
    case "$app" in
        whatsapp)
            # Always use the SNI path for WhatsApp. It layers SNI (hostname match) +
            # a dedicated QUIC/UDP-443 block + the WhatsApp IP set. In aggressive mode
            # ensure_ipset() additionally loads the broad Meta ranges, so
            # aggressive = balanced + Meta IPs (strictly stronger). The old aggressive
            # path was IP-set-only (no SNI, no QUIC block) and leaked WhatsApp over
            # TCP 443 to Meta edge IPs (edge-dgw-shv-*.facebook.com) not in the set.
            return 0
            ;;
        messenger)
            # Messenger also uses Meta infrastructure
            return 0
            ;;
        facebook)
            # Facebook shares Meta IPs with Instagram, Messenger, and WhatsApp.
            return 0
            ;;
        *)
            # Other apps have dedicated IPs, use IP blocking
            return 1
            ;;
    esac
}

# ═══════════════════════════════════════════════════════════════════════════════
reset_preexisting_app_sessions() {
    local ip="$1"
    local app="$2"
    local port

    [[ "$app" == "whatsapp" || "$app" == "facebook" ]] || return 0
    if [[ ! -x /usr/sbin/conntrack ]]; then
        log_warn "conntrack is unavailable; existing $app sessions may remain active"
        return 0
    fi

    if [[ "$app" == "facebook" ]]; then
        local range
        # Mark only established TCP sessions to shared Meta destinations. The
        # per-device Facebook chain resets those sockets without touching other
        # providers. Remove Meta QUIC state so the new UDP policy applies now.
        for range in "${WHATSAPP_META_IPS[@]}"; do
            /usr/sbin/conntrack -U -f ipv4 -s "$ip" -d "$range" \
                -p tcp --dport 443 \
                --mark "$FACEBOOK_STALE_CONNMARK/$FACEBOOK_STALE_CONNMARK_MASK" \
                >/dev/null 2>&1 || true
            /usr/sbin/conntrack -D -f ipv4 -s "$ip" -d "$range" \
                -p udp --dport 443 >/dev/null 2>&1 || true
        done
        log_info "Reset pre-existing Facebook sessions for $ip"
        return 0
    fi

    # Keep the conntrack entry long enough for REJECT --tcp-reset to terminate
    # the real socket. Deleting a loose TCP entry alone lets the next packet
    # recreate it without forcing a new application handshake.
    for port in 80 443 5222 5223; do
        /usr/sbin/conntrack -U -f ipv4 -s "$ip" -p tcp --dport "$port" \
            --mark "$WHATSAPP_STALE_CONNMARK/$WHATSAPP_STALE_CONNMARK_MASK" \
            >/dev/null 2>&1 || true
    done
    for port in 443 3478 19302; do
        /usr/sbin/conntrack -D -f ipv4 -s "$ip" -p udp --dport "$port" >/dev/null 2>&1 || true
    done

    log_info "Reset pre-existing encrypted sessions for $ip after enabling WhatsApp blocking"
}

# BLOCKING FUNCTIONS
# ═══════════════════════════════════════════════════════════════════════════════

setup_app_blocking() {
    local ip="$1"
    local apps="$2"
    local mac="${3:-}"
    local identity="$ip"
    if [[ -n "$mac" ]]; then
        is_valid_mac "$mac" || { log_error "Invalid MAC address: $mac"; return 1; }
        identity="$mac"
    fi
    
    IFS=',' read -ra APP_LIST <<< "$apps"
    
    for app in "${APP_LIST[@]}"; do
        app=$(echo "$app" | tr '[:upper:]' '[:lower:]' | tr -d ' ')
        
        # Skip if not a known app
        if [[ ! " telegram whatsapp signal tor messenger facebook snapchat wechat viber imessage discord line " =~ " $app " ]]; then
            log_error "Unknown app: $app"
            continue
        fi
        
        local chain
        chain=$(get_chain_name "$identity" "$app")
        
        # Skip if already exists and has rules; otherwise reuse empty chain
        local chain_ready=0
        if chain_exists "$chain"; then
            if chain_has_rules "$chain"; then
                ensure_jump_unique iptables OUTPUT "$ip" "$chain" "$mac"
                ensure_jump_unique iptables FORWARD "$ip" "$chain" "$mac"
                log_info "Blocking already active for $ip -> $app"
                continue
            fi
            # Chain exists but empty (likely referenced by jump rules) - reuse it
            iptables -F "$chain" 2>/dev/null || true
            chain_ready=1
        fi

        # Special handling for Tor (dynamic exit nodes + ports)
        if [[ "$app" == "tor" ]]; then
            update_tor_list

            # Create chain if needed
            if [[ "$chain_ready" -eq 0 ]]; then
                if ! create_chain_if_needed "$chain"; then
                    log_error "Failed to create chain $chain"
                    continue
                fi
            fi

            # Block Tor exit nodes (ipset)
            if ipset_exists "$TOR_IPSET"; then
                local tor_count
                tor_count=$(ipset list "$TOR_IPSET" 2>/dev/null | grep -c "^[0-9]" || echo "0")
                if [[ "$tor_count" -gt 0 ]]; then
                    iptables -A "$chain" -m set --match-set "$TOR_IPSET" dst -j REJECT --reject-with icmp-host-unreachable
                    log_info "Added Tor ipset rule ($tor_count nodes)"
                fi
            fi

            # Block Tor ports
            for port_spec in ${APP_PORTS[tor]}; do
                local proto="${port_spec%%:*}"
                local port="${port_spec##*:}"
                iptables -A "$chain" -p "$proto" --dport "$port" -j REJECT --reject-with icmp-port-unreachable
            done

            # Insert jump rules (idempotent; no duplicates)
            ensure_jump_unique iptables OUTPUT "$ip" "$chain" "$mac"
            ensure_jump_unique iptables FORWARD "$ip" "$chain" "$mac"

            log_info "✓ App blocking enabled: $ip -> $app"
            continue
        fi
        
        # Create chain first (if not already present)
        if [[ "$chain_ready" -eq 0 ]]; then
            if ! create_chain_if_needed "$chain"; then
                log_error "Failed to create chain $chain"
                continue
            fi
        fi

        # Prism DPI: inline in-kernel u32 drop of the app's first-packet signature
        # (no daemon; see /opt/EasyPi/prism_dpi/README.md). No-op for apps without one.
        add_prism_signature_block "$chain" "$app"

        if [[ "$app" == "whatsapp" ]]; then
            iptables -I "$chain" 1 -p tcp \
                -m connmark --mark "$WHATSAPP_STALE_CONNMARK/$WHATSAPP_STALE_CONNMARK_MASK" \
                -j REJECT --reject-with tcp-reset
        fi
        if [[ "$app" == "facebook" ]]; then
            iptables -I "$chain" 1 -p tcp \
                -m connmark --mark "$FACEBOOK_STALE_CONNMARK/$FACEBOOK_STALE_CONNMARK_MASK" \
                -j REJECT --reject-with tcp-reset
        fi

        # Use SNI for apps that share infrastructure with other Meta products.
        if use_sni_blocking "$app"; then
            # Add SNI-based blocking (blocks by TLS domain name)
            add_sni_blocking "$chain" "$app"
            
            # Facebook has no exclusive IP ranges. Other SNI-mode apps retain
            # their dedicated ranges as a second layer.
            if [[ "$app" != "facebook" ]]; then
                ensure_ipset "$app"
                local ipset_name
                ipset_name=$(get_ipset_name "$app")
                local ipset_count
                ipset_count=$(ipset list "$ipset_name" 2>/dev/null | grep -c "^[0-9]" || true)

                if [[ "${ipset_count:-0}" -gt 0 ]]; then
                    iptables -A "$chain" -m set --match-set "$ipset_name" dst -j REJECT --reject-with icmp-host-unreachable
                    log_info "Added ipset rule for $app ($ipset_count ranges)"
                fi
            fi
            
            # CRITICAL: Block QUIC (UDP 443) to Meta IP ranges
            # WhatsApp uses QUIC by default to Meta IPs, Facebook/Instagram use TCP
            # This blocks WhatsApp QUIC connections without affecting Facebook/Instagram HTTPS
            if [[ "$app" == "whatsapp" ]]; then
                # Create temporary ipset for Meta QUIC blocking
                local quic_ipset="easypi_wa_quic"
                ipset create "$quic_ipset" hash:net 2>/dev/null || ipset flush "$quic_ipset" 2>/dev/null || true
                
                # Add Meta IP ranges where WhatsApp uses QUIC
                # These ranges are also used by Facebook/Instagram but only WhatsApp uses QUIC heavily
                local meta_quic_ranges=(
                    "31.13.64.0/18"      # Meta main
                    "102.132.96.0/20"    # Meta Africa
                    "129.134.0.0/17"     # Meta
                    "157.240.0.0/16"     # Meta
                    "163.70.128.0/17"    # Meta
                    "179.60.192.0/22"    # Meta Latin America
                    "185.60.216.0/22"    # Meta Europe
                    "204.15.20.0/22"     # Meta
                )
                for range in "${meta_quic_ranges[@]}"; do
                    ipset add "$quic_ipset" "$range" 2>/dev/null || true
                done
                
                # Block only QUIC (UDP 443) to Meta IPs - leaves TCP 443 for FB/IG
                iptables -A "$chain" -p udp --dport 443 -m set --match-set "$quic_ipset" dst -j REJECT --reject-with icmp-port-unreachable
                log_info "Added QUIC blocking for WhatsApp (Meta IPs, UDP 443 only)"
            fi
            if [[ "$app" == "facebook" ]]; then
                local quic_ipset="easypi_fb_quic"
                ipset create "$quic_ipset" hash:net 2>/dev/null || ipset flush "$quic_ipset" 2>/dev/null || true
                for range in "${WHATSAPP_META_IPS[@]}"; do
                    ipset add "$quic_ipset" "$range" 2>/dev/null || true
                done
                # QUIC Initial is not consistently identifiable on every Meta
                # edge. Force only Meta UDP/443 to TCP, where Facebook SNI is
                # visible; TCP for other Meta products remains allowed.
                iptables -A "$chain" -p udp --dport 443 \
                    -m set --match-set "$quic_ipset" dst \
                    -j REJECT --reject-with icmp-port-unreachable
                log_info "Added Facebook Meta QUIC fallback rule"
            fi
            
            # Block WhatsApp ports (XMPP, STUN)
            local ports="${APP_PORTS[$app]}"
            if [[ -n "$ports" ]]; then
                for port_spec in $ports; do
                    local proto="${port_spec%%:*}"
                    local port="${port_spec##*:}"
                    if [[ "$port" != "443" && "$port" != "80" ]]; then
                        iptables -A "$chain" -p "$proto" --dport "$port" -j REJECT --reject-with icmp-port-unreachable
                    fi
                done
            fi
            
            # Insert jump rules (idempotent; no duplicates)
            ensure_jump_unique iptables OUTPUT "$ip" "$chain" "$mac"
            ensure_jump_unique iptables FORWARD "$ip" "$chain" "$mac"
            reset_preexisting_app_sessions "$ip" "$app"
            
            log_info "✓ App blocking enabled (SNI mode): $ip -> $app"
            continue
        fi
        
        # Standard IP-based blocking for other apps
        ensure_ipset "$app"
        ensure_ipset_v6 "$app" 2>/dev/null || true
        
        # Block by IP ranges (using ipset for efficiency)
        local ipset_name
        ipset_name=$(get_ipset_name "$app")
        local ipset_count
        ipset_count=$(ipset list "$ipset_name" 2>/dev/null | grep -c "^[0-9]" || echo "0")
        
        if [[ "$ipset_count" -gt 0 ]]; then
            iptables -A "$chain" -m set --match-set "$ipset_name" dst -j REJECT --reject-with icmp-host-unreachable
            log_info "Added ipset rule for $app ($ipset_count ranges)"
        fi
        
        # Block by ports (as additional layer)
        local ports="${APP_PORTS[$app]}"
        if [[ -n "$ports" ]]; then
            for port_spec in $ports; do
                local proto="${port_spec%%:*}"
                local port="${port_spec##*:}"
                
                # Only block specific ports if they're non-standard
                # Don't block 443/80 by port alone as it would break everything
                if [[ "$port" != "443" && "$port" != "80" ]]; then
                    iptables -A "$chain" -p "$proto" --dport "$port" -j REJECT --reject-with icmp-port-unreachable
                fi
            done
        fi
        
        # Insert jump rules (idempotent; no duplicates)
        ensure_jump_unique iptables OUTPUT "$ip" "$chain" "$mac"
        ensure_jump_unique iptables FORWARD "$ip" "$chain" "$mac"
        
        log_info "✓ App blocking enabled: $ip -> $app"
    done
    
    # Also setup IPv6 if ip6tables available
    if command -v ip6tables &>/dev/null; then
        setup_app_blocking_v6 "$ip" "$apps" "$mac" 2>/dev/null || true
    fi
}

setup_app_blocking_v6() {
    local ip="$1"
    local apps="$2"
    local mac="${3:-}"
    local identity="$ip"
    [[ -n "$mac" ]] && identity="$mac"
    
    # For IPv6, we need the IPv6 address of the device
    # This is typically derived from MAC or configured separately
    # For now, skip if client_ip is IPv4
    if [[ -z "$mac" && "$ip" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        return 0
    fi
    
    IFS=',' read -ra APP_LIST <<< "$apps"
    
    for app in "${APP_LIST[@]}"; do
        app=$(echo "$app" | tr '[:upper:]' '[:lower:]' | tr -d ' ')
        
        local chain
        chain="$(get_chain_name "$identity" "$app")6"
        
        if chain_exists_v6 "$chain" && ip6tables -S "$chain" 2>/dev/null | grep -q "^-A "; then
            # Ensure source jump exists exactly once, even for existing chain
            ensure_jump_unique ip6tables OUTPUT "$ip" "$chain" "$mac"
            ensure_jump_unique ip6tables FORWARD "$ip" "$chain" "$mac"
            continue
        fi
        
        local ipset_name
        ipset_name=$(get_ipset_name "${app}_v6")
        
        if ! ipset_exists "$ipset_name"; then
            continue
        fi
        
        create_chain_if_needed_v6 "$chain" || continue
        ip6tables -F "$chain" 2>/dev/null || true
        ip6tables -A "$chain" -m set --match-set "$ipset_name" dst -j REJECT
        ensure_jump_unique ip6tables OUTPUT "$ip" "$chain" "$mac"
        ensure_jump_unique ip6tables FORWARD "$ip" "$chain" "$mac"
    done
}

remove_app_blocking() {
    local ip="$1"
    local apps="$2"
    local mac="${3:-}"
    local identity="$ip"
    [[ -n "$mac" ]] && identity="$mac"
    
    if [[ "$apps" == "all" ]]; then
        APP_LIST=("telegram" "whatsapp" "signal" "tor" "messenger" "facebook" "snapchat" "wechat" "viber" "imessage" "discord" "line")
    else
        IFS=',' read -ra APP_LIST <<< "$apps"
    fi
    
    for app in "${APP_LIST[@]}"; do
        app=$(echo "$app" | tr '[:upper:]' '[:lower:]' | tr -d ' ')
        
        local chain
        chain=$(get_chain_name "$identity" "$app")
        
        if ! chain_exists "$chain"; then
            continue
        fi
        
        # Remove all jump rules (including duplicates)
        remove_chain_references iptables "$chain" "$ip"
        
        # Flush and delete chain
        iptables -F "$chain" 2>/dev/null || true
        iptables -X "$chain" 2>/dev/null || true
        
        log_info "✓ App blocking removed: $ip -> $app"
    done
    
    # Also remove IPv6 rules
    if command -v ip6tables &>/dev/null; then
        for app in "${APP_LIST[@]}"; do
            local chain
            chain="$(get_chain_name "$identity" "$app")6"
            remove_chain_references ip6tables "$chain" "$ip"
            ip6tables -F "$chain" 2>/dev/null || true
            ip6tables -X "$chain" 2>/dev/null || true
        done
    fi
}

get_status() {
    local ip="$1"
    local mac="${2:-}"
    local identity="$ip"
    [[ -n "$mac" ]] && identity="$mac"
    local active_apps=()
    
    for app in telegram whatsapp signal tor messenger facebook snapchat wechat viber imessage discord line; do
        local chain
        chain=$(get_chain_name "$identity" "$app")
        
        if chain_exists "$chain"; then
            active_apps+=("$app")
        fi
    done
    
    if [[ ${#active_apps[@]} -gt 0 ]]; then
        local joined
        joined=$(printf '"%s",' "${active_apps[@]}")
        joined=${joined%,}
        echo "{\"active\": true, \"apps\": [${joined}]}"
    else
        echo "{\"active\": false, \"apps\": []}"
    fi
}

sync_from_devices() {
    local devices_file="$DATA_DIR/devices.json"
    
    if [[ ! -f "$devices_file" ]]; then
        log_info "No devices.json found"
        return 0
    fi
    
    log_info "Syncing app blocking from devices.json..."
    
    # Get devices with blocked apps
    local tmp_err
    local tmp_ips
    tmp_err="$(mktemp "$RUNTIME_DIR/device-errors.XXXXXX")"
    tmp_ips="$(mktemp "$RUNTIME_DIR/device-ips.XXXXXX")"
    if ! /usr/sbin/runuser -u easypi -- /usr/bin/python3 - "$devices_file" >"$tmp_ips" 2>"$tmp_err" <<'PY'; then
import ipaddress
import json
import sys

devices_file = sys.argv[1]
try:
    with open(devices_file) as f:
        devices = json.load(f)
    for device in devices:
        if not device.get("enabled", True):
            continue
        blocked_services = device.get("blocked_services", [])
        blocked_apps = device.get("blocked_apps", [])  # New field for IP-based blocking
        device_ip = device.get("ip", "")
        device_mac = str(device.get("mac") or "").strip().lower()

        all_blocked = set(blocked_apps)

        ip_block_services = {
            "telegram",
            "whatsapp",
            "signal",
            "tor",
            "messenger",
            "facebook",
            "snapchat",
            "wechat",
            "viber",
            "imessage",
            "discord",
            "line",
        }
        for svc in blocked_services:
            svc_lower = str(svc).lower()
            if svc_lower.endswith("_ip"):
                svc_lower = svc_lower[:-3]
            if svc_lower == "messaging":
                all_blocked.update(ip_block_services - {"facebook"})
                continue
            if svc_lower in ip_block_services:
                all_blocked.add(svc_lower)

        if not all_blocked or not device_ip or not device_mac:
            continue
        try:
            ip_obj = ipaddress.ip_address(device_ip)
        except ValueError:
            continue
        if ip_obj.version != 4:
            continue
        if not __import__("re").fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", device_mac):
            continue
        print(f"{device_ip}\t{device_mac}\t{','.join(sorted(all_blocked))}")
except Exception as e:
    sys.stderr.write(f"Error: {e}\n")
    sys.exit(1)
PY
        local err
        err="$(head -n 1 "$tmp_err" 2>/dev/null || true)"
        rm -f "$tmp_err" "$tmp_ips"
        log_error "Failed to parse devices.json${err:+: $err}"
        return 1
    fi
    if [[ -s "$tmp_err" ]]; then
        local err
        err="$(head -n 1 "$tmp_err" 2>/dev/null || true)"
        rm -f "$tmp_err" "$tmp_ips"
        log_error "Failed to parse devices.json${err:+: $err}"
        return 1
    fi
    rm -f "$tmp_err"
    
    declare -A desired_chains desired_ips desired_macs desired_apps
    local ip mac apps app chain
    while IFS=$'\t' read -r ip mac apps; do
        is_valid_ipv4 "$ip" || continue
        is_valid_mac "$mac" || continue
        IFS=',' read -ra app_list <<< "$apps"
        for app in "${app_list[@]}"; do
            app=$(echo "$app" | tr '[:upper:]' '[:lower:]' | tr -d '[:space:]')
            is_known_app "$app" || continue
            chain=$(get_chain_name "$mac" "$app")
            desired_chains["$chain"]=1
            desired_ips["$chain"]="$ip"
            desired_macs["$chain"]="$mac"
            desired_apps["$chain"]="$app"
        done
    done < "$tmp_ips"
    rm -f "$tmp_ips"

    # Remove obsolete MAC chains and every legacy IP-named chain.
    while IFS= read -r chain; do
        [[ -n "$chain" ]] || continue
        if [[ "$chain" =~ ^EP_[0-9] || -z "${desired_chains[$chain]:-}" ]]; then
            remove_chain_references iptables "$chain"
            iptables -F "$chain" 2>/dev/null || true
            iptables -X "$chain" 2>/dev/null || true
            remove_chain_references ip6tables "${chain}6"
            ip6tables -F "${chain}6" 2>/dev/null || true
            ip6tables -X "${chain}6" 2>/dev/null || true
        fi
    done < <(iptables -L -n 2>/dev/null | awk '/^Chain (EP_|EPM_)/ {print $2}')

    for chain in "${!desired_chains[@]}"; do
        setup_app_blocking "${desired_ips[$chain]}" "${desired_apps[$chain]}" "${desired_macs[$chain]}"
    done
    
    log_info "App blocking sync completed"
}

update_ip_lists() {
    log_info "Updating app IP lists from external sources..."
    
    # Telegram ranges are release-pinned. They are updated only through a
    # publisher-signed EasyPi release, never from an unsigned runtime feed that
    # could otherwise inject arbitrary networks into root firewall policy.
    local telegram_file="$DATA_DIR/telegram_ips.txt"
    local telegram_source telegram_v4 telegram_v6
    telegram_source="$(mktemp "$RUNTIME_DIR/telegram-source.XXXXXX")"
    telegram_v4="$(mktemp "$RUNTIME_DIR/telegram-v4.XXXXXX")"
    telegram_v6="$(mktemp "$RUNTIME_DIR/telegram-v6.XXXXXX")"
    printf '%s\n' "${TELEGRAM_IPS[@]}" > "$telegram_v4"
    printf '%s\n' "${TELEGRAM_IPS_V6[@]}" > "$telegram_v6"
    {
        printf '# Release-pinned Telegram IPv4 ranges\n'
        cat "$telegram_v4"
        printf '# Release-pinned Telegram IPv6 ranges\n'
        cat "$telegram_v6"
    } > "$telegram_source"
    publish_data_file "$telegram_source" "$telegram_file"
    publish_data_file "$telegram_v4" "$TELEGRAM_DYNAMIC_IPS_FILE"
    publish_data_file "$telegram_v6" "$TELEGRAM_DYNAMIC_IPS_V6_FILE"
    rm -f "$telegram_source" "$telegram_v4" "$telegram_v6"

    ensure_ipset "telegram" 1
    ensure_ipset_v6 "telegram" 1
    log_info "Installed release-pinned Telegram IPs: IPv4=${#TELEGRAM_IPS[@]} IPv6=${#TELEGRAM_IPS_V6[@]}"

    update_whatsapp_dynamic_lists || true
    ensure_ipset "whatsapp" 1
    ensure_ipset_v6 "whatsapp" 1

    update_tor_list
}

clear_runtime_rules() {
    local bin chain
    local -a chains=()

    # EP_/EPM_ are reserved EasyPi app-policy chains.  Remove only those exact
    # product namespaces and leave all administrator/firewall-manager rules
    # untouched.  Persistent device policy is deliberately preserved so a
    # later reinstall can rebuild it.
    for bin in iptables ip6tables; do
        command -v "$bin" >/dev/null 2>&1 || continue
        chains=()
        while IFS= read -r chain; do
            [[ "$chain" =~ ^(EP_|EPM_)[A-Za-z0-9_]+$ ]] || continue
            chains+=("$chain")
        done < <("$bin" -S 2>/dev/null | awk '$1 == "-N" {print $2}' || true)

        for chain in "${chains[@]}"; do
            remove_chain_references "$bin" "$chain"
        done
        for chain in "${chains[@]}"; do
            "$bin" -F "$chain" 2>/dev/null || true
        done
        for chain in "${chains[@]}"; do
            "$bin" -X "$chain" 2>/dev/null || true
        done
    done

    log_info "EasyPi app-blocking runtime rules cleared"
}

# ═══════════════════════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════════════════════

case "$ACTION" in
    add)
        if [[ -z "$CLIENT_IP" ]]; then
            log_error "IP address required for 'add' action"
            exit 1
        fi
        if [[ -z "$APPS" || "$APPS" == "all" ]]; then
            APPS="telegram,whatsapp,signal,tor,messenger,facebook,snapchat,wechat,viber,imessage,discord,line"
        fi
        setup_app_blocking "$CLIENT_IP" "$APPS" "$CLIENT_MAC"
        ;;
    
    remove)
        if [[ -z "$CLIENT_IP" ]]; then
            log_error "IP address required for 'remove' action"
            exit 1
        fi
        remove_app_blocking "$CLIENT_IP" "$APPS" "$CLIENT_MAC"
        ;;

    clear-runtime)
        clear_runtime_rules
        ;;
    
    status)
        if [[ -z "$CLIENT_IP" ]]; then
            log_error "IP address required for 'status' action"
            exit 1
        fi
        get_status "$CLIENT_IP" "$CLIENT_MAC"
        ;;
    
    sync)
        sync_from_devices
        ;;
    
    update-lists)
        update_ip_lists
        ;;

    learn-whatsapp)
        learn_whatsapp_ips "$CLIENT_IP" "$APPS"
        ;;

    set-whatsapp-mode)
        # In this action, 2nd arg is mode (balanced|aggressive), not client IP.
        set_whatsapp_mode "$CLIENT_IP"
        # Apply mode immediately to active rules.
        sync_from_devices
        ;;

    get-whatsapp-mode)
        get_whatsapp_mode
        ;;
    
    *)
        echo "Usage: $0 {add|remove|clear-runtime|status|sync|update-lists|learn-whatsapp|set-whatsapp-mode|get-whatsapp-mode} [client_ip|mode] [apps]" >&2
        echo "" >&2
        echo "Actions:" >&2
        echo "  add <ip> [apps]      - Enable app blocking for IP (apps: telegram,whatsapp,signal,tor,messenger,facebook,snapchat,wechat,viber,imessage,discord,line)" >&2
        echo "  remove <ip> [apps]   - Disable app blocking (apps or 'all')" >&2
        echo "  clear-runtime        - Remove all EasyPi app-blocking runtime rules" >&2
        echo "  status <ip>          - Get blocking status for IP" >&2
        echo "  sync                 - Sync blocking from devices.json" >&2
        echo "  update-lists         - Update IP lists from external sources" >&2
        echo "  learn-whatsapp <ip> [seconds] - Learn WhatsApp IPs by observing traffic (default 20s)" >&2
        echo "  set-whatsapp-mode <balanced|aggressive> - Balanced: SNI; Aggressive: full IP + Meta ranges" >&2
        echo "  get-whatsapp-mode    - Print current WhatsApp blocking mode" >&2
        echo "" >&2
        echo "Supported apps: telegram, whatsapp, signal, tor, messenger, facebook, snapchat, wechat, viber, imessage, discord, line" >&2
        exit 1
        ;;
esac
