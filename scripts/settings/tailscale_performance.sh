#!/bin/bash
set -Eeuo pipefail

export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
unset PYTHONPATH PYTHONHOME BASH_ENV ENV CDPATH GLOBIGNORE
umask 077

ACTION="${1:-}"
STATE_DIR="/var/lib/easypi/tailscale-performance"
STATE_FILE="${STATE_DIR}/tailscale-performance.state"

[[ "$ACTION" == "apply" || "$ACTION" == "auto" || "$ACTION" == "restore" ]] || {
    echo "usage: tailscale_performance.sh <apply|auto|restore>" >&2
    exit 2
}

[[ $EUID -eq 0 ]] || {
    echo "tailscale performance configuration requires root" >&2
    exit 1
}

restore_settings() {
    [[ -e "$STATE_FILE" ]] || return 0
    [[ -f "$STATE_FILE" && ! -L "$STATE_FILE" ]] || {
        echo "refusing unsafe Tailscale performance state" >&2
        return 1
    }
    [[ "$(stat -Lc '%u:%a' -- "$STATE_FILE" 2>/dev/null)" == "0:600" ]] || {
        echo "refusing untrusted Tailscale performance state" >&2
        return 1
    }

    saved_interface="$(/usr/bin/awk -F= '$1 == "interface" { print $2; exit }' "$STATE_FILE")"
    saved_udp="$(/usr/bin/awk -F= '$1 == "rx_udp_gro_forwarding" { print $2; exit }' "$STATE_FILE")"
    saved_list="$(/usr/bin/awk -F= '$1 == "rx_gro_list" { print $2; exit }' "$STATE_FILE")"
    [[ "$saved_interface" =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] || return 1
    [[ "$saved_udp" == "on" || "$saved_udp" == "off" ]] || return 1
    [[ "$saved_list" == "on" || "$saved_list" == "off" ]] || return 1
    if [[ -d "/sys/class/net/$saved_interface" && -x /usr/sbin/ethtool ]]; then
        /usr/sbin/ethtool -K "$saved_interface" \
            rx-udp-gro-forwarding "$saved_udp" rx-gro-list "$saved_list"
    fi
    rm -f -- "$STATE_FILE"
    rmdir -- "$STATE_DIR" 2>/dev/null || true
}

if [[ "$ACTION" == "restore" ]]; then
    restore_settings
    exit 0
fi

if [[ "$ACTION" == "auto" ]]; then
    [[ -x /usr/bin/tailscale ]] || exit 0
    prefs="$(/usr/bin/tailscale debug prefs 2>/dev/null || true)"
    grep -Eq '"AdvertiseExitNode"[[:space:]]*:[[:space:]]*true' <<<"$prefs" || exit 0
fi

[[ -x /usr/sbin/ethtool ]] || {
    echo "ethtool is unavailable; Tailscale UDP forwarding optimization was skipped" >&2
    exit 1
}

interface="$(/usr/bin/ip -o route get 8.8.8.8 2>/dev/null \
    | /usr/bin/awk '{ for (index = 1; index <= NF; index++) if ($index == "dev") { print $(index + 1); exit } }')"
[[ "$interface" =~ ^[A-Za-z0-9_.:-]{1,15}$ && -d "/sys/class/net/$interface" ]] || {
    echo "could not determine the trusted default-route interface" >&2
    exit 1
}

features="$(/usr/sbin/ethtool -k "$interface" 2>/dev/null || true)"
grep -q '^rx-udp-gro-forwarding:' <<<"$features" || exit 0
grep -q '^rx-gro-list:' <<<"$features" || exit 0

if [[ -e "$STATE_FILE" || -L "$STATE_FILE" ]]; then
    [[ -f "$STATE_FILE" && ! -L "$STATE_FILE" ]] || {
        echo "refusing unsafe Tailscale performance state" >&2
        exit 1
    }
    [[ "$(stat -Lc '%u:%a' -- "$STATE_FILE" 2>/dev/null)" == "0:600" ]] || {
        echo "refusing untrusted Tailscale performance state" >&2
        exit 1
    }
    saved_interface="$(/usr/bin/awk -F= '$1 == "interface" { print $2; exit }' "$STATE_FILE")"
    if [[ -n "$saved_interface" && "$saved_interface" != "$interface" ]]; then
        restore_settings
    fi
fi

[[ ! -L "$STATE_DIR" ]] || {
    echo "refusing symlinked Tailscale performance state directory" >&2
    exit 1
}
install -d -o root -g root -m 0700 "$STATE_DIR"
if [[ ! -e "$STATE_FILE" ]]; then
    previous_udp="$(/usr/bin/awk '/^rx-udp-gro-forwarding:/ { print $2; exit }' <<<"$features")"
    previous_list="$(/usr/bin/awk '/^rx-gro-list:/ { print $2; exit }' <<<"$features")"
    [[ "$previous_udp" == "on" || "$previous_udp" == "off" ]] || exit 0
    [[ "$previous_list" == "on" || "$previous_list" == "off" ]] || exit 0
    temporary="$(mktemp "${STATE_DIR}/.tailscale-performance.XXXXXX")"
    chmod 0600 "$temporary"
    printf 'interface=%s\nrx_udp_gro_forwarding=%s\nrx_gro_list=%s\n' \
        "$interface" "$previous_udp" "$previous_list" > "$temporary"
    mv -f -- "$temporary" "$STATE_FILE"
    chmod 0600 "$STATE_FILE"
fi

/usr/sbin/ethtool -K "$interface" rx-udp-gro-forwarding on rx-gro-list off
