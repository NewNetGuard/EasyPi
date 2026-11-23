#!/usr/bin/env bash
set -euo pipefail

[[ "${EUID}" -eq 0 ]] || {
    echo "This regression test requires root network-namespace privileges" >&2
    exit 77
}

for command_name in awk cut grep head iptables unshare; do
    command -v "$command_name" >/dev/null 2>&1 || {
        echo "Missing required command: $command_name" >&2
        exit 77
    }
done

root_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
vpn_script="$root_dir/scripts/settings/setup_vpn_blocking.sh"
dispatch_line="$(grep -n '^case "\$ACTION" in' "$vpn_script" | cut -d: -f1)"
[[ "$dispatch_line" =~ ^[0-9]+$ ]] || {
    echo "Could not locate setup_vpn_blocking.sh command dispatcher" >&2
    exit 1
}
grep -Fq 'reconcile_dns_redirects "${desired_dns_redirects[@]}" || return 1' \
    "$vpn_script"

unshare -n bash -s -- "$vpn_script" "$dispatch_line" <<'BASH'
set -euo pipefail

install() { :; }
source <(head -n "$(( $2 - 1 ))" "$1")
unset -f install

stale_mac="02:00:00:00:00:31"
kept_mac="02:00:00:00:00:32"
failure_mac="02:00:00:00:00:33"
legacy_ip="192.0.2.32"

add_mac_redirect() {
    local mac="$1" proto="$2"
    command iptables -t nat -A PREROUTING -m mac --mac-source "$mac" \
        -p "$proto" --dport 53 -m comment --comment "$DNS_REDIRECT_COMMENT" \
        -j REDIRECT --to-ports 53
}

for proto in udp tcp; do
    add_mac_redirect "$stale_mac" "$proto"
    add_mac_redirect "$kept_mac" "$proto"
    command iptables -t nat -A PREROUTING -s "$legacy_ip" -p "$proto" \
        --dport 53 -m comment --comment "$DNS_REDIRECT_COMMENT" \
        -j REDIRECT --to-ports 53
done

reconcile_dns_redirects "mac:$kept_mac"
rules="$(command iptables -t nat -S PREROUTING)"
[[ "$(grep -Fc -- "$kept_mac" <<< "$rules")" -eq 2 ]]
! grep -Fq -- "$stale_mac" <<< "$rules"
! grep -Fq -- "-s $legacy_ip/32" <<< "$rules"

add_mac_redirect "$failure_mac" udp
failure_mode="delete"
iptables() {
    local arg
    if [[ "$failure_mode" == "read" && "$*" == "-t nat -S PREROUTING" ]]; then
        return 4
    fi
    if [[ "$failure_mode" == "delete" ]]; then
        for arg in "$@"; do
            [[ "$arg" == "-D" ]] && return 4
        done
    fi
    command iptables "$@"
}

if reconcile_dns_redirects "mac:$kept_mac" 2>/dev/null; then
    echo "DNS redirect deletion failure was incorrectly accepted" >&2
    exit 1
fi
command iptables -t nat -S PREROUTING | grep -Fq -- "$failure_mac"

failure_mode="read"
if reconcile_dns_redirects "mac:$kept_mac" 2>/dev/null; then
    echo "DNS redirect enumeration failure was incorrectly accepted" >&2
    exit 1
fi
unset -f iptables

echo "PARENTAL_FIREWALL_ROLLBACK=PASS"
BASH
