#!/bin/bash
set -euo pipefail

PATH=/usr/sbin:/usr/bin:/sbin:/bin
export PATH
umask 077

ACTION="${1:-}"

die() {
    printf 'network_firewall: %s\n' "$1" >&2
    exit 1
}

validate_iface() {
    local iface="$1"
    [[ "$iface" =~ ^[A-Za-z0-9_.:-]{1,32}$ ]] || die "invalid interface"
    [[ -d "/sys/class/net/$iface" ]] || die "interface does not exist"
}

validate_ip() {
    python3 - "$1" <<'PY' >/dev/null
import ipaddress
import sys
ipaddress.ip_address(sys.argv[1])
PY
}

validate_ipv4() {
    python3 - "$1" <<'PY' >/dev/null
import ipaddress
import sys
value = ipaddress.ip_address(sys.argv[1])
if value.version != 4:
    raise ValueError("IPv4 address required")
PY
}

validate_cidr() {
    python3 - "$1" <<'PY' >/dev/null
import ipaddress
import sys
ipaddress.ip_network(sys.argv[1], strict=False)
PY
}

validate_port() {
    local value="$1"
    [[ "$value" =~ ^[0-9]{1,5}(:[0-9]{1,5})?$ ]] || die "invalid port"
    python3 - "$value" <<'PY' >/dev/null
import sys
parts = [int(part) for part in sys.argv[1].split(":")]
if any(part < 1 or part > 65535 for part in parts):
    raise ValueError("port out of range")
if len(parts) == 2 and parts[0] > parts[1]:
    raise ValueError("invalid port range")
PY
}

validate_source() {
    [[ "$1" == "any" ]] && return 0
    validate_cidr "$1"
}

validate_connection() {
    local connection="$1"
    local pattern='^[A-Za-z0-9][A-Za-z0-9_.:() -]{0,127}$'
    [[ "$connection" =~ $pattern ]] \
        || die "invalid connection name"
    nmcli connection show "$connection" >/dev/null 2>&1 \
        || die "connection does not exist"
}

validate_dns_list() {
    python3 - "$1" <<'PY' >/dev/null
import ipaddress
import re
import sys
values = [part for part in re.split(r"[\s,]+", sys.argv[1].strip()) if part]
if not values or len(values) > 8:
    raise ValueError("invalid DNS list")
for value in values:
    ipaddress.ip_address(value)
PY
}

ensure_rule() {
    local command="$1"
    shift
    if [[ "${1:-}" == "-t" && "$#" -ge 3 ]]; then
        local table="$2"
        shift 2
        "$command" -t "$table" -C "$@" 2>/dev/null \
            || "$command" -t "$table" -A "$@"
    else
        "$command" -C "$@" 2>/dev/null || "$command" -A "$@"
    fi
}

remove_rule() {
    local command="$1"
    shift
    if [[ "${1:-}" == "-t" && "$#" -ge 3 ]]; then
        local table="$2"
        shift 2
        while "$command" -t "$table" -C "$@" 2>/dev/null; do
            "$command" -t "$table" -D "$@"
        done
    else
        while "$command" -C "$@" 2>/dev/null; do
            "$command" -D "$@"
        done
    fi
}

persist_rules() {
    local target_dir=/etc/iptables
    local tmp_v4 tmp_v6
    install -d -o root -g root -m 0755 "$target_dir"
    tmp_v4="$(mktemp "$target_dir/.rules.v4.XXXXXX")"
    iptables-save >"$tmp_v4"
    chown root:root "$tmp_v4"
    chmod 0644 "$tmp_v4"
    mv -f -- "$tmp_v4" "$target_dir/rules.v4"
    if command -v ip6tables-save >/dev/null 2>&1; then
        tmp_v6="$(mktemp "$target_dir/.rules.v6.XXXXXX")"
        ip6tables-save >"$tmp_v6"
        chown root:root "$tmp_v6"
        chmod 0644 "$tmp_v6"
        mv -f -- "$tmp_v6" "$target_dir/rules.v6"
    fi
}

case "$ACTION" in
    block-ip)
        [[ "$#" -eq 3 ]] || die "usage: block-ip add|remove IP"
        verb="$2"
        ip="$3"
        validate_ip "$ip" || die "invalid IP address"
        command=iptables
        [[ "$ip" == *:* ]] && command=ip6tables
        case "$verb" in
            add) ensure_rule "$command" INPUT -s "$ip" -j DROP ;;
            remove) remove_rule "$command" INPUT -s "$ip" -j DROP ;;
            *) die "invalid block-ip action" ;;
        esac
        ;;
    gateway-enable)
        [[ "$#" -eq 3 ]] || die "usage: gateway-enable WAN_IFACE LAN_IFACE"
        wan="$2"
        lan="$3"
        validate_iface "$wan"
        validate_iface "$lan"
        sysctl -w net.ipv4.ip_forward=1 >/dev/null
        # In a router-on-a-stick setup LAN clients and the upstream router use
        # the same interface. Linux would otherwise send ICMP redirects telling
        # clients to bypass EasyPi and use the upstream router directly.
        sysctl -w net.ipv4.conf.all.send_redirects=0 >/dev/null
        sysctl -w net.ipv4.conf.default.send_redirects=0 >/dev/null
        sysctl -w "net.ipv4.conf.${wan}.send_redirects=0" >/dev/null
        sysctl -w "net.ipv4.conf.${lan}.send_redirects=0" >/dev/null
        ensure_rule iptables -t nat POSTROUTING -o "$wan" -j MASQUERADE
        ensure_rule iptables FORWARD -i "$lan" -o "$wan" -j ACCEPT
        ensure_rule iptables FORWARD -i "$wan" -o "$lan" \
            -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
        ;;
    gateway-disable)
        [[ "$#" -eq 3 ]] || die "usage: gateway-disable WAN_IFACE LAN_IFACE"
        wan="$2"
        lan="$3"
        validate_iface "$wan"
        validate_iface "$lan"
        remove_rule iptables -t nat POSTROUTING -o "$wan" -j MASQUERADE
        remove_rule iptables FORWARD -i "$lan" -o "$wan" -j ACCEPT
        remove_rule iptables FORWARD -i "$wan" -o "$lan" \
            -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
        sysctl -w net.ipv4.ip_forward=0 >/dev/null
        ;;
    masquerade)
        [[ "$#" -eq 3 ]] || die "usage: masquerade add|remove IFACE"
        verb="$2"
        iface="$3"
        validate_iface "$iface"
        case "$verb" in
            add) ensure_rule iptables -t nat POSTROUTING -o "$iface" -j MASQUERADE ;;
            remove) remove_rule iptables -t nat POSTROUTING -o "$iface" -j MASQUERADE ;;
            *) die "invalid masquerade action" ;;
        esac
        ;;
    transparent-dns-enable)
        [[ "$#" -eq 5 ]] || die "usage: transparent-dns-enable IFACE IP OLD_IFACE OLD_IP"
        iface="$2"
        ip="$3"
        old_iface="$4"
        old_ip="$5"
        validate_iface "$iface"
        validate_ipv4 "$ip" || die "invalid IPv4 address"
        validate_iface "$old_iface"
        validate_ipv4 "$old_ip" || die "invalid old IPv4 address"
        for proto in udp tcp; do
            remove_rule iptables -t nat PREROUTING -i "$old_iface" -p "$proto" \
                --dport 53 ! -d "$old_ip" -j DNAT --to-destination "$old_ip:53"
            remove_rule iptables -t nat PREROUTING -p "$proto" --dport 53 \
                -j REDIRECT --to-port 53
            ensure_rule iptables -t nat PREROUTING -i "$iface" -p "$proto" \
                --dport 53 ! -d "$ip" -j DNAT --to-destination "$ip:53"
        done
        sysctl -w net.ipv4.ip_forward=1 >/dev/null
        ;;
    transparent-dns-disable)
        [[ "$#" -eq 3 ]] || die "usage: transparent-dns-disable IFACE IP"
        iface="$2"
        ip="$3"
        validate_iface "$iface"
        validate_ipv4 "$ip" || die "invalid IPv4 address"
        for proto in udp tcp; do
            remove_rule iptables -t nat PREROUTING -i "$iface" -p "$proto" \
                --dport 53 ! -d "$ip" -j DNAT --to-destination "$ip:53"
            remove_rule iptables -t nat PREROUTING -p "$proto" --dport 53 \
                -j REDIRECT --to-port 53
        done
        ;;
    tailscale-nat)
        [[ "$#" -eq 4 ]] || die "usage: tailscale-nat add|remove CIDR OUT_IFACE"
        verb="$2"
        cidr="$3"
        iface="$4"
        validate_cidr "$cidr" || die "invalid CIDR"
        validate_iface "$iface"
        case "$verb" in
            add) ensure_rule iptables -t nat POSTROUTING -s "$cidr" -o "$iface" -j MASQUERADE ;;
            remove) remove_rule iptables -t nat POSTROUTING -s "$cidr" -o "$iface" -j MASQUERADE ;;
            *) die "invalid tailscale-nat action" ;;
        esac
        ;;
    forwarding-enable)
        [[ "$#" -eq 1 ]] || die "forwarding-enable takes no arguments"
        printf '%s\n' \
            'net.ipv4.ip_forward = 1' \
            'net.ipv6.conf.all.forwarding = 1' \
            > /etc/sysctl.d/99-easypi-forwarding.conf
        chown root:root /etc/sysctl.d/99-easypi-forwarding.conf
        chmod 0644 /etc/sysctl.d/99-easypi-forwarding.conf
        sysctl -w net.ipv4.ip_forward=1 >/dev/null
        sysctl -w net.ipv6.conf.all.forwarding=1 >/dev/null
        ;;
    ufw-status)
        [[ "$#" -eq 2 ]] || die "usage: ufw-status normal|numbered|verbose"
        case "$2" in
            normal) ufw status ;;
            numbered) ufw status numbered ;;
            verbose) ufw status verbose ;;
            *) die "invalid ufw status mode" ;;
        esac
        ;;
    ufw-toggle)
        [[ "$#" -eq 2 ]] || die "usage: ufw-toggle enable|disable"
        case "$2" in
            enable) ufw --force enable ;;
            disable) ufw --force disable ;;
            *) die "invalid ufw toggle action" ;;
        esac
        ;;
    ufw-rule)
        [[ "$#" -eq 6 ]] || die "usage: ufw-rule add|delete ACTION PROTOCOL PORT SOURCE"
        verb="$2"
        rule_action="$3"
        protocol="$4"
        port="$5"
        source="$6"
        [[ "$verb" == "add" || "$verb" == "delete" ]] || die "invalid ufw rule verb"
        [[ "$rule_action" =~ ^(allow|deny|limit|reject)$ ]] || die "invalid ufw rule action"
        [[ "$protocol" =~ ^(tcp|udp)$ ]] || die "invalid protocol"
        validate_port "$port" || die "invalid port"
        validate_source "$source" || die "invalid source"
        if [[ "$verb" == "add" ]]; then
            ufw "$rule_action" proto "$protocol" from "$source" to any port "$port"
        else
            ufw --force delete "$rule_action" proto "$protocol" from "$source" to any port "$port"
        fi
        ;;
    ufw-delete-number)
        [[ "$#" -eq 2 && "$2" =~ ^[1-9][0-9]{0,3}$ ]] \
            || die "invalid ufw rule number"
        ufw --force delete "$2"
        ;;
    ufw-route)
        [[ "$#" -eq 4 ]] || die "usage: ufw-route add|delete LAN_IFACE WAN_IFACE"
        verb="$2"
        lan="$3"
        wan="$4"
        validate_iface "$lan"
        validate_iface "$wan"
        case "$verb" in
            add) ufw route allow in on "$lan" out on "$wan" ;;
            delete) ufw route delete allow in on "$lan" out on "$wan" ;;
            *) die "invalid ufw route action" ;;
        esac
        ;;
    ufw-reload)
        [[ "$#" -eq 1 ]] || die "ufw-reload takes no arguments"
        ufw reload
        ;;
    nmcli-dns)
        [[ "$#" -eq 5 ]] || die "usage: nmcli-dns set CONNECTION DNS YES_OR_NO"
        [[ "$2" == "set" ]] || die "invalid nmcli-dns action"
        connection="$3"
        dns="$4"
        ignore_auto="$5"
        validate_connection "$connection"
        validate_dns_list "$dns" || die "invalid DNS list"
        [[ "$ignore_auto" == "yes" || "$ignore_auto" == "no" ]] \
            || die "invalid ignore-auto-dns value"
        nmcli connection modify "$connection" \
            ipv4.dns "$dns" ipv4.ignore-auto-dns "$ignore_auto"
        nmcli connection up "$connection"
        ;;
    nmcli-dns-reset)
        [[ "$#" -eq 2 ]] || die "usage: nmcli-dns-reset CONNECTION"
        connection="$2"
        validate_connection "$connection"
        nmcli connection modify "$connection" \
            ipv4.dns "" ipv4.ignore-auto-dns no
        nmcli connection up "$connection"
        ;;
    nmcli-gateway-static)
        [[ "$#" -eq 5 ]] || die "usage: nmcli-gateway-static CONNECTION CIDR GATEWAY DNS"
        connection="$2"
        cidr="$3"
        gateway="$4"
        dns="$5"
        validate_connection "$connection"
        validate_cidr "$cidr" || die "invalid gateway CIDR"
        validate_ipv4 "$gateway" || die "invalid gateway"
        validate_ipv4 "$dns" || die "invalid DNS"
        nmcli connection modify "$connection" \
            ipv4.addresses "$cidr" ipv4.gateway "$gateway" \
            ipv4.dns "$dns" ipv4.method manual
        nmcli connection up "$connection"
        ;;
    nmcli-gateway-dhcp)
        [[ "$#" -eq 2 ]] || die "usage: nmcli-gateway-dhcp CONNECTION"
        connection="$2"
        validate_connection "$connection"
        nmcli connection modify "$connection" \
            ipv4.method auto ipv4.addresses "" ipv4.gateway "" ipv4.dns ""
        nmcli connection up "$connection"
        ;;
    persist)
        [[ "$#" -eq 1 ]] || die "persist takes no arguments"
        persist_rules
        ;;
    *)
        die "unsupported action"
        ;;
esac

case "$ACTION" in
    block-ip|gateway-enable|gateway-disable|masquerade|transparent-dns-enable|transparent-dns-disable|tailscale-nat)
        persist_rules
        ;;
esac
