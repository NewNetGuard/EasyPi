#!/bin/bash
# Install and control the bounded PRISM Counterfactual Flow Lab.

set -euo pipefail

export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
umask 077

EASYPI_ROOT="/opt/EasyPi"
SERVICE="easypi-prism-counterfactual.service"
SERVICE_USER="easypi-prism"
UNIT_PATH="/etc/systemd/system/${SERVICE}"
ENV_PATH="/etc/default/easypi-prism-counterfactual"
STATE_DIR="/var/lib/easypi/prism-counterfactual"
PLAN_PATH="${STATE_DIR}/plan.json"
CHAIN="EASYPI_PRISM_COUNTERFACTUAL"
CANARY_SET="easypi_prism_counterfactual"
LINEAGE_CANARY_SET="easypi_prism_lineage"
CANARY_TTL_SEC=360
QUEUE_NUMBER=4243
IPTABLES="/usr/sbin/iptables"
IPTABLES_SAVE="/usr/sbin/iptables-save"
IPSET="/usr/sbin/ipset"
SYSTEMCTL="/usr/bin/systemctl"
PYTHON="/usr/bin/python3"

die() {
    echo "setup_prism_counterfactual: $*" >&2
    exit 1
}

require_root() {
    [[ $EUID -eq 0 ]] || die "root privileges are required"
}

is_private_ipv4() {
    local value="$1" a b c d extra octet
    IFS=. read -r a b c d extra <<< "$value"
    [[ -z "${extra:-}" ]] || return 1
    for octet in "$a" "$b" "$c" "$d"; do
        [[ "$octet" =~ ^[0-9]{1,3}$ ]] || return 1
        ((10#$octet <= 255)) || return 1
    done
    if ((10#$a == 10)); then
        return 0
    fi
    if ((10#$a == 192 && 10#$b == 168)); then
        return 0
    fi
    ((10#$a == 172 && 10#$b >= 16 && 10#$b <= 31))
}

is_public_ipv4() {
    local value="$1" a b c d extra octet
    IFS=. read -r a b c d extra <<< "$value"
    [[ -z "${extra:-}" ]] || return 1
    for octet in "$a" "$b" "$c" "$d"; do
        [[ "$octet" =~ ^[0-9]{1,3}$ ]] || return 1
        ((10#$octet <= 255)) || return 1
    done
    ((10#$a != 0 && 10#$a != 10 && 10#$a != 127 && 10#$a < 224)) || return 1
    ((10#$a == 169 && 10#$b == 254)) && return 1
    ((10#$a == 172 && 10#$b >= 16 && 10#$b <= 31)) && return 1
    ((10#$a == 192 && 10#$b == 168)) && return 1
    return 0
}

generation() {
    /usr/bin/date +%s%N
}

remove_forward_jumps() {
    while "$IPTABLES" -w 5 -C FORWARD -j "$CHAIN" >/dev/null 2>&1; do
        "$IPTABLES" -w 5 -D FORWARD -j "$CHAIN"
    done
}

write_plan_disarmed() {
    local temp value
    value="$(generation)"
    temp="$(/usr/bin/mktemp "${STATE_DIR}/.plan.XXXXXX")"
    /usr/bin/printf '{"armed":false,"generation":%s}\n' "$value" > "$temp"
    /usr/bin/chown root:"$SERVICE_USER" "$temp"
    /usr/bin/chmod 0640 "$temp"
    /usr/bin/mv -f -- "$temp" "$PLAN_PATH"
}

write_plan_armed() {
    local client_ip="$1" protocol="$2" selection="$3" target_ordinal="$4"
    local target_server_ip="$5" intervention_ms="$6" max_drops="$7"
    local discovery_ms="$8" temp value
    value="$(generation)"
    temp="$(/usr/bin/mktemp "${STATE_DIR}/.plan.XXXXXX")"
    /usr/bin/printf \
        '{"armed":true,"generation":%s,"client_ip":"%s","protocol":"%s","selection":"%s","target_ordinal":%s,"target_server_ip":"%s","intervention_ms":%s,"max_drops":%s,"discovery_ms":%s}\n' \
        "$value" "$client_ip" "$protocol" "$selection" "$target_ordinal" \
        "$target_server_ip" \
        "$intervention_ms" "$max_drops" "$discovery_ms" > "$temp"
    /usr/bin/chown root:"$SERVICE_USER" "$temp"
    /usr/bin/chmod 0640 "$temp"
    /usr/bin/mv -f -- "$temp" "$PLAN_PATH"
}

write_environment() {
    local temp
    temp="$(/usr/bin/mktemp /etc/default/.easypi-prism-counterfactual.XXXXXX)"
    /usr/bin/printf 'PRISM_COUNTERFACTUAL_QUEUE=%s\n' "$QUEUE_NUMBER" > "$temp"
    /usr/bin/chown root:root "$temp"
    /usr/bin/chmod 0644 "$temp"
    /usr/bin/mv -f -- "$temp" "$ENV_PATH"
}

write_unit() {
    local temp
    temp="$(/usr/bin/mktemp /etc/systemd/system/.easypi-prism-counterfactual.XXXXXX)"
    /usr/bin/cat > "$temp" <<'EOF'
[Unit]
Description=EasyPi PRISM Counterfactual Flow Lab
After=network-online.target
Wants=network-online.target
ConditionPathExists=/opt/EasyPi/prism_dpi/counterfactual_lab/__main__.py
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=easypi-prism
Group=easypi-prism
UMask=0027
WorkingDirectory=/opt/EasyPi
EnvironmentFile=/etc/default/easypi-prism-counterfactual
Environment=PYTHONPATH=/opt/EasyPi
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=/usr/bin/python3 -m prism_dpi.counterfactual_lab live --queue ${PRISM_COUNTERFACTUAL_QUEUE}
Restart=on-failure
RestartSec=2
TimeoutStopSec=5
Nice=5

AmbientCapabilities=CAP_NET_ADMIN
CapabilityBoundingSet=CAP_NET_ADMIN
NoNewPrivileges=yes

ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
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
RestrictAddressFamilies=AF_NETLINK AF_UNIX
ReadWritePaths=/var/lib/easypi/prism-counterfactual

LimitNOFILE=1024
MemoryMax=64M
CPUQuota=10%

StandardOutput=journal
StandardError=journal
SyslogIdentifier=easypi-prism-counterfactual

[Install]
WantedBy=multi-user.target
EOF
    /usr/bin/chown root:root "$temp"
    /usr/bin/chmod 0644 "$temp"
    /usr/bin/mv -f -- "$temp" "$UNIT_PATH"
}

append_queue_rule() {
    local protocol="$1" port_direction="$2" set_direction="$3"
    "$IPTABLES" -w 5 -A "$CHAIN" -p "$protocol" "$port_direction" 443 \
        -m set --match-set "$CANARY_SET" "$set_direction" \
        -j NFQUEUE --queue-num "$QUEUE_NUMBER" --queue-bypass
}

install_firewall_rules() {
    [[ -x "$IPTABLES" && -x "$IPSET" ]] || die "iptables and ipset are required"
    /usr/sbin/modprobe nfnetlink_queue >/dev/null 2>&1 || true
    if ! "$IPTABLES" -w 5 -nL "$CHAIN" >/dev/null 2>&1; then
        "$IPTABLES" -w 5 -N "$CHAIN"
    fi
    remove_forward_jumps
    "$IPTABLES" -w 5 -F "$CHAIN"
    "$IPSET" destroy "$CANARY_SET" 2>/dev/null || true
    "$IPSET" create "$CANARY_SET" hash:ip \
        family inet timeout "$CANARY_TTL_SEC" maxelem 1
    append_queue_rule tcp --dport src
    append_queue_rule tcp --sport dst
    append_queue_rule udp --dport src
    append_queue_rule udp --sport dst
    "$IPTABLES" -w 5 -A "$CHAIN" -j RETURN
    "$IPTABLES" -w 5 -I FORWARD 1 -j "$CHAIN"
}

install_lab() {
    [[ -d "$EASYPI_ROOT/prism_dpi/counterfactual_lab" ]] || die "Counterfactual Lab is not deployed"
    "$PYTHON" -c 'import netfilterqueue' >/dev/null 2>&1 ||
        die "python3-netfilterqueue is not installed"
    if ! /usr/bin/id -u "$SERVICE_USER" >/dev/null 2>&1; then
        /usr/sbin/useradd --system --home-dir "$STATE_DIR" \
            --shell /usr/sbin/nologin --user-group "$SERVICE_USER"
    fi
    /usr/bin/install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 "$STATE_DIR"
    write_plan_disarmed
    write_environment
    write_unit
    "$SYSTEMCTL" daemon-reload
    "$SYSTEMCTL" enable "$SERVICE"
    "$SYSTEMCTL" restart "$SERVICE"
    "$SYSTEMCTL" is-active --quiet "$SERVICE" || die "counterfactual service failed to start"
    install_firewall_rules
    echo "PRISM Counterfactual Flow Lab installed; plan disarmed and canary empty"
}

persist_ipv4_rules() {
    local target_dir="/etc/iptables" target temporary
    target="${target_dir}/rules.v4"
    [[ -x "$IPTABLES_SAVE" ]] || die "iptables-save is required to persist firewall cleanup"
    /usr/bin/install -d -o root -g root -m 0755 "$target_dir"
    temporary="$(/usr/bin/mktemp "${target_dir}/.rules.v4.XXXXXX")"
    if ! "$IPTABLES_SAVE" > "$temporary"; then
        /usr/bin/rm -f -- "$temporary"
        die "failed to save cleaned IPv4 firewall rules"
    fi
    /usr/bin/chown root:root "$temporary"
    /usr/bin/chmod 0644 "$temporary"
    /usr/bin/mv -f -- "$temporary" "$target"
}

remove_lab() {
    "$SYSTEMCTL" disable --now "$SERVICE" >/dev/null 2>&1 || true
    remove_forward_jumps
    if "$IPTABLES" -w 5 -nL "$CHAIN" >/dev/null 2>&1; then
        "$IPTABLES" -w 5 -F "$CHAIN"
        "$IPTABLES" -w 5 -X "$CHAIN"
    fi
    "$IPSET" destroy "$CANARY_SET" 2>/dev/null || true
    persist_ipv4_rules
    /usr/bin/rm -f -- "$UNIT_PATH" "$ENV_PATH"
    "$SYSTEMCTL" daemon-reload
    "$SYSTEMCTL" reset-failed "$SERVICE" >/dev/null 2>&1 || true
    echo "PRISM Counterfactual Flow Lab removed"
}

arm_lab() {
    local client_ip="$1" protocol="$2" target_ordinal="$3"
    local intervention_ms="$4" max_drops="$5"
    is_private_ipv4 "$client_ip" || die "client IP must be private IPv4"
    [[ "$protocol" == "tcp" || "$protocol" == "udp" ]] || die "protocol must be tcp or udp"
    [[ "$target_ordinal" =~ ^[0-9]{1,2}$ ]] || die "target ordinal must be numeric"
    ((10#$target_ordinal >= 1 && 10#$target_ordinal <= 32)) || die "target ordinal out of range"
    [[ "$intervention_ms" =~ ^[0-9]{3,4}$ ]] || die "intervention must be milliseconds"
    ((10#$intervention_ms >= 250 && 10#$intervention_ms <= 5000)) || die "intervention duration out of range"
    [[ "$max_drops" =~ ^[0-9]{1,2}$ ]] || die "max drops must be numeric"
    ((10#$max_drops >= 1 && 10#$max_drops <= 64)) || die "max drops out of range"
    "$SYSTEMCTL" is-active --quiet "$SERVICE" || die "counterfactual service is not active"
    "$IPTABLES" -w 5 -nL "$CHAIN" >/dev/null 2>&1 || die "counterfactual chain is not installed"
    if "$IPSET" test "$LINEAGE_CANARY_SET" "$client_ip" >/dev/null 2>&1; then
        die "disable the Lineage Gate canary for this IP first"
    fi
    "$IPSET" flush "$CANARY_SET"
    write_plan_armed "$client_ip" "$protocol" ordinal "$target_ordinal" "" \
        "$intervention_ms" "$max_drops" 15000
    "$IPSET" add "$CANARY_SET" "$client_ip" timeout "$CANARY_TTL_SEC"
    echo "PRISM counterfactual experiment armed for $client_ip (${CANARY_TTL_SEC}s canary TTL)"
}

arm_server_lab() {
    local client_ip="$1" protocol="$2" target_server_ip="$3"
    local intervention_ms="$4" max_drops="$5"
    is_private_ipv4 "$client_ip" || die "client IP must be private IPv4"
    [[ "$protocol" == "tcp" || "$protocol" == "udp" ]] || die "protocol must be tcp or udp"
    is_public_ipv4 "$target_server_ip" || die "target server must be public IPv4"
    [[ "$intervention_ms" =~ ^[0-9]{3,6}$ ]] || die "intervention must be milliseconds"
    ((10#$intervention_ms >= 250 && 10#$intervention_ms <= 300000)) || die "intervention duration out of range"
    [[ "$max_drops" =~ ^[0-9]{1,4}$ ]] || die "max drops must be numeric"
    ((10#$max_drops >= 1 && 10#$max_drops <= 4096)) || die "max drops out of range"
    "$SYSTEMCTL" is-active --quiet "$SERVICE" || die "counterfactual service is not active"
    "$IPTABLES" -w 5 -nL "$CHAIN" >/dev/null 2>&1 || die "counterfactual chain is not installed"
    if "$IPSET" test "$LINEAGE_CANARY_SET" "$client_ip" >/dev/null 2>&1; then
        die "disable the Lineage Gate canary for this IP first"
    fi
    "$IPSET" flush "$CANARY_SET"
    write_plan_armed "$client_ip" "$protocol" server 0 "$target_server_ip" \
        "$intervention_ms" "$max_drops" 300000
    "$IPSET" add "$CANARY_SET" "$client_ip" timeout "$CANARY_TTL_SEC"
    echo "PRISM counterfactual server-cohort experiment armed for $client_ip (${CANARY_TTL_SEC}s canary TTL)"
}

arm_root_sni_lab() {
    local client_ip="$1" intervention_ms="$2" max_drops="$3" selection="$4"
    is_private_ipv4 "$client_ip" || die "client IP must be private IPv4"
    [[ "$selection" == "root_sni" || "$selection" == "first_root_sni" || \
        "$selection" == "causal_root_sni" ]] || \
        die "invalid root-SNI selection"
    [[ "$intervention_ms" =~ ^[0-9]{3,6}$ ]] || die "intervention must be milliseconds"
    ((10#$intervention_ms >= 250 && 10#$intervention_ms <= 300000)) || die "intervention duration out of range"
    [[ "$max_drops" =~ ^[0-9]{1,4}$ ]] || die "max drops must be numeric"
    ((10#$max_drops >= 1 && 10#$max_drops <= 4096)) || die "max drops out of range"
    "$SYSTEMCTL" is-active --quiet "$SERVICE" || die "counterfactual service is not active"
    "$IPTABLES" -w 5 -nL "$CHAIN" >/dev/null 2>&1 || die "counterfactual chain is not installed"
    if "$IPSET" test "$LINEAGE_CANARY_SET" "$client_ip" >/dev/null 2>&1; then
        die "disable the Lineage Gate canary for this IP first"
    fi
    "$IPSET" flush "$CANARY_SET"
    write_plan_armed "$client_ip" tcp "$selection" 0 "" \
        "$intervention_ms" "$max_drops" 300000
    "$IPSET" add "$CANARY_SET" "$client_ip" timeout "$CANARY_TTL_SEC"
    echo "PRISM counterfactual ${selection} experiment armed for $client_ip (${CANARY_TTL_SEC}s canary TTL)"
}

disarm_lab() {
    local client_ip="$1"
    is_private_ipv4 "$client_ip" || die "client IP must be private IPv4"
    "$IPSET" del "$CANARY_SET" "$client_ip" 2>/dev/null || true
    write_plan_disarmed
    echo "PRISM counterfactual experiment disarmed for $client_ip"
}

show_status() {
    "$SYSTEMCTL" is-enabled "$SERVICE" || true
    "$SYSTEMCTL" is-active "$SERVICE" || true
    "$IPTABLES" -w 5 -nL "$CHAIN" -v --line-numbers 2>/dev/null || true
    "$IPSET" list "$CANARY_SET" 2>/dev/null || true
    /usr/bin/cat "$PLAN_PATH" 2>/dev/null || true
    /usr/bin/cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null || true
    if [[ -f "$STATE_DIR/lab.jsonl" && ! -L "$STATE_DIR/lab.jsonl" ]]; then
        /usr/bin/tail -n 10 "$STATE_DIR/lab.jsonl"
    fi
}

require_root
case "${1:-}" in
    install)
        [[ $# -eq 1 ]] || die "usage: setup_prism_counterfactual.sh install"
        install_lab
        ;;
    remove)
        [[ $# -eq 1 ]] || die "usage: setup_prism_counterfactual.sh remove"
        remove_lab
        ;;
    arm)
        [[ $# -eq 6 ]] || die "usage: setup_prism_counterfactual.sh arm PRIVATE_IPV4 tcp|udp ORDINAL DURATION_MS MAX_DROPS"
        arm_lab "$2" "$3" "$4" "$5" "$6"
        ;;
    arm-server)
        [[ $# -eq 6 ]] || die "usage: setup_prism_counterfactual.sh arm-server PRIVATE_IPV4 tcp|udp PUBLIC_IPV4 DURATION_MS MAX_DROPS"
        arm_server_lab "$2" "$3" "$4" "$5" "$6"
        ;;
    arm-root-sni)
        [[ $# -eq 4 ]] || die "usage: setup_prism_counterfactual.sh arm-root-sni PRIVATE_IPV4 DURATION_MS MAX_DROPS"
        arm_root_sni_lab "$2" "$3" "$4" root_sni
        ;;
    arm-first-root-sni)
        [[ $# -eq 4 ]] || die "usage: setup_prism_counterfactual.sh arm-first-root-sni PRIVATE_IPV4 DURATION_MS MAX_DROPS"
        arm_root_sni_lab "$2" "$3" "$4" first_root_sni
        ;;
    arm-causal-root-sni)
        [[ $# -eq 4 ]] || die "usage: setup_prism_counterfactual.sh arm-causal-root-sni PRIVATE_IPV4 DURATION_MS MAX_DROPS"
        arm_root_sni_lab "$2" "$3" "$4" causal_root_sni
        ;;
    disarm)
        [[ $# -eq 2 ]] || die "usage: setup_prism_counterfactual.sh disarm PRIVATE_IPV4"
        disarm_lab "$2"
        ;;
    status)
        [[ $# -eq 1 ]] || die "usage: setup_prism_counterfactual.sh status"
        show_status
        ;;
    *) die "unsupported action" ;;
esac
