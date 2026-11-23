#!/bin/bash
# Install and control the fail-open PRISM TLS Lineage Gate canary.

set -euo pipefail

export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
umask 077

EASYPI_ROOT="/opt/EasyPi"
SERVICE="easypi-prism-lineage.service"
SERVICE_USER="easypi-prism"
UNIT_PATH="/etc/systemd/system/${SERVICE}"
ENV_PATH="/etc/default/easypi-prism-lineage"
STATE_DIR="/var/lib/easypi/prism-lineage"
CHAIN="EASYPI_PRISM_LINEAGE"
CANARY_SET="easypi_prism_lineage"
CANARY_TTL_SEC=900
QUEUE_NUMBER=4242
IPTABLES="/usr/sbin/iptables"
IPTABLES_SAVE="/usr/sbin/iptables-save"
IPSET="/usr/sbin/ipset"
SYSTEMCTL="/usr/bin/systemctl"
PYTHON="/usr/bin/python3"

die() {
    echo "setup_prism_lineage: $*" >&2
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

remove_forward_jumps() {
    while "$IPTABLES" -w 5 -C FORWARD -j "$CHAIN" >/dev/null 2>&1; do
        "$IPTABLES" -w 5 -D FORWARD -j "$CHAIN"
    done
}

write_environment() {
    local temp
    temp="$(/usr/bin/mktemp /etc/default/.easypi-prism-lineage.XXXXXX)"
    /usr/bin/printf 'PRISM_LINEAGE_QUEUE=%s\n' "$QUEUE_NUMBER" > "$temp"
    /usr/bin/chown root:root "$temp"
    /usr/bin/chmod 0644 "$temp"
    /usr/bin/mv -f -- "$temp" "$ENV_PATH"
}

write_unit() {
    local temp
    temp="$(/usr/bin/mktemp /etc/systemd/system/.easypi-prism-lineage.XXXXXX)"
    /usr/bin/cat > "$temp" <<'EOF'
[Unit]
Description=EasyPi PRISM TLS Lineage Gate
After=network-online.target
Wants=network-online.target
ConditionPathExists=/opt/EasyPi/prism_dpi/lineage_gate/__main__.py
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=easypi-prism
Group=easypi-prism
UMask=0027
WorkingDirectory=/opt/EasyPi
EnvironmentFile=/etc/default/easypi-prism-lineage
Environment=PYTHONPATH=/opt/EasyPi
Environment=PYTHONDONTWRITEBYTECODE=1
ExecStart=/usr/bin/python3 -m prism_dpi.lineage_gate live --queue ${PRISM_LINEAGE_QUEUE}
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
ReadWritePaths=/var/lib/easypi/prism-lineage

LimitNOFILE=1024
MemoryMax=64M
CPUQuota=10%

StandardOutput=journal
StandardError=journal
SyslogIdentifier=easypi-prism-lineage

[Install]
WantedBy=multi-user.target
EOF
    /usr/bin/chown root:root "$temp"
    /usr/bin/chmod 0644 "$temp"
    /usr/bin/mv -f -- "$temp" "$UNIT_PATH"
}

install_firewall_rules() {
    local output matcher port u32_expr hex_pattern server_name installed=0
    [[ -x "$IPTABLES" && -x "$IPSET" ]] || die "iptables and ipset are required"
    /usr/sbin/modprobe nfnetlink_queue >/dev/null 2>&1 || true
    "$IPSET" create "$CANARY_SET" hash:ip \
        family inet timeout "$CANARY_TTL_SEC" maxelem 128 -exist
    if ! "$IPTABLES" -w 5 -nL "$CHAIN" >/dev/null 2>&1; then
        "$IPTABLES" -w 5 -N "$CHAIN"
    fi
    "$IPTABLES" -w 5 -F "$CHAIN"
    cd "$EASYPI_ROOT"
    output="$("$PYTHON" -m prism_dpi.rule mobile_ads_yandex)" ||
        die "PRISM rule generation failed"
    while IFS=$'\t' read -r matcher port u32_expr hex_pattern server_name; do
        [[ -n "$matcher" ]] || continue
        [[ "$matcher" == "tls-sni-shadow" ]] || die "unsupported matcher"
        [[ "$port" =~ ^[0-9]{1,5}$ ]] || die "invalid destination port"
        ((10#$port >= 1 && 10#$port <= 65535)) || die "port out of range"
        [[ "$u32_expr" =~ ^[0-9A-Fx@\>\&\=]+$ ]] || die "invalid u32 expression"
        [[ "$hex_pattern" =~ ^\|[0-9a-f]+\|$ ]] || die "invalid SNI pattern"
        [[ "$server_name" =~ ^[a-z0-9]+([.-][a-z0-9]+)*$ ]] ||
            die "invalid server name"
        "$IPTABLES" -w 5 -A "$CHAIN" -p tcp --dport "$port" \
            -m set --match-set "$CANARY_SET" src \
            -m u32 --u32 "$u32_expr" \
            -m string --hex-string "$hex_pattern" --algo bm \
            -j NFQUEUE --queue-num "$QUEUE_NUMBER" --queue-bypass
        installed=$((installed + 1))
    done <<< "$output"
    ((installed > 0)) || die "no lineage queue rules were generated"
    "$IPTABLES" -w 5 -A "$CHAIN" -p udp --dport 443 \
        -m set --match-set "$CANARY_SET" src \
        -j NFQUEUE --queue-num "$QUEUE_NUMBER" --queue-bypass
    "$IPTABLES" -w 5 -A "$CHAIN" -p udp --sport 443 \
        -m set --match-set "$CANARY_SET" dst \
        -j NFQUEUE --queue-num "$QUEUE_NUMBER" --queue-bypass
    "$IPTABLES" -w 5 -A "$CHAIN" -j RETURN
    remove_forward_jumps
    "$IPTABLES" -w 5 -I FORWARD 1 -j "$CHAIN"
}

install_gate() {
    [[ -d "$EASYPI_ROOT/prism_dpi/lineage_gate" ]] || die "Lineage Gate is not deployed"
    "$PYTHON" -c 'import netfilterqueue' >/dev/null 2>&1 ||
        die "python3-netfilterqueue is not installed"
    if ! /usr/bin/id -u "$SERVICE_USER" >/dev/null 2>&1; then
        /usr/sbin/useradd --system --home-dir "$STATE_DIR" \
            --shell /usr/sbin/nologin --user-group "$SERVICE_USER"
    fi
    /usr/bin/install -d -o "$SERVICE_USER" -g "$SERVICE_USER" -m 0750 "$STATE_DIR"
    write_environment
    write_unit
    "$SYSTEMCTL" daemon-reload
    "$SYSTEMCTL" enable "$SERVICE"
    "$SYSTEMCTL" restart "$SERVICE"
    "$SYSTEMCTL" is-active --quiet "$SERVICE" || die "lineage service failed to start"
    install_firewall_rules
    echo "PRISM TLS Lineage Gate installed; canary set is empty"
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

remove_gate() {
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
    echo "PRISM TLS Lineage Gate removed"
}

enable_canary() {
    local client_ip="$1"
    is_private_ipv4 "$client_ip" || die "canary IP must be private IPv4"
    "$SYSTEMCTL" is-active --quiet "$SERVICE" || die "lineage service is not active"
    "$IPTABLES" -w 5 -nL "$CHAIN" >/dev/null 2>&1 || die "lineage chain is not installed"
    "$IPSET" add "$CANARY_SET" "$client_ip" timeout "$CANARY_TTL_SEC" -exist
    echo "PRISM TLS Lineage Gate canary enabled for $client_ip (${CANARY_TTL_SEC}s)"
}

disable_canary() {
    local client_ip="$1"
    is_private_ipv4 "$client_ip" || die "canary IP must be private IPv4"
    "$IPSET" del "$CANARY_SET" "$client_ip" 2>/dev/null || true
    echo "PRISM TLS Lineage Gate canary disabled for $client_ip"
}

show_status() {
    "$SYSTEMCTL" is-enabled "$SERVICE" || true
    "$SYSTEMCTL" is-active "$SERVICE" || true
    "$IPTABLES" -w 5 -nL "$CHAIN" -v --line-numbers 2>/dev/null || true
    "$IPSET" list "$CANARY_SET" 2>/dev/null || true
    /usr/bin/cat /proc/net/netfilter/nfnetlink_queue 2>/dev/null || true
    if [[ -f "$STATE_DIR/gate.jsonl" && ! -L "$STATE_DIR/gate.jsonl" ]]; then
        /usr/bin/tail -n 10 "$STATE_DIR/gate.jsonl"
    fi
}

require_root
case "${1:-}" in
    install)
        [[ $# -eq 1 ]] || die "usage: setup_prism_lineage.sh install"
        install_gate
        ;;
    remove)
        [[ $# -eq 1 ]] || die "usage: setup_prism_lineage.sh remove"
        remove_gate
        ;;
    canary-enable)
        [[ $# -eq 2 ]] || die "usage: setup_prism_lineage.sh canary-enable PRIVATE_IPV4"
        enable_canary "$2"
        ;;
    canary-disable)
        [[ $# -eq 2 ]] || die "usage: setup_prism_lineage.sh canary-disable PRIVATE_IPV4"
        disable_canary "$2"
        ;;
    status)
        [[ $# -eq 1 ]] || die "usage: setup_prism_lineage.sh status"
        show_status
        ;;
    *) die "unsupported action" ;;
esac
