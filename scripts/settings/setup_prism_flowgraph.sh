#!/bin/bash
# Install and control the metadata-only PRISM FlowGraph observer.

set -euo pipefail

export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
umask 077

EASYPI_ROOT="/opt/EasyPi"
SERVICE="easypi-prism-flowgraph.service"
UNIT_PATH="/etc/systemd/system/${SERVICE}"
SHADOW_SERVICE="easypi-prism-shadow.service"
SHADOW_UNIT_PATH="/etc/systemd/system/${SHADOW_SERVICE}"
SHADOW_SETUP="${EASYPI_ROOT}/scripts/settings/setup_prism_shadow.sh"
ENV_PATH="/etc/default/easypi-prism-flowgraph"
STATE_DIR="/var/lib/easypi/prism"
SYSTEMCTL="/usr/bin/systemctl"
IP="/usr/sbin/ip"

die() {
    echo "setup_prism_flowgraph: $*" >&2
    exit 1
}

require_root() {
    [[ $EUID -eq 0 ]] || die "root privileges are required"
}

detect_interface() {
    local interface
    interface="$($IP -4 route show default 2>/dev/null | /usr/bin/awk 'NR == 1 { for (i = 1; i <= NF; i++) if ($i == "dev") { print $(i + 1); exit } }')"
    [[ "$interface" =~ ^[A-Za-z0-9_.:-]{1,15}$ ]] ||
        die "cannot determine a safe default network interface"
    [[ -d "/sys/class/net/$interface" ]] || die "network interface does not exist"
    printf '%s\n' "$interface"
}

write_environment() {
    local interface="$1" temp
    temp="$(/usr/bin/mktemp /etc/default/.easypi-prism-flowgraph.XXXXXX)"
    /usr/bin/printf 'PRISM_INTERFACE=%s\n' "$interface" > "$temp"
    /usr/bin/chown root:root "$temp"
    /usr/bin/chmod 0644 "$temp"
    /usr/bin/mv -f -- "$temp" "$ENV_PATH"
}

verify_shadow_setup() {
    local owner mode
    [[ -f "$SHADOW_SETUP" && ! -L "$SHADOW_SETUP" && -x "$SHADOW_SETUP" ]] ||
        die "trusted Prism shadow setup script is missing"
    owner="$(/usr/bin/stat -c '%u' -- "$SHADOW_SETUP")" ||
        die "cannot inspect Prism shadow setup owner"
    mode="$(/usr/bin/stat -c '%a' -- "$SHADOW_SETUP")" ||
        die "cannot inspect Prism shadow setup mode"
    [[ "$owner" == "0" ]] || die "Prism shadow setup must be root-owned"
    (( (8#$mode & 8#022) == 0 )) ||
        die "Prism shadow setup must not be group/other writable"
}

write_shadow_unit() {
    local temp
    temp="$(/usr/bin/mktemp /etc/systemd/system/.easypi-prism-shadow.XXXXXX)"
    /usr/bin/cat > "$temp" <<'EOF'
[Unit]
Description=EasyPi PRISM exact-flow firewall foundation
After=network-online.target
Wants=network-online.target
Before=easypi-prism-flowgraph.service
ConditionPathExists=/opt/EasyPi/scripts/settings/setup_prism_shadow.sh
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=oneshot
RemainAfterExit=yes
UMask=0077
ExecStart=/opt/EasyPi/scripts/settings/setup_prism_shadow.sh ensure
ExecReload=/opt/EasyPi/scripts/settings/setup_prism_shadow.sh ensure
ExecStop=/opt/EasyPi/scripts/settings/setup_prism_shadow.sh disable
NoNewPrivileges=yes
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_MODULE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_SYS_MODULE
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectKernelTunables=yes
ProtectKernelLogs=yes
ProtectControlGroups=yes
ProtectClock=yes
ProtectHostname=yes
RestrictNamespaces=yes
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
SystemCallArchitectures=native
RestrictAddressFamilies=AF_NETLINK AF_INET AF_INET6 AF_UNIX
LimitNOFILE=1024
MemoryMax=64M
CPUQuota=20%

StandardOutput=journal
StandardError=journal
SyslogIdentifier=easypi-prism-shadow

[Install]
WantedBy=multi-user.target
EOF
    /usr/bin/chown root:root "$temp"
    /usr/bin/chmod 0644 "$temp"
    /usr/bin/mv -f -- "$temp" "$SHADOW_UNIT_PATH"
}

write_unit() {
    local temp
    temp="$(/usr/bin/mktemp /etc/systemd/system/.easypi-prism-flowgraph.XXXXXX)"
    /usr/bin/cat > "$temp" <<'EOF'
[Unit]
Description=EasyPi PRISM FlowGraph shadow analyzer
After=network-online.target easypi-prism-shadow.service
Wants=network-online.target
Requires=easypi-prism-shadow.service
ConditionPathExists=/opt/EasyPi/prism_dpi/flowgraph/__main__.py
StartLimitIntervalSec=300
StartLimitBurst=5

[Service]
Type=simple
User=easypi
Group=easypi
UMask=0027
WorkingDirectory=/opt/EasyPi
EnvironmentFile=/etc/default/easypi-prism-flowgraph
Environment=PYTHONPATH=/opt/EasyPi
Environment=PYTHONDONTWRITEBYTECODE=1
Environment=PRISM_STATE_PATH=/var/lib/easypi/prism/flowgraph.jsonl
ExecStart=/usr/bin/python3 -m prism_dpi.flowgraph live --interface ${PRISM_INTERFACE}
Restart=on-failure
RestartSec=3
TimeoutStopSec=10
Nice=10

# Passive capture only. The service cannot alter routes or firewall policy.
AmbientCapabilities=CAP_NET_RAW
CapabilityBoundingSet=CAP_NET_RAW
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
RestrictAddressFamilies=AF_PACKET AF_INET AF_INET6 AF_NETLINK AF_UNIX
ReadWritePaths=/var/lib/easypi/prism

LimitNOFILE=4096
MemoryMax=128M
CPUQuota=15%

StandardOutput=journal
StandardError=journal
SyslogIdentifier=easypi-prism-flowgraph

[Install]
WantedBy=multi-user.target
EOF
    /usr/bin/chown root:root "$temp"
    /usr/bin/chmod 0644 "$temp"
    /usr/bin/mv -f -- "$temp" "$UNIT_PATH"
}

install_service() {
    local interface
    [[ -x /usr/bin/python3 ]] || die "python3 is not available"
    [[ -x "$IP" ]] || die "iproute2 is not available"
    [[ -d "$EASYPI_ROOT/prism_dpi/flowgraph" ]] || die "PRISM FlowGraph is not deployed"
    /usr/bin/id -u easypi >/dev/null 2>&1 || die "easypi service account does not exist"
    verify_shadow_setup
    interface="$(detect_interface)"
    /usr/bin/install -d -o easypi -g easypi -m 0750 "$STATE_DIR"
    write_environment "$interface"
    write_shadow_unit
    write_unit
    "$SYSTEMCTL" daemon-reload
    "$SYSTEMCTL" enable "$SHADOW_SERVICE"
    "$SYSTEMCTL" enable "$SERVICE"
    "$SYSTEMCTL" restart "$SHADOW_SERVICE" ||
        die "Prism firewall foundation failed to start"
    "$SYSTEMCTL" is-active --quiet "$SHADOW_SERVICE" ||
        die "Prism firewall foundation is not active"
    "$SYSTEMCTL" restart "$SERVICE"
    "$SYSTEMCTL" is-active --quiet "$SERVICE" ||
        die "Prism FlowGraph is not active"
    echo "PRISM FlowGraph installed with exact-flow enforcement ready on $interface"
}

remove_service() {
    "$SYSTEMCTL" disable --now "$SERVICE" >/dev/null 2>&1 || true
    "$SYSTEMCTL" disable --now "$SHADOW_SERVICE" >/dev/null 2>&1 || true
    /usr/bin/rm -f -- "$UNIT_PATH" "$SHADOW_UNIT_PATH" "$ENV_PATH"
    "$SYSTEMCTL" daemon-reload
    echo "PRISM FlowGraph service removed; captured metadata retained"
}

control_service() {
    local action="$1"
    [[ -f "$UNIT_PATH" ]] || die "PRISM FlowGraph service is not installed"
    if [[ "$action" == "start" || "$action" == "restart" ]]; then
        "$SYSTEMCTL" reload-or-restart "$SHADOW_SERVICE"
    fi
    "$SYSTEMCTL" "$action" "$SERVICE"
}

show_status() {
    if [[ ! -f "$UNIT_PATH" ]]; then
        echo "PRISM FlowGraph is not installed"
        return 3
    fi
    "$SYSTEMCTL" is-active "$SHADOW_SERVICE"
    "$SYSTEMCTL" is-enabled "$SERVICE" || true
    "$SYSTEMCTL" is-active "$SERVICE"
    if [[ -f "$STATE_DIR/flowgraph.jsonl" && ! -L "$STATE_DIR/flowgraph.jsonl" ]]; then
        /usr/bin/tail -n 5 "$STATE_DIR/flowgraph.jsonl"
    fi
}

require_root
case "${1:-}" in
    install)
        [[ $# -eq 1 ]] || die "usage: setup_prism_flowgraph.sh install"
        install_service
        ;;
    remove)
        [[ $# -eq 1 ]] || die "usage: setup_prism_flowgraph.sh remove"
        remove_service
        ;;
    start|stop|restart)
        [[ $# -eq 1 ]] || die "usage: setup_prism_flowgraph.sh ${1:-ACTION}"
        control_service "$1"
        ;;
    status)
        [[ $# -eq 1 ]] || die "usage: setup_prism_flowgraph.sh status"
        show_status
        ;;
    *) die "unsupported action" ;;
esac
