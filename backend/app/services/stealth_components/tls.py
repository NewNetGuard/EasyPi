"""StealthTlsMixin implementation."""

from __future__ import annotations

# ruff: noqa: F401

from app.services.stealth_components.context import (
    Any,
    CLIENT_LOG,
    CONFIG_NAME,
    Dict,
    Ed25519PrivateKey,
    List,
    META_NAME,
    Optional,
    Path,
    REMOTE_SERVER_DIR,
    SCRIPT_REL,
    SECRET_SCRIPT_REL,
    SERVER_BIN,
    X25519PrivateKey,
    _DUCKDNS_DOMAIN,
    _DeploymentLease,
    _HEX32,
    _deployment_locked,
    _friendly_ssh_err,
    _gen_psk,
    _gen_x25519_public,
    _normalize_server_addr,
    asyncio,
    base64,
    detect_routing_conflict,
    get_easypi_root,
    get_netprotection_data_dir,
    hashlib,
    hmac,
    httpx,
    io,
    ipaddress,
    json,
    logger,
    logging,
    os,
    posixpath,
    re,
    require_public_ipv4,
    routing_claim,
    serialization,
    socket,
    ssl,
    subprocess,
    time,
    wraps,
)


class StealthTlsMixin:
    def _server_config_json(
        self,
        meta: Dict[str, Any],
        tls_identity: Optional[str] = None,
    ) -> str:
        addr = meta.get("server_address", "")
        m = re.search(r":(\d+)\s*$", addr)
        listen_port = int(m.group(1)) if m else 443
        if listen_port == 22:  # never bind sshd's port (common client-side typo)
            listen_port = 443
        endpoint_ip = self._ip_shield_address(meta)
        deployed_domain = str(meta.get("ssh", {}).get("domain") or "")
        if not meta.get("ssh", {}).get("domain_tls_deployed"):
            deployed_domain = ""
        identity = tls_identity or deployed_domain or endpoint_ip
        cfg = {
            "listen_port": listen_port,
            "bootstrap_port": 8443,
            "frontend_mode": "nginx",
            "backend_address": "127.0.0.1:9080",
            "psk_key": meta["psk_key"],
            "client_auth_key": meta.get("client_auth_key", ""),
            "mobile_clients_file": f"{REMOTE_SERVER_DIR}/mobile_clients.json",
            "reality_public_key": meta["reality_public"],
            "shield_preset": "ip",
            "shield_domain": "",
            "probe_mode": "local",
            "probe_target": "127.0.0.1:9443",
            "block_quic_udp443": bool(meta.get("block_quic")),
            "upstream_dns": "1.1.1.1:53",
            "log_level": "info",
            "tls_cert": f"{REMOTE_SERVER_DIR}/tls/fullchain.pem",
            "tls_key": f"{REMOTE_SERVER_DIR}/tls/privkey.pem",
            "domain": identity,
            "site_dir": "site",
            # Sessions, server-wide. Behind nginx each registered device holds
            # at most one live session (the registry allows 200 devices), so
            # this is a ceiling, not a target; memory stays bounded by the
            # unit's MemoryHigh/MemoryMax and nginx's own limits.
            "max_connections": 4096,
            "max_requests_per_session": 8,
            "max_sessions_per_source": 8,
            "max_pre_auth_connections": 256,
            "max_pre_auth_per_ip": 32,
        }
        return json.dumps(cfg, indent=2)

    @staticmethod
    def _nginx_frontend_config(meta: Dict[str, Any]) -> str:
        """Return the real public TLS/H2 cover frontend for Chameleon."""
        psk = bytes.fromhex(str(meta["psk_key"]))
        digest = hmac.new(
            psk, b"chameleon-route-prefix-v1", hashlib.sha256
        ).digest()
        alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        route_prefix = "".join(
            alphabet[int.from_bytes(digest[index : index + 2], "big") % len(alphabet)]
            for index in range(0, 16, 2)
        )
        # IPv6 too: some mobile networks reach the VPS cleanly only over IPv6
        # (its IPv4 transit into Telekom lost ~44% of the tunnel's data).
        return f"""server {{
    listen 0.0.0.0:443 ssl http2 default_server;
    listen [::]:443 ssl http2 default_server;
    server_name _;
    server_tokens off;

    ssl_certificate {REMOTE_SERVER_DIR}/tls/fullchain.pem;
    ssl_certificate_key {REMOTE_SERVER_DIR}/tls/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:CHAMELEON:10m;
    ssl_session_timeout 1d;

    access_log off;
    error_log /var/log/nginx/chameleon-error.log crit;
    root {REMOTE_SERVER_DIR}/site;
    index index.html;
    client_max_body_size 0;
    # A browser keeps using one connection to a site. The default of 1000
    # requests made nginx send GOAWAY and pushed the tunnel onto extra
    # connections; the client already replaces its connection on its own.
    keepalive_requests 1000000;

    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options SAMEORIGIN always;
    add_header Referrer-Policy strict-origin-when-cross-origin always;

    location ^~ /{route_prefix}/ {{
        proxy_pass http://127.0.0.1:9080;
        proxy_http_version 1.1;
        proxy_request_buffering off;
        proxy_buffering off;
        # Read the tunnel stream in up to 16 KiB pieces. The 4 KiB default made
        # every downstream TLS record exactly 4122 bytes, unlike real sites.
        proxy_buffer_size 16k;
        proxy_buffers 8 16k;
        proxy_cache off;
        proxy_socket_keepalive on;
        proxy_read_timeout 24h;
        proxy_send_timeout 24h;
        send_timeout 24h;
        # The upload stream is one long request that stays silent while the
        # network is idle; the 60 s default cut it and the client reconnected
        # every minute.
        client_body_timeout 24h;
        # With unbuffered bodies nginx returns HTTP/2 flow-control credit only
        # as this buffer drains, so it caps each upload at about one buffer per
        # round trip: the 16 KiB default held uploads near 1 MB/s and 512k
        # near 15 MB/s at 30 ms. 1m is the size the WINDOW_UPDATE threshold
        # patch was measured with (chameleon/tools/nginx-h2-window): full
        # speed with about 100 updates per 25 MB. Each streamed request gets
        # one buffer, but only the part actually filled becomes resident.
        client_body_buffer_size 1m;
        proxy_set_header Host $http_host;
        proxy_set_header Connection "";
        proxy_set_header X-Real-IP "";
        proxy_set_header X-Forwarded-For "";
        proxy_set_header X-Forwarded-Proto "";
        proxy_hide_header Server;
        # Authentication failures look exactly like any other missing page,
        # so the tunnel path cannot be told apart from the rest of the site.
        proxy_intercept_errors on;
        error_page 401 403 404 405 =404 @not_found;
    }}

    location @not_found {{
        return 404;
    }}

    location = / {{
        try_files /index.html =404;
    }}

    location = /index.html {{
    }}

    location = /robots.txt {{
    }}

    location = /favicon.ico {{
    }}

    # The cover site is a flat directory, published under /assets/ exactly as
    # the server's own frontend does (http.StripPrefix + FileServer).
    location ^~ /assets/ {{
        alias {REMOTE_SERVER_DIR}/site/;
    }}

    location / {{
        return 404;
    }}
}}
"""

    @staticmethod
    def _server_systemd_unit() -> str:
        """Return the least-privilege unit for the loopback Chameleon backend."""
        return (
            "[Unit]\nDescription=Chameleon stealth server\nAfter=network-online.target\n"
            "Wants=network-online.target\nRequires=chameleon-network.service\n"
            "BindsTo=chameleon-network.service\n"
            "After=chameleon-network.service\n[Service]\n"
            "User=chameleon\nGroup=chameleon\n"
            f"ExecStart={REMOTE_SERVER_DIR}/chameleon-server\n"
            f"WorkingDirectory={REMOTE_SERVER_DIR}\n"
            "Environment=CHAMELEON_NETWORK_PREPARED=1\n"
            "CapabilityBoundingSet=\n"
            "DeviceAllow=/dev/net/tun rw\n"
            "NoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\n"
            "ProtectHome=yes\nProtectKernelTunables=yes\nProtectKernelModules=yes\n"
            "ProtectControlGroups=yes\n"
            "ProtectClock=yes\nProtectHostname=yes\nRestrictSUIDSGID=yes\n"
            "LockPersonality=yes\nSystemCallArchitectures=native\n"
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n"
            "UMask=0077\nMemoryHigh=60%\nMemoryMax=75%\nTasksMax=512\n"
            "Restart=always\nRestartSec=3\nLimitNOFILE=65536\n"
            "[Install]\nWantedBy=multi-user.target\n"
        )

    @staticmethod
    def _network_setup_script() -> str:
        return f"""#!/bin/sh
set -eu
TUN=chameleon0
CIDR=10.10.0.1/24
SUBNET=10.10.0.0/24
CONFIG={REMOTE_SERVER_DIR}/server_config.json
ACTION="${{1:-start}}"
iface="$(ip route get 1.1.1.1 | awk '{{for(i=1;i<=NF;i++) if ($i=="dev") {{print $(i+1); exit}}}}')"
test -n "$iface"
remove_rule() {{
  table="$1"; shift
  if [ "$table" = filter ]; then
    while iptables -C "$@" >/dev/null 2>&1; do iptables -D "$@"; done
  else
    while iptables -t "$table" -C "$@" >/dev/null 2>&1; do iptables -t "$table" -D "$@"; done
  fi
}}
# Tunnel clients may reach the internet and the VPS's public address (exactly
# as anyone on the internet can), never the VPS's internal addresses or the
# networks behind it (docker, WireGuard, the tunnel subnet itself). The denied
# list matches the TCP stream server's destination policy.
TUN_IN_CHAIN=CHAMELEON_TUN_IN
TUN_FWD_CHAIN=CHAMELEON_TUN_FWD
DENIED_DESTINATIONS="0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.0.0.0/24 192.0.2.0/24 192.88.99.0/24 192.168.0.0/16 198.18.0.0/15 198.51.100.0/24 203.0.113.0/24 224.0.0.0/4 240.0.0.0/4"
remove_tunnel_isolation() {{
  while iptables -C INPUT -i "$TUN" -j "$TUN_IN_CHAIN" >/dev/null 2>&1; do
    iptables -D INPUT -i "$TUN" -j "$TUN_IN_CHAIN"
  done
  while iptables -C FORWARD -i "$TUN" -j "$TUN_FWD_CHAIN" >/dev/null 2>&1; do
    iptables -D FORWARD -i "$TUN" -j "$TUN_FWD_CHAIN"
  done
  while iptables -C DOCKER-USER -i "$TUN" -j "$TUN_FWD_CHAIN" >/dev/null 2>&1; do
    iptables -D DOCKER-USER -i "$TUN" -j "$TUN_FWD_CHAIN"
  done
  for chain in "$TUN_IN_CHAIN" "$TUN_FWD_CHAIN"; do
    iptables -F "$chain" >/dev/null 2>&1 || true
    iptables -X "$chain" >/dev/null 2>&1 || true
  done
}}
install_tunnel_isolation() {{
  uplink="$1"
  remove_tunnel_isolation
  public="$(ip -4 -o addr show dev "$uplink" | awk '{{split($4, a, "/"); print a[1]}}')"
  test -n "$public"
  iptables -N "$TUN_IN_CHAIN"
  iptables -A "$TUN_IN_CHAIN" -m conntrack --ctstate RELATED,ESTABLISHED -j RETURN
  for address in $public; do
    iptables -A "$TUN_IN_CHAIN" -d "$address" -j RETURN
  done
  iptables -A "$TUN_IN_CHAIN" -j DROP
  iptables -N "$TUN_FWD_CHAIN"
  for address in $public; do
    # Services published on the public address (DNAT, e.g. docker ports).
    iptables -A "$TUN_FWD_CHAIN" -m conntrack --ctstate DNAT --ctorigdst "$address" -j RETURN
  done
  for prefix in $DENIED_DESTINATIONS; do
    iptables -A "$TUN_FWD_CHAIN" -d "$prefix" -j DROP
  done
  iptables -A "$TUN_FWD_CHAIN" ! -o "$uplink" -j DROP
  iptables -I INPUT 1 -i "$TUN" -j "$TUN_IN_CHAIN"
  iptables -I FORWARD 1 -i "$TUN" -j "$TUN_FWD_CHAIN"
  # Docker re-inserts its FORWARD jumps at the top when it restarts and
  # accepts published container ports there; DOCKER-USER runs before them.
  if iptables -n -L DOCKER-USER >/dev/null 2>&1; then
    iptables -I DOCKER-USER 1 -i "$TUN" -j "$TUN_FWD_CHAIN"
  fi
}}
if [ "$ACTION" = stop ]; then
  remove_tunnel_isolation
  remove_rule filter FORWARD -i "$TUN" -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable
  remove_rule filter OUTPUT -o "$iface" -p udp -s "$SUBNET" --dport 443 -j REJECT --reject-with icmp-port-unreachable
  remove_rule mangle FORWARD -o "$TUN" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
  remove_rule mangle FORWARD -i "$TUN" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
  remove_rule filter FORWARD -o "$TUN" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
  remove_rule filter FORWARD -i "$TUN" -j ACCEPT
  remove_rule nat POSTROUTING -s "$SUBNET" -o "$iface" -j MASQUERADE
  ip link delete "$TUN" 2>/dev/null || true
  exit 0
fi
test "$ACTION" = start
created_tun=0
if ! ip link show dev "$TUN" >/dev/null 2>&1; then
  ip tuntap add dev "$TUN" mode tun user chameleon
  created_tun=1
fi
expected_uid="$(id -u chameleon)"
if ! ip -j tuntap show dev "$TUN" 2>/dev/null | python3 -c '
import json
import sys

rows = json.load(sys.stdin)
name = sys.argv[1]
uid = int(sys.argv[2])
matches = [row for row in rows if row.get("ifname") == name]
valid = (
    len(matches) == 1
    and "tun" in matches[0].get("flags", [])
    and matches[0].get("user") == uid
)
raise SystemExit(0 if valid else 1)
' "$TUN" "$expected_uid"; then
  if [ "$created_tun" = 1 ]; then
    ip link delete "$TUN" 2>/dev/null || true
  fi
  echo "existing $TUN is not a TUN owned by chameleon; refusing firewall changes" >&2
  exit 70
fi
ip link set dev "$TUN" mtu 1420
ip addr replace "$CIDR" dev "$TUN"
ip link set dev "$TUN" up
sysctl -q -w net.ipv4.ip_forward=1
# The restricted Chameleon service cannot tune kernel networking itself. Apply
# the same best-effort throughput settings used by the standalone server path
# from this root-owned setup unit. Unsupported kernels keep their current
# congestion control; deployment must never fail solely because BBR is absent.
sysctl -q -w net.core.rmem_max=67108864 || true
sysctl -q -w net.core.wmem_max=67108864 || true
sysctl -q -w 'net.ipv4.tcp_rmem=4096 87380 67108864' || true
sysctl -q -w 'net.ipv4.tcp_wmem=4096 65536 67108864' || true
if modprobe tcp_bbr >/dev/null 2>&1; then
  sysctl -q -w net.core.default_qdisc=fq || true
  sysctl -q -w net.ipv4.tcp_congestion_control=bbr || true
fi
ensure_rule() {{
  table="$1"; shift
  if [ "$table" = filter ]; then
    iptables -C "$@" >/dev/null 2>&1 || iptables -A "$@"
  else
    iptables -t "$table" -C "$@" >/dev/null 2>&1 || iptables -t "$table" -A "$@"
  fi
}}
ensure_rule nat POSTROUTING -s "$SUBNET" -o "$iface" -j MASQUERADE
ensure_rule filter FORWARD -i "$TUN" -j ACCEPT
ensure_rule filter FORWARD -o "$TUN" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
ensure_rule mangle FORWARD -i "$TUN" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
ensure_rule mangle FORWARD -o "$TUN" -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu
install_tunnel_isolation "$iface"
block_quic="$(python3 -c 'import json,sys; print("1" if json.load(open(sys.argv[1])) .get("block_quic_udp443") else "0")' "$CONFIG")"
while iptables -C FORWARD -i "$TUN" -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable >/dev/null 2>&1; do
  iptables -D FORWARD -i "$TUN" -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable
done
while iptables -C OUTPUT -o "$iface" -p udp -s "$SUBNET" --dport 443 -j REJECT --reject-with icmp-port-unreachable >/dev/null 2>&1; do
  iptables -D OUTPUT -o "$iface" -p udp -s "$SUBNET" --dport 443 -j REJECT --reject-with icmp-port-unreachable
done
if [ "$block_quic" = 1 ]; then
  iptables -I FORWARD 1 -i "$TUN" -p udp --dport 443 -j REJECT --reject-with icmp-port-unreachable
  iptables -I OUTPUT 1 -o "$iface" -p udp -s "$SUBNET" --dport 443 -j REJECT --reject-with icmp-port-unreachable
fi
"""

    @staticmethod
    def _network_systemd_unit() -> str:
        return (
            "[Unit]\nDescription=Prepare Chameleon TUN and firewall\n"
            "After=network-online.target\nWants=network-online.target\n"
            "PartOf=chameleon-server.service\nBefore=chameleon-server.service\n"
            "[Service]\nType=oneshot\nRemainAfterExit=yes\n"
            "ExecStart=/usr/local/sbin/chameleon-network-setup start\n"
            "ExecStop=/usr/local/sbin/chameleon-network-setup stop\n"
            "User=root\nGroup=root\nCapabilityBoundingSet=CAP_NET_ADMIN\n"
            "DeviceAllow=/dev/net/tun rw\n"
            "NoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\n"
            "ProtectHome=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\n"
            "ProtectClock=yes\nProtectHostname=yes\nRestrictSUIDSGID=yes\n"
            "LockPersonality=yes\nSystemCallArchitectures=native\n"
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n"
            "[Install]\nWantedBy=multi-user.target\n"
        )

    @staticmethod
    def _certificate_install_script() -> str:
        return f"""#!/bin/sh
set -eu
lineage="${{RENEWED_LINEAGE:-}}"
case "$lineage" in
  /etc/letsencrypt/live/*) ;;
  *) echo "invalid certificate lineage" >&2; exit 1 ;;
esac
test -s "$lineage/fullchain.pem"
test -s "$lineage/privkey.pem"
install -d -o root -g chameleon -m 0750 {REMOTE_SERVER_DIR}/tls
install -o root -g chameleon -m 0640 "$lineage/fullchain.pem" {REMOTE_SERVER_DIR}/tls/.fullchain.pem.new
install -o root -g chameleon -m 0640 "$lineage/privkey.pem" {REMOTE_SERVER_DIR}/tls/.privkey.pem.new
mv -f -- {REMOTE_SERVER_DIR}/tls/.fullchain.pem.new {REMOTE_SERVER_DIR}/tls/fullchain.pem
mv -f -- {REMOTE_SERVER_DIR}/tls/.privkey.pem.new {REMOTE_SERVER_DIR}/tls/privkey.pem
if [ "${{CHAMELEON_CERT_INSTALL_ONLY:-0}}" = 1 ]; then
  exit 0
fi
systemctl restart chameleon-network.service chameleon-server.service
systemctl is-active --quiet chameleon-network.service
systemctl is-active --quiet chameleon-server.service
ip link show dev chameleon0 >/dev/null 2>&1
if [ -s /etc/nginx/conf.d/easypi-chameleon.conf ]; then
  nginx -t
  # Standalone HTTP-01 temporarily stops nginx. In that path the wrapper starts
  # it after Certbot exits, which loads the renewed certificate. Other calls
  # reload the already running frontend without interrupting existing streams.
  if systemctl is-active --quiet nginx.service; then
    systemctl reload nginx.service
  fi
fi
"""

    @staticmethod
    def _tls_material_install_command(
        identity: str, *, install_only: bool = False
    ) -> str:
        install_mode = "CHAMELEON_CERT_INSTALL_ONLY=1 " if install_only else ""
        return (
            f"RENEWED_LINEAGE=/etc/letsencrypt/live/{identity} "
            f"{install_mode}/usr/local/sbin/chameleon-install-cert"
        )

    @staticmethod
    def _standalone_certbot_wrapper() -> str:
        """Run standalone Certbot without leaving the VPS web server stopped."""
        return """#!/bin/sh
set -eu
runtime_dir=/run/chameleon-certbot
marker=$runtime_dir/nginx-was-active
guard=/usr/local/sbin/easypi-vps-guard
certbot_lock=/run/easypi-certbot.lock

install -d -o root -g root -m 0700 "$runtime_dir"

restore_nginx() {
  if [ -e "$marker" ]; then
    if systemctl start nginx.service; then
      rm -f -- "$marker"
      return 0
    fi
    echo "failed to restore nginx.service after certificate operation" >&2
    return 1
  fi
}

cleanup() {
  rc=$?
  trap - EXIT HUP INT TERM
  guard_rc=0
  if [ -x "$guard" ] && ! "$guard" acme-close; then
    echo "failed to close public TCP port 80 after certificate operation" >&2
    guard_rc=1
  fi
  nginx_rc=0
  if ! restore_nginx; then
    nginx_rc=1
  fi
  if [ "$guard_rc" -ne 0 ] || [ "$nginx_rc" -ne 0 ]; then
    exit 74
  fi
  exit "$rc"
}

trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [ "${1:-}" = "--restore" ]; then
  if [ -x "$guard" ]; then
    "$guard" acme-close
  fi
  restore_nginx
  exit 0
fi

# Recover nginx after an interrupted earlier invocation before doing anything
# else. The marker is root-owned in /run and cannot be planted by Chameleon.
restore_nginx

exec 9>"$certbot_lock"
if ! flock -w 180 9; then
  echo "timed out waiting for another EasyPi certificate operation" >&2
  exit 75
fi

if [ -x "$guard" ]; then
  "$guard" acme-open
fi

if ss -H -ltn 'sport = :80' 2>/dev/null | grep -q .; then
  if ! systemctl is-active --quiet nginx.service; then
    echo "TCP port 80 is occupied by a non-nginx process; refusing to stop it" >&2
    exit 73
  fi
  : > "$marker"
  chmod 0600 "$marker"
  systemctl stop nginx.service
  if ss -H -ltn 'sport = :80' 2>/dev/null | grep -q .; then
    echo "TCP port 80 remains occupied after nginx.service stopped" >&2
    exit 73
  fi
fi

"$@"
""".replace("\r\n", "\n")

    @staticmethod
    def _vps_guard_script() -> str:
        """Keep public HTTP and echo-request closed except during ACME."""
        return """#!/bin/sh
set -eu
chain=EASYPI_VPS_GUARD
action="${1:-apply}"

has_v6=0
if command -v ip6tables >/dev/null 2>&1 && ip6tables -S INPUT >/dev/null 2>&1; then
  has_v6=1
fi

ensure_chain() {
  tool="$1"
  "$tool" -N "$chain" 2>/dev/null || true
  "$tool" -C INPUT -j "$chain" >/dev/null 2>&1 || "$tool" -I INPUT 1 -j "$chain"
}

ensure_rule() {
  tool="$1"; shift
  "$tool" -C "$chain" "$@" >/dev/null 2>&1 || "$tool" -A "$chain" "$@"
}

remove_rule() {
  tool="$1"; shift
  while "$tool" -C "$chain" "$@" >/dev/null 2>&1; do
    "$tool" -D "$chain" "$@"
  done
}

apply_base() {
  tool="$1"; proto="$2"; type_option="$3"; echo_type="$4"
  ensure_chain "$tool"
  ensure_rule "$tool" '!' -i lo -p "$proto" "$type_option" "$echo_type" -j DROP
}

close_http() {
  tool="$1"
  ensure_chain "$tool"
  ensure_rule "$tool" '!' -i lo -p tcp --dport 80 -j DROP
}

open_http() {
  tool="$1"
  ensure_chain "$tool"
  remove_rule "$tool" '!' -i lo -p tcp --dport 80 -j DROP
}

remove_all() {
  tool="$1"
  while "$tool" -C INPUT -j "$chain" >/dev/null 2>&1; do
    "$tool" -D INPUT -j "$chain"
  done
  "$tool" -F "$chain" 2>/dev/null || true
  "$tool" -X "$chain" 2>/dev/null || true
}

case "$action" in
  apply|acme-close)
    apply_base iptables icmp --icmp-type echo-request
    close_http iptables
    if [ "$has_v6" -eq 1 ]; then
      apply_base ip6tables ipv6-icmp --icmpv6-type echo-request
      close_http ip6tables
    fi
    ;;
  acme-open)
    apply_base iptables icmp --icmp-type echo-request
    open_http iptables
    if [ "$has_v6" -eq 1 ]; then
      apply_base ip6tables ipv6-icmp --icmpv6-type echo-request
      open_http ip6tables
    fi
    ;;
  remove)
    remove_all iptables
    if [ "$has_v6" -eq 1 ]; then remove_all ip6tables; fi
    ;;
  *)
    echo "usage: $0 {apply|acme-open|acme-close|remove}" >&2
    exit 64
    ;;
esac
""".replace("\r\n", "\n")

    @staticmethod
    def _vps_guard_unit() -> str:
        return (
            "[Unit]\nDescription=EasyPi VPS public HTTP and ping guard\n"
            "After=local-fs.target\nBefore=network.target nginx.service "
            "chameleon-server.service\n"
            "[Service]\nType=oneshot\nRemainAfterExit=yes\n"
            "ExecStart=/usr/local/sbin/easypi-vps-guard apply\n"
            "ExecReload=/usr/local/sbin/easypi-vps-guard apply\n"
            "User=root\nGroup=root\n"
            "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW\n"
            "ReadWritePaths=/run/xtables.lock\n"
            "NoNewPrivileges=yes\nPrivateTmp=yes\nProtectSystem=strict\n"
            "ProtectHome=yes\nProtectKernelModules=yes\nProtectControlGroups=yes\n"
            "ProtectClock=yes\nProtectHostname=yes\nRestrictSUIDSGID=yes\n"
            "LockPersonality=yes\nSystemCallArchitectures=native\n"
            "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK\n"
            "[Install]\nWantedBy=multi-user.target\n"
        )

    @staticmethod
    def _certbot_guard_override() -> str:
        return (
            "[Service]\n"
            "ExecStartPre=/usr/local/sbin/easypi-vps-guard acme-open\n"
            "ExecStopPost=/usr/local/sbin/easypi-vps-guard acme-close\n"
        )

    @staticmethod
    def _ip_certificate_issue_command(identity: str) -> str:
        return (
            "/usr/local/sbin/chameleon-certbot-standalone "
            "/opt/chameleon-certbot/bin/certbot certonly --non-interactive --agree-tos "
            "--register-unsafely-without-email --preferred-profile shortlived "
            f"--standalone --ip-address {identity} --cert-name {identity} "
            "--keep-until-expiring"
        )

    @staticmethod
    def _domain_certificate_setup_command(identity: str) -> str:
        certbot = "/opt/chameleon-certbot/bin/certbot"
        wrapper = "/usr/local/sbin/chameleon-certbot-standalone"
        renewal = f"/etc/letsencrypt/renewal/{identity}.conf"
        return (
            f"if test -s {renewal} && "
            f"grep -Eq '^[[:space:]]*authenticator[[:space:]]*=[[:space:]]*"
            f"standalone[[:space:]]*$' {renewal}; then :; "
            f"elif test -s {renewal}; then "
            f"{wrapper} {certbot} reconfigure --non-interactive --agree-tos "
            f"--standalone --preferred-challenges http --cert-name {identity}; "
            "else "
            f"{wrapper} {certbot} certonly --non-interactive --agree-tos "
            "--register-unsafely-without-email --preferred-challenges http "
            f"--standalone -d {identity} --cert-name {identity}; "
            "fi"
        )

    @staticmethod
    def _certificate_renewal_service(*, identity: str) -> str:
        writable = "/etc/letsencrypt /var/lib/letsencrypt /var/log/letsencrypt "
        writable += (
            f"{REMOTE_SERVER_DIR}/tls /run/chameleon-certbot "
            "/run/easypi-certbot.lock"
        )
        return (
            "[Unit]\nDescription=Renew Chameleon TLS certificate\n"
            "After=network-online.target\nWants=network-online.target\n"
            "[Service]\nType=oneshot\n"
            "RuntimeDirectory=chameleon-certbot\nRuntimeDirectoryMode=0700\n"
            "RuntimeDirectoryPreserve=yes\n"
            "ExecStart=/usr/local/sbin/chameleon-certbot-standalone "
            f"/opt/chameleon-certbot/bin/certbot renew --quiet --cert-name {identity} "
            "--deploy-hook /usr/local/sbin/chameleon-install-cert\n"
            "ExecStopPost=/usr/local/sbin/chameleon-certbot-standalone --restore\n"
            "PrivateTmp=true\nProtectHome=true\nProtectSystem=strict\n"
            "NoNewPrivileges=true\n"
            f"ReadWritePaths={writable}\n"
        )

    @staticmethod
    def _legacy_duckdns_cleanup_command() -> str:
        return (
            "rm -f -- /etc/chameleon-secrets/duckdns-token.cred "
            "/etc/chameleon-duckdns.json "
            f"{REMOTE_SERVER_DIR}/duckdns-hook.py "
            "/run/.chameleon-duckdns-token.upload"
        )

    @staticmethod
    def _verify_domain_tls(domain: str, expected_ip: str, timeout: int = 120) -> None:
        deadline = time.monotonic() + timeout
        last_error = "DNS did not resolve to the VPS"
        while time.monotonic() < deadline:
            try:
                public_answers: List[set[str]] = []
                for url in (
                    "https://1.1.1.1/dns-query",
                    "https://8.8.8.8/resolve",
                ):
                    try:
                        response = httpx.get(
                            url,
                            params={"name": domain, "type": "A"},
                            headers={"accept": "application/dns-json"},
                            timeout=8,
                        )
                        response.raise_for_status()
                        payload = response.json()
                        answers = {
                            str(item.get("data"))
                            for item in payload.get("Answer", [])
                            if item.get("type") == 1
                        }
                        if answers:
                            public_answers.append(answers)
                    except Exception:  # noqa: BLE001
                        continue
                if not public_answers:
                    raise RuntimeError("public DNS-over-HTTPS resolvers did not answer")
                if any(expected_ip not in answers for answers in public_answers):
                    visible = sorted(set().union(*public_answers))
                    last_error = (
                        f"public DNS resolves to {', '.join(visible) or 'nothing'}"
                    )
                    time.sleep(3)
                    continue
                context = ssl.create_default_context()
                context.set_alpn_protocols(["h2", "http/1.1"])
                # Connect to the already verified public A record directly. This
                # avoids a stale/negative answer in EasyPi's own filtering resolver
                # while still validating the certificate against the domain/SNI.
                with socket.create_connection((expected_ip, 443), timeout=10) as raw:
                    with context.wrap_socket(raw, server_hostname=domain) as tls_conn:
                        if tls_conn.selected_alpn_protocol() != "h2":
                            raise RuntimeError("server did not negotiate HTTP/2")
                return
            except Exception as exc:  # noqa: BLE001
                last_error = str(exc)
                time.sleep(3)
        raise RuntimeError(f"Domain TLS verification failed: {last_error}")

    @staticmethod
    def _verify_ip_tls(expected_ip: str, timeout: int = 60) -> None:
        """Verify the trusted IP certificate and HTTP/2 before switching the client."""
        endpoint_ip = require_public_ipv4(expected_ip, label="IP Shield endpoint")
        deadline = time.monotonic() + timeout
        last_error = "IP HTTPS endpoint did not answer"
        while time.monotonic() < deadline:
            try:
                context = ssl.create_default_context()
                context.set_alpn_protocols(["h2", "http/1.1"])
                with socket.create_connection((endpoint_ip, 443), timeout=10) as raw:
                    with context.wrap_socket(
                        raw, server_hostname=endpoint_ip
                    ) as tls_conn:
                        if tls_conn.selected_alpn_protocol() != "h2":
                            raise RuntimeError("server did not negotiate HTTP/2")
                return
            except Exception as exc:  # noqa: BLE001
                last_error = str(exc)
                time.sleep(2)
        raise RuntimeError(f"IP Shield TLS verification failed: {last_error}")

    @_deployment_locked("domain-tls")
    async def configure_domain_tls(self) -> Dict[str, Any]:
        """Configure trusted domain TLS, then switch the live client transactionally."""
        meta = self._meta()
        ssh = meta["ssh"]
        domain = self._normalize_duckdns_domain(str(ssh.get("domain") or ""))
        if not domain:
            return {
                "success": False,
                "log": "Enter the DuckDNS domain first.",
            }
        if not ssh.get("acme_terms_accepted"):
            return {
                "success": False,
                "log": "Accept the Let's Encrypt Subscriber Agreement first.",
            }
        if not (
            ssh.get("host") and self._has_ssh_auth(ssh) and ssh.get("host_key_data")
        ):
            return {"success": False, "log": "Save and trust the VPS connection first."}
        try:
            secured = await asyncio.to_thread(self._ensure_secure_credentials)
        except Exception as exc:  # noqa: BLE001
            return {
                "success": False,
                "log": f"Secure SSH credential setup failed: {exc}",
            }
        if not secured.get("success"):
            return secured
        meta = self._meta()
        ssh = meta["ssh"]
        try:
            endpoint_ip = require_public_ipv4(str(ssh["host"]), label="Stealth VPS")
            server_cfg = self._server_config_json(meta, tls_identity=domain)
        except ValueError as exc:
            return {"success": False, "log": str(exc)}

        remote = REMOTE_SERVER_DIR
        old_server_address = str(meta.get("server_address") or "")
        previous_domain_active = bool(ssh.get("domain_tls_deployed"))
        http_renewal_service = self._certificate_renewal_service(identity=domain)

        def _do() -> Dict[str, Any]:
            log: List[str] = []
            previous_config = ""
            previous_renewal = ""
            c = None
            try:
                c = self._connect(ssh)

                def run_checked(command: str, label: str, timeout: int = 300) -> str:
                    _, stdout, stderr = c.exec_command(command, timeout=timeout)
                    output = stdout.read().decode(errors="ignore").strip()
                    error = stderr.read().decode(errors="ignore").strip()
                    rc = stdout.channel.recv_exit_status()
                    detail = "\n".join(part for part in (output, error) if part)
                    log.append(f"{label}: {'ok' if rc == 0 else 'failed'}")
                    if rc != 0:
                        raise RuntimeError(
                            f"{label} failed{(': ' + detail[-500:]) if detail else ''}"
                        )
                    return output

                sftp = c.open_sftp()
                with sftp.file(f"{remote}/server_config.json", "r") as handle:
                    previous_config = handle.read().decode("utf-8")
                try:
                    with sftp.file(
                        "/etc/systemd/system/chameleon-cert-renew.service", "r"
                    ) as handle:
                        previous_renewal = handle.read().decode("utf-8")
                except OSError:
                    previous_renewal = ""
                with sftp.file("/usr/local/sbin/chameleon-install-cert", "w") as handle:
                    handle.write(self._certificate_install_script())
                sftp.chmod("/usr/local/sbin/chameleon-install-cert", 0o700)
                with sftp.file(
                    "/usr/local/sbin/chameleon-certbot-standalone", "w"
                ) as handle:
                    handle.write(self._standalone_certbot_wrapper())
                sftp.chmod("/usr/local/sbin/chameleon-certbot-standalone", 0o700)
                sftp.close()

                run_checked(
                    "/opt/chameleon-certbot/bin/certbot --version 2>/dev/null | "
                    "grep -qx 'certbot 5.4.0' || { rm -rf /opt/chameleon-certbot; "
                    "apt-get update -qq >/dev/null 2>&1; DEBIAN_FRONTEND=noninteractive "
                    "apt-get install -y -qq python3-venv >/dev/null 2>&1; "
                    "python3 -m venv /opt/chameleon-certbot; "
                    "/opt/chameleon-certbot/bin/pip install --disable-pip-version-check "
                    "--no-cache-dir -q certbot==5.4.0; }",
                    "Certbot 5.4 installation",
                    timeout=300,
                )
                run_checked(
                    self._domain_certificate_setup_command(domain),
                    "Domain certificate setup",
                    timeout=360,
                )
                # Certbot now remembers standalone HTTP-01. Publish the matching
                # wrapper unit before deleting legacy DNS hooks so interruption
                # cannot leave the two renewal layers inconsistent.
                sftp = c.open_sftp()
                with sftp.file(
                    "/etc/systemd/system/chameleon-cert-renew.service", "w"
                ) as handle:
                    handle.write(http_renewal_service)
                sftp.close()
                run_checked(
                    "systemctl daemon-reload",
                    "HTTP renewal activation",
                    timeout=30,
                )
                run_checked(
                    self._legacy_duckdns_cleanup_command(),
                    "Legacy DuckDNS cleanup",
                    timeout=30,
                )
                run_checked(
                    f"test -s /etc/letsencrypt/live/{domain}/fullchain.pem && "
                    f"test -s /etc/letsencrypt/live/{domain}/privkey.pem",
                    "Domain certificate verification",
                    timeout=20,
                )
                run_checked(
                    self._tls_material_install_command(domain),
                    "Restricted TLS material install",
                    timeout=20,
                )

                sftp = c.open_sftp()
                config_upload = f"{remote}/.server_config.domain.upload"
                with sftp.file(config_upload, "w") as handle:
                    handle.write(server_cfg)
                sftp.chmod(config_upload, 0o600)
                with sftp.file(
                    "/etc/systemd/system/chameleon-cert-renew.service", "w"
                ) as handle:
                    handle.write(http_renewal_service)
                sftp.close()
                run_checked(
                    f"mv -f -- {config_upload} {remote}/server_config.json && "
                    f"chown root:chameleon {remote}/server_config.json && "
                    f"chmod 0640 {remote}/server_config.json && "
                    "systemctl daemon-reload && systemctl restart chameleon-network && "
                    "systemctl restart chameleon-server",
                    "Chameleon domain activation",
                    timeout=45,
                )
                run_checked(
                    "systemctl is-active chameleon-server",
                    "Chameleon health",
                    timeout=20,
                )
                self._verify_domain_tls(domain, endpoint_ip)
                log.append("DNS, certificate identity, SNI and HTTP/2: verified")
                c.close()
                return {
                    "success": True,
                    "active": True,
                    "log": "\n".join(log),
                    "_previous_config": previous_config,
                    "_previous_renewal": (
                        http_renewal_service
                        if previous_domain_active
                        else previous_renewal
                    ),
                }
            except Exception as exc:  # noqa: BLE001
                log.append(f"ERROR: {exc}{_friendly_ssh_err(str(exc))}")
                try:
                    if previous_config:
                        sftp = c.open_sftp()
                        rollback_upload = f"{remote}/.server_config.rollback.upload"
                        with sftp.file(rollback_upload, "w") as handle:
                            handle.write(previous_config)
                        sftp.chmod(rollback_upload, 0o600)
                        rollback_renewal = (
                            http_renewal_service
                            if previous_domain_active
                            else previous_renewal
                        )
                        if rollback_renewal:
                            with sftp.file(
                                "/etc/systemd/system/chameleon-cert-renew.service", "w"
                            ) as handle:
                                handle.write(rollback_renewal)
                        sftp.close()
                        c.exec_command(
                            f"mv -f -- {rollback_upload} {remote}/server_config.json && "
                            f"chown root:chameleon {remote}/server_config.json && "
                            f"chmod 0640 {remote}/server_config.json && "
                            "systemctl daemon-reload && systemctl restart chameleon-network && "
                            "systemctl restart chameleon-server",
                            timeout=45,
                        )[1].channel.recv_exit_status()
                        log.append("Previous server configuration restored")
                    if c is not None:
                        c.close()
                except Exception:  # noqa: BLE001
                    log.append("WARNING: automatic server rollback failed")
                return {"success": False, "log": "\n".join(log)}

        def _restore_remote(previous_config: str, previous_renewal: str) -> bool:
            if not previous_config:
                return False
            c = None
            try:
                c = self._connect(ssh)
                sftp = c.open_sftp()
                rollback_upload = f"{remote}/.server_config.rollback.upload"
                with sftp.file(rollback_upload, "w") as handle:
                    handle.write(previous_config)
                sftp.chmod(rollback_upload, 0o600)
                if previous_renewal:
                    with sftp.file(
                        "/etc/systemd/system/chameleon-cert-renew.service", "w"
                    ) as handle:
                        handle.write(previous_renewal)
                sftp.close()
                _, stdout, _ = c.exec_command(
                    f"mv -f -- {rollback_upload} {remote}/server_config.json && "
                    f"chown root:chameleon {remote}/server_config.json && "
                    f"chmod 0640 {remote}/server_config.json && "
                    "systemctl daemon-reload && systemctl restart chameleon-network && "
                    "systemctl restart chameleon-server && "
                    "systemctl is-active chameleon-server",
                    timeout=60,
                )
                return stdout.channel.recv_exit_status() == 0
            except Exception:  # noqa: BLE001
                return False
            finally:
                if c is not None:
                    c.close()

        result = await asyncio.to_thread(_do)
        previous_config = result.pop("_previous_config", "")
        previous_renewal = result.pop("_previous_renewal", "")
        if not result.get("success"):
            return result

        current = self._meta()
        current["server_address"] = f"{domain}:443"
        current["ssh"]["domain_tls_deployed"] = True
        current["ssh"]["ip_shield_deployed"] = True
        self._save_meta(current)
        self._write_client_conf(current)
        if current.get("enabled"):
            client_status = await self.enable(confirm_routing_conflict=True)
            if not client_status.get("connected"):
                current["server_address"] = old_server_address
                current["ssh"]["domain_tls_deployed"] = False
                self._save_meta(current)
                self._write_client_conf(current)
                restored = await asyncio.to_thread(
                    _restore_remote, previous_config, previous_renewal
                )
                await self.enable(confirm_routing_conflict=True)
                result["success"] = False
                result["log"] += (
                    "\nDomain client verification failed; restored the previous client endpoint."
                )
                result["log"] += (
                    " Previous server configuration restored."
                    if restored
                    else " WARNING: automatic server rollback failed."
                )
                return result
            result["log"] += (
                "\nLocal Stealth client switched to the domain and connected."
            )
        return result

    @_deployment_locked("domain-tls-remove")
    async def remove_domain_tls(self) -> Dict[str, Any]:
        """Safely leave domain mode and remove its stored identity."""
        meta = self._meta()
        ssh = meta["ssh"]
        domain = str(ssh.get("domain") or "")
        domain_active = bool(ssh.get("domain_tls_deployed"))
        if not (domain or domain_active):
            return {"success": True, "log": "No Domain HTTPS settings are stored."}

        try:
            endpoint_ip = require_public_ipv4(
                str(ssh.get("host") or ""), label="Stealth VPS"
            )
        except ValueError as exc:
            if domain_active:
                return {
                    "success": False,
                    "log": f"Cannot safely leave domain mode: {exc}",
                }
            endpoint_ip = ""

        if domain_active and not (
            endpoint_ip and self._has_ssh_auth(ssh) and ssh.get("host_key_data")
        ):
            return {
                "success": False,
                "log": "Cannot safely leave domain mode without the trusted VPS connection.",
            }

        remote = REMOTE_SERVER_DIR
        previous_server_address = str(meta.get("server_address") or "")
        previous_domain_deployed = domain_active
        previous_config = ""
        previous_renewal = ""

        def _restore_remote() -> bool:
            if not previous_config:
                return False
            connection = None
            try:
                connection = self._connect(ssh)
                sftp = connection.open_sftp()
                rollback_upload = f"{remote}/.server_config.rollback.upload"
                with sftp.file(rollback_upload, "w") as handle:
                    handle.write(previous_config)
                sftp.chmod(rollback_upload, 0o600)
                if previous_renewal:
                    with sftp.file(
                        "/etc/systemd/system/chameleon-cert-renew.service", "w"
                    ) as handle:
                        handle.write(previous_renewal)
                sftp.close()
                _, stdout, _ = connection.exec_command(
                    f"mv -f -- {rollback_upload} {remote}/server_config.json && "
                    f"chown root:chameleon {remote}/server_config.json && "
                    f"chmod 0640 {remote}/server_config.json && "
                    "systemctl daemon-reload && systemctl restart chameleon-network && "
                    "systemctl restart chameleon-server && "
                    "systemctl is-active chameleon-server",
                    timeout=60,
                )
                return stdout.channel.recv_exit_status() == 0
            except Exception:  # noqa: BLE001
                return False
            finally:
                if connection is not None:
                    connection.close()

        def _switch_server_to_ip() -> Dict[str, Any]:
            nonlocal previous_config, previous_renewal
            log: List[str] = []
            connection = None
            try:
                ip_server_config = self._server_config_json(
                    meta, tls_identity=endpoint_ip
                )
                connection = self._connect(ssh)

                def run_checked(command: str, label: str, timeout: int = 240) -> str:
                    _, stdout, stderr = connection.exec_command(
                        command, timeout=timeout
                    )
                    output = stdout.read().decode(errors="ignore").strip()
                    error = stderr.read().decode(errors="ignore").strip()
                    rc = stdout.channel.recv_exit_status()
                    log.append(f"{label}: {'ok' if rc == 0 else 'failed'}")
                    if rc != 0:
                        detail = "\n".join(part for part in (output, error) if part)
                        raise RuntimeError(
                            f"{label} failed{(': ' + detail[-500:]) if detail else ''}"
                        )
                    return output

                sftp = connection.open_sftp()
                with sftp.file(f"{remote}/server_config.json", "r") as handle:
                    previous_config = handle.read().decode("utf-8")
                with sftp.file(
                    "/etc/systemd/system/chameleon-cert-renew.service", "r"
                ) as handle:
                    previous_renewal = handle.read().decode("utf-8")
                with sftp.file(
                    "/usr/local/sbin/chameleon-certbot-standalone", "w"
                ) as handle:
                    handle.write(self._standalone_certbot_wrapper())
                sftp.chmod("/usr/local/sbin/chameleon-certbot-standalone", 0o700)
                sftp.close()

                run_checked(
                    self._ip_certificate_issue_command(endpoint_ip),
                    "IP certificate issuance",
                )
                run_checked(
                    f"test -s /etc/letsencrypt/live/{endpoint_ip}/fullchain.pem && "
                    f"test -s /etc/letsencrypt/live/{endpoint_ip}/privkey.pem",
                    "IP certificate verification",
                    timeout=20,
                )
                sftp = connection.open_sftp()
                with sftp.file("/usr/local/sbin/chameleon-install-cert", "w") as handle:
                    handle.write(self._certificate_install_script())
                sftp.chmod("/usr/local/sbin/chameleon-install-cert", 0o700)
                sftp.close()
                run_checked(
                    self._tls_material_install_command(endpoint_ip),
                    "Restricted TLS material install",
                    timeout=20,
                )

                renewal_service = self._certificate_renewal_service(
                    identity=endpoint_ip,
                )
                sftp = connection.open_sftp()
                config_upload = f"{remote}/.server_config.ip.upload"
                with sftp.file(config_upload, "w") as handle:
                    handle.write(ip_server_config)
                sftp.chmod(config_upload, 0o600)
                with sftp.file(
                    "/etc/systemd/system/chameleon-cert-renew.service", "w"
                ) as handle:
                    handle.write(renewal_service)
                sftp.close()
                run_checked(
                    f"mv -f -- {config_upload} {remote}/server_config.json && "
                    f"chown root:chameleon {remote}/server_config.json && "
                    f"chmod 0640 {remote}/server_config.json && "
                    "systemctl daemon-reload && systemctl restart chameleon-network && "
                    "systemctl restart chameleon-server",
                    "IP Shield activation",
                    timeout=60,
                )
                run_checked(
                    "systemctl is-active chameleon-server",
                    "Chameleon health",
                    timeout=20,
                )
                self._verify_ip_tls(endpoint_ip)
                log.append("IP certificate identity and HTTP/2: verified")
                return {"success": True, "log": "\n".join(log)}
            except Exception as exc:  # noqa: BLE001
                log.append(f"ERROR: {exc}{_friendly_ssh_err(str(exc))}")
                if previous_config:
                    if connection is not None:
                        connection.close()
                        connection = None
                    log.append(
                        "Previous domain configuration restored."
                        if _restore_remote()
                        else "WARNING: automatic server rollback failed."
                    )
                return {"success": False, "log": "\n".join(log)}
            finally:
                if connection is not None:
                    connection.close()

        def _cleanup_legacy_remote_state() -> Dict[str, Any]:
            if not (
                endpoint_ip
                and self._has_ssh_auth(ssh)
                and ssh.get("host_key_data")
                and (domain_active or ssh.get("ssh_key_verified"))
            ):
                return {
                    "success": True,
                    "log": "No legacy remote DuckDNS state was installed.",
                }
            connection = None
            try:
                connection = self._connect(ssh)
                _, stdout, stderr = connection.exec_command(
                    self._legacy_duckdns_cleanup_command(),
                    timeout=30,
                )
                error = stderr.read().decode(errors="ignore").strip()
                rc = stdout.channel.recv_exit_status()
                if rc != 0:
                    raise RuntimeError(error[-500:] or "remote cleanup command failed")
                return {
                    "success": True,
                    "log": "Legacy VPS DuckDNS state removed.",
                }
            except Exception as exc:  # noqa: BLE001
                return {
                    "success": False,
                    "log": f"Legacy VPS cleanup failed: {exc}{_friendly_ssh_err(str(exc))}",
                }
            finally:
                if connection is not None:
                    connection.close()

        log: List[str] = []
        if domain_active:
            switch_result = await asyncio.to_thread(_switch_server_to_ip)
            log.append(switch_result["log"])
            if not switch_result.get("success"):
                return {"success": False, "log": "\n".join(log)}

            current = self._meta()
            current["server_address"] = f"{endpoint_ip}:443"
            current["ssh"]["domain_tls_deployed"] = False
            current["ssh"]["ip_shield_deployed"] = True
            self._save_meta(current)
            self._write_client_conf(current)
            if current.get("enabled"):
                client_status = await self.enable(confirm_routing_conflict=True)
                if not client_status.get("connected"):
                    current["server_address"] = previous_server_address
                    current["ssh"]["domain_tls_deployed"] = previous_domain_deployed
                    self._save_meta(current)
                    self._write_client_conf(current)
                    restored = await asyncio.to_thread(_restore_remote)
                    await self.enable(confirm_routing_conflict=True)
                    log.append(
                        "IP client verification failed; restored the domain endpoint."
                    )
                    log.append(
                        "Previous server configuration restored."
                        if restored
                        else "WARNING: automatic server rollback failed."
                    )
                    return {"success": False, "log": "\n".join(log)}
                log.append("Local Stealth client switched to IP Shield and connected.")

        cleanup_result = await asyncio.to_thread(_cleanup_legacy_remote_state)
        log.append(cleanup_result["log"])
        if not cleanup_result.get("success"):
            return {"success": False, "log": "\n".join(log)}

        try:
            self._secret_delete("duckdns-token")
        except RuntimeError as exc:
            log.append(f"Local DuckDNS credential cleanup failed: {exc}")
            return {"success": False, "log": "\n".join(log)}

        current = self._meta()
        current["ssh"]["domain"] = ""
        current["ssh"]["domain_tls_deployed"] = False
        self._save_meta(current)
        if current.get("server_address"):
            self._write_client_conf(current)
        log.append("Domain HTTPS identity removed from EasyPi.")
        return {
            "success": True,
            "active": bool(current.get("enabled")),
            "log": "\n".join(log),
        }
