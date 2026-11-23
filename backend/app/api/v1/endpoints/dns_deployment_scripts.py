"""Immutable shell payloads used by the Personal DNS deploy API."""

SECURE_DEPLOYMENT_SCRIPT = r"""#!/bin/bash
set -Eeuo pipefail
umask 077

STAGE="initialization"
DOMAIN="__DOMAIN__"
CERT_EMAIL="__CERT_EMAIL__"
ALLOWED_CLIENTS=(__ALLOWED_CLIENTS__)
NP_IMAGE="${NETPROTECTION_IMAGE:-netprotectionhome:local}"
NP_ROOT="/opt/easypi-personal-dns"
NP_DATA="$NP_ROOT/data"
NP_TLS="$NP_ROOT/tls"
NP_NGINX="/etc/nginx/conf.d/easypi-personal-dns.conf"

on_error() {
    rc=$?
    echo "EASYPI_DEPLOY_ERROR stage=$STAGE line=$1 exit=$rc" >&2
    exit "$rc"
}
trap 'on_error $LINENO' ERR

run_certbot_with_optional_vps_guard() (
    set -Eeuo pipefail
    guard="/usr/local/sbin/easypi-vps-guard"
    guard_opened=false
    certbot_lock="/run/easypi-certbot.lock"
    certbot_log="$(mktemp /tmp/easypi-certbot.XXXXXX)"
    chmod 0600 "$certbot_log"

    close_acme_port() {
        rc=$?
        trap - EXIT HUP INT TERM
        if [ "$guard_opened" = true ] && ! "$guard" acme-close; then
            echo "Failed to close public TCP port 80 after certificate operation." >&2
            [ "$rc" -ne 0 ] || rc=74
        fi
        rm -f -- "$certbot_log"
        exit "$rc"
    }

    trap close_acme_port EXIT
    trap 'exit 129' HUP
    trap 'exit 130' INT
    trap 'exit 143' TERM

    exec 9>"$certbot_lock"
    if ! flock -w 180 9; then
        echo "Timed out waiting for another EasyPi certificate operation." >&2
        exit 75
    fi

    attempt=1
    while :; do
        : > "$certbot_log"
        if [ -x "$guard" ]; then
            "$guard" acme-open
            guard_opened=true
        fi

        if "$@" >"$certbot_log" 2>&1; then
            rc=0
        else
            rc=$?
        fi

        if [ "$guard_opened" = true ]; then
            if ! "$guard" acme-close; then
                echo "Failed to close public TCP port 80 after certificate operation." >&2
                exit 74
            fi
            guard_opened=false
        fi

        if [ "$rc" -eq 0 ]; then
            cat "$certbot_log"
            exit 0
        fi
        if ! grep -Fq "Another instance of Certbot is already running." "$certbot_log"; then
            cat "$certbot_log" >&2
            exit "$rc"
        fi
        if [ "$attempt" -ge 24 ]; then
            cat "$certbot_log" >&2
            echo "Certbot remained busy for two minutes; deployment stopped safely." >&2
            exit 75
        fi

        echo "Another Certbot operation is active; retrying in 5 seconds ($attempt/24)." >&2
        attempt=$((attempt + 1))
        sleep 5
    done
)

if [ "$(id -u)" -ne 0 ]; then
    echo "EASYPI_DEPLOY_ERROR stage=preflight reason=root-required" >&2
    exit 1
fi

echo "=== Personal DNS secure deployment ==="
echo "Mode: $([ -n "$DOMAIN" ] && echo 'DNS + WireGuard + DoH/DoT' || echo 'DNS + WireGuard')"

STAGE="domain-conflict-preflight"
if [ -n "$DOMAIN" ] && command -v nginx >/dev/null 2>&1; then
    if nginx -T 2>/dev/null | grep -Fq "server_name $DOMAIN;"; then
        if [ ! -f "$NP_NGINX" ] || ! grep -Fq "server_name $DOMAIN;" "$NP_NGINX"; then
            echo "The domain $DOMAIN is already owned by another nginx service." >&2
            echo "Use a separate DNS hostname (for example another DuckDNS name)." >&2
            exit 42
        fi
    fi
fi

STAGE="package-install"
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
packages=(docker.io wireguard qrencode iptables curl)
if [ -n "$DOMAIN" ]; then
    packages+=(nginx certbot util-linux)
fi
apt-get install -y -qq "${packages[@]}"
systemctl enable --now docker

STAGE="wireguard-setup"
install -d -m 0700 /etc/wireguard
OUTBOUND_IF="$(ip -4 route show default | awk 'NR==1 {print $5}')"
if [ -z "$OUTBOUND_IF" ]; then
    echo "Could not determine the VPS outbound network interface." >&2
    exit 1
fi

if [ -f /etc/wireguard/wg0.conf ] && ! grep -Eq '^Address[[:space:]]*=[[:space:]]*10\.66\.66\.1/24([[:space:]]|$)' /etc/wireguard/wg0.conf; then
    echo "Existing wg0 belongs to another VPN configuration; refusing to overwrite it." >&2
    exit 43
fi

if [ ! -f /etc/wireguard/wg0.conf ]; then
    wg genkey | tee /etc/wireguard/server_private.key | wg pubkey > /etc/wireguard/server_public.key
    chmod 0600 /etc/wireguard/server_private.key
    SERVER_PRIVATE="$(cat /etc/wireguard/server_private.key)"
    cat > /etc/wireguard/wg0.conf <<WGEOF
# Managed by EasyPi Personal DNS
[Interface]
Address = 10.66.66.1/24
ListenPort = 51820
PrivateKey = $SERVER_PRIVATE
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT; iptables -A FORWARD -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -A POSTROUTING -o $OUTBOUND_IF -j MASQUERADE
PostDown = iptables -D FORWARD -i wg0 -j ACCEPT; iptables -D FORWARD -o wg0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -D POSTROUTING -o $OUTBOUND_IF -j MASQUERADE
WGEOF
    chmod 0600 /etc/wireguard/wg0.conf
fi
if ! grep -Fq '# Managed by EasyPi Personal DNS' /etc/wireguard/wg0.conf; then
    sed -i '1i# Managed by EasyPi Personal DNS' /etc/wireguard/wg0.conf
fi

if [ ! -f /etc/wireguard/client1.conf ]; then
    [ -f /etc/wireguard/server_public.key ] || awk -F' *= *' '/^PrivateKey/ {print $2}' /etc/wireguard/wg0.conf | wg pubkey > /etc/wireguard/server_public.key
    wg genkey | tee /etc/wireguard/client1_private.key | wg pubkey > /etc/wireguard/client1_public.key
    chmod 0600 /etc/wireguard/client1_private.key
    CLIENT_PRIVATE="$(cat /etc/wireguard/client1_private.key)"
    CLIENT_PUBLIC="$(cat /etc/wireguard/client1_public.key)"
    SERVER_PUBLIC="$(cat /etc/wireguard/server_public.key)"
    VPS_IP="$(curl -4fsS --max-time 10 https://api.ipify.org)"
    cat >> /etc/wireguard/wg0.conf <<WGPEER

[Peer]
PublicKey = $CLIENT_PUBLIC
AllowedIPs = 10.66.66.2/32
WGPEER
    cat > /etc/wireguard/client1.conf <<WGCLIENT
[Interface]
PrivateKey = $CLIENT_PRIVATE
Address = 10.66.66.2/24
DNS = 10.66.66.1

[Peer]
PublicKey = $SERVER_PUBLIC
Endpoint = $VPS_IP:51820
AllowedIPs = 10.66.66.0/24
PersistentKeepalive = 25
WGCLIENT
    chmod 0600 /etc/wireguard/client1.conf
fi

cat > /etc/sysctl.d/90-easypi-personal-dns.conf <<'SYSCTL'
net.ipv4.ip_forward=1
SYSCTL
sysctl --system >/dev/null
systemctl enable wg-quick@wg0 >/dev/null
systemctl restart wg-quick@wg0

STAGE="dns-port-preflight"
docker rm -f netprotectionhome >/dev/null 2>&1 || true
if systemctl is-active --quiet systemd-resolved; then
    systemctl disable --now systemd-resolved
    [ -e /etc/resolv.conf ] && cp -a /etc/resolv.conf /etc/resolv.conf.easypi-backup || true
    rm -f /etc/resolv.conf
    printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' > /etc/resolv.conf
fi
if ss -H -lntu '( sport = :53 )' | grep -q .; then
    echo "Port 53 is already used by another service; refusing to stop an unknown DNS server." >&2
    ss -H -lntup '( sport = :53 )' >&2 || true
    exit 44
fi
if [ -n "$DOMAIN" ] && ss -H -lnt '( sport = :853 )' | grep -q .; then
    echo "Port 853 is already used by another service." >&2
    ss -H -lntp '( sport = :853 )' >&2 || true
    exit 45
fi
if [ -n "$DOMAIN" ]; then
    while read -r _state _recvq _sendq local_address process_info; do
        case "$local_address" in
            127.0.0.1:8443|\[::1\]:8443)
                # Chameleon bootstrap/cover listeners are loopback-only and do
                # not conflict with nginx bound to the public VPS IPv4.
                continue
                ;;
        esac
        if [[ "$process_info" == *nginx* ]] && [ -f "$NP_NGINX" ] && \
            grep -Fq "server_name $DOMAIN;" "$NP_NGINX"; then
            continue
        fi
        echo "Public port 8443 is already used by another service." >&2
        ss -H -lntp '( sport = :8443 )' >&2 || true
        exit 47
    done < <(ss -H -lntp '( sport = :8443 )')
fi

STAGE="netprotection-build"
install -d -m 0750 /opt/netprotection-src
rm -rf /opt/netprotection-src/easypi_netprotection
NP_TMP="$(mktemp -d /tmp/easypi-netprotection.XXXXXX)"
chmod 0700 "$NP_TMP"
trap 'rm -rf -- "$NP_TMP"' EXIT
cat > "$NP_TMP/source.tgz.b64" <<'B64'
__NP_TARBALL_B64__
B64
base64 -d "$NP_TMP/source.tgz.b64" > "$NP_TMP/source.tgz"
tar -xzf "$NP_TMP/source.tgz" -C /opt/netprotection-src
test -s /opt/netprotection-src/easypi_netprotection/system/bootstrap.py
docker build --build-arg "EASYPI_SOURCE_SHA256=__NP_SOURCE_SHA256__" -t "$NP_IMAGE" -f /opt/netprotection-src/easypi_netprotection/Dockerfile /opt/netprotection-src/easypi_netprotection
rm -rf /opt/netprotection-src/easypi_netprotection

STAGE="certificate-setup"
if [ -n "$DOMAIN" ]; then
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then
        ufw allow 80/tcp >/dev/null
    fi
    install -d -o root -g root -m 0755 /var/www/easypi-acme
    cat > "$NP_NGINX" <<NGINXHTTP
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    location ^~ /.well-known/acme-challenge/ { root /var/www/easypi-acme; }
    location / { return 404; }
}
NGINXHTTP
    nginx -t
    systemctl enable --now nginx
    systemctl reload nginx
    run_certbot_with_optional_vps_guard \
        certbot certonly --webroot -w /var/www/easypi-acme \
        --non-interactive --agree-tos --keep-until-expiring \
        --cert-name "$DOMAIN" --email "$CERT_EMAIL" -d "$DOMAIN"
    install -d -o root -g root -m 0700 "$NP_TLS"
    install -o root -g root -m 0600 "/etc/letsencrypt/live/$DOMAIN/fullchain.pem" "$NP_TLS/fullchain.pem"
    install -o root -g root -m 0600 "/etc/letsencrypt/live/$DOMAIN/privkey.pem" "$NP_TLS/privkey.pem"
    chown -R 65532:65532 "$NP_TLS"
fi

STAGE="firewall-preinstall"
cat > /usr/local/sbin/easypi-personal-dns-firewall <<'FIREWALL'
#!/bin/bash
set -euo pipefail
ALLOWED_CLIENTS=(__ALLOWED_CLIENTS__)
DOT_ENABLED=__DOT_ENABLED__
IPT=(iptables -w 10)
LIVE_CHAIN=EASYPI_PERSONAL_DNS
NEXT_CHAIN=EASYPI_PERSONAL_DNS_NEXT
GUARD_CHAIN=EASYPI_PERSONAL_DNS_GUARD

chain_exists() {
    "${IPT[@]}" -S "$1" >/dev/null 2>&1
}

remove_hooks() {
    local chain="$1"
    while "${IPT[@]}" -C DOCKER-USER -j "$chain" >/dev/null 2>&1; do
        "${IPT[@]}" -D DOCKER-USER -j "$chain"
    done
}

# Install an independent deny guard before touching either generation. If any
# later command fails, public plain DNS stays closed. Never flush this chain:
# it can be the only remaining protection after an interrupted earlier update.
"${IPT[@]}" -N "$GUARD_CHAIN" 2>/dev/null || true
"${IPT[@]}" -C "$GUARD_CHAIN" -p udp --dport 5353 -j DROP 2>/dev/null || \
    "${IPT[@]}" -A "$GUARD_CHAIN" -p udp --dport 5353 -j DROP
"${IPT[@]}" -C "$GUARD_CHAIN" -p tcp --dport 5353 -j DROP 2>/dev/null || \
    "${IPT[@]}" -A "$GUARD_CHAIN" -p tcp --dport 5353 -j DROP
"${IPT[@]}" -C DOCKER-USER -j "$GUARD_CHAIN" 2>/dev/null || \
    "${IPT[@]}" -I DOCKER-USER 1 -j "$GUARD_CHAIN"

# A stale staging chain can exist after a killed update. The guard is already
# active, so removing that incomplete generation cannot open public DNS.
remove_hooks "$NEXT_CHAIN"
if chain_exists "$NEXT_CHAIN"; then
    "${IPT[@]}" -F "$NEXT_CHAIN"
    "${IPT[@]}" -X "$NEXT_CHAIN"
fi
"${IPT[@]}" -N "$NEXT_CHAIN"

# Plain DNS is fail-closed: WireGuard and explicitly approved public IPv4
# sources are accepted; every other source is dropped before Docker can
# forward a packet to the container.
"${IPT[@]}" -A "$NEXT_CHAIN" -i wg0 -p udp --dport 5353 -j ACCEPT
"${IPT[@]}" -A "$NEXT_CHAIN" -i wg0 -p tcp --dport 5353 -j ACCEPT
for client in "${ALLOWED_CLIENTS[@]}"; do
    "${IPT[@]}" -A "$NEXT_CHAIN" -s "$client" -p udp --dport 5353 -j ACCEPT
    "${IPT[@]}" -A "$NEXT_CHAIN" -s "$client" -p tcp --dport 5353 -j ACCEPT
done
"${IPT[@]}" -A "$NEXT_CHAIN" -p udp --dport 5353 -j DROP
"${IPT[@]}" -A "$NEXT_CHAIN" -p tcp --dport 5353 -j DROP

if [ "$DOT_ENABLED" = true ]; then
    # Android Private DNS normally keeps only a few long-lived TLS sessions.
    # These limits allow normal shared-NAT households while containing abusive
    # reconnect floods and per-source connection exhaustion.
    "${IPT[@]}" -A "$NEXT_CHAIN" -p tcp --dport 8853 \
        -m conntrack --ctstate NEW \
        -m connlimit --connlimit-above 20 --connlimit-mask 32 \
        -j REJECT --reject-with tcp-reset
    "${IPT[@]}" -A "$NEXT_CHAIN" -p tcp --dport 8853 \
        -m conntrack --ctstate NEW \
        -m hashlimit --hashlimit-above 60/minute --hashlimit-burst 20 \
        --hashlimit-mode srcip --hashlimit-srcmask 32 \
        --hashlimit-name easypi_personal_dot \
        -j DROP
fi

"${IPT[@]}" -A "$NEXT_CHAIN" -j RETURN

# Activate the complete generation before retiring the old one. During the
# switch both the new policy and the deny guard are present, so every failure
# mode remains fail-closed.
"${IPT[@]}" -I DOCKER-USER 1 -j "$NEXT_CHAIN"
remove_hooks "$LIVE_CHAIN"
if chain_exists "$LIVE_CHAIN"; then
    "${IPT[@]}" -F "$LIVE_CHAIN"
    "${IPT[@]}" -X "$LIVE_CHAIN"
fi
"${IPT[@]}" -E "$NEXT_CHAIN" "$LIVE_CHAIN"

# The renamed live chain is now fully active. Remove the temporary guard last.
remove_hooks "$GUARD_CHAIN"
"${IPT[@]}" -F "$GUARD_CHAIN"
"${IPT[@]}" -X "$GUARD_CHAIN"
FIREWALL
chmod 0700 /usr/local/sbin/easypi-personal-dns-firewall
cat > /etc/systemd/system/easypi-personal-dns-firewall.service <<'UNIT'
[Unit]
Description=EasyPi Personal DNS firewall allowlist
After=docker.service wg-quick@wg0.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/easypi-personal-dns-firewall
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl enable easypi-personal-dns-firewall.service >/dev/null
systemctl restart easypi-personal-dns-firewall.service

if command -v ufw >/dev/null 2>&1 && ufw status | grep -q '^Status: active'; then
    ufw allow 51820/udp >/dev/null
    ufw allow in on wg0 to any port 53 proto udp >/dev/null
    ufw allow in on wg0 to any port 53 proto tcp >/dev/null
    for client in "${ALLOWED_CLIENTS[@]}"; do
        ufw allow from "$client" to any port 53 proto udp >/dev/null
        ufw allow from "$client" to any port 53 proto tcp >/dev/null
    done
    if [ -n "$DOMAIN" ]; then
        ufw allow 80/tcp >/dev/null
        ufw allow 8443/tcp >/dev/null
        ufw allow 853/tcp >/dev/null
    fi
fi

# Only publish ports after the DOCKER-USER policy above has been installed.
# Binding to the validated VPS IPv4 also prevents an unintended IPv6 listener
# from bypassing the IPv4 allowlist on Docker installations with userland proxy.
STAGE="container-start"
install -d -o root -g root -m 0700 "$NP_DATA"
chown 65532:65532 "$NP_DATA"
DOCKER_GATEWAY="$(docker network inspect bridge --format '{{(index .IPAM.Config 0).Gateway}}')"
docker_args=(
    --name netprotectionhome
    --restart unless-stopped
    --user 65532:65532
    --cap-drop ALL
    --security-opt no-new-privileges:true
    -e NETPROTECTION_LISTENER__ADDRESS=0.0.0.0
    -e NETPROTECTION_LISTENER__PORT=5353
    -e NETPROTECTION_RUNTIME_ROOT=/data
    -e NETPROTECTION_VAULT__DB_PATH=/data/netprotection.db
    -e NETPROTECTION_CHRONICLE__SALT_FILE=/data/.salt
    # LAN admission requires a MAC+IP identity. A public encrypted resolver
    # sees only the NAT/public client IP, so applying the LAN quarantine here
    # would classify every legitimate Android Private DNS client as unknown
    # and return the block response for every domain. This explicit,
    # root-controlled deployment override affects only that admission stage;
    # the normal ad, tracker, malware and parental DNS verdict pipeline stays on.
    -e NETPROTECTION_UNKNOWN_DEVICE_MODE=default
    -e "NETPROTECTION_TRUSTED_PROXIES=$DOCKER_GATEWAY"
    -v "$NP_DATA:/data"
    -p "__VPS_IP__:53:5353/tcp"
    -p "__VPS_IP__:53:5353/udp"
    -p "10.66.66.1:53:5353/tcp"
    -p "10.66.66.1:53:5353/udp"
)
if [ -n "$DOMAIN" ]; then
    docker_args+=(
        -e NETPROTECTION_ENCRYPTED_DNS__DOH_ENABLED=true
        -e NETPROTECTION_ENCRYPTED_DNS__DOH_ADDRESS=0.0.0.0
        -e NETPROTECTION_ENCRYPTED_DNS__DOH_PORT=8053
        -e NETPROTECTION_ENCRYPTED_DNS__DOT_ENABLED=true
        -e NETPROTECTION_ENCRYPTED_DNS__DOT_ADDRESS=0.0.0.0
        -e NETPROTECTION_ENCRYPTED_DNS__DOT_PORT=8853
        -e NETPROTECTION_ENCRYPTED_DNS__TLS_CERT_PATH=/certs/fullchain.pem
        -e NETPROTECTION_ENCRYPTED_DNS__TLS_KEY_PATH=/certs/privkey.pem
        -v "$NP_TLS:/certs:ro"
        -p 127.0.0.1:8053:8053/tcp
        -p "__VPS_IP__:853:8853/tcp"
    )
fi
docker run -d "${docker_args[@]}" "$NP_IMAGE"
CONTAINER_READY=false
for _attempt in $(seq 1 60); do
    if [ "$(docker inspect -f '{{.State.Running}}' netprotectionhome 2>/dev/null || true)" = "true" ] && \
        docker exec netprotectionhome python -c \
            'import socket; s=socket.create_connection(("127.0.0.1", 5353), 1); s.close()' \
            >/dev/null 2>&1; then
        CONTAINER_READY=true
        break
    fi
    sleep 2
done
if [ "$CONTAINER_READY" != true ]; then
    echo "EASYPI_DEPLOY_ERROR stage=container-start reason=readiness-timeout exit=46" >&2
    docker inspect -f \
        'state={{.State.Status}} exit={{.State.ExitCode}} oom={{.State.OOMKilled}} error={{.State.Error}}' \
        netprotectionhome >&2 || true
    docker logs --tail 80 netprotectionhome >&2 || true
    exit 46
fi

STAGE="nginx-doh-routing"
if [ -n "$DOMAIN" ]; then
    NGINX_VERSION="$(nginx -v 2>&1 | sed -n 's#^nginx version: nginx/\([0-9.]*\).*$#\1#p')"
    NGINX_HTTP2_LISTEN="listen __VPS_IP__:8443 ssl http2;"
    NGINX_HTTP2_DIRECTIVE=""
    if [ -n "$NGINX_VERSION" ] && dpkg --compare-versions "$NGINX_VERSION" ge 1.25.1; then
        NGINX_HTTP2_LISTEN="listen __VPS_IP__:8443 ssl;"
        NGINX_HTTP2_DIRECTIVE="    http2 on;"
    fi
    cat > "$NP_NGINX" <<NGINXFINAL
limit_req_zone \$binary_remote_addr zone=easypi_personal_dns_doh:10m rate=30r/s;
server {
    listen 80;
    listen [::]:80;
    server_name $DOMAIN;
    location ^~ /.well-known/acme-challenge/ { root /var/www/easypi-acme; }
    location / { return 404; }
}
server {
$NGINX_HTTP2_LISTEN
$NGINX_HTTP2_DIRECTIVE
    server_name $DOMAIN;
    ssl_certificate /etc/letsencrypt/live/$DOMAIN/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/$DOMAIN/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    add_header X-Content-Type-Options nosniff always;
    add_header Referrer-Policy no-referrer always;
    location = /dns-query {
        limit_req zone=easypi_personal_dns_doh burst=60 nodelay;
        proxy_pass https://127.0.0.1:8053/dns-query;
        proxy_ssl_verify off;
        proxy_set_header Host \$host;
        proxy_set_header X-Real-IP \$remote_addr;
        proxy_set_header X-Forwarded-For \$remote_addr;
        proxy_request_buffering off;
        client_max_body_size 64k;
    }
    location / { return 404; }
}
NGINXFINAL
    nginx -t
    systemctl reload nginx
    install -d -o root -g root -m 0755 /etc/letsencrypt/renewal-hooks/deploy
    cat > /etc/letsencrypt/renewal-hooks/deploy/easypi-personal-dns <<RENEW
#!/bin/bash
set -euo pipefail
install -o root -g root -m 0600 /etc/letsencrypt/live/$DOMAIN/fullchain.pem $NP_TLS/fullchain.pem
install -o root -g root -m 0600 /etc/letsencrypt/live/$DOMAIN/privkey.pem $NP_TLS/privkey.pem
chown 65532:65532 $NP_TLS/fullchain.pem $NP_TLS/privkey.pem
docker restart netprotectionhome >/dev/null
nginx -t && systemctl reload nginx
RENEW
    chmod 0700 /etc/letsencrypt/renewal-hooks/deploy/easypi-personal-dns
fi

STAGE="complete"
echo "=== WIREGUARD_CLIENT_CONFIG_START ==="
cat /etc/wireguard/client1.conf
echo "=== WIREGUARD_CLIENT_CONFIG_END ==="
echo "WG_INSTALLED=true"
echo "DIRECT_DNS_ENABLED=$([ ${#ALLOWED_CLIENTS[@]} -gt 0 ] && echo true || echo false)"
echo "=== Personal DNS deployed successfully ==="
"""

CLEANUP_SCRIPT = r"""#!/bin/bash
set -Eeuo pipefail
umask 077

echo "=== Removing Personal DNS resources only ==="
docker rm -f netprotectionhome >/dev/null 2>&1 || true
docker image rm netprotectionhome:local >/dev/null 2>&1 || true

systemctl disable --now easypi-personal-dns-firewall.service >/dev/null 2>&1 || true
if command -v iptables >/dev/null 2>&1; then
    for chain in \
        EASYPI_PERSONAL_DNS_NEXT \
        EASYPI_PERSONAL_DNS_GUARD \
        EASYPI_PERSONAL_DNS; do
        while iptables -C DOCKER-USER -j "$chain" >/dev/null 2>&1; do
            iptables -D DOCKER-USER -j "$chain" >/dev/null 2>&1 || break
        done
        iptables -F "$chain" >/dev/null 2>&1 || true
        iptables -X "$chain" >/dev/null 2>&1 || true
    done
fi
rm -f -- /etc/systemd/system/easypi-personal-dns-firewall.service
rm -f -- /usr/local/sbin/easypi-personal-dns-firewall
rm -f -- /etc/letsencrypt/renewal-hooks/deploy/easypi-personal-dns

if [ -f /etc/nginx/conf.d/easypi-personal-dns.conf ]; then
    rm -f -- /etc/nginx/conf.d/easypi-personal-dns.conf
    nginx -t && systemctl reload nginx
fi

if [ -f /etc/wireguard/wg0.conf ] && grep -Fq '# Managed by EasyPi Personal DNS' /etc/wireguard/wg0.conf; then
    systemctl disable --now wg-quick@wg0 >/dev/null 2>&1 || true
    rm -f -- /etc/wireguard/wg0.conf \
        /etc/wireguard/server_private.key /etc/wireguard/server_public.key \
        /etc/wireguard/client1_private.key /etc/wireguard/client1_public.key \
        /etc/wireguard/client1.conf
fi

rm -rf -- /opt/easypi-personal-dns
rm -rf -- /opt/NetProtectionhome
rm -rf -- /opt/netprotection-src/easypi_netprotection
systemctl daemon-reload

echo "=== Disk Usage ==="
df -h / | tail -1
echo "=== Personal DNS cleanup complete; Docker, nginx, logs and Chameleon were preserved ==="
"""


__all__ = [
    "CLEANUP_SCRIPT",
    "SECURE_DEPLOYMENT_SCRIPT",
]
