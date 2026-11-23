#!/bin/bash
#
# Tailscale Exit Node Setup Script for EasyPi
# Автоматическая настройка exit node + DNS через Tailscale
#
# Usage: sudo ./tailscale_exit_node.sh
#

set -e

GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}╔════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  Tailscale Exit Node Setup for EasyPi         ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════╝${NC}"
echo ""

# Проверка root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}✗ This script must be run as root${NC}"
    echo "  Usage: sudo $0"
    exit 1
fi

# Проверка наличия Tailscale
if ! command -v tailscale &> /dev/null; then
    echo -e "${RED}✗ Tailscale not installed${NC}"
    echo "  Install: curl -fsSL https://tailscale.com/install.sh | sh"
    exit 1
fi

# Получить основной сетевой интерфейс
INTERNET_IFACE=$(ip route get 8.8.8.8 | awk '{print $5; exit}')
TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "")

if [ -z "$TAILSCALE_IP" ]; then
    echo -e "${RED}✗ Tailscale not running${NC}"
    echo "  Start: sudo tailscale up"
    exit 1
fi

echo -e "${YELLOW}📡 Tailscale IP: $TAILSCALE_IP${NC}"
echo -e "${YELLOW}🌐 Internet interface: $INTERNET_IFACE${NC}"
echo ""

# 1. Включить IP forwarding
echo -e "${GREEN}[1/5] Enabling IP forwarding...${NC}"

install -d -o root -g root -m 0755 /etc/sysctl.d
cat > /etc/sysctl.d/99-easypi-tailscale-exit-node.conf <<'EOF'
# Managed by EasyPi. Removed by uninstall.sh.
net.ipv4.ip_forward=1
net.ipv6.conf.all.forwarding=1
EOF

sysctl -w net.ipv4.ip_forward=1 > /dev/null
sysctl -w net.ipv6.conf.all.forwarding=1 > /dev/null

echo -e "  ✓ IPv4 forwarding: enabled"
echo -e "  ✓ IPv6 forwarding: enabled"
echo ""

# 2. Настроить UFW для DNS
echo -e "${GREEN}[2/5] Configuring UFW for DNS...${NC}"

# Проверить, включен ли UFW
if ! ufw status | grep -q "Status: active"; then
    echo -e "  ${YELLOW}⚠ UFW is not active, skipping firewall rules${NC}"
else
    # DNS rules for port 53 (standard DNS)
    if ! ufw status | grep -q "53/udp.*tailscale0"; then
        ufw allow in on tailscale0 to any port 53 proto udp comment 'EasyPi Tailscale DNS' > /dev/null
        echo -e "  ✓ Added: 53/udp on tailscale0"
    else
        echo -e "  ✓ Already exists: 53/udp on tailscale0"
    fi

    if ! ufw status | grep -q "53/tcp.*tailscale0"; then
        ufw allow in on tailscale0 to any port 53 proto tcp comment 'EasyPi Tailscale DNS' > /dev/null
        echo -e "  ✓ Added: 53/tcp on tailscale0"
    else
        echo -e "  ✓ Already exists: 53/tcp on tailscale0"
    fi
    
    # DNS-over-TLS (port 853) - для Tailscale DNS (100.100.100.100)
    if ! ufw status | grep -q "853/tcp.*tailscale0"; then
        ufw allow in on tailscale0 to any port 853 proto tcp comment 'EasyPi Tailscale DoT' > /dev/null
        echo -e "  ✓ Added: 853/tcp on tailscale0 (DoT)"
    else
        echo -e "  ✓ Already exists: 853/tcp on tailscale0"
    fi
    
    # DNS-over-HTTPS (port 443) - уже открыт обычно, но проверим
    if ! ufw status | grep -q "443/tcp.*tailscale0"; then
        ufw allow in on tailscale0 to any port 443 proto tcp comment 'EasyPi Tailscale HTTPS' > /dev/null
        echo -e "  ✓ Added: 443/tcp on tailscale0 (DoH)"
    else
        echo -e "  ✓ Already exists: 443/tcp on tailscale0"
    fi
fi
echo ""

# 3. Настроить UFW route для exit node
echo -e "${GREEN}[3/5] Configuring UFW routes for exit node...${NC}"

if ufw status | grep -q "Status: active"; then
    # Route rule для основного интерфейса
    if ! ufw status | grep -q "Anywhere on $INTERNET_IFACE.*Anywhere on tailscale0.*ALLOW FWD"; then
        ufw route allow in on tailscale0 out on $INTERNET_IFACE comment 'EasyPi Tailscale exit node' > /dev/null
        echo -e "  ✓ Added: route tailscale0 → $INTERNET_IFACE"
    else
        echo -e "  ✓ Already exists: route tailscale0 → $INTERNET_IFACE"
    fi

    # Если есть wlan0 (WiFi), добавить и его
    if ip link show wlan0 &>/dev/null && [ "$INTERNET_IFACE" != "wlan0" ]; then
        if ! ufw status | grep -q "Anywhere on wlan0.*Anywhere on tailscale0.*ALLOW FWD"; then
            ufw route allow in on tailscale0 out on wlan0 comment 'EasyPi Tailscale exit WiFi' > /dev/null
            echo -e "  ✓ Added: route tailscale0 → wlan0"
        else
            echo -e "  ✓ Already exists: route tailscale0 → wlan0"
        fi
    fi

    ufw reload > /dev/null
    echo -e "  ✓ Firewall reloaded"
else
    echo -e "  ${YELLOW}⚠ UFW is not active, NAT will work via Tailscale rules only${NC}"
fi
echo ""

# 4. Включить Tailscale exit node
echo -e "${GREEN}[4/5] Enabling Tailscale exit node...${NC}"

# Сохранить текущие флаги
CURRENT_FLAGS="--accept-dns=false --accept-routes"

if tailscale status --json 2>/dev/null | grep -q "AdvertiseExitNode"; then
    echo -e "  ✓ Exit node already advertised"
else
    tailscale up --advertise-exit-node $CURRENT_FLAGS
    echo -e "  ✓ Exit node enabled"
fi
echo ""

# 5. Настройка NAT MASQUERADE для exit node
echo -e "${GREEN}[5/5] Configuring NAT MASQUERADE...${NC}"

# Tailscale добавляет свой MASQUERADE (ts-postrouting)
if iptables -t nat -S | grep -q "ts-postrouting.*MASQUERADE"; then
    echo -e "  ✓ Tailscale MASQUERADE rule exists"
else
    echo -e "  ${YELLOW}⚠ No Tailscale MASQUERADE rule found${NC}"
fi

# Tailscale owns its `ts-*` netfilter chains and recreates them on daemon
# startup. Do not append generic interface-wide MASQUERADE rules and do not
# overwrite the host's global /etc/iptables/rules.v4 snapshot: both would claim
# firewall state that may belong to the administrator or another product.
if iptables -t nat -S 2>/dev/null | grep -q "ts-postrouting.*MASQUERADE"; then
    echo -e "  ✓ Tailscale-managed NAT is active"
else
    echo -e "  ${YELLOW}⚠ Tailscale NAT is not visible yet; check tailscaled after route approval${NC}"
fi
echo ""

# Финальная информация
echo -e "${GREEN}╔════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  ✓ Tailscale Exit Node Setup Complete         ║${NC}"
echo -e "${GREEN}╚════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo ""
echo -e "1. Open Tailscale Admin Console:"
echo -e "   ${GREEN}https://login.tailscale.com/admin/machines${NC}"
echo ""
echo -e "2. Find machine 'easypi' → Edit route settings"
echo -e "   Enable: ${GREEN}Exit node${NC} (approve if needed)"
echo ""
echo -e "3. On your phone/client:"
echo -e "   • Exit node → select ${GREEN}easypi${NC}"
echo -e "   • DNS → ${GREEN}$TAILSCALE_IP${NC}"
echo -e "   • Use Tailscale DNS → ${GREEN}ON${NC}"
echo ""
echo -e "4. Test:"
echo -e "   ${GREEN}https://ifconfig.me${NC} (should show server IP)"
echo ""
echo -e "${YELLOW}Troubleshooting:${NC}"
echo -e "  View logs: ${GREEN}sudo journalctl -u easypi-netprotection -f${NC}"
echo -e "  Check DNS: ${GREEN}dig @$TAILSCALE_IP google.com${NC}"
echo -e "  Monitor:   ${GREEN}sudo tcpdump -ni tailscale0 'tcp port 443' -c 5${NC}"
echo ""
