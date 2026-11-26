#!/usr/bin/env bash
# =============================================================================
# EasyPi - Unbound Recursive DNS Resolver Setup
# =============================================================================
# Installs and configures Unbound as a local recursive DNS resolver.
# NetProtection uses Unbound instead of public DNS (Quad9, Cloudflare, Google)
# for complete privacy - DNS queries go directly to root servers.
#
# Architecture:
#   Client → NetProtection (port 53) → Unbound (port 5354) → Root DNS Servers
#                   ↓
#             Your blocklists
#
# Usage:
#   sudo ./setup_unbound.sh [--uninstall]
#
# © 2025 EasyPi Project
# =============================================================================

set -euo pipefail

# Colors
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
BLUE="\033[0;34m"
NC="\033[0m"

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
header() { echo -e "\n${BLUE}=== $1 ===${NC}\n"; }

# Configuration
UNBOUND_PORT=5354
UNBOUND_CONF_DIR="/etc/unbound/unbound.conf.d"
UNBOUND_CONF_FILE="${UNBOUND_CONF_DIR}/easypi-recursive.conf"
NETPROTECTION_CONFIG="/opt/EasyPi/config/netprotection.toml"

check_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        error "This script must be run as root (sudo)"
        exit 1
    fi
}

uninstall_unbound() {
    header "Uninstalling Unbound"
    
    if systemctl is-active --quiet unbound 2>/dev/null; then
        info "Stopping Unbound..."
        systemctl stop unbound
    fi
    
    if [[ -f "${UNBOUND_CONF_FILE}" ]]; then
        info "Removing EasyPi Unbound configuration..."
        rm -f "${UNBOUND_CONF_FILE}"
    fi
    rm -f "${UNBOUND_CONF_DIR}/easypi-transport.conf"
    
    # Restore NetProtection to use public DNS
    if [[ -f "${NETPROTECTION_CONFIG}" ]]; then
        info "Restoring NetProtection to use public DNS..."
        python3 -c "
import re
with open('${NETPROTECTION_CONFIG}', 'r') as f:
    content = f.read()
content = re.sub(
    r'servers = \\[.*?\\]',
    '''servers = [
    \"https://dns.quad9.net/dns-query\",
    \"tls://1.1.1.1:853\",
    \"https://dns.google/dns-query\",
]''',
    content,
    flags=re.DOTALL
)
with open('${NETPROTECTION_CONFIG}', 'w') as f:
    f.write(content)
"
        info "NetProtection restored to public DNS servers"
    fi
    
    info "Unbound configuration removed (package not uninstalled)"
    info "To fully remove: apt remove unbound"
}

install_unbound() {
    header "Installing Unbound Recursive DNS Resolver"
    
    # Check if already installed
    if command -v unbound &>/dev/null; then
        info "Unbound already installed"
    else
        info "Installing Unbound..."
        apt-get update -qq
        apt-get install -y unbound
    fi
    
    # Create configuration directory
    mkdir -p "${UNBOUND_CONF_DIR}"
    
    # Remove old configuration files to avoid conflicts
    if [[ -f "${UNBOUND_CONF_DIR}/recursive.conf" ]]; then
        info "Removing old recursive.conf to avoid conflicts..."
        rm -f "${UNBOUND_CONF_DIR}/recursive.conf"
    fi
    
    header "Configuring Unbound as Recursive Resolver"
    
    cat > "${UNBOUND_CONF_FILE}" << 'UNBOUND_CONFIG'
# =============================================================================
# EasyPi Unbound Configuration - Recursive DNS Resolver
# =============================================================================
# This makes Unbound work as a TRUE recursive resolver that queries
# root DNS servers directly, providing complete privacy.
#
# NO public DNS servers (Quad9, Cloudflare, Google) are used!
# =============================================================================

server:
    # Listen only on localhost, NetProtection will forward to us
    interface: 127.0.0.1
    port: 5354
    
    # Only allow local connections
    access-control: 127.0.0.0/8 allow
    access-control: ::1/128 allow
    access-control: 0.0.0.0/0 refuse
    access-control: ::/0 refuse
    
    # Run as unbound user
    username: "unbound"
    
    # Chroot disabled for simplicity
    chroot: ""
    
    # =========================================================================
    # RECURSIVE RESOLVER - No forwarders!
    # =========================================================================
    # Unbound will query root servers → TLD servers → authoritative servers
    # This is the key to privacy - no third-party DNS sees your queries
    
    # Root hints for finding root servers
    # NOTE: auto-trust-anchor-file is already defined in system config
    # (/etc/unbound/unbound.conf.d/root-auto-trust-anchor-file.conf)
    root-hints: "/usr/share/dns/root.hints"
    
    # =========================================================================
    # Performance & Caching
    # =========================================================================
    
    # Cache settings
    cache-max-ttl: 86400
    cache-min-ttl: 300
    prefetch: yes
    prefetch-key: yes
    
    # Serve stale data while refreshing
    serve-expired: yes
    serve-expired-ttl: 86400
    
    # Threading (2 threads for Raspberry Pi)
    num-threads: 2
    
    # Memory slabs (power of 2, equal to threads)
    msg-cache-slabs: 2
    rrset-cache-slabs: 2
    infra-cache-slabs: 2
    key-cache-slabs: 2
    
    # Cache sizes
    rrset-cache-size: 64m
    msg-cache-size: 32m
    key-cache-size: 8m
    neg-cache-size: 4m
    
    # =========================================================================
    # Security Hardening
    # =========================================================================
    
    # Hide identity
    hide-identity: yes
    hide-version: yes
    
    # DNSSEC hardening
    harden-glue: yes
    harden-dnssec-stripped: yes
    # harden-referral-path stays at Unbound's default (no). It is an
    # experimental, non-standard option that validates every nameserver NS set
    # and address on the referral path; that multiplies the upstream queries of
    # a cold lookup and pushes requests over max-global-quota, so they fail with
    # SERVFAIL. Answers are still validated from the root trust anchor down.
    harden-referral-path: no

    # How long an answer that failed validation is served from cache. A zone
    # whose DNSKEY fetch failed is already held as bad for Unbound's fixed 60 s;
    # the default 60 s here came on top of that (about 105 s of SERVFAIL after
    # a 4 s outage, against 60 s with 10). Bogus data is still never returned.
    val-bogus-ttl: 10
    harden-algo-downgrade: yes
    harden-below-nxdomain: yes
    harden-large-queries: yes
    harden-short-bufsize: yes
    
    # Minimal responses
    minimal-responses: yes
    
    # QNAME minimisation (privacy)
    qname-minimisation: yes
    qname-minimisation-strict: no
    
    # Aggressive NSEC (faster NXDOMAIN)
    aggressive-nsec: yes
    
    # =========================================================================
    # Private addresses (RFC 1918) - don't look up
    # =========================================================================
    private-address: 10.0.0.0/8
    private-address: 172.16.0.0/12
    private-address: 192.168.0.0/16
    private-address: 169.254.0.0/16
    private-address: fd00::/8
    private-address: fe80::/10
    private-address: ::ffff:0:0/96
    
    # =========================================================================
    # Logging (minimal for production)
    # =========================================================================
    verbosity: 1
    log-queries: no
    log-replies: no
    log-local-actions: no
    log-servfail: yes
    
    # Don't print stats to log
    statistics-interval: 0
    extended-statistics: no

UNBOUND_CONFIG

    info "Unbound configuration created at ${UNBOUND_CONF_FILE}"
    
    # Download/update root hints
    header "Updating Root Hints"
    
    if [[ -f /usr/share/dns/root.hints ]]; then
        info "Root hints file exists"
    else
        info "Downloading root hints..."
        curl -s https://www.internic.net/domain/named.cache -o /usr/share/dns/root.hints || \
            warn "Could not download root hints, using system default"
    fi
    
    # Initialize DNSSEC trust anchor
    header "Initializing DNSSEC Trust Anchor"
    
    if [[ ! -f /var/lib/unbound/root.key ]]; then
        info "Fetching DNSSEC root key..."
        unbound-anchor -a /var/lib/unbound/root.key 2>/dev/null || true
    fi
    chown unbound:unbound /var/lib/unbound/root.key 2>/dev/null || true
    
    # IPv6 transport follows measured IPv6 reachability (do-ip6 in its own
    # snippet); the timer installed by install.sh keeps it current afterwards.
    header "Checking IPv6 Transport"

    local transport_script
    transport_script="$(dirname "$(readlink -f "$0")")/../maintenance/unbound_ipv6_transport.sh"
    if [[ -f "${transport_script}" ]]; then
        bash "${transport_script}" --no-reload || warn "IPv6 transport check failed; Unbound keeps its current transport"
    else
        warn "IPv6 transport check not found: ${transport_script}"
    fi

    # Test configuration
    header "Testing Unbound Configuration"
    
    if unbound-checkconf; then
        info "Configuration is valid"
    else
        error "Configuration check failed!"
        exit 1
    fi
    
    # Restart Unbound
    header "Starting Unbound"
    
    systemctl enable unbound
    systemctl restart unbound
    
    sleep 2
    
    if systemctl is-active --quiet unbound; then
        info "Unbound is running"
    else
        error "Unbound failed to start!"
        journalctl -u unbound -n 20 --no-pager
        exit 1
    fi
    
    # Test DNS resolution
    header "Testing DNS Resolution"
    
    info "Testing recursive resolution..."
    if dig @127.0.0.1 -p ${UNBOUND_PORT} google.com +short +time=5 | head -1; then
        info "DNS resolution working!"
    else
        warn "DNS test failed - may need a moment to initialize"
    fi
    
    # Configure NetProtection to use Unbound
    header "Configuring NetProtection"
    
    if [[ -f "${NETPROTECTION_CONFIG}" ]]; then
        info "Updating NetProtection to use local Unbound..."
        python3 -c "
import re
with open('${NETPROTECTION_CONFIG}', 'r') as f:
    content = f.read()
content = re.sub(
    r'servers = \\[.*?\\]',
    'servers = [\n    \"127.0.0.1:${UNBOUND_PORT}\",\n]',
    content,
    flags=re.DOTALL
)
with open('${NETPROTECTION_CONFIG}', 'w') as f:
    f.write(content)
"
        info "NetProtection configured to use Unbound on port ${UNBOUND_PORT}"
        
        # Restart NetProtection if running
        if systemctl is-active --quiet easypi-netprotection 2>/dev/null; then
            info "Restarting NetProtection..."
            systemctl restart easypi-netprotection
        fi
    else
        warn "NetProtection config not found at ${NETPROTECTION_CONFIG}"
        warn "You may need to manually configure upstream DNS to 127.0.0.1:${UNBOUND_PORT}"
    fi
    
    header "Installation Complete!"
    
    echo ""
    info "Unbound recursive DNS resolver is now active"
    info ""
    info "Architecture:"
    info "  Client → NetProtection (port 53) → Unbound (port ${UNBOUND_PORT}) → Root DNS"
    info ""
    info "Privacy benefits:"
    info "  ✓ No third-party DNS (Quad9/Cloudflare/Google) sees your queries"
    info "  ✓ DNSSEC validation enabled"
    info "  ✓ QNAME minimisation for additional privacy"
    info ""
    info "To check status: systemctl status unbound"
    info "To uninstall: $0 --uninstall"
    echo ""
}

# Main
check_root

if [[ "${1:-}" == "--uninstall" ]] || [[ "${1:-}" == "-u" ]]; then
    uninstall_unbound
else
    install_unbound
fi
