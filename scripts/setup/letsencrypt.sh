#!/bin/bash
# EasyPi Let's Encrypt Certificate Setup
# For users with DDNS or public domain

set -e

CERT_DIR="${EASYPI_CERT_DIR:-/opt/EasyPi/certs}"
WEBROOT="/opt/EasyPi/frontend/dist"
EMAIL="${LETSENCRYPT_EMAIL:-}"
DOMAIN="${LETSENCRYPT_DOMAIN:-}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_success() { echo -e "${GREEN}[OK]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }

# Check if certbot is installed
check_certbot() {
    if ! command -v certbot &> /dev/null; then
        log_info "Installing certbot..."
        
        if command -v apt-get &> /dev/null; then
            sudo apt-get update
            sudo apt-get install -y certbot python3-certbot-nginx
        elif command -v dnf &> /dev/null; then
            sudo dnf install -y certbot python3-certbot-nginx
        elif command -v yum &> /dev/null; then
            sudo yum install -y certbot python3-certbot-nginx
        else
            log_error "Cannot install certbot. Please install manually."
            exit 1
        fi
        
        log_success "Certbot installed"
    fi
}

# Interactive setup
interactive_setup() {
    echo ""
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  Let's Encrypt Certificate Setup${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    echo "This will obtain a FREE trusted SSL certificate from Let's Encrypt."
    echo "Requirements:"
    echo "  • A domain name (e.g., myhome.duckdns.org)"
    echo "  • Port 80 accessible from internet (for HTTP-01 challenge)"
    echo "  • OR DNS provider API access (for DNS-01 challenge)"
    echo ""
    
    # Get domain
    if [[ -z "$DOMAIN" ]]; then
        read -p "Enter your domain name (e.g., mypi.duckdns.org): " DOMAIN
    fi
    
    if [[ -z "$DOMAIN" ]]; then
        log_error "Domain is required"
        exit 1
    fi
    
    # Get email
    if [[ -z "$EMAIL" ]]; then
        read -p "Enter email for certificate notifications: " EMAIL
    fi
    
    echo ""
    echo "Challenge type:"
    echo "  1) HTTP-01 (port 80 must be open)"
    echo "  2) DNS-01 (requires DNS provider plugin)"
    echo ""
    read -p "Select challenge type [1]: " challenge_type
    challenge_type=${challenge_type:-1}
    
    case $challenge_type in
        1)
            obtain_http_cert
            ;;
        2)
            obtain_dns_cert
            ;;
        *)
            log_error "Invalid selection"
            exit 1
            ;;
    esac
}

# Obtain certificate via HTTP-01 challenge
obtain_http_cert() {
    log_info "Obtaining certificate via HTTP-01 challenge..."
    
    check_certbot
    
    # Stop nginx temporarily if running
    local nginx_was_running=false
    if systemctl is-active --quiet nginx 2>/dev/null; then
        nginx_was_running=true
        log_info "Stopping nginx temporarily..."
        sudo systemctl stop nginx
    fi
    
    # Obtain certificate
    local certbot_args=(
        certonly
        --standalone
        -d "$DOMAIN"
        --non-interactive
        --agree-tos
    )
    
    if [[ -n "$EMAIL" ]]; then
        certbot_args+=(--email "$EMAIL")
    else
        certbot_args+=(--register-unsafely-without-email)
    fi
    
    if sudo certbot "${certbot_args[@]}"; then
        log_success "Certificate obtained!"
        
        # Link certificates
        link_letsencrypt_certs
    else
        log_error "Failed to obtain certificate"
        
        # Restart nginx if it was running
        if $nginx_was_running; then
            sudo systemctl start nginx
        fi
        exit 1
    fi
    
    # Restart nginx if it was running
    if $nginx_was_running; then
        sudo systemctl start nginx
    fi
}

# Obtain certificate via DNS-01 challenge
obtain_dns_cert() {
    log_info "DNS-01 challenge selected"
    echo ""
    echo "Supported DNS providers:"
    echo "  1) DuckDNS (duckdns.org)"
    echo "  2) Cloudflare"
    echo "  3) Manual DNS (any provider)"
    echo ""
    read -p "Select DNS provider [1]: " dns_provider
    dns_provider=${dns_provider:-1}
    
    check_certbot
    
    case $dns_provider in
        1)
            obtain_duckdns_cert
            ;;
        2)
            obtain_cloudflare_cert
            ;;
        3)
            obtain_manual_dns_cert
            ;;
        *)
            log_error "Invalid selection"
            exit 1
            ;;
    esac
}

# DuckDNS certificate
obtain_duckdns_cert() {
    log_info "Setting up DuckDNS DNS-01 challenge..."
    
    # Install DuckDNS plugin
    if ! pip3 show certbot-dns-duckdns &>/dev/null; then
        log_info "Installing certbot-dns-duckdns plugin..."
        sudo pip3 install certbot-dns-duckdns
    fi
    
    read -p "Enter your DuckDNS token: " duckdns_token
    
    # Create credentials file
    local creds_file="/etc/letsencrypt/duckdns.ini"
    sudo mkdir -p /etc/letsencrypt
    echo "dns_duckdns_token = $duckdns_token" | sudo tee "$creds_file" > /dev/null
    sudo chmod 600 "$creds_file"
    
    # Obtain certificate
    local certbot_args=(
        certonly
        --authenticator dns-duckdns
        --dns-duckdns-credentials "$creds_file"
        --dns-duckdns-propagation-seconds 60
        -d "$DOMAIN"
        --non-interactive
        --agree-tos
    )
    
    if [[ -n "$EMAIL" ]]; then
        certbot_args+=(--email "$EMAIL")
    else
        certbot_args+=(--register-unsafely-without-email)
    fi
    
    if sudo certbot "${certbot_args[@]}"; then
        log_success "Certificate obtained!"
        link_letsencrypt_certs
    else
        log_error "Failed to obtain certificate"
        exit 1
    fi
}

# Cloudflare certificate
obtain_cloudflare_cert() {
    log_info "Setting up Cloudflare DNS-01 challenge..."
    
    # Install Cloudflare plugin
    if ! command -v certbot &> /dev/null || ! pip3 show certbot-dns-cloudflare &>/dev/null; then
        log_info "Installing certbot-dns-cloudflare plugin..."
        if command -v apt-get &> /dev/null; then
            sudo apt-get install -y python3-certbot-dns-cloudflare
        else
            sudo pip3 install certbot-dns-cloudflare
        fi
    fi
    
    read -p "Enter your Cloudflare API token: " cf_token
    
    # Create credentials file
    local creds_file="/etc/letsencrypt/cloudflare.ini"
    sudo mkdir -p /etc/letsencrypt
    echo "dns_cloudflare_api_token = $cf_token" | sudo tee "$creds_file" > /dev/null
    sudo chmod 600 "$creds_file"
    
    # Obtain certificate
    local certbot_args=(
        certonly
        --dns-cloudflare
        --dns-cloudflare-credentials "$creds_file"
        -d "$DOMAIN"
        --non-interactive
        --agree-tos
    )
    
    if [[ -n "$EMAIL" ]]; then
        certbot_args+=(--email "$EMAIL")
    else
        certbot_args+=(--register-unsafely-without-email)
    fi
    
    if sudo certbot "${certbot_args[@]}"; then
        log_success "Certificate obtained!"
        link_letsencrypt_certs
    else
        log_error "Failed to obtain certificate"
        exit 1
    fi
}

# Manual DNS certificate
obtain_manual_dns_cert() {
    log_info "Manual DNS-01 challenge..."
    log_warn "You will need to manually add a TXT record to your DNS."
    
    local certbot_args=(
        certonly
        --manual
        --preferred-challenges dns
        -d "$DOMAIN"
        --agree-tos
    )
    
    if [[ -n "$EMAIL" ]]; then
        certbot_args+=(--email "$EMAIL")
    else
        certbot_args+=(--register-unsafely-without-email)
    fi
    
    if sudo certbot "${certbot_args[@]}"; then
        log_success "Certificate obtained!"
        link_letsencrypt_certs
    else
        log_error "Failed to obtain certificate"
        exit 1
    fi
}

# Link Let's Encrypt certificates to EasyPi cert directory
link_letsencrypt_certs() {
    local le_cert_dir="/etc/letsencrypt/live/$DOMAIN"
    
    if [[ ! -d "$le_cert_dir" ]]; then
        log_error "Let's Encrypt certificate directory not found: $le_cert_dir"
        exit 1
    fi
    
    mkdir -p "$CERT_DIR"
    
    # Create symlinks
    ln -sf "$le_cert_dir/fullchain.pem" "$CERT_DIR/cert.pem"
    ln -sf "$le_cert_dir/privkey.pem" "$CERT_DIR/key.pem"
    
    # Mark as Let's Encrypt
    echo "$DOMAIN" > "$CERT_DIR/.letsencrypt"
    
    log_success "Certificates linked to $CERT_DIR"
    
    # Setup auto-renewal
    setup_auto_renewal
    
    # Reload nginx
    if systemctl is-active --quiet nginx 2>/dev/null; then
        log_info "Reloading nginx..."
        sudo systemctl reload nginx
    fi
    
    echo ""
    log_success "Let's Encrypt setup complete!"
    echo ""
    echo -e "${GREEN}Your EasyPi is now accessible at:${NC}"
    echo -e "  https://$DOMAIN"
    echo ""
    echo -e "${BLUE}Certificate will auto-renew before expiry.${NC}"
}

# Setup auto-renewal for Let's Encrypt
setup_auto_renewal() {
    log_info "Setting up Let's Encrypt auto-renewal..."
    
    # Create renewal hook
    local hook_dir="/etc/letsencrypt/renewal-hooks/deploy"
    sudo mkdir -p "$hook_dir"
    
    sudo tee "$hook_dir/easypi-reload.sh" > /dev/null << 'EOF'
#!/bin/bash
# Reload nginx after certificate renewal
systemctl reload nginx 2>/dev/null || true
EOF
    
    sudo chmod +x "$hook_dir/easypi-reload.sh"
    
    # Enable certbot timer
    if systemctl list-unit-files | grep -q certbot.timer; then
        sudo systemctl enable --now certbot.timer
        log_success "Certbot auto-renewal enabled"
    else
        # Setup cron for systems without systemd timer
        if ! crontab -l 2>/dev/null | grep -q "certbot renew"; then
            (crontab -l 2>/dev/null; echo "0 3 * * * certbot renew --quiet") | crontab -
            log_success "Cron job for auto-renewal added"
        fi
    fi
}

# Check Let's Encrypt certificate status
check_status() {
    if [[ -f "$CERT_DIR/.letsencrypt" ]]; then
        local domain=$(cat "$CERT_DIR/.letsencrypt")
        log_info "Let's Encrypt certificate for: $domain"
        sudo certbot certificates -d "$domain" 2>/dev/null || true
    else
        log_warn "No Let's Encrypt certificate configured"
        log_info "Using self-signed certificate"
    fi
}

# Revoke and remove Let's Encrypt certificate
revoke() {
    if [[ ! -f "$CERT_DIR/.letsencrypt" ]]; then
        log_error "No Let's Encrypt certificate to revoke"
        exit 1
    fi
    
    local domain=$(cat "$CERT_DIR/.letsencrypt")
    
    read -p "Are you sure you want to revoke certificate for $domain? [y/N]: " confirm
    if [[ "$confirm" =~ ^[Yy]$ ]]; then
        sudo certbot revoke --cert-name "$domain" --delete-after-revoke
        rm -f "$CERT_DIR/.letsencrypt"
        rm -f "$CERT_DIR/cert.pem" "$CERT_DIR/key.pem"
        
        log_success "Certificate revoked"
        log_info "Generating new self-signed certificate..."
        /opt/EasyPi/scripts/setup/generate_certs.sh ca-signed
    fi
}

# Main
case "${1:-setup}" in
    setup|obtain)
        interactive_setup
        ;;
    renew)
        sudo certbot renew
        ;;
    status|check)
        check_status
        ;;
    revoke)
        revoke
        ;;
    *)
        echo "Usage: $0 {setup|renew|status|revoke}"
        echo ""
        echo "Commands:"
        echo "  setup   Interactive Let's Encrypt certificate setup"
        echo "  renew   Renew certificates"
        echo "  status  Check certificate status"
        echo "  revoke  Revoke and remove Let's Encrypt certificate"
        exit 1
        ;;
esac
