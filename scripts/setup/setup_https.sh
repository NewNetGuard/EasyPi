#!/bin/bash
# EasyPi Nginx Reverse Proxy Setup
# Configures nginx as HTTPS reverse proxy

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
EASYPI_ROOT="${EASYPI_ROOT:-/opt/EasyPi}"
CERT_DIR="${EASYPI_CERT_DIR:-$EASYPI_ROOT/certs}"
NGINX_CONF_DIR="/etc/nginx"

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

# Install nginx if not present
install_nginx() {
    if command -v nginx &> /dev/null; then
        log_success "nginx is already installed"
        return
    fi
    
    log_info "Installing nginx..."
    
    if command -v apt-get &> /dev/null; then
        sudo apt-get update
        sudo apt-get install -y nginx
    elif command -v dnf &> /dev/null; then
        sudo dnf install -y nginx
    elif command -v yum &> /dev/null; then
        sudo yum install -y nginx
    elif command -v pacman &> /dev/null; then
        sudo pacman -S --noconfirm nginx
    else
        log_error "Unsupported package manager. Please install nginx manually."
        exit 1
    fi
    
    log_success "nginx installed"
}

# Generate SSL certificates
generate_certificates() {
    local certificate_action="ca-signed"
    if [[ -f "$CERT_DIR/cert.pem" ]] && [[ -f "$CERT_DIR/key.pem" ]]; then
        log_info "Certificates already exist at $CERT_DIR"
        if [[ -f "$CERT_DIR/.letsencrypt" ]]; then
            log_info "The active certificate is managed by Let's Encrypt; leaving it unchanged."
            return
        fi
        # In non-interactive mode, skip regeneration
        if [[ "${NONINTERACTIVE:-}" == "1" ]] || [[ ! -t 0 ]]; then
            return
        fi
        if [[ -f "$CERT_DIR/ca.pem" ]] || [[ -f "$CERT_DIR/ca-key.pem" ]]; then
            read -p "Renew the server certificate while preserving the trusted EasyPi Root CA? [y/N]: " regenerate
            certificate_action="renew"
        else
            read -p "Replace the existing certificate with a new EasyPi local-CA certificate? [y/N]: " regenerate
        fi
        if [[ ! "$regenerate" =~ ^[Yy]$ ]]; then
            return
        fi
    fi
    
    log_info "Generating SSL certificates..."
    
    # Use CA-signed for better trust experience
    "$SCRIPT_DIR/generate_certs.sh" "$certificate_action"
}

# Configure nginx
configure_nginx() {
    log_info "Configuring nginx..."
    
    # Backup existing config
    if [[ -f "$NGINX_CONF_DIR/sites-enabled/default" ]]; then
        sudo mv "$NGINX_CONF_DIR/sites-enabled/default" "$NGINX_CONF_DIR/sites-enabled/default.bak" 2>/dev/null || true
    fi
    
    # Copy EasyPi nginx config
    sudo cp "$EASYPI_ROOT/templates/nginx/easypi.conf" "$NGINX_CONF_DIR/sites-available/easypi"
    sudo cp "$EASYPI_ROOT/templates/nginx/easypi-mobile-link.conf" "$NGINX_CONF_DIR/sites-available/easypi-mobile-link"
    
    # Update paths in config
    sudo sed -i "s|/opt/EasyPi|$EASYPI_ROOT|g" "$NGINX_CONF_DIR/sites-available/easypi"
    sudo sed -i "s|/opt/EasyPi|$EASYPI_ROOT|g" "$NGINX_CONF_DIR/sites-available/easypi-mobile-link"
    
    # Enable site
    sudo ln -sf "$NGINX_CONF_DIR/sites-available/easypi" "$NGINX_CONF_DIR/sites-enabled/easypi"
    sudo ln -sf "$NGINX_CONF_DIR/sites-available/easypi-mobile-link" "$NGINX_CONF_DIR/sites-enabled/easypi-mobile-link"
    
    # Test nginx config
    if sudo nginx -t; then
        log_success "nginx configuration valid"
    else
        log_error "nginx configuration invalid!"
        exit 1
    fi
}

# Configure firewall
configure_firewall() {
    log_info "Configuring firewall..."
    
    if command -v ufw &> /dev/null; then
        sudo ufw allow 80/tcp comment 'HTTP'
        sudo ufw allow 443/tcp comment 'HTTPS'
        log_success "UFW rules added"
    elif command -v firewall-cmd &> /dev/null; then
        sudo firewall-cmd --permanent --add-service=http
        sudo firewall-cmd --permanent --add-service=https
        sudo firewall-cmd --reload
        log_success "firewalld rules added"
    else
        log_warn "No firewall detected. Make sure ports 80 and 443 are open."
    fi
}

# Start and enable nginx
start_nginx() {
    log_info "Starting nginx..."
    
    sudo systemctl enable nginx
    sudo systemctl restart nginx
    
    if systemctl is-active --quiet nginx; then
        log_success "nginx is running"
    else
        log_error "nginx failed to start"
        sudo systemctl status nginx
        exit 1
    fi
}

# Update backend CORS and cookie settings
update_backend_settings() {
    log_info "Updating backend security settings..."
    
    local config_file="$EASYPI_ROOT/backend/config.py"
    
    if [[ -f "$config_file" ]]; then
        # Check if already configured for HTTPS
        if grep -q "SECURE_COOKIES" "$config_file"; then
            log_info "Backend already configured for HTTPS"
        else
            log_warn "Please update $config_file to enable secure cookies"
            echo ""
            echo "Add these settings to your config.py:"
            echo "  SECURE_COOKIES = True"
            echo "  COOKIE_SAMESITE = 'Lax'"
            echo "  TRUSTED_HOSTS = ['localhost', '127.0.0.1', 'your-domain.com']"
        fi
    fi
}

# Print access information (only when run standalone)
print_access_info() {
    # Skip if called from install script (EASYPI_INSTALL is set)
    if [[ "${EASYPI_INSTALL:-}" == "1" ]]; then
        return
    fi
    
    local ips=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '^127\.' | head -3)
    local hostname=$(hostname -f 2>/dev/null || hostname)
    
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${GREEN}  EasyPi HTTPS Setup Complete!${NC}"
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    echo -e "${BLUE}Access EasyPi at:${NC}"
    echo "  https://localhost"
    echo "  https://$hostname"
    for ip in $ips; do
        echo "  https://$ip"
    done
    echo ""
    echo -e "${YELLOW}⚠ Browser will show a security warning for self-signed certificate.${NC}"
    echo -e "${YELLOW}  This is normal and expected for local network access.${NC}"
    echo ""
    echo -e "${BLUE}To remove the warning, import the CA certificate:${NC}"
    echo "  Download: https://localhost/ca.pem"
    echo "  Or copy:  $CERT_DIR/ca.pem"
    echo ""
    echo -e "${BLUE}For detailed instructions:${NC}"
    echo "  $SCRIPT_DIR/generate_certs.sh trust"
    echo ""
    echo -e "${BLUE}For a trusted certificate with your own domain:${NC}"
    echo "  $SCRIPT_DIR/letsencrypt.sh setup"
    echo ""
    echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
}

# Main setup
main() {
    # Suppress header when called from install script
    if [[ "${EASYPI_INSTALL:-}" != "1" ]]; then
        echo ""
        echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
        echo -e "${BLUE}  EasyPi HTTPS Reverse Proxy Setup${NC}"
        echo -e "${BLUE}═══════════════════════════════════════════════════════════════${NC}"
        echo ""
    fi
    
    # Check if running as root or with sudo
    if [[ $EUID -ne 0 ]]; then
        log_warn "This script requires sudo privileges"
    fi
    
    install_nginx
    generate_certificates
    configure_nginx
    configure_firewall
    start_nginx
    update_backend_settings
    print_access_info
}

# Handle arguments
case "${1:-}" in
    --help|-h)
        echo "Usage: $0 [options]"
        echo ""
        echo "Options:"
        echo "  --help      Show this help"
        echo "  --no-cert   Skip certificate generation"
        echo "  --restart   Just restart nginx"
        exit 0
        ;;
    --no-cert)
        install_nginx
        configure_nginx
        configure_firewall
        start_nginx
        ;;
    --restart)
        sudo systemctl restart nginx
        log_success "nginx restarted"
        ;;
    *)
        main
        ;;
esac
