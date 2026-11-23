#!/bin/bash
# EasyPi SSL Certificate Generator
# Creates self-signed certificates with proper SAN for local access

set -e

CERT_DIR="${EASYPI_CERT_DIR:-/opt/EasyPi/certs}"
CERT_DAYS="${CERT_DAYS:-${EASYPI_SSL_DAYS:-36500}}"
CA_DAYS="${EASYPI_CA_DAYS:-3650}"
RENEWAL_WINDOW_SECONDS="${EASYPI_CERT_RENEWAL_WINDOW_SECONDS:-2592000}"
CERT_BITS="${CERT_BITS:-4096}"
# Service account/group that runs the backend + NetProtection engine. They must
# be able to read the SERVER cert/key (for HTTPS, DoH and DoT); the CA signing
# key stays restricted to root.
EASYPI_GROUP="${EASYPI_GROUP:-easypi}"

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

# Get all local IP addresses
get_local_ips() {
    local ips=""
    # Get IPv4 addresses
    if command -v ip &> /dev/null; then
        ips=$(ip -4 addr show | grep -oP '(?<=inet\s)\d+(\.\d+){3}' | grep -v '^127\.' | sort -u)
    elif command -v hostname &> /dev/null; then
        ips=$(hostname -I 2>/dev/null | tr ' ' '\n' | grep -E '^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$' | grep -v '^127\.' | sort -u)
    fi
    echo "$ips"
}

# Get hostname
get_hostname() {
    hostname -f 2>/dev/null || hostname 2>/dev/null || echo "easypi"
}

# Generate OpenSSL config with SAN
generate_openssl_config() {
    local config_file="$1"
    local hostname=$(get_hostname)
    local ips=$(get_local_ips)
    
    cat > "$config_file" << EOF
[req]
default_bits = ${CERT_BITS}
prompt = no
default_md = sha256
x509_extensions = v3_req
distinguished_name = dn

[dn]
C = US
ST = Local
L = Local
O = EasyPi
OU = Self-Signed
CN = ${hostname}

[v3_req]
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
DNS.2 = ${hostname}
DNS.3 = ${hostname}.local
DNS.4 = easypi
DNS.5 = easypi.local
IP.1 = 127.0.0.1
IP.2 = ::1
EOF

    # Add all local IPs
    local ip_counter=3
    for ip in $ips; do
        echo "IP.${ip_counter} = ${ip}" >> "$config_file"
        ((ip_counter++))
    done
    
    log_info "Generated OpenSSL config with SANs:"
    grep -E "^(DNS|IP)\." "$config_file" | sed 's/^/  /'
}

# Make the SERVER cert/key readable by the service group so the NetProtection
# engine and backend (running as $EASYPI_GROUP) can load them for HTTPS/DoH/DoT.
# Without this the engine cannot read the key and the DoH/DoT listeners silently
# fail to start. The CA private key is kept root-only.
apply_service_perms() {
    if getent group "$EASYPI_GROUP" >/dev/null 2>&1; then
        chgrp "$EASYPI_GROUP" "$CERT_DIR" 2>/dev/null || true
        chmod 750 "$CERT_DIR"
        if [ -f "$CERT_DIR/key.pem" ]; then
            chgrp "$EASYPI_GROUP" "$CERT_DIR/key.pem" 2>/dev/null || true
            chmod 640 "$CERT_DIR/key.pem"
        fi
        for pub in cert.pem ca.pem; do
            if [ -f "$CERT_DIR/$pub" ]; then
                chgrp "$EASYPI_GROUP" "$CERT_DIR/$pub" 2>/dev/null || true
                chmod 644 "$CERT_DIR/$pub"
            fi
        done
    else
        # Service group not present yet — keep the directory locked down; the
        # installer re-runs this (or fixes ownership) once the account exists.
        chmod 700 "$CERT_DIR"
    fi
    # CA signing key is never exposed to the service account.
    if [ -f "$CERT_DIR/ca-key.pem" ]; then
        chown root:root "$CERT_DIR/ca-key.pem" 2>/dev/null || true
        chmod 600 "$CERT_DIR/ca-key.pem"
    fi
}

# Generate self-signed certificate
generate_self_signed() {
    log_info "Generating self-signed certificate..."
    
    mkdir -p "$CERT_DIR"
    chmod 700 "$CERT_DIR"
    
    local config_file=$(mktemp)
    generate_openssl_config "$config_file"
    
    # Generate private key and certificate
    openssl req -x509 -nodes -days "$CERT_DAYS" -newkey rsa:"$CERT_BITS" \
        -keyout "$CERT_DIR/key.pem" \
        -out "$CERT_DIR/cert.pem" \
        -config "$config_file" \
        2>/dev/null
    
    rm -f "$config_file"
    
    # Set proper permissions
    chmod 600 "$CERT_DIR/key.pem"
    chmod 644 "$CERT_DIR/cert.pem"
    apply_service_perms

    # Verify certificate
    if openssl x509 -in "$CERT_DIR/cert.pem" -noout -text &>/dev/null; then
        log_success "Certificate generated successfully!"
        log_info "Certificate location: $CERT_DIR/cert.pem"
        log_info "Private key location: $CERT_DIR/key.pem"
        
        # Show certificate info
        echo ""
        log_info "Certificate details:"
        openssl x509 -in "$CERT_DIR/cert.pem" -noout -subject -dates -ext subjectAltName 2>/dev/null | sed 's/^/  /'
    else
        log_error "Certificate generation failed!"
        return 1
    fi
}

# Confirm that a private key belongs to a certificate without exposing either.
certificate_key_matches() {
    local key_file="$1"
    local cert_file="$2"
    local key_public=""
    local cert_public=""

    key_public="$(mktemp)"
    cert_public="$(mktemp)"
    if ! openssl pkey -in "$key_file" -pubout -outform DER \
        > "$key_public" 2>/dev/null \
        || ! openssl x509 -in "$cert_file" -pubkey -noout 2>/dev/null \
        | openssl pkey -pubin -outform DER > "$cert_public" 2>/dev/null; then
        rm -f -- "$key_public" "$cert_public"
        return 1
    fi

    local matches=0
    if ! cmp -s -- "$key_public" "$cert_public"; then
        matches=1
    fi
    rm -f -- "$key_public" "$cert_public"
    return "$matches"
}

validate_certificate_paths() {
    if [ -L "$CERT_DIR" ]; then
        log_error "Certificate directory must not be a symlink: $CERT_DIR"
        return 1
    fi
    mkdir -p "$CERT_DIR"
    chmod 700 "$CERT_DIR"

    local protected_file
    for protected_file in ca-key.pem ca.pem key.pem cert.pem .letsencrypt; do
        if [ -L "$CERT_DIR/$protected_file" ]; then
            log_error "Certificate material must not be a symlink: $CERT_DIR/$protected_file"
            return 1
        fi
    done
}

ca_material_exists() {
    [ -e "$CERT_DIR/ca-key.pem" ] || [ -e "$CERT_DIR/ca.pem" ]
}

ca_material_valid() {
    [ -f "$CERT_DIR/ca-key.pem" ] \
        && [ -f "$CERT_DIR/ca.pem" ] \
        && openssl pkey -in "$CERT_DIR/ca-key.pem" -check -noout >/dev/null 2>&1 \
        && openssl x509 -checkend "$RENEWAL_WINDOW_SECONDS" -noout \
            -in "$CERT_DIR/ca.pem" >/dev/null 2>&1 \
        && openssl verify -CAfile "$CERT_DIR/ca.pem" \
            "$CERT_DIR/ca.pem" >/dev/null 2>&1 \
        && certificate_key_matches "$CERT_DIR/ca-key.pem" "$CERT_DIR/ca.pem"
}

server_material_valid() {
    ca_material_valid \
        && [ -f "$CERT_DIR/key.pem" ] \
        && [ -f "$CERT_DIR/cert.pem" ] \
        && openssl pkey -in "$CERT_DIR/key.pem" -check -noout >/dev/null 2>&1 \
        && openssl x509 -checkend "$RENEWAL_WINDOW_SECONDS" -noout \
            -in "$CERT_DIR/cert.pem" >/dev/null 2>&1 \
        && openssl verify -CAfile "$CERT_DIR/ca.pem" \
            "$CERT_DIR/cert.pem" >/dev/null 2>&1 \
        && certificate_key_matches "$CERT_DIR/key.pem" "$CERT_DIR/cert.pem"
}

install_atomically() {
    local source_file="$1"
    local target_file="$2"
    local file_mode="$3"
    local staged_file=""

    staged_file="$(mktemp "${target_file}.new.XXXXXX")"
    if ! install -m "$file_mode" "$source_file" "$staged_file"; then
        rm -f -- "$staged_file"
        return 1
    fi
    mv -f -- "$staged_file" "$target_file"
}

build_server_material() {
    local ca_cert="$1"
    local ca_key="$2"
    local work_dir="$3"
    local reusable_key="${4:-}"
    local config_file="$work_dir/openssl.cnf"
    local ext_file="$work_dir/extensions.cnf"

    if [ -n "$reusable_key" ]; then
        cp -- "$reusable_key" "$work_dir/key.pem"
        chmod 600 "$work_dir/key.pem"
    elif ! openssl genrsa -out "$work_dir/key.pem" "$CERT_BITS" 2>/dev/null; then
        return 1
    fi

    generate_openssl_config "$config_file"
    if ! openssl req -new -key "$work_dir/key.pem" \
        -out "$work_dir/server.csr" \
        -config "$config_file" \
        2>/dev/null; then
        return 1
    fi

    cat > "$ext_file" << 'EOF'
basicConstraints = CA:FALSE
keyUsage = nonRepudiation, digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
EOF
    grep -E "^(DNS|IP)\." "$config_file" >> "$ext_file"

    if ! openssl x509 -req -in "$work_dir/server.csr" \
        -CA "$ca_cert" \
        -CAkey "$ca_key" \
        -CAserial "$work_dir/ca.srl" \
        -CAcreateserial \
        -out "$work_dir/cert.pem" \
        -days "$CERT_DAYS" \
        -sha256 \
        -extfile "$ext_file" \
        2>/dev/null; then
        return 1
    fi

    openssl pkey -in "$work_dir/key.pem" -check -noout >/dev/null 2>&1 \
        && openssl x509 -in "$work_dir/cert.pem" -noout >/dev/null 2>&1 \
        && openssl verify -CAfile "$ca_cert" "$work_dir/cert.pem" >/dev/null 2>&1 \
        && certificate_key_matches "$work_dir/key.pem" "$work_dir/cert.pem"
}

renew_ca_signed_server_certificate() {
    if ! ca_material_valid; then
        log_error "The existing EasyPi Root CA is missing, invalid, mismatched, or expires soon."
        log_error "Refusing to replace trusted CA material implicitly; run '$0 rotate-ca' explicitly."
        return 1
    fi

    local work_dir=""
    local reusable_key=""
    work_dir="$(mktemp -d "$CERT_DIR/.server-renewal.XXXXXX")"
    chmod 700 "$work_dir"

    if [ -f "$CERT_DIR/key.pem" ] \
        && openssl pkey -in "$CERT_DIR/key.pem" -check -noout >/dev/null 2>&1; then
        reusable_key="$CERT_DIR/key.pem"
    fi

    if ! build_server_material \
        "$CERT_DIR/ca.pem" "$CERT_DIR/ca-key.pem" "$work_dir" "$reusable_key"; then
        rm -rf -- "$work_dir"
        log_error "Server certificate renewal failed; the installed certificate was left unchanged."
        return 1
    fi

    # A normal renewal reuses a valid server key, so the certificate can be
    # replaced with a single same-filesystem rename. Replace the key only when
    # the old one was missing or invalid.
    if [ -z "$reusable_key" ]; then
        install_atomically "$work_dir/key.pem" "$CERT_DIR/key.pem" 0600
    fi
    install_atomically "$work_dir/cert.pem" "$CERT_DIR/cert.pem" 0644
    rm -rf -- "$work_dir"
    apply_service_perms
    log_success "Server certificate renewed; existing EasyPi Root CA preserved."
}

create_ca_signed_bundle() {
    local work_dir=""
    work_dir="$(mktemp -d "$CERT_DIR/.ca-rotation.XXXXXX")"
    chmod 700 "$work_dir"

    if ! openssl genrsa -out "$work_dir/ca-key.pem" "$CERT_BITS" 2>/dev/null \
        || ! openssl req -x509 -new -nodes -key "$work_dir/ca-key.pem" \
            -sha256 -days "$CA_DAYS" \
            -out "$work_dir/ca.pem" \
            -subj "/C=US/ST=Local/L=Local/O=EasyPi CA/CN=EasyPi Root CA" \
            -addext "basicConstraints=critical,CA:TRUE,pathlen:0" \
            -addext "keyUsage=critical,keyCertSign,cRLSign" \
            2>/dev/null \
        || ! build_server_material \
            "$work_dir/ca.pem" "$work_dir/ca-key.pem" "$work_dir"; then
        rm -rf -- "$work_dir"
        log_error "CA-signed certificate generation failed; installed material was left unchanged."
        return 1
    fi

    install_atomically "$work_dir/ca-key.pem" "$CERT_DIR/ca-key.pem" 0600
    install_atomically "$work_dir/ca.pem" "$CERT_DIR/ca.pem" 0644
    install_atomically "$work_dir/key.pem" "$CERT_DIR/key.pem" 0600
    install_atomically "$work_dir/cert.pem" "$CERT_DIR/cert.pem" 0644
    rm -rf -- "$work_dir"
    apply_service_perms

    log_success "CA-signed certificate generated!"
    log_info "CA certificate (import this): $CERT_DIR/ca.pem"
    log_info "Server certificate: $CERT_DIR/cert.pem"
    log_info "Server private key: $CERT_DIR/key.pem"
}

# Ensure a CA and server certificate exist without silently replacing the
# installation Root CA trusted by browsers and managed clients.
generate_ca_signed() {
    log_info "Ensuring CA and server certificate..."

    # Let's Encrypt deployments own the active server certificate lifecycle.
    # An install or local-CA maintenance pass must never replace that identity.
    if [ -f "$CERT_DIR/.letsencrypt" ]; then
        if [ -L "$CERT_DIR" ] || [ -L "$CERT_DIR/.letsencrypt" ]; then
            log_error "Let's Encrypt certificate metadata must not be a symlink."
            return 1
        fi
        if [ -f "$CERT_DIR/key.pem" ] \
            && [ -f "$CERT_DIR/cert.pem" ] \
            && openssl pkey -in "$CERT_DIR/key.pem" -check -noout >/dev/null 2>&1 \
            && openssl x509 -in "$CERT_DIR/cert.pem" -noout >/dev/null 2>&1 \
            && certificate_key_matches "$CERT_DIR/key.pem" "$CERT_DIR/cert.pem"; then
            log_success "Externally managed Let's Encrypt certificate preserved."
            return 0
        fi
        log_error "Let's Encrypt certificate material is invalid; repair or renew it with the Let's Encrypt workflow."
        return 1
    fi

    validate_certificate_paths

    if server_material_valid; then
        apply_service_perms
        log_success "Existing CA and server certificate are valid; preserving installation trust"
        return 0
    fi

    if ca_material_valid; then
        log_info "The server certificate is missing, invalid, or expires soon; renewing it with the existing Root CA."
        renew_ca_signed_server_certificate
        return 0
    fi

    if ca_material_exists; then
        log_error "Existing EasyPi Root CA material is incomplete, invalid, mismatched, or expires soon."
        log_error "Refusing an implicit trust reset; run '$0 rotate-ca' and redistribute ca.pem if rotation is intended."
        return 1
    fi

    log_info "No EasyPi Root CA exists; generating a new installation trust bundle."
    create_ca_signed_bundle
    
    echo ""
    print_trust_instructions
}

rotate_ca() {
    log_warn "Rotating the EasyPi Root CA. Every client that trusted the old ca.pem must import the new one."
    if [ -e "$CERT_DIR/.letsencrypt" ] || [ -L "$CERT_DIR/.letsencrypt" ]; then
        log_error "Disable the Let's Encrypt certificate workflow before rotating to a local EasyPi Root CA."
        return 1
    fi
    validate_certificate_paths
    create_ca_signed_bundle
    echo ""
    print_trust_instructions
}

# Print instructions for trusting the certificate
print_trust_instructions() {
    local ca_cert="$CERT_DIR/ca.pem"
    local ips=$(get_local_ips | head -1)
    
    echo ""
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo -e "${YELLOW}  HOW TO TRUST THE CERTIFICATE (removes browser warnings)${NC}"
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
    echo ""
    
    echo -e "${BLUE}📁 Certificate file to import:${NC} $ca_cert"
    echo -e "${BLUE}📋 Or download from:${NC} https://${ips:-localhost}:443/ca.pem"
    echo ""
    
    echo -e "${GREEN}▶ Windows:${NC}"
    echo "  1. Download ca.pem and rename to ca.crt"
    echo "  2. Double-click ca.crt → Install Certificate"
    echo "  3. Choose 'Local Machine' → Next"
    echo "  4. Select 'Place all certificates in the following store'"
    echo "  5. Browse → 'Trusted Root Certification Authorities' → OK"
    echo "  6. Next → Finish → Restart browser"
    echo ""
    
    echo -e "${GREEN}▶ macOS:${NC}"
    echo "  1. Download ca.pem"
    echo "  2. Double-click to open in Keychain Access"
    echo "  3. Find 'EasyPi Root CA' in System keychain"
    echo "  4. Double-click → Trust → 'Always Trust'"
    echo "  5. Close and restart browser"
    echo ""
    
    echo -e "${GREEN}▶ Linux (Ubuntu/Debian):${NC}"
    echo "  sudo cp $ca_cert /usr/local/share/ca-certificates/easypi-ca.crt"
    echo "  sudo update-ca-certificates"
    echo "  # Restart browser"
    echo ""
    
    echo -e "${GREEN}▶ Linux (Fedora/RHEL):${NC}"
    echo "  sudo cp $ca_cert /etc/pki/ca-trust/source/anchors/easypi-ca.pem"
    echo "  sudo update-ca-trust"
    echo "  # Restart browser"
    echo ""
    
    echo -e "${GREEN}▶ Android:${NC}"
    echo "  1. Copy ca.pem to device"
    echo "  2. Settings → Security → Encryption & credentials"
    echo "  3. Install a certificate → CA certificate"
    echo "  4. Select ca.pem file"
    echo "  5. Name it 'EasyPi CA'"
    echo ""
    
    echo -e "${GREEN}▶ iOS:${NC}"
    echo "  1. Download ca.pem via Safari"
    echo "  2. Settings → Profile Downloaded → Install"
    echo "  3. Settings → General → About → Certificate Trust Settings"
    echo "  4. Enable 'EasyPi Root CA'"
    echo ""
    
    echo -e "${YELLOW}═══════════════════════════════════════════════════════════════${NC}"
}

# Check certificate expiry
check_certificate() {
    if [[ ! -f "$CERT_DIR/cert.pem" ]]; then
        log_warn "No certificate found at $CERT_DIR/cert.pem"
        return 1
    fi
    
    local expiry=$(openssl x509 -in "$CERT_DIR/cert.pem" -noout -enddate 2>/dev/null | cut -d= -f2)
    local expiry_epoch=$(date -d "$expiry" +%s 2>/dev/null || date -j -f "%b %d %T %Y %Z" "$expiry" +%s 2>/dev/null)
    local now_epoch=$(date +%s)
    local days_left=$(( (expiry_epoch - now_epoch) / 86400 ))
    
    echo ""
    log_info "Certificate status:"
    echo "  Expires: $expiry"
    echo "  Days remaining: $days_left"
    
    if [[ $days_left -lt 30 ]]; then
        log_warn "Certificate expires in less than 30 days!"
        return 2
    elif [[ $days_left -lt 0 ]]; then
        log_error "Certificate has EXPIRED!"
        return 3
    else
        log_success "Certificate is valid"
    fi
}

# Renew certificate
renew_certificate() {
    log_info "Renewing certificate..."
    
    if [ -f "$CERT_DIR/.letsencrypt" ]; then
        log_error "This certificate is managed by Let's Encrypt; use the configured certbot renewal workflow."
        return 1
    fi
    validate_certificate_paths
    if ca_material_exists; then
        renew_ca_signed_server_certificate
    else
        generate_self_signed
    fi
    
    # Reload nginx if running
    if systemctl is-active --quiet nginx 2>/dev/null; then
        log_info "Reloading nginx..."
        sudo systemctl reload nginx
    fi
    
    log_success "Certificate renewed!"
}

# Setup auto-renewal cron job
setup_auto_renewal() {
    local cron_file="/etc/cron.monthly/easypi-cert-renewal"
    
    log_info "Setting up monthly certificate renewal..."
    
    sudo tee "$cron_file" > /dev/null << 'EOF'
#!/bin/bash
# EasyPi certificate auto-renewal
/opt/EasyPi/scripts/setup/generate_certs.sh ca-signed >> /var/log/easypi-cert-renewal.log 2>&1
EOF
    
    sudo chmod +x "$cron_file"
    log_success "Auto-renewal configured (monthly)"
}

# Main
case "${1:-generate}" in
    generate|self-signed)
        generate_self_signed
        ;;
    ca|ca-signed)
        generate_ca_signed
        ;;
    check|status)
        check_certificate
        ;;
    renew)
        renew_certificate
        ;;
    rotate-ca)
        rotate_ca
        ;;
    auto-renewal)
        setup_auto_renewal
        ;;
    trust|instructions)
        print_trust_instructions
        ;;
    *)
        echo "Usage: $0 {generate|ca-signed|check|renew|rotate-ca|auto-renewal|trust}"
        echo ""
        echo "Commands:"
        echo "  generate      Generate simple self-signed certificate"
        echo "  ca-signed     Generate CA + server certificate (recommended for trusting)"
        echo "  check         Check certificate expiry"
        echo "  renew         Renew only the server certificate; preserve the trusted Root CA"
        echo "  rotate-ca     Explicitly replace the Root CA and server certificate"
        echo "  auto-renewal  Setup monthly auto-renewal cron job"
        echo "  trust         Show instructions for trusting the certificate"
        exit 1
        ;;
esac
