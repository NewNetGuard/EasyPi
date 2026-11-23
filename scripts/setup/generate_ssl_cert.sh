#!/usr/bin/env bash
# Generate self-signed SSL certificate for EasyPi
set -euo pipefail

CERT_DIR="/etc/ssl/certs"
KEY_DIR="/etc/ssl/private"
CERT_FILE="${CERT_DIR}/easypi-selfsigned.crt"
KEY_FILE="${KEY_DIR}/easypi-selfsigned.key"
DAYS_VALID="${EASYPI_SSL_DAYS:-36500}"

# Colors
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
NC="\033[0m"

info() { echo -e "${GREEN}==>${NC} $1"; }
warn() { echo -e "${YELLOW}==>${NC} $1"; }

# Check if running as root
if [[ "${EUID}" -ne 0 ]]; then
    echo "Please run with sudo"
    exit 1
fi

# Check if certificate already exists and is valid
if [[ -f "${CERT_FILE}" ]] && [[ -f "${KEY_FILE}" ]]; then
    # Check expiry
    if openssl x509 -checkend 2592000 -noout -in "${CERT_FILE}" 2>/dev/null; then
        info "Valid certificate already exists at ${CERT_FILE}"
        exit 0
    else
        warn "Certificate exists but expires soon, regenerating..."
    fi
fi

info "Generating self-signed SSL certificate..."

# Get hostname and IP for certificate
HOSTNAME=$(hostname -f 2>/dev/null || hostname)
LOCAL_IP=$(hostname -I | awk '{print $1}')

# Create certificate with SAN (Subject Alternative Names)
openssl req -x509 -nodes -days ${DAYS_VALID} \
    -newkey rsa:2048 \
    -keyout "${KEY_FILE}" \
    -out "${CERT_FILE}" \
    -subj "/CN=${HOSTNAME}/O=EasyPi/C=US" \
    -addext "subjectAltName=DNS:${HOSTNAME},DNS:easypi.local,DNS:localhost,IP:${LOCAL_IP},IP:127.0.0.1"

# Set permissions
chmod 644 "${CERT_FILE}"
chmod 600 "${KEY_FILE}"

info "SSL certificate generated successfully!"
info "  Certificate: ${CERT_FILE}"
info "  Private key: ${KEY_FILE}"
info "  Valid for: ${DAYS_VALID} days"
warn "Note: Browsers will show a security warning for self-signed certificates."
warn "This is expected - click 'Advanced' and 'Proceed' to continue."
