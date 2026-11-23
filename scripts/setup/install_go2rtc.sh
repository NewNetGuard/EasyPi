#!/bin/bash
# Install go2rtc for RTSP camera streaming and WebRTC support

set -e

GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
NC="\033[0m"

info() {
    echo -e "${GREEN}==>${NC} $1"
}

warn() {
    echo -e "${YELLOW}==>${NC} $1"
}

error() {
    echo -e "${RED}==>${NC} $1"
}

# Pinned release with published SHA-256 hashes.
GO2RTC_VERSION="v1.9.14"
GO2RTC_DIR="/opt/go2rtc"
GO2RTC_BIN="$GO2RTC_DIR/go2rtc"
GO2RTC_CONFIG="$GO2RTC_DIR/go2rtc.yaml"
GO2RTC_ENV="$GO2RTC_DIR/api.env"
GO2RTC_MARKER="$GO2RTC_DIR/.easypi-managed"
SYSTEMD_SERVICE="/etc/systemd/system/go2rtc.service"

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)
        GO2RTC_ARCH="amd64"
        GO2RTC_SHA256="32d616af226bd731678ffde328b94cfb94e30339bfefc469cfb76323144615a6"
        ;;
    aarch64|arm64)
        GO2RTC_ARCH="arm64"
        GO2RTC_SHA256="359fabade8a7a51e81a55fe6df6b0ef81764a5e1d63179577534eaaa71904b50"
        ;;
    armv7l|armv7)
        GO2RTC_ARCH="arm"
        GO2RTC_SHA256="4d7e1639af5a2722a28e864468fd8099b3c1682565446c798bf9e3b38fde12e4"
        ;;
    *)
        error "Unsupported architecture: $ARCH"
        exit 1
        ;;
esac

info "Detected architecture: $ARCH (using $GO2RTC_ARCH)"

# Check sudo
if [[ $EUID -ne 0 ]] && ! sudo -n true 2>/dev/null; then
    error "This script requires sudo privileges"
    exit 1
fi

# Stop existing service
if systemctl is-active --quiet go2rtc 2>/dev/null; then
    info "Stopping existing go2rtc service..."
    sudo systemctl stop go2rtc
fi

info "Using pinned version: $GO2RTC_VERSION"

# Download URL
DOWNLOAD_URL="https://github.com/AlexxIT/go2rtc/releases/download/${GO2RTC_VERSION}/go2rtc_linux_${GO2RTC_ARCH}"

# Create directory
info "Creating go2rtc directory..."
sudo mkdir -p "$GO2RTC_DIR"
sudo chmod 755 "$GO2RTC_DIR"

# Download binary
info "Downloading go2rtc binary..."
DOWNLOAD_TMP=$(mktemp)
CONFIG_TMP=$(mktemp)
CREDENTIALS_TMP=$(mktemp)
MARKER_TMP=$(mktemp)
CURL_CONFIG_TMP=$(mktemp)
trap 'rm -f "$DOWNLOAD_TMP" "$CONFIG_TMP" "$CREDENTIALS_TMP" "$MARKER_TMP" "$CURL_CONFIG_TMP"' EXIT
if ! curl -fL --proto '=https' --tlsv1.2 --progress-bar -o "$DOWNLOAD_TMP" "$DOWNLOAD_URL"; then
    error "Failed to download go2rtc from: $DOWNLOAD_URL"
    error "Please check your internet connection"
    exit 1
fi

# Verify download
if [[ ! -s "$DOWNLOAD_TMP" ]]; then
    error "Download failed - file is missing or empty"
    exit 1
fi

FILE_SIZE=$(stat -c%s "$DOWNLOAD_TMP" 2>/dev/null || echo "0")
if [[ "$FILE_SIZE" -lt 1000000 ]]; then
    error "Downloaded file is too small ($FILE_SIZE bytes) - download may have failed"
    exit 1
fi

printf '%s  %s\n' "$GO2RTC_SHA256" "$DOWNLOAD_TMP" | sha256sum -c - >/dev/null || {
    error "go2rtc SHA-256 verification failed"
    exit 1
}

info "Downloaded go2rtc binary (${FILE_SIZE} bytes)"

# Set permissions
info "Setting permissions..."
sudo install -o root -g root -m 0755 "$DOWNLOAD_TMP" "$GO2RTC_BIN"
printf '%s\n' 'easypi-managed-go2rtc-v1' > "$MARKER_TMP"
sudo install -o root -g root -m 0644 "$MARKER_TMP" "$GO2RTC_MARKER"

if ! getent group go2rtc >/dev/null 2>&1; then
    sudo groupadd --system go2rtc
fi
if ! id go2rtc >/dev/null 2>&1; then
    sudo useradd --system --gid go2rtc --home-dir "$GO2RTC_DIR" \
        --shell /usr/sbin/nologin go2rtc
fi

# Protect the localhost management API as well. go2rtc otherwise skips Basic
# authentication for loopback clients, which exposes its config and mutation
# endpoints to every local process.
API_USERNAME="easypi_internal"
API_PASSWORD=""
if [[ -f "$GO2RTC_ENV" && ! -L "$GO2RTC_ENV" ]]; then
    while IFS='=' read -r key value; do
        case "$key" in
            GO2RTC_API_USERNAME) API_USERNAME="$value" ;;
            GO2RTC_API_PASSWORD) API_PASSWORD="$value" ;;
        esac
    done < "$GO2RTC_ENV"
fi
if [[ ! "$API_USERNAME" =~ ^[A-Za-z0-9_-]{8,64}$ ]] \
   || [[ ! "$API_PASSWORD" =~ ^[A-Za-z0-9_-]{32,128}$ ]]; then
    API_USERNAME="easypi_internal"
    API_PASSWORD="$(python3 -c 'import secrets; print(secrets.token_urlsafe(48))')"
fi
printf 'GO2RTC_API_USERNAME=%s\nGO2RTC_API_PASSWORD=%s\n' \
    "$API_USERNAME" "$API_PASSWORD" > "$CREDENTIALS_TMP"
sudo install -o root -g go2rtc -m 0640 "$CREDENTIALS_TMP" "$GO2RTC_ENV"
# Older releases stored an nginx Basic-auth include here. Browser traffic no
# longer reaches go2rtc directly; only the authenticated backend uses this API.
sudo rm -f "$GO2RTC_DIR/nginx-auth.conf"

# Create config file
info "Creating configuration file..."
cat > "$CONFIG_TMP" << EOF
# go2rtc configuration
app:
  modules: [api, ws, rtsp, mp4]

api:
  listen: "127.0.0.1:1984"
  username: "\${GO2RTC_API_USERNAME}"
  password: "\${GO2RTC_API_PASSWORD}"
  local_auth: true
  allow_paths: [/, /api, /api/streams, /api/ws]

# RTSP server
rtsp:
  listen: "127.0.0.1:8554"

# Logging
log:
  # Source errors can contain complete RTSP URLs. EasyPi reports camera health
  # through its own API without writing camera credentials to the journal.
  level: disabled

# Reserved credential-free placeholder used by camera path discovery.
streams:
  easypi_discovery: "rtsp://127.0.0.1:9/unavailable"
EOF

sudo install -o root -g go2rtc -m 0640 "$CONFIG_TMP" "$GO2RTC_CONFIG"
rm -f "$CONFIG_TMP"

# Create systemd service
info "Creating systemd service..."
sudo tee "$SYSTEMD_SERVICE" > /dev/null << 'EOF'
[Unit]
Description=go2rtc camera media bridge
Documentation=https://github.com/AlexxIT/go2rtc
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=go2rtc
Group=go2rtc
EnvironmentFile=/opt/go2rtc/api.env
ExecStart=/opt/go2rtc/go2rtc -c /opt/go2rtc/go2rtc.yaml
Restart=on-failure
RestartSec=10
StandardOutput=journal
StandardError=journal
SyslogIdentifier=go2rtc

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
PrivateDevices=true
ReadOnlyPaths=/opt/go2rtc
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
RestrictNamespaces=true
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true
MemoryDenyWriteExecute=false
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd
info "Reloading systemd configuration..."
sudo systemctl daemon-reload

# Enable and start service
info "Enabling and starting go2rtc service..."
sudo systemctl enable go2rtc
sudo systemctl start go2rtc

# Wait for service to start
sleep 2

# Verify service is running
if ! systemctl is-active --quiet go2rtc; then
    error "go2rtc service failed to start"
    sudo journalctl -u go2rtc -n 20 --no-pager
    exit 1
fi

# Test API endpoint
info "Testing go2rtc API..."
printf 'silent\nfail\noutput = "/dev/null"\nuser = "%s:%s"\nurl = "http://127.0.0.1:1984/api/streams"\n' \
    "$API_USERNAME" "$API_PASSWORD" > "$CURL_CONFIG_TMP"
chmod 0600 "$CURL_CONFIG_TMP"
if curl --config "$CURL_CONFIG_TMP"; then
    info "go2rtc is running and API is accessible"
else
    warn "go2rtc service is running but its authenticated API test failed"
fi

# Display status
echo ""
sudo systemctl status go2rtc --no-pager -l
echo ""

info "go2rtc installation complete!"
info "Service: go2rtc"
info "API endpoint: http://127.0.0.1:1984"
info "Config: $GO2RTC_CONFIG"
info "Logs: sudo journalctl -u go2rtc -f"

exit 0
