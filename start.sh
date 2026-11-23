#!/bin/bash
# EasyPi Auto-start Script
# Automatically configures nginx/certs, installs deps, and starts backend

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$SCRIPT_DIR/backend"
CERT_DIR="${EASYPI_CERT_DIR:-$SCRIPT_DIR/certs}"
HTTPS_SETUP_SCRIPT="$SCRIPT_DIR/scripts/setup/setup_https.sh"
LOG_DIR="$SCRIPT_DIR/logs"
NETPROTECTION_LOG_DIR="$LOG_DIR/netprotection"

echo "🚀 Starting EasyPi..."
echo ""

# Step 0.1: Ensure EasyPi runner exists and is executable
RUNNER_SRC="$SCRIPT_DIR/scripts/runner"
RUNNER_DEST="/opt/EasyPi/scripts/runner"
if sudo test -f "$RUNNER_SRC" 2>/dev/null; then
    sudo mkdir -p "$(dirname "$RUNNER_DEST")"
    RUNNER_SRC_REAL="$(readlink -f "$RUNNER_SRC" 2>/dev/null || true)"
    RUNNER_DEST_REAL="$(readlink -f "$RUNNER_DEST" 2>/dev/null || true)"
    if [[ -n "$RUNNER_SRC_REAL" && -n "$RUNNER_DEST_REAL" && "$RUNNER_SRC_REAL" == "$RUNNER_DEST_REAL" ]]; then
        echo "ℹ️  Runner already in place."
    elif sudo test -f "$RUNNER_DEST" 2>/dev/null; then
        if sudo cmp -s "$RUNNER_SRC" "$RUNNER_DEST" 2>/dev/null; then
            echo "ℹ️  Runner already up to date."
        else
            echo "🛠️  Updating EasyPi runner..."
            sudo cp "$RUNNER_SRC" "$RUNNER_DEST"
        fi
    else
        echo "🛠️  Installing EasyPi runner..."
        sudo cp "$RUNNER_SRC" "$RUNNER_DEST"
    fi
    sudo chmod 750 "$RUNNER_DEST" 2>/dev/null || true
    # Normalize line endings to avoid "/bin/bash^M" issues
    sudo sed -i 's/\r$//' "$RUNNER_DEST" 2>/dev/null || true
else
    echo "⚠️  Runner source not found at $RUNNER_SRC"
fi

# Normalize line endings for service scripts copied from Windows
if [[ -d "$SCRIPT_DIR/scripts" ]]; then
    sudo find "$SCRIPT_DIR/scripts" -type f -name "*.sh" -exec sed -i 's/\r$//' {} + 2>/dev/null || true
fi

# Step 0.2: Harden script permissions/ownership for security
if [[ -d "$SCRIPT_DIR/scripts" ]]; then
    echo "🔒 Hardening script permissions..."
    sudo chown -R root:root "$SCRIPT_DIR/scripts" 2>/dev/null || true
    sudo find "$SCRIPT_DIR/scripts" -type d -exec chmod 750 {} + 2>/dev/null || true
    sudo find "$SCRIPT_DIR/scripts" -type f -name "*.sh" -exec chmod 750 {} + 2>/dev/null || true
    # Ensure key launch scripts are executable by the current user
    sudo chmod 755 "$SCRIPT_DIR/scripts/runner" 2>/dev/null || true
    sudo chmod 755 "$SCRIPT_DIR/scripts/build_netprotection_image.sh" 2>/dev/null || true
    sudo chmod 755 "$SCRIPT_DIR/scripts/setup/setup_https.sh" 2>/dev/null || true
    if [[ -d "$SCRIPT_DIR/scripts/sudoers.d" ]]; then
        sudo find "$SCRIPT_DIR/scripts/sudoers.d" -type f -exec chmod 440 {} + 2>/dev/null || true
    fi
fi

# Step 0: Ensure HTTPS is set up (nginx + certs)
if sudo test -x "$HTTPS_SETUP_SCRIPT" 2>/dev/null; then
    if [[ ! -f "$CERT_DIR/cert.pem" || ! -f "$CERT_DIR/key.pem" ]]; then
        echo "🔐 HTTPS certificates missing, running setup..."
        EASYPI_ROOT="$SCRIPT_DIR" EASYPI_INSTALL="1" sudo "$HTTPS_SETUP_SCRIPT" || {
            echo "   ⚠️  HTTPS setup failed (continuing without HTTPS)"
        }
    fi
else
    echo "⚠️  HTTPS setup script not found, skipping..."
fi

# Step 1: Update nginx config if changed
echo "📝 Updating nginx configuration..."
sudo cp "$SCRIPT_DIR/templates/nginx/easypi.conf" /etc/nginx/sites-available/easypi 2>/dev/null || true

# Step 2: Test nginx config
echo "✅ Testing nginx configuration..."
if sudo nginx -t 2>/dev/null; then
    echo "   nginx config OK"
else
    echo "   ⚠️  nginx config has errors (continuing anyway)"
fi

# Step 3: Start/restart nginx if not running
echo "🔄 Starting nginx..."
if systemctl is-active --quiet nginx; then
    echo "   nginx already running, reloading config..."
    sudo systemctl reload nginx 2>/dev/null || sudo systemctl restart nginx
else
    echo "   nginx not running, starting..."
    sudo systemctl start nginx 2>/dev/null || echo "   ⚠️  Could not start nginx (port 80 might be occupied by NetProtectionHome)"
fi

# Step 4: Show nginx status
if systemctl is-active --quiet nginx; then
    echo "   ✅ nginx is running"
else
    echo "   ⚠️  nginx is NOT running (will work without HTTPS)"
fi

# Step 4.1: Ensure go2rtc is installed and running (for camera streaming)
GO2RTC_INSTALL_SCRIPT="$SCRIPT_DIR/scripts/setup/install_go2rtc.sh"
FFMPEG_INSTALL_SCRIPT="$SCRIPT_DIR/scripts/setup/install_ffmpeg.sh"

if ! systemctl is-active --quiet go2rtc 2>/dev/null; then
    if [[ -f "$GO2RTC_INSTALL_SCRIPT" ]]; then
        echo "📹 Installing go2rtc for camera streaming..."
        sudo bash "$GO2RTC_INSTALL_SCRIPT" || echo "   ⚠️  go2rtc installation failed (cameras may not work)"
    else
        echo "   ⚠️  go2rtc not installed (camera live view and snapshots will not work)"
    fi
else
    echo "   ✅ go2rtc is running"
fi

# Step 4.2: Ensure FFmpeg is installed (for camera snapshot fallback)
if ! command -v ffmpeg &> /dev/null; then
    if [[ -f "$FFMPEG_INSTALL_SCRIPT" ]]; then
        echo "🎥 Installing FFmpeg for camera snapshots..."
        sudo bash "$FFMPEG_INSTALL_SCRIPT" || echo "   ⚠️  FFmpeg installation failed (snapshot fallback may not work)"
    else
        echo "   ⚠️  FFmpeg not installed (snapshot fallback will not work)"
    fi
else
    echo "   ✅ FFmpeg is installed"
fi

echo ""
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "  EasyPi Backend Starting..."
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""

# Step 4.5: Ensure Python venv and dependencies
CURRENT_USER="$(id -un)"

# Step 4.3: Ensure log directories are writable
mkdir -p "$LOG_DIR" "$NETPROTECTION_LOG_DIR"
sudo chown -R "$CURRENT_USER":"$CURRENT_USER" "$LOG_DIR" 2>/dev/null || true
chmod 750 "$LOG_DIR" "$NETPROTECTION_LOG_DIR" 2>/dev/null || true
if [[ ! -x "$BACKEND_DIR/.venv/bin/python" ]]; then
    echo "🐍 Creating Python virtual environment..."
    if ! python3 -m venv "$BACKEND_DIR/.venv" 2>/dev/null; then
        if command -v apt-get &> /dev/null; then
            echo "   Installing python3-venv..."
            sudo apt-get update -qq
            sudo apt-get install -y -qq python3-venv
        fi
        if ! python3 -m venv "$BACKEND_DIR/.venv" 2>/dev/null; then
            sudo python3 -m venv "$BACKEND_DIR/.venv"
        fi
    fi
fi

if [[ -d "$BACKEND_DIR/.venv" && ! -w "$BACKEND_DIR/.venv" ]]; then
    sudo chown -R "$CURRENT_USER":"$CURRENT_USER" "$BACKEND_DIR/.venv"
fi

REQ_LOCK="$BACKEND_DIR/requirements.lock"
REQ_MARKER="$BACKEND_DIR/.venv/.requirements.installed"
if [[ ! -f "$REQ_LOCK" ]]; then
    echo "❌ Hashed backend requirements lock is missing; refusing an unpinned start." >&2
    exit 1
fi
if [[ ! -f "$REQ_MARKER" || "$REQ_LOCK" -nt "$REQ_MARKER" ]]; then
    echo "📦 Installing backend dependencies..."
    "$BACKEND_DIR/.venv/bin/python" -m pip install --require-hashes -r "$REQ_LOCK"
    touch "$REQ_MARKER"
fi

# Step 5: Create symlink for easypi_netprotection if not exists
if [[ ! -L "$BACKEND_DIR/easypi_netprotection" && -d "$SCRIPT_DIR/easypi_netprotection" ]]; then
    echo "🔗 Creating symlink for easypi_netprotection..."
    ln -sf "$SCRIPT_DIR/easypi_netprotection" "$BACKEND_DIR/easypi_netprotection"
fi


# Step 6: Start backend
cd "$BACKEND_DIR"
# Skip direct start if systemd service is already running
if systemctl is-active --quiet easypi-backend; then
    echo "ℹ️  easypi-backend service is already running. Skipping direct start."
    exit 0
fi
# Add parent dir to PYTHONPATH for easypi_netprotection module
export PYTHONPATH="$SCRIPT_DIR:$PYTHONPATH"
# proxy-headers: Trust X-Forwarded-* headers from nginx for real client IP
exec "$BACKEND_DIR/.venv/bin/uvicorn" main:app \
  --host "${API_HOST:-127.0.0.1}" \
  --port 8000 \
  --proxy-headers \
  --forwarded-allow-ips="${EASYPI_FORWARDED_ALLOW_IPS:-127.0.0.1,::1}"
