#!/bin/bash
set -euo pipefail

# AI Assistant Installation Script
# Installs Ollama and downloads selected model
# Usage:
#   ai.sh install              - Only install Ollama (no model download)
#   ai.sh [model_name]         - Install Ollama and download model

LOGFILE="/var/log/easypi/ai_install.log"
OLLAMA_VERSION="v0.30.8"
ACTION="${1:-}"
MODEL="${1:-qwen2.5:3b}"
MODEL_SIZE="~1.9GB"
EST_SIZE=1900000000

# Privileged logs must not live in the backend-writable application log tree.
install -d -o root -g easypi -m 0750 "$(dirname "$LOGFILE")"
[[ ! -L "$LOGFILE" ]] || { echo "Refusing symlink log file: $LOGFILE" >&2; exit 1; }
touch "$LOGFILE"
chown root:easypi "$LOGFILE"
chmod 0640 "$LOGFILE"

# Function to log with timestamp - defined early for uninstall to use
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1" | tee -a "$LOGFILE"
}

retry_curl() {
    local url="$1"
    local out="$2"
    curl -fsSL -4 --connect-timeout 30 --max-time 600 --retry 5 --retry-delay 2 --retry-connrefused \
        "$url" -o "$out"
}

is_elf() {
    local file="$1"
    local magic
    magic="$(head -c 4 "$file" 2>/dev/null | od -An -t x1 | tr -d ' \n' || true)"
    [[ "$magic" == "7f454c46" ]]
}

install_ollama_direct() {
    local arch
    arch="$(uname -m)"
    local ollama_arch=""
    local expected_sha256=""

    case "$arch" in
        x86_64|amd64)
            ollama_arch="amd64"
            expected_sha256="ffe2b2c2f2f5f5b30c081ec353c2e0bb2d9ead516064a8e22663b24b8fd8dca0"
            ;;
        aarch64|arm64)
            ollama_arch="arm64"
            expected_sha256="668a6f934b0b0455128bb4a76c9e50b9e5f274f9dc7710a066b7073e5bd36588"
            ;;
        *)
            log "Unsupported architecture for direct Ollama install: $arch"
            return 1
            ;;
    esac

    local tmpdir
    tmpdir="$(mktemp -d)"
    local tmpfile="${tmpdir}/ollama-linux-${ollama_arch}.tar.zst"
    local url="https://github.com/ollama/ollama/releases/download/${OLLAMA_VERSION}/ollama-linux-${ollama_arch}.tar.zst"

    if ! command -v zstd >/dev/null 2>&1; then
        log "zstd not found; installing zstd for .tar.zst support..."
        export DEBIAN_FRONTEND=noninteractive
        apt-get update >> "$LOGFILE" 2>&1 || true
        apt-get install -y zstd >> "$LOGFILE" 2>&1 || true
    fi

    log "Downloading pinned Ollama ${OLLAMA_VERSION}: $url"
    retry_curl "$url" "$tmpfile" || {
        rm -rf "$tmpdir"
        return 1
    }
    printf '%s  %s\n' "$expected_sha256" "$tmpfile" | sha256sum -c - \
        >> "$LOGFILE" 2>&1 || {
        log "Ollama archive checksum verification failed"
        rm -rf "$tmpdir"
        return 1
    }
    tar --zstd -tf "$tmpfile" >/dev/null 2>&1 \
        || {
        log "Ollama archive validation failed"
        rm -rf "$tmpdir"
        return 1
    }
    log "Extracting verified Ollama archive to /usr..."
    tar --zstd -xf "$tmpfile" -C /usr >> "$LOGFILE" 2>&1
    rm -rf "$tmpdir"
    command -v ollama >/dev/null 2>&1 || [[ -x /usr/bin/ollama ]]
}

# Check if first argument is "install" - install Ollama only
INSTALL_ONLY=false
if [ "$ACTION" == "install" ]; then
    INSTALL_ONLY=true
fi

# The runner is invoked by the fixed easypi service account. Never derive a
# deletion target through shell expansion.
INVOKING_USER="${SUDO_USER:-easypi}"
[[ "$INVOKING_USER" =~ ^[a-z_][a-z0-9_.-]{0,31}$ ]] || INVOKING_USER="easypi"
SUDO_USER_HOME="$(getent passwd "$INVOKING_USER" | cut -d: -f6 || true)"
case "$SUDO_USER_HOME" in
    /home/*|/opt/EasyPi) ;;
    *) SUDO_USER_HOME="" ;;
esac

if [ "$ACTION" == "uninstall" ]; then
    # Full removal
    log "===== AI Assistant Uninstall Started ====="
    OLLAMA_BIN_PATH="$(command -v ollama 2>/dev/null || true)"
    log "Stopping Ollama service..."
    systemctl stop ollama >/dev/null 2>&1 || true
    systemctl disable ollama >/dev/null 2>&1 || true

    log "Removing Ollama service files..."
    rm -f /etc/systemd/system/ollama.service 2>/dev/null || true
    rm -f /usr/lib/systemd/system/ollama.service 2>/dev/null || true
    rm -rf /etc/systemd/system/ollama.service.d 2>/dev/null || true
    rm -f /etc/systemd/system/multi-user.target.wants/ollama.service 2>/dev/null || true
    systemctl daemon-reload >/dev/null 2>&1 || true

    log "Removing Ollama binaries..."
    rm -f /usr/local/bin/ollama /usr/bin/ollama /bin/ollama /usr/local/lib/ollama/ollama /usr/lib/ollama/ollama 2>/dev/null || true
    if [ -n "${OLLAMA_BIN_PATH}" ]; then
        rm -f "${OLLAMA_BIN_PATH}" 2>/dev/null || true
    fi

    log "Removing Ollama libraries..."
    rm -rf /usr/local/lib/ollama /usr/lib/ollama 2>/dev/null || true

    log "Removing models and data..."
    rm -rf /usr/share/ollama 2>/dev/null || true
    rm -rf /home/ollama /root/.ollama 2>/dev/null || true
    if [ -n "${SUDO_USER_HOME:-}" ]; then
        rm -rf "${SUDO_USER_HOME}/.ollama" 2>/dev/null || true
    fi

    if id ollama >/dev/null 2>&1; then
        log "Removing ollama user..."
        userdel -r ollama >/dev/null 2>&1 || userdel ollama >/dev/null 2>&1 || true
    fi

    if command -v ollama >/dev/null 2>&1 || [ -x /usr/local/bin/ollama ] || [ -x /usr/bin/ollama ]; then
        log "ERROR: Ollama binary still present after uninstall"
        exit 1
    fi

    log "===== AI Assistant Uninstall Completed ====="
    exit 0
fi

case "$MODEL" in
    "install")
        # Skip model size check for install-only mode
        ;;
    "qwen2.5:3b")
        MODEL_SIZE="~1.9GB"
        EST_SIZE=1900000000
        ;;
    "llama3.1:8b")
        MODEL_SIZE="~4.3GB"
        EST_SIZE=4300000000
        ;;
    "qwen2.5:14b")
        MODEL_SIZE="~8.6GB"
        EST_SIZE=8600000000
        ;;
    "deepseek-r1:14b")
        MODEL_SIZE="~9.2GB"
        EST_SIZE=9200000000
        ;;
    *)
        MODEL_SIZE="~6GB"
        EST_SIZE=6000000000
        ;;
esac

# Ensure systemd service/unit and model paths exist
secure_ollama_runtime_permissions() {
    local runtime_dir="/usr/lib/ollama"
    local llama_server="${runtime_dir}/llama-server"

    if [[ ! -d "$runtime_dir" || ! -f "$llama_server" ]]; then
        log "ERROR: Verified Ollama runtime is incomplete: ${llama_server} is missing"
        return 1
    fi

    # The release archive may preserve a root-only mode on its top-level
    # runtime directory. Keep runtime code root-owned and non-writable by the
    # service account, but allow the unprivileged Ollama process to traverse
    # the directory and execute the pinned llama-server binary.
    chown root:root "$runtime_dir" "$llama_server"
    chmod 0755 "$runtime_dir" "$llama_server"

    if find "$runtime_dir" -xdev \( -type f -o -type d \) -perm /022 -print -quit | grep -q .; then
        log "ERROR: Ollama runtime contains a group- or world-writable path"
        return 1
    fi

    if ! runuser -u ollama -- test -x "$llama_server"; then
        log "ERROR: Ollama service account cannot execute ${llama_server}"
        return 1
    fi
}

ensure_ollama_service() {
    export PATH="/usr/local/bin:/usr/bin:/bin:${PATH}"
    local ollama_bin
    ollama_bin="$(command -v ollama || true)"
    if [[ -z "$ollama_bin" ]]; then
        log "ERROR: Ollama binary not found for service setup"
        return 1
    fi

    # Create model storage + user if missing
    mkdir -p /usr/share/ollama/.ollama
    # Best-effort: create home for ollama user (may fail on read-only /home)
    mkdir -p /home/ollama/.ollama 2>/dev/null || true
    
    # Create ollama group if not exists
    getent group ollama >/dev/null 2>&1 || groupadd -r ollama
    
    # Create ollama user if not exists (use existing group if present)
    if ! id ollama >/dev/null 2>&1; then
        useradd -r -s /bin/false -d /home/ollama -g ollama ollama
    fi

    secure_ollama_runtime_permissions || return 1
    
    chown -R ollama:ollama /usr/share/ollama 2>/dev/null || true
    chown -R ollama:ollama /home/ollama 2>/dev/null || true

    # Create systemd service if missing
    if ! systemctl list-unit-files | grep -q "^ollama.service"; then
        log "Creating Ollama systemd service..."
        cat > /etc/systemd/system/ollama.service <<EOF
[Unit]
Description=Ollama Service
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=$ollama_bin serve
User=ollama
Group=ollama
Restart=always
RestartSec=3
WorkingDirectory=/usr/share/ollama
Environment=OLLAMA_HOST=127.0.0.1:11434
Environment=OLLAMA_MODELS=/usr/share/ollama
Environment=HOME=/usr/share/ollama
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
    fi

    # Configure systemd override for model path
    mkdir -p /etc/systemd/system/ollama.service.d
    tee /etc/systemd/system/ollama.service.d/override.conf > /dev/null <<EOF
[Service]
Environment=OLLAMA_MODELS=/usr/share/ollama
Environment=HOME=/usr/share/ollama
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/usr/share/ollama
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictSUIDSGID=yes
LockPersonality=yes
RestrictRealtime=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
MemoryHigh=60%
MemoryMax=75%
CPUQuota=350%
TasksMax=512
UMask=0077
EOF

    systemctl daemon-reload
}

log "===== AI Assistant Installation Started ====="

if [ "$ACTION" == "service" ]; then
    log "===== Ollama Service Setup Started ====="
    if ensure_ollama_service; then
        log "===== Ollama Service Setup Completed ====="
        exit 0
    else
        log "ERROR: Failed to setup Ollama service"
        exit 1
    fi
fi

# Check if Ollama is already installed
if command -v ollama &> /dev/null && ollama --version &> /dev/null; then
    log "Ollama is already installed"
    OLLAMA_VERSION=$(ollama --version 2>&1 || echo "unknown")
    log "Version: $OLLAMA_VERSION"
else
    log "Installing Ollama..."
    
    # Remove any partial downloads
    rm -f /usr/local/bin/ollama 2>/dev/null || true
    rm -rf /usr/local/lib/ollama 2>/dev/null || true
    
    # Pre-create directories that the installer expects
    mkdir -p /usr/local/lib/ollama
    mkdir -p /usr/local/bin
    
    if install_ollama_direct; then
        log "Ollama installed successfully from verified release archive"
    else
        log "ERROR: Failed to install verified Ollama release"
        exit 1
    fi
    
    # Wait a moment for file to be fully written
    sleep 2
    # Ensure the ollama binary is available after install
    export PATH="/usr/local/bin:/usr/bin:/bin:${PATH}"
    if ! command -v ollama &> /dev/null; then
        # Sometimes the installer writes the binary slightly позже — подождём
        for _ in {1..10}; do
            if [[ -x /usr/local/bin/ollama || -x /usr/bin/ollama ]]; then
                break
            fi
            sleep 1
        done
    fi
    if ! command -v ollama &> /dev/null && [[ ! -x /usr/local/bin/ollama && ! -x /usr/bin/ollama ]]; then
        log "ERROR: ollama binary not found after installation"
        dump_ollama_debug_info
        exit 1
    fi
fi

log "Configuring Ollama service and storage..."
if ! ensure_ollama_service; then
    log "ERROR: Failed to setup Ollama service"
    exit 1
fi
export OLLAMA_MODELS=/usr/share/ollama

# Diagnostic helper to capture systemd/journal/process state for Ollama
dump_ollama_debug_info() {
    log "=== OLLAMA DEBUG START ==="
    log "OLLAMA_BINARY: $(command -v ollama 2>/dev/null || echo 'not found')"
    if command -v ollama &>/dev/null; then
        log "OLLAMA --version: $(ollama --version 2>&1 || echo 'error')"
    fi
    log "systemctl status ollama:"
    systemctl status ollama -l >> "$LOGFILE" 2>&1 || log "systemctl status failed"
    log "journalctl -u ollama (last 200):"
    journalctl -u ollama --no-pager -n 200 >> "$LOGFILE" 2>&1 || log "journalctl failed"
    if [ -f "/etc/systemd/system/ollama.service.d/override.conf" ]; then
        log "Contents of override.conf:"
        cat /etc/systemd/system/ollama.service.d/override.conf >> "$LOGFILE" 2>&1 || true
    fi
    log "ps aux | grep ollama:"
    ps aux | grep -i '[o]llama' >> "$LOGFILE" 2>&1 || true
    log "ls -la /usr/share/ollama:"
    ls -la /usr/share/ollama >> "$LOGFILE" 2>&1 || true
    if [ -n "$SUDO_USER_HOME" ]; then
        log "ls -la $SUDO_USER_HOME/.ollama:"
        ls -la "$SUDO_USER_HOME/.ollama" >> "$LOGFILE" 2>&1 || true
    fi
    log "socket/listen check for 11434:"
    (ss -ltnp | grep 11434 >> "$LOGFILE" 2>&1) || (netstat -ltnp | grep 11434 >> "$LOGFILE" 2>&1) || true
    log "=== OLLAMA DEBUG END ==="
}


# Start Ollama service
log "Starting Ollama service..."
if systemctl is-active --quiet ollama; then
    log "Ollama service is already running"
else
    systemctl start ollama || {
        log "Failed to start ollama service"
        dump_ollama_debug_info
        exit 1
    }
fi

# Enable Ollama service on boot
log "Enabling Ollama service on boot..."
systemctl enable ollama 2>/dev/null || log "Could not enable service (may not be systemd-managed)"

# Wait for Ollama to be ready
log "Waiting for Ollama API to be ready..."
for i in {1..30}; do
    if curl -s http://127.0.0.1:11434/api/tags > /dev/null 2>&1; then
        log "Ollama API is ready"
        break
    fi
    
    if [ $i -eq 30 ]; then
        log "WARNING: Ollama API did not start in time, restarting service..."
        systemctl restart ollama || {
            log "Failed to restart ollama service"
        }
        sleep 5
        systemctl status ollama >> "$LOGFILE" 2>&1 || log "Service status check failed"
        log "Retrying Ollama health check..."
        if curl -s http://127.0.0.1:11434/api/tags > /dev/null 2>&1; then
            log "Ollama API became ready after restart"
            break
        else
            log "ERROR: Ollama API did not become ready even after restart"
            # Try to start Ollama manually as the 'ollama' user to capture any startup errors
            OLLAMA_BIN=$(command -v ollama || echo "/usr/bin/ollama")
            if [ -x "$OLLAMA_BIN" ]; then
                log "Attempting manual run with $OLLAMA_BIN as user 'ollama' to capture errors"
                sudo -u ollama env OLLAMA_MODELS=/usr/share/ollama "$OLLAMA_BIN" serve >> "$LOGFILE" 2>&1 &
                sleep 5
            fi
            # Capture debug info to help diagnose why the service won't start
            dump_ollama_debug_info
            exit 1
        fi
    fi
    
    sleep 2
done

# If install-only mode, exit here after Ollama is installed and running
if [ "$INSTALL_ONLY" = true ]; then
    log "===== Ollama Installation Completed Successfully ====="
    log "Ollama API: http://127.0.0.1:11434"
    log "Ollama is ready. Use 'ollama pull <model>' to download models."
    exit 0
fi

## Pull the model with progress monitoring
log "Downloading model: $MODEL (this may take a while)..."
log "Model size: $MODEL_SIZE - please be patient"

# Emit a marker for the backend to know the download started
echo "MODEL_DOWNLOAD_STARTED: $MODEL"

# Pull model and parse ollama's native progress output
# Ollama outputs lines like: "pulling 8de95da68dc4...  78% ▕██████████████    ▏ 3.5 GB/4.7 GB  15 MB/s"
ollama pull "$MODEL" 2>&1 | while IFS= read -r line; do
    # Log to file
    echo "$line" >> "$LOGFILE"
    
    # Parse progress line from ollama
    # Format: "pulling abc123...  45% ▕████      ▏ 2.1 GB/4.7 GB  12 MB/s"
    if echo "$line" | grep -qE '[0-9]+%.*▕.*▏'; then
        # Extract percent
        PERCENT=$(echo "$line" | grep -oE '[0-9]+%' | head -1 | tr -d '%')
        
        # Extract sizes (e.g., "2.1 GB/4.7 GB")
        SIZES=$(echo "$line" | grep -oE '[0-9.]+\s*[KMGT]?B/[0-9.]+\s*[KMGT]?B' | head -1)
        if [ -n "$SIZES" ]; then
            DOWNLOADED=$(echo "$SIZES" | cut -d'/' -f1 | xargs)
            TOTAL=$(echo "$SIZES" | cut -d'/' -f2 | xargs)
        else
            DOWNLOADED=""
            TOTAL=""
        fi
        
        # Extract speed (e.g., "15 MB/s")
        SPEED=$(echo "$line" | grep -oE '[0-9.]+\s*[KMGT]?B/s' | head -1)
        [ -z "$SPEED" ] && SPEED="--"
        
        # Output in our format
        if [ -n "$PERCENT" ]; then
            echo "MODEL_DOWNLOAD_PROGRESS: ${PERCENT} ${DOWNLOADED} ${TOTAL} ${SPEED}"
        fi
    elif echo "$line" | grep -qi "pulling manifest"; then
        echo "MODEL_DOWNLOAD_PROGRESS: 0 -- --"
    elif echo "$line" | grep -qi "verifying"; then
        echo "MODEL_DOWNLOAD_PROGRESS: 99 verifying"
    elif echo "$line" | grep -qi "success"; then
        echo "MODEL_DOWNLOAD_PROGRESS: 100 complete"
    fi
done

PULL_RC=${PIPESTATUS[0]}

if [ $PULL_RC -eq 0 ]; then
    echo "MODEL_DOWNLOAD_PROGRESS: 100 complete"
    log "Model $MODEL downloaded successfully"
else
    log "ERROR: Failed to download model $MODEL (exit $PULL_RC)"
    exit 1
fi

# Verify model is available
log "Verifying model..."
if ollama list | grep -q "$MODEL"; then
    log "Model $MODEL is ready to use"
else
    log "WARNING: Model may not be properly installed"
fi

# Health check
log "Running health check..."
HEALTH_RESPONSE=$(curl -s http://127.0.0.1:11434/api/tags)
if [ -n "$HEALTH_RESPONSE" ]; then
    log "Health check passed"
    log "Available models: $(echo $HEALTH_RESPONSE | jq -r '.models[].name' 2>/dev/null || echo 'N/A')"
else
    log "WARNING: Health check returned empty response"
fi

log "===== AI Assistant Installation Completed Successfully ====="
log "Ollama API: http://127.0.0.1:11434"
log "Model: $MODEL"

exit 0
