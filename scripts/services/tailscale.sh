#!/bin/bash
set -euo pipefail

# Tailscale Installation Script
# Installs Tailscale using the official install script
# Usage:
#   tailscale.sh install    - Install Tailscale
#   tailscale.sh uninstall  - Uninstall Tailscale

LOGFILE="/var/log/easypi/tailscale_install.log"
TAILSCALE_KEY_FINGERPRINT="2596A99EAAB33821893C0A79458CA832957F5868"
ACTION="${1:-}"

[[ $# -eq 1 ]] || {
    echo "Usage: $0 {install|uninstall}" >&2
    exit 2
}

# Privileged logs must not live in the backend-writable application log tree.
install -d -o root -g easypi -m 0750 "$(dirname "$LOGFILE")"
[[ ! -L "$LOGFILE" ]] || { echo "Refusing symlink log file: $LOGFILE" >&2; exit 1; }
touch "$LOGFILE"
chown root:easypi "$LOGFILE"
chmod 0640 "$LOGFILE"

log() {
    local msg="$(date '+%Y-%m-%d %H:%M:%S') $1"
    echo "$msg" | tee -a "$LOGFILE"
}

error_exit() {
    log "ERROR: $1"
    exit 1
}

check_already_installed() {
    if command -v tailscale &> /dev/null; then
        local version
        version=$(tailscale --version 2>/dev/null | head -1 || echo "unknown")
        log "Tailscale is already installed (version: $version); verifying daemon"
        if ! systemctl enable --now tailscaled >> "$LOGFILE" 2>&1; then
            error_exit "Tailscale is installed but tailscaled could not be started"
        fi
        if ! systemctl is-active --quiet tailscaled; then
            error_exit "Tailscale is installed but tailscaled is not active"
        fi
        if systemctl cat easypi-taildrop-import.service >/dev/null 2>&1; then
            systemctl enable --now easypi-taildrop-import.service >> "$LOGFILE" 2>&1 \
                || log "WARNING: PiCloud Taildrop importer could not be started"
        fi
        echo "ALREADY_INSTALLED:$version"
        exit 0
    fi
}

install_tailscale() {
    log "Starting Tailscale installation..."
    
    # Check internet connectivity
    log "Checking internet connectivity..."
    if ! curl -fsSL --connect-timeout 10 "https://tailscale.com" > /dev/null 2>&1; then
        error_exit "Cannot reach tailscale.com. Check internet connection."
    fi
    log "Internet connectivity OK"
    
    # Install via apt to avoid read-only filesystem issues
    log "Adding Tailscale repository..."
    export DEBIAN_FRONTEND=noninteractive
    
    # Add the pinned repository key. TLS alone is not the trust anchor.
    local key_tmp key_fingerprint public_key_count verify_dir
    verify_dir="$(mktemp -d)"
    chmod 0700 "$verify_dir"
    key_tmp="$verify_dir/tailscale-archive-keyring.gpg"
    mkdir -m 0700 "$verify_dir/gnupg"
    trap 'rm -rf -- "${verify_dir:-}"' RETURN
    curl -fsSL --proto '=https' --proto-redir '=https' \
        "https://pkgs.tailscale.com/stable/debian/$(lsb_release -cs).noarmor.gpg" \
        -o "$key_tmp"
    public_key_count="$(
        GNUPGHOME="$verify_dir/gnupg" gpg --batch --no-options \
            --show-keys --with-colons "$key_tmp" 2>/dev/null |
            awk -F: '$1 == "pub" { count++ } END { print count + 0 }'
    )"
    key_fingerprint="$(
        GNUPGHOME="$verify_dir/gnupg" gpg --batch --no-options \
            --show-keys --with-colons "$key_tmp" 2>/dev/null |
            awk -F: '$1 == "fpr" { print $10; exit }'
    )"
    if [[ "$public_key_count" != "1" || "$key_fingerprint" != "$TAILSCALE_KEY_FINGERPRINT" ]]; then
        error_exit "Tailscale repository signing key fingerprint mismatch"
    fi
    install -o root -g root -m 0644 "$key_tmp" /usr/share/keyrings/tailscale-archive-keyring.gpg
    rm -rf -- "$verify_dir"
    trap - RETURN
    
    # Add repository
    echo "deb [signed-by=/usr/share/keyrings/tailscale-archive-keyring.gpg] https://pkgs.tailscale.com/stable/debian $(lsb_release -cs) main" | tee /etc/apt/sources.list.d/tailscale.list
    
    log "Installing Tailscale via apt..."
    apt-get update >> "$LOGFILE" 2>&1
    
    if apt-get install -y tailscale >> "$LOGFILE" 2>&1; then
        log "Tailscale installed successfully via apt"
    else
        error_exit "apt install failed. Check $LOGFILE for details."
    fi
    
    # Verify installation
    if command -v tailscale &> /dev/null; then
        local version
        version=$(tailscale --version 2>/dev/null | head -1 || echo "unknown")
        log "Tailscale installed successfully (version: $version)"
        
        # Enable and start the service
        log "Enabling tailscaled service..."
        if ! systemctl enable --now tailscaled >> "$LOGFILE" 2>&1; then
            error_exit "Tailscale installed, but tailscaled could not be started"
        fi
        if ! systemctl is-active --quiet tailscaled; then
            error_exit "Tailscale installed, but tailscaled is not active"
        fi
        if systemctl cat easypi-taildrop-import.service >/dev/null 2>&1; then
            systemctl enable --now easypi-taildrop-import.service >> "$LOGFILE" 2>&1 \
                || log "WARNING: PiCloud Taildrop importer could not be started"
        fi
        
        echo "INSTALL_SUCCESS:$version"
    else
        error_exit "Installation completed but tailscale binary not found"
    fi
}

uninstall_tailscale() {
    log "Starting Tailscale uninstall..."

    systemctl disable --now easypi-taildrop-import.service >> "$LOGFILE" 2>&1 || true

    # Revoke the local node session while the daemon is still available.
    if command -v tailscale &> /dev/null; then
        tailscale down >> "$LOGFILE" 2>&1 || true
        tailscale logout >> "$LOGFILE" 2>&1 || log "WARNING: Tailscale logout failed; remove the stale device in the admin console"
    fi

    # Stop service after logout so the CLI can reach the local daemon.
    log "Stopping tailscaled service..."
    systemctl stop tailscaled >> "$LOGFILE" 2>&1 || true
    systemctl disable tailscaled >> "$LOGFILE" 2>&1 || true

    # Remove package if installed
    if command -v apt-get &> /dev/null; then
        if dpkg -s tailscale > /dev/null 2>&1; then
            log "Purging Tailscale packages..."
            apt-get purge -y tailscale tailscale-archive-keyring >> "$LOGFILE" 2>&1 || true
            apt-get autoremove -y >> "$LOGFILE" 2>&1 || true
        else
            log "Tailscale package not installed"
        fi
    else
        log "apt-get not found; skipping package removal"
    fi

    # Remove repo, keyring, and state
    rm -f /etc/apt/sources.list.d/tailscale.list
    rm -f /usr/share/keyrings/tailscale-archive-keyring.gpg
    rm -rf /var/lib/tailscale /var/cache/tailscale
    rm -f /etc/default/tailscaled
    rm -f /etc/systemd/system/tailscaled.service
    rm -f /usr/lib/systemd/system/tailscaled.service
    rm -f /etc/systemd/system/multi-user.target.wants/tailscaled.service

    # Remove leftover binaries (from manual installs)
    rm -f /usr/local/bin/tailscale /usr/local/sbin/tailscaled
    rm -f /usr/bin/tailscale /usr/sbin/tailscaled
    rm -f /bin/tailscale /sbin/tailscaled

    # Reload systemd so removed units don't linger
    systemctl daemon-reload >> "$LOGFILE" 2>&1 || true

    log "Tailscale uninstall completed"
    echo "UNINSTALL_SUCCESS"
}

# Main
case "$ACTION" in
    install)
        log "=== Tailscale Install Started ==="
        check_already_installed
        install_tailscale
        log "=== Tailscale Install Completed ==="
        ;;
    uninstall)
        log "=== Tailscale Uninstall Started ==="
        uninstall_tailscale
        log "=== Tailscale Uninstall Completed ==="
        ;;
    *)
        echo "Usage: $0 {install|uninstall}"
        echo ""
        echo "Commands:"
        echo "  install    Install Tailscale"
        echo "  uninstall  Uninstall Tailscale"
        exit 1
        ;;
esac
