#!/bin/bash
#
# Add user to the EasyPi data-sharing group
#
# Usage: sudo bash add_user_permissions.sh [username]
#        If no username provided, uses the current user (SUDO_USER)
#

set -euo pipefail

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

EASYPI_GROUP="easypi"

log_info() { echo -e "${GREEN}[INFO]${NC} $*"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $*"; }
log_error() { echo -e "${RED}[ERROR]${NC} $*"; }

# Check if running as root
if [[ $EUID -ne 0 ]]; then
    log_error "This script must be run as root (use sudo)"
    exit 1
fi

# Determine target user
if [[ $# -ge 1 ]]; then
    TARGET_USER="$1"
else
    TARGET_USER="${SUDO_USER:-}"
fi

if [[ -z "$TARGET_USER" || "$TARGET_USER" == "root" ]]; then
    log_error "Please specify a username: sudo bash $0 USERNAME"
    exit 1
fi

if [[ ! "$TARGET_USER" =~ ^[a-z_][a-z0-9_.-]{0,31}$ ]]; then
    log_error "Invalid username"
    exit 1
fi

# Check if user exists
if ! id "$TARGET_USER" >/dev/null 2>&1; then
    log_error "User '$TARGET_USER' does not exist"
    exit 1
fi

# Create group if it doesn't exist
if ! getent group "$EASYPI_GROUP" >/dev/null; then
    log_info "Creating group '$EASYPI_GROUP'..."
    groupadd --system "$EASYPI_GROUP"
fi

# Check if user is already in group
if id -nG "$TARGET_USER" | grep -qw "$EASYPI_GROUP"; then
    log_info "User '$TARGET_USER' is already in group '$EASYPI_GROUP'"
else
    # Add user to group
    usermod -aG "$EASYPI_GROUP" "$TARGET_USER"
    log_info "Added user '$TARGET_USER' to group '$EASYPI_GROUP'"
fi

# Check if sudoers file exists
SUDOERS_FILE="/etc/sudoers.d/easypi"
if [[ ! -f "$SUDOERS_FILE" ]]; then
    log_warn "Sudoers file not found at $SUDOERS_FILE"
    template="/opt/EasyPi/scripts/sudoers.d/easypi"
    [[ -f "$template" && ! -L "$template" ]] || {
        log_error "Sudoers template not found: $template"
        exit 1
    }
    template_uid="$(stat -c '%u' -- "$template")"
    template_mode="$(stat -c '%a' -- "$template")"
    if [[ "$template_uid" != "0" || $((8#$template_mode & 8#022)) -ne 0 ]]; then
        log_error "Sudoers template ownership or mode is unsafe"
        exit 1
    fi
    if ! visudo -c -f "$template" >/dev/null 2>&1; then
        log_error "Sudoers template is invalid"
        exit 1
    fi
    install -o root -g root -m 0440 "$template" "$SUDOERS_FILE"
    log_info "Sudoers configuration created"
fi

echo ""
log_info "============================================"
log_info "User '$TARGET_USER' now has EasyPi data access."
log_info "============================================"
echo ""
log_warn "⚠️  IMPORTANT: Log out and log back in for changes to take effect!"
echo ""
log_info "To verify, after re-login run:"
log_info "  groups"
log_info "  # Should show: $TARGET_USER ... easypi ..."
echo ""

exit 0
