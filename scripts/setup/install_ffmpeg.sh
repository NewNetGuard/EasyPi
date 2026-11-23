#!/usr/bin/env bash
# Install FFmpeg for camera recording and snapshot fallback.

set -euo pipefail

export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
export DEBIAN_FRONTEND=noninteractive
umask 077

readonly PACKAGE_LOCK_FILE="/run/lock/easypi-package-manager.lock"

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

if [[ ${EUID} -ne 0 ]]; then
    error "This helper must run through the EasyPi privileged runner"
    exit 1
fi

command -v flock >/dev/null 2>&1 || {
    error "flock is required"
    exit 1
}
[[ -d /run/lock && ! -L /run/lock ]] || {
    error "Trusted /run/lock is unavailable"
    exit 1
}
if [[ -e "${PACKAGE_LOCK_FILE}" || -L "${PACKAGE_LOCK_FILE}" ]]; then
    [[ -f "${PACKAGE_LOCK_FILE}" && ! -L "${PACKAGE_LOCK_FILE}" ]] || {
        error "Unsafe package-manager lock"
        exit 1
    }
    [[ "$(stat -Lc '%u' -- "${PACKAGE_LOCK_FILE}")" == "0" ]] || {
        error "Unsafe package-manager lock owner"
        exit 1
    }
fi
exec 9>"${PACKAGE_LOCK_FILE}"
chmod 0600 "${PACKAGE_LOCK_FILE}"
flock -w 10 9 || {
    error "Another EasyPi package operation is running"
    exit 1
}

# Check if FFmpeg is already installed.
if command -v ffmpeg >/dev/null 2>&1; then
    FFMPEG_VERSION="$(ffmpeg -version | head -n1)"
    info "FFmpeg is already installed: $FFMPEG_VERSION"
    exit 0
fi

info "Installing FFmpeg..."

if [[ ! -f /etc/os-release ]]; then
    error "Cannot detect OS"
    exit 1
fi
. /etc/os-release

case "${ID:-unknown}" in
    debian|ubuntu|raspbian)
        /usr/bin/apt-get update -qq
        /usr/bin/apt-get install -y -qq \
            -o Dpkg::Options::=--force-confdef \
            -o Dpkg::Options::=--force-confold \
            -o Dpkg::Use-Pty=0 \
            ffmpeg
        ;;
    *)
        error "Unsupported OS: ${ID:-unknown}"
        exit 1
        ;;
esac

# Verify installation
if command -v ffmpeg >/dev/null 2>&1; then
    FFMPEG_VERSION="$(ffmpeg -version | head -n1)"
    info "FFmpeg installed successfully: $FFMPEG_VERSION"
else
    error "Failed to install FFmpeg"
    exit 1
fi
