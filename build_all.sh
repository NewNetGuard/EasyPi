#!/usr/bin/env bash
#
# EasyPi Full Build Script
#
# Builds both frontend and backend, creates full release archive.
#
# Usage:
#   ./build_all.sh              # Full build with dependencies
#   ./build_all.sh --skip-deps  # Skip pip install (offline mode)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="${SCRIPT_DIR}"
BUILD_DIR="${PROJECT_ROOT}/.build"
ARCH="$(uname -m)"
DISTRO_CODENAME="$(. /etc/os-release 2>/dev/null && echo "${VERSION_CODENAME:-unknown}" || echo "unknown")"
GLIBC_OUTPUT="$(ldd --version 2>/dev/null || true)"
GLIBC_VERSION="$(printf '%s\n' "${GLIBC_OUTPUT}" | awk '
    NR == 1 {
        for (i = 1; i <= NF; i++) {
            if ($i ~ /^[0-9]+([.][0-9]+)+$/) version = $i
        }
    }
    END { print version == "" ? "unknown" : version }
')"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Parse arguments
SKIP_DEPS=""
for arg in "$@"; do
    case $arg in
        --skip-deps)
            SKIP_DEPS="--skip-deps"
            ;;
    esac
done

info "============================================"
info "EasyPi Full Build"
info "Architecture: ${ARCH}"
info "Distro codename: ${DISTRO_CODENAME}"
info "============================================"

# Step 1: Validate release toolchain
info ""
info "=== Step 1: Validating release toolchain ==="

if ! command -v npm &> /dev/null; then
    error "npm not found. Please install Node.js"
fi
info "Frontend will be built from the clean Git export used by the backend packager."

# Step 2: Build Backend Binary
info ""
info "=== Step 2: Building clean frontend and backend binary ==="
cd "${PROJECT_ROOT}/backend/packaging"
./build_binary.sh --clean ${SKIP_DEPS}

if [[ ! -f "${BUILD_DIR}/dist/easypi-backend" ]]; then
    error "Backend build failed - binary not found"
fi
info "Backend build complete!"

# build_binary.sh is the single release packager. It copies the compiled
# frontend, backend runtime, NetProtection, Prism and reviewed Chameleon source,
# writes the manifest, and creates the archive. Do not mutate or repack its
# output here: that could invalidate the manifest or reintroduce local binaries.
TARBALL_NAME="easypi-full-${ARCH}-${DISTRO_CODENAME}.tar.gz"
TARBALL_PATH="${BUILD_DIR}/${TARBALL_NAME}"
[[ -s "${TARBALL_PATH}" ]] || error "Full release archive was not created"

info ""
info "============================================"
info "BUILD COMPLETE!"
info "============================================"
info ""
info "Release archive: ${TARBALL_PATH}"
info "Size: $(du -h "${TARBALL_PATH}" | cut -f1)"
info ""
info "Next step: validate and sign the release archive:"
info "  ./scripts/release/prepare_public_repo.sh --asset ${TARBALL_PATH} --signing-key /secure/path/release-key.pem"
info "End users must install through the independently distributed easypi-install-release bootstrap."
info ""
