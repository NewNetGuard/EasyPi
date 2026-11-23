#!/usr/bin/env bash
#
# EasyPi Backend PyInstaller Build Script
#
# Builds native binary for the current architecture.
# Run this on the target architecture (arm64 for Raspberry Pi, amd64 for servers).
#
# Usage:
#   ./build_binary.sh           # Build for current architecture
#   ./build_binary.sh --clean   # Clean build (remove previous artifacts)
#   ./build_binary.sh --skip-deps  # Skip pip install (use cached packages)
#
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BACKEND_DIR="$(dirname "${SCRIPT_DIR}")"
PROJECT_ROOT="$(dirname "${BACKEND_DIR}")"
SOURCE_PROJECT_ROOT="${PROJECT_ROOT}"
BUILD_DIR="${PROJECT_ROOT}/.build"
VENV_DIR="${BUILD_DIR}/venv"
DIST_DIR="${BUILD_DIR}/dist"
WORK_DIR="${BUILD_DIR}/work"
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
RELEASE_VERSION="$(tr -d '\r\n[:space:]' < "${SOURCE_PROJECT_ROOT}/VERSION" 2>/dev/null || true)"

# Color output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Check for flags
CLEAN_BUILD=false
SKIP_DEPS=false
for arg in "$@"; do
    case $arg in
        --clean)
            CLEAN_BUILD=true
            ;;
        --skip-deps)
            SKIP_DEPS=true
            ;;
    esac
done

info "EasyPi Backend Binary Builder"
info "Architecture: ${ARCH}"
info "Distro codename: ${DISTRO_CODENAME}"
info "Project root: ${SOURCE_PROJECT_ROOT}"

# Release checks are read-only. Do not try to refresh a root-owned Git index
# when the builder runs under the restricted easypi service account.
export GIT_OPTIONAL_LOCKS=0

[[ "${RELEASE_VERSION}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z][0-9A-Za-z.-]*)?$ ]] \
    || error "VERSION must contain one SemVer-compatible release version"
git -C "${SOURCE_PROJECT_ROOT}" rev-parse --is-inside-work-tree >/dev/null 2>&1 \
    || error "Binary releases must be built from a Git checkout"
[[ -z "$(git -C "${SOURCE_PROJECT_ROOT}" status --porcelain=v1 --untracked-files=all)" ]] \
    || error "Refusing to build a release from a dirty Git working tree"
if env | grep -q '^VITE_[A-Za-z0-9_]*='; then
    error "Refusing ambient VITE_* variables in an official frontend build"
fi
for command_name in git tar npm; do
    command -v "${command_name}" >/dev/null 2>&1 \
        || error "${command_name} is required for a clean release build"
done

# Clean previous build if requested (keep venv to work offline)
if [[ "${CLEAN_BUILD}" == "true" ]]; then
    info "Cleaning previous build artifacts..."
    rm -rf "${DIST_DIR}"
    rm -rf "${WORK_DIR}"
    rm -rf "${SOURCE_PROJECT_ROOT}/backend/build"
    rm -f "${SOURCE_PROJECT_ROOT}/backend"/*.spec 2>/dev/null || true
fi

# Create build directories
mkdir -p "${BUILD_DIR}"
mkdir -p "${DIST_DIR}"
mkdir -p "${WORK_DIR}"

# Keep package-manager state inside the disposable build tree. The easypi
# account can have a root-owned home from an earlier installation, and a
# release build must neither depend on nor mutate that state.
export npm_config_cache="${BUILD_DIR}/npm-cache"
export PIP_CACHE_DIR="${BUILD_DIR}/pip-cache"
export PYINSTALLER_CONFIG_DIR="${BUILD_DIR}/pyinstaller-config"
mkdir -p "${npm_config_cache}" "${PIP_CACHE_DIR}" "${PYINSTALLER_CONFIG_DIR}"

# Build only from tracked bytes in the current commit. Git-ignored captures,
# databases, credentials and runtime state never enter PyInstaller's input.
SOURCE_COMMIT="$(git -C "${SOURCE_PROJECT_ROOT}" rev-parse --verify HEAD)"
SOURCE_EXPORT="${BUILD_DIR}/release-source"
rm -rf -- "${SOURCE_EXPORT}"
mkdir -p "${SOURCE_EXPORT}"
git -C "${SOURCE_PROJECT_ROOT}" archive --format=tar "${SOURCE_COMMIT}" \
    | tar -xf - -C "${SOURCE_EXPORT}"
if find "${SOURCE_EXPORT}" -type l -print -quit | grep -q .; then
    error "Tracked source export contains a symbolic link"
fi

PROJECT_ROOT="${SOURCE_EXPORT}"
BACKEND_DIR="${PROJECT_ROOT}/backend"
SCRIPT_DIR="${BACKEND_DIR}/packaging"
RELEASE_VERSION="$(tr -d '\r\n[:space:]' < "${PROJECT_ROOT}/VERSION" 2>/dev/null || true)"

info "Installing locked frontend dependencies in clean source export..."
( cd "${PROJECT_ROOT}/frontend" && npm ci ) \
    || error "Locked frontend dependency installation failed"
info "Building frontend from clean source export..."
( cd "${PROJECT_ROOT}/frontend" && EASYPI_BUILD_ID="${SOURCE_COMMIT}" npm run build ) \
    || error "Frontend build failed"
[[ -s "${PROJECT_ROOT}/frontend/dist/index.html" ]] \
    || error "Frontend build did not produce index.html"

# Create the virtual environment when absent or incomplete. A copied or
# interrupted build tree may contain a venv directory without Linux entrypoints.
if [[ ! -x "${VENV_DIR}/bin/python" || ! -r "${VENV_DIR}/bin/activate" ]]; then
    rm -rf -- "${VENV_DIR}"
    info "Creating virtual environment..."
    python3 -m venv "${VENV_DIR}"
fi

# Activate virtual environment
info "Activating virtual environment..."
source "${VENV_DIR}/bin/activate"

# Install dependencies unless --skip-deps is passed
BUILD_LOCK="${BACKEND_DIR}/requirements-build.lock"
BUILD_REQUIREMENTS="${BACKEND_DIR}/requirements-build.txt"
[[ -f "${BUILD_LOCK}" ]] || error "Hashed build-tool lock is missing: ${BUILD_LOCK}"
[[ -f "${BUILD_REQUIREMENTS}" ]] || error "Pinned build-tool requirements are missing: ${BUILD_REQUIREMENTS}"

if [[ "${SKIP_DEPS}" == "false" ]]; then
    info "Installing pinned build toolchain..."
    python -m pip install --require-hashes -r "${BUILD_LOCK}" \
        || error "Pinned build toolchain installation failed"

    info "Installing locked backend dependencies..."
    python -m pip install --require-hashes -r "${BACKEND_DIR}/requirements.lock" \
        || error "Hashed runtime dependency installation failed"
else
    info "Skipping dependency installation (--skip-deps)"
fi

# --skip-deps is an offline/cache mode, not a way around the pinned toolchain.
# Verify every direct build tool before executing code that will be signed.
python - "${BUILD_REQUIREMENTS}" <<'PY' || error "Build toolchain does not match pinned requirements"
import importlib.metadata
import pathlib
import sys

for raw in pathlib.Path(sys.argv[1]).read_text(encoding="utf-8").splitlines():
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    name, expected = line.split("==", 1)
    actual = importlib.metadata.version(name.strip())
    if actual != expected.strip():
        raise SystemExit(f"{name}: expected {expected}, installed {actual}")
PY

# Build the binary using spec file
info "Building binary with PyInstaller..."
cd "${BACKEND_DIR}"

# Pass BACKEND_DIR as environment variable to spec file
export BACKEND_DIR="${BACKEND_DIR}"

# Run the pinned PyInstaller with the reviewed spec file.
python -m PyInstaller \
    --clean \
    --noconfirm \
    --distpath "${DIST_DIR}" \
    --workpath "${WORK_DIR}" \
    "${BACKEND_DIR}/packaging/easypi-backend.spec"

# Check if build succeeded
if [[ -f "${DIST_DIR}/easypi-backend" ]]; then
    # Exercise the embedded module before publishing a binary that cannot run
    # its optional observer. This mode must never initialize the backend.
    "${DIST_DIR}/easypi-backend" --prism-tls-check \
        || error "Embedded Prism TLS Endpoint Bridge check failed"
    info "Build successful!"
    info "Binary: ${DIST_DIR}/easypi-backend"
    
    # Get binary info
    BINARY_SIZE=$(du -h "${DIST_DIR}/easypi-backend" | cut -f1)
    info "Binary size: ${BINARY_SIZE}"
    
    # Create release structure
    RELEASE_DIR="${BUILD_DIR}/release"
    rm -rf "${RELEASE_DIR}"
    mkdir -p "${RELEASE_DIR}/backend/bin"
    mkdir -p "${RELEASE_DIR}/backend/data"
    mkdir -p "${RELEASE_DIR}/scripts"
    mkdir -p "${RELEASE_DIR}/frontend"
    mkdir -p "${RELEASE_DIR}/config"
    mkdir -p "${RELEASE_DIR}/templates"
    
    # Copy binary
    cp "${DIST_DIR}/easypi-backend" "${RELEASE_DIR}/backend/bin/"

    # A full release must update both supported installation modes. Existing
    # EasyPi boxes may still run uvicorn from backend/app, while clean binary
    # installs run backend/bin/easypi-backend. Shipping the reviewed runtime
    # source beside the binary prevents a successful UI update from leaving a
    # source-mode backend on stale code.
    cp -r "${BACKEND_DIR}/app" "${RELEASE_DIR}/backend/"
    cp -r "${BACKEND_DIR}/alembic" "${RELEASE_DIR}/backend/"
    cp -r "${BACKEND_DIR}/templates" "${RELEASE_DIR}/backend/"
    if [[ -d "${BACKEND_DIR}/backend" ]]; then
        cp -r "${BACKEND_DIR}/backend" "${RELEASE_DIR}/backend/"
    fi
    for backend_file in \
        main.py \
        config.py \
        requirements.txt \
        requirements.lock \
        alembic.ini \
        telegram_bot_runner.py; do
        [[ -f "${BACKEND_DIR}/${backend_file}" ]] \
            || error "Required backend runtime file missing: ${backend_file}"
        cp "${BACKEND_DIR}/${backend_file}" "${RELEASE_DIR}/backend/${backend_file}"
    done
    
    # Copy data files
    cp "${BACKEND_DIR}/data/services.json" "${RELEASE_DIR}/backend/data/" 2>/dev/null || warn "services.json not found"
    
    # Copy scripts
    cp -r "${PROJECT_ROOT}/scripts/"* "${RELEASE_DIR}/scripts/" 2>/dev/null || warn "scripts not found"
    
    # Copy templates
    cp -r "${PROJECT_ROOT}/templates/"* "${RELEASE_DIR}/templates/" 2>/dev/null || warn "templates not found"
    
    # Copy config
    cp -r "${PROJECT_ROOT}/config/"* "${RELEASE_DIR}/config/" 2>/dev/null || warn "config not found"

    # Copy the compiled frontend. A binary release without frontend/dist can
    # pass a backend-only smoke test but is not a deployable EasyPi release.
    mkdir -p "${RELEASE_DIR}/frontend/dist"
    cp -a "${PROJECT_ROOT}/frontend/dist/." "${RELEASE_DIR}/frontend/dist/"

    # Copy NetProtection module (needed for easypi-netprotection service)
    if [[ -d "${PROJECT_ROOT}/easypi_netprotection" ]]; then
        cp -r "${PROJECT_ROOT}/easypi_netprotection" "${RELEASE_DIR}/"
    else
        warn "easypi_netprotection not found"
    fi

    # PRISM is installed as root-owned runtime code by install.sh. It is kept
    # separate from Chameleon conceptually, but both must be present in a full
    # EasyPi binary release because the existing installer references them.
    if [[ -d "${PROJECT_ROOT}/prism_dpi" ]]; then
        cp -r "${PROJECT_ROOT}/prism_dpi" "${RELEASE_DIR}/"
    else
        error "prism_dpi not found"
    fi

    [[ -f "${PROJECT_ROOT}/prism_tls_bridge/entrypoint.py" ]] \
        || error "Prism TLS Endpoint Bridge runtime is missing"
    mkdir -p "${RELEASE_DIR}/prism_tls_bridge"
    # Whitelist runtime Python modules; never copy experiment/test directories.
    cp "${PROJECT_ROOT}/prism_tls_bridge/"*.py "${RELEASE_DIR}/prism_tls_bridge/"
    cp "${PROJECT_ROOT}/prism_tls_bridge/UPSTREAM.md" "${RELEASE_DIR}/prism_tls_bridge/"
    mkdir -p "${RELEASE_DIR}/docs"
    cp "${PROJECT_ROOT}/docs/PRISM_TLS_ENDPOINT_BRIDGE.md" "${RELEASE_DIR}/docs/"

    # Captures are development evidence and can contain traffic samples, so
    # never publish them accidentally.
    rm -rf -- "${RELEASE_DIR}/prism_dpi/captures"

    # Never ship prebuilt Chameleon executables. Ship normalized reviewed Go
    # source so install.sh compiles a fresh server and the client matching the
    # user's EasyPi architecture. The staging helper is exercised directly by
    # a real shell regression test.
    # The stager intentionally requires a real clean Git checkout because it
    # creates its own archive of HEAD. Point it at the original checkout; HEAD
    # is the same SOURCE_COMMIT used to create PROJECT_ROOT above.
    bash "${SOURCE_PROJECT_ROOT}/scripts/release/stage_chameleon_source.sh" \
        "${SOURCE_PROJECT_ROOT}/chameleon" "${RELEASE_DIR}/chameleon" \
        || error "Failed to stage Chameleon source"

    # Copy only reviewed NetProtection defaults. Never copy the whole runtime
    # directory: it can contain user databases, secrets, logs and third-party
    # feeds that must not enter a release archive.
    mkdir -p "${RELEASE_DIR}/data/netprotection"
    for default_file in whatsapp_extra_ips.txt; do
        if [[ -f "${PROJECT_ROOT}/data/netprotection/${default_file}" &&
              ! -L "${PROJECT_ROOT}/data/netprotection/${default_file}" ]]; then
            cp "${PROJECT_ROOT}/data/netprotection/${default_file}" \
               "${RELEASE_DIR}/data/netprotection/${default_file}"
        fi
    done

    # Ship EasyPi terms and reviewed third-party notices, never third-party data.
    for legal_file in LICENSE EULA.txt THIRD_PARTY_LICENSES.md; do
        cp "${PROJECT_ROOT}/${legal_file}" "${RELEASE_DIR}/${legal_file}"
    done
    blocklist_license="${PROJECT_ROOT}/third_party/blocklists/blocklistproject-UNLICENSE.txt"
    if [[ ! -f "${blocklist_license}" || -L "${blocklist_license}" ]]; then
        error "Reviewed Block List Project license is missing or unsafe"
        exit 1
    fi
    mkdir -p "${RELEASE_DIR}/third_party/blocklists"
    cp "${blocklist_license}" \
       "${RELEASE_DIR}/third_party/blocklists/blocklistproject-UNLICENSE.txt"
    
    # A release must be independently installable and removable. Refuse to
    # produce a partial artifact instead of silently omitting lifecycle tools.
    for lifecycle_script in install.sh update.sh uninstall.sh; do
        if [[ ! -f "${PROJECT_ROOT}/${lifecycle_script}" || -L "${PROJECT_ROOT}/${lifecycle_script}" ]]; then
            error "Required lifecycle script is missing or unsafe: ${lifecycle_script}"
        fi
        cp "${PROJECT_ROOT}/${lifecycle_script}" "${RELEASE_DIR}/${lifecycle_script}"
    done

    # Normalize permissions (important if sources came from Windows)
    chmod 755 "${RELEASE_DIR}/backend/bin/easypi-backend" 2>/dev/null || true
    chmod 755 "${RELEASE_DIR}/install.sh" 2>/dev/null || true
    chmod 755 "${RELEASE_DIR}/update.sh" 2>/dev/null || true
    chmod 755 "${RELEASE_DIR}/uninstall.sh" 2>/dev/null || true
    find "${RELEASE_DIR}/scripts" -type f -name "*.sh" -exec chmod 755 {} \; 2>/dev/null || true
    chmod 750 "${RELEASE_DIR}/scripts/runner" 2>/dev/null || true
    
    # The updater compares VERSION directly. Keep it machine-readable and put
    # build metadata in a separate file so downgrade protection cannot be
    # bypassed by a legacy multiline value.
    printf '%s\n' "${RELEASE_VERSION}" > "${RELEASE_DIR}/VERSION"
    cat > "${RELEASE_DIR}/BUILD_INFO" <<EOF
EasyPi full binary release
Architecture: ${ARCH}
Build distro codename: ${DISTRO_CODENAME}
Build glibc: ${GLIBC_VERSION}
Source commit: ${SOURCE_COMMIT}
Build date: $(date -Iseconds)
EOF

    # Release artifacts must never carry local credentials or generated Python
    # caches. Refuse symlinks and private-key material before signing.
    find "${RELEASE_DIR}" -type d -name __pycache__ -prune -exec rm -rf -- {} +
    find "${RELEASE_DIR}" -type f \( -name '*.pyc' -o -name '*.pyo' \) -delete
    if find "${RELEASE_DIR}" -type l -print -quit | grep -q .; then
        error "Release contains a symbolic link"
    fi
    if find "${RELEASE_DIR}" -type f \
        \( -name '.env' -o -name '.env.*' -o -name '*.key' -o -name 'vapid_private.pem' \) \
        -print -quit | grep -q .; then
        error "Release contains a forbidden secret-bearing filename"
    fi
    # Match an actual PEM header line, not UI/help/validation code that merely
    # mentions the marker as part of a quoted string.
    if grep -RIlE -- '^-----BEGIN ([A-Z0-9]+ )*PRIVATE KEY-----\r?$' "${RELEASE_DIR}" | grep -q .; then
        error "Release contains private-key material"
    fi

    # A manifest makes the full payload auditable after extraction. The archive
    # signature remains the trust gate used by the updater.
    ( cd "${RELEASE_DIR}" && \
      find . -type f ! -name RELEASE_MANIFEST.sha256 -print0 | sort -z | \
      xargs -0 sha256sum > RELEASE_MANIFEST.sha256 )
    
    # Create tarball
    TARBALL_NAME="easypi-full-${ARCH}-${DISTRO_CODENAME}.tar.gz"
    cd "${BUILD_DIR}"
    tar --create --gzip --file "${TARBALL_NAME}" \
        --owner=0 --group=0 --numeric-owner -C release .

    # Never report a successful release build until the exact archive passes
    # the same structural and manifest checks used before signing/installing.
    python3 "${PROJECT_ROOT}/scripts/release/validate_release_archive.py" \
        "${BUILD_DIR}/${TARBALL_NAME}" \
        --expected-arch "${ARCH}" \
        --expected-codename "${DISTRO_CODENAME}" \
        || error "Release archive validation failed"
    
    info "Release archive: ${BUILD_DIR}/${TARBALL_NAME}"
    info ""
    info "Next step: sign and validate the archive with:"
    info "  scripts/release/prepare_public_repo.sh --asset ${BUILD_DIR}/${TARBALL_NAME} --signing-key /secure/path/release-key.pem"
    info "Do not publish unsigned extract-and-run instructions."
else
    error "Build failed! Binary not found."
fi

deactivate 2>/dev/null || true
info "Done!"
