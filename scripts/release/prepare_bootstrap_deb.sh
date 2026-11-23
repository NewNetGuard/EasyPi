#!/usr/bin/env bash
set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
OUT_DIR="${ROOT_DIR}/.build/bootstrap"

usage() {
  cat <<'EOF'
Build the independently distributed EasyPi signed-release bootstrap package.

Usage:
  ./scripts/release/prepare_bootstrap_deb.sh [--out DIR]

Publish the resulting .deb only through an authenticated APT repository (or an
equivalently authenticated independent channel). Never place it in the same
binary-release channel as the EasyPi archive it authenticates.
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --out) OUT_DIR="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[ERROR] Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

for command_name in dpkg-deb install realpath; do
  command -v "${command_name}" >/dev/null 2>&1 || {
    echo "[ERROR] Required command not found: ${command_name}" >&2
    exit 1
  }
done

VERSION="$(tr -d '[:space:]' < "${ROOT_DIR}/VERSION")"
[[ "${VERSION}" =~ ^[0-9]+[.][0-9]+[.][0-9]+([+-][0-9A-Za-z.-]+)?$ ]] || {
  echo "[ERROR] VERSION is not a supported package version" >&2
  exit 1
}

mkdir -p "${OUT_DIR}"
OUT_DIR="$(realpath -- "${OUT_DIR}")"
[[ "${OUT_DIR}" != "/" && "${OUT_DIR}" != "${ROOT_DIR}" ]] || {
  echo "[ERROR] Refusing unsafe output directory: ${OUT_DIR}" >&2
  exit 1
}

WORK="$(mktemp -d)"
trap 'rm -rf -- "${WORK}"' EXIT
PACKAGE_ROOT="${WORK}/easypi-release-bootstrap"

install -d -m 0755 \
  "${PACKAGE_ROOT}/DEBIAN" \
  "${PACKAGE_ROOT}/usr/bin" \
  "${PACKAGE_ROOT}/usr/lib/easypi-release" \
  "${PACKAGE_ROOT}/usr/share/keyrings" \
  "${PACKAGE_ROOT}/usr/share/doc/easypi-release-bootstrap"

cat > "${PACKAGE_ROOT}/DEBIAN/control" <<EOF
Package: easypi-release-bootstrap
Version: ${VERSION}
Section: admin
Priority: optional
Architecture: all
Depends: ca-certificates, curl, openssl, python3, tar, sudo
Maintainer: EasyPi Release Team
Description: Authenticated bootstrap for signed EasyPi binary releases
 Downloads, verifies, validates, and installs an EasyPi release using a trust
 key delivered independently through the package repository.
EOF

install -m 0755 \
  "${ROOT_DIR}/scripts/maintenance/install_signed_release.sh" \
  "${PACKAGE_ROOT}/usr/bin/easypi-install-release"
install -m 0644 \
  "${ROOT_DIR}/scripts/maintenance/update_url_guard.py" \
  "${PACKAGE_ROOT}/usr/lib/easypi-release/update_url_guard.py"
install -m 0644 \
  "${ROOT_DIR}/scripts/release/validate_release_archive.py" \
  "${PACKAGE_ROOT}/usr/lib/easypi-release/validate_release_archive.py"
install -m 0644 \
  "${ROOT_DIR}/scripts/maintenance/update_signing_key.pub" \
  "${PACKAGE_ROOT}/usr/share/keyrings/easypi-release.pub"
install -m 0644 "${ROOT_DIR}/LICENSE" \
  "${PACKAGE_ROOT}/usr/share/doc/easypi-release-bootstrap/copyright"

# umask 077 protects temporary content, but package-owned system directories
# must not narrow existing /usr traversal permissions when dpkg installs them.
find "${PACKAGE_ROOT}" -type d -exec chmod 0755 {} +

PACKAGE_PATH="${OUT_DIR}/easypi-release-bootstrap_${VERSION}_all.deb"
rm -f -- "${PACKAGE_PATH}"
dpkg-deb --root-owner-group --build "${PACKAGE_ROOT}" "${PACKAGE_PATH}" >/dev/null
dpkg-deb --info "${PACKAGE_PATH}" >/dev/null

printf '[OK] Bootstrap package: %s\n' "${PACKAGE_PATH}"
printf '[IMPORTANT] Publish it through a signed APT repository independent of the binary-release channel.\n'
