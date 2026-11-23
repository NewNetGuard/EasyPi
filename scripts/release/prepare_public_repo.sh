#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/../.." && pwd)"
TEMPLATE_DIR="${ROOT_DIR}/distribution/public_repo_template"

OUT_DIR="${ROOT_DIR}/.build/public_repo"
ASSET_PATH=""
ASSET_URL=""
SIGNING_KEY="${EASYPI_RELEASE_SIGNING_KEY:-}"
COPY_ASSET=1

usage() {
  cat <<'USAGE'
Prepare public binary-only repository bundle.

Usage:
  ./scripts/release/prepare_public_repo.sh --asset /path/to/easypi-full-aarch64-trixie.tar.gz --signing-key /secure/path/release-key.pem [--asset-url URL] [--out DIR]

Options:
  --asset PATH      Path to release archive (required)
  --signing-key PATH Private release key (required; or EASYPI_RELEASE_SIGNING_KEY)
  --asset-url URL   Direct URL to asset in GitHub Releases (optional, for README template replacement)
  --copy-asset      Deprecated compatibility flag; the archive is always copied
  --out DIR         Output directory (default: ./.build/public_repo)
  -h, --help        Show help
USAGE
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --asset)
      ASSET_PATH="${2:-}"
      shift 2
      ;;
    --asset-url)
      ASSET_URL="${2:-}"
      shift 2
      ;;
    --signing-key)
      SIGNING_KEY="${2:-}"
      shift 2
      ;;
    --out)
      OUT_DIR="${2:-}"
      shift 2
      ;;
    --copy-asset)
      COPY_ASSET=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "[ERROR] Unknown argument: $1" >&2
      usage
      exit 1
      ;;
  esac
done

if [[ -z "${ASSET_PATH}" ]]; then
  echo "[ERROR] --asset is required" >&2
  usage
  exit 1
fi

if [[ ! -f "${ASSET_PATH}" || -L "${ASSET_PATH}" ]]; then
  echo "[ERROR] Asset not found: ${ASSET_PATH}" >&2
  exit 1
fi

if [[ -z "${SIGNING_KEY}" || ! -f "${SIGNING_KEY}" || -L "${SIGNING_KEY}" ]]; then
  echo "[ERROR] A regular --signing-key file is required" >&2
  exit 1
fi
for command_name in openssl python3 realpath sha256sum stat mktemp; do
  command -v "${command_name}" >/dev/null 2>&1 || {
    echo "[ERROR] ${command_name} is required to prepare the release" >&2
    exit 1
  }
done
KEY_MODE="$(stat -c '%a' "${SIGNING_KEY}")"
if (( (8#${KEY_MODE} & 077) != 0 )); then
  echo "[ERROR] Signing key must not be readable or writable by group/others" >&2
  exit 1
fi

ASSET_PATH="$(realpath -e -- "${ASSET_PATH}")"
SIGNING_KEY="$(realpath -e -- "${SIGNING_KEY}")"
OUT_DIR="$(realpath -m -- "${OUT_DIR}")"
if [[ "${OUT_DIR}" == "/" || "${OUT_DIR}" == "${ROOT_DIR}" ]]; then
  echo "[ERROR] Refusing unsafe output directory: ${OUT_DIR}" >&2
  exit 1
fi
if [[ -L "${OUT_DIR}" || (-e "${OUT_DIR}" && ! -d "${OUT_DIR}") ]]; then
  echo "[ERROR] Output path must be a real directory or a new path: ${OUT_DIR}" >&2
  exit 1
fi
if [[ -d "${OUT_DIR}" ]] \
    && find "${OUT_DIR}" -mindepth 1 -maxdepth 1 -print -quit | grep -q .; then
  echo "[ERROR] Refusing to overwrite a non-empty output directory: ${OUT_DIR}" >&2
  echo "        Choose a new/empty --out directory." >&2
  exit 1
fi
case "${ASSET_PATH}" in
  "${OUT_DIR}"/*) echo "[ERROR] Release asset must be outside the output directory" >&2; exit 1 ;;
esac
case "${SIGNING_KEY}" in
  "${OUT_DIR}"/*) echo "[ERROR] Signing key must be outside the output directory" >&2; exit 1 ;;
esac

OUT_PARENT="$(dirname -- "${OUT_DIR}")"
mkdir -p "${OUT_PARENT}"
OUT_PARENT="$(realpath -e -- "${OUT_PARENT}")"
STAGE_DIR="$(mktemp -d "${OUT_PARENT}/.easypi-public-repo.XXXXXX")"
cleanup() {
  if [[ -n "${STAGE_DIR:-}" && -d "${STAGE_DIR}" ]]; then
    rm -rf -- "${STAGE_DIR}"
  fi
}
trap cleanup EXIT

cp -a "${TEMPLATE_DIR}/." "${STAGE_DIR}/"
cp -a "${ROOT_DIR}/LICENSE" "${STAGE_DIR}/LICENSE"
cp -a "${ROOT_DIR}/EULA.txt" "${STAGE_DIR}/EULA.txt"
cp -a "${ROOT_DIR}/THIRD_PARTY_LICENSES.md" "${STAGE_DIR}/THIRD_PARTY_LICENSES.md"
BLOCKLIST_LICENSE="${ROOT_DIR}/third_party/blocklists/blocklistproject-UNLICENSE.txt"
if [[ ! -f "${BLOCKLIST_LICENSE}" || -L "${BLOCKLIST_LICENSE}" ]]; then
  echo "[ERROR] Reviewed Block List Project license is missing or unsafe" >&2
  exit 1
fi
mkdir -p "${STAGE_DIR}/third_party/blocklists"
cp -a "${BLOCKLIST_LICENSE}" \
  "${STAGE_DIR}/third_party/blocklists/blocklistproject-UNLICENSE.txt"

ASSET_NAME="$(basename "${ASSET_PATH}")"
[[ "${ASSET_NAME}" == "easypi-full-aarch64-trixie.tar.gz" ]] || {
  echo "[ERROR] Official release asset must be named easypi-full-aarch64-trixie.tar.gz" >&2
  exit 1
}
python3 "${ROOT_DIR}/scripts/release/validate_release_archive.py" \
  "${ASSET_PATH}" --expected-arch aarch64 --expected-codename trixie

ASSET_HASH="$(sha256sum "${ASSET_PATH}" | awk '{print $1}')"
cp -a "${ASSET_PATH}" "${STAGE_DIR}/${ASSET_NAME}"
printf '%s  %s\n' "${ASSET_HASH}" "${ASSET_NAME}" > "${STAGE_DIR}/checksums.txt"
chmod 0644 "${STAGE_DIR}/checksums.txt"
SIGNATURE_PATH="${STAGE_DIR}/${ASSET_NAME}.sig"
openssl dgst -sha256 -sign "${SIGNING_KEY}" -out "${SIGNATURE_PATH}" "${ASSET_PATH}"
openssl dgst -sha256 \
  -verify "${ROOT_DIR}/scripts/maintenance/update_signing_key.pub" \
  -signature "${SIGNATURE_PATH}" "${ASSET_PATH}" >/dev/null 2>&1 || {
    rm -f -- "${SIGNATURE_PATH}"
    echo "[ERROR] Signing key does not match the trusted EasyPi release key" >&2
    exit 1
  }
chmod 0644 "${SIGNATURE_PATH}"

README_FILE="${STAGE_DIR}/README.md"
if [[ -n "${ASSET_URL}" ]]; then
  python3 - "${ASSET_URL}" "${ASSET_NAME}" <<'PY'
import sys
from urllib.parse import urlsplit

value = sys.argv[1]
asset_name = sys.argv[2]
parsed = urlsplit(value)
if (
    parsed.scheme.lower() != "https"
    or not parsed.hostname
    or parsed.username is not None
    or parsed.password is not None
    or parsed.fragment
    or parsed.query
    or not parsed.path.endswith("/" + asset_name)
    or any(character in value for character in ('"', "'", "`", "$", "\\", "!"))
    or any(character.isspace() or ord(character) < 0x20 for character in value)
):
    raise SystemExit(
        "[ERROR] --asset-url must be a shell-safe direct HTTPS URL ending in the asset name, without userinfo, query, or fragment"
    )
PY
  README_ASSET_URL="${ASSET_URL}"
else
  README_ASSET_URL="<PASTE_RELEASE_ASSET_URL_HERE>"
fi
python3 - "${README_FILE}" "${ASSET_NAME}" "${README_ASSET_URL}" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])
text = path.read_text(encoding="utf-8")
text = text.replace("__ASSET_NAME__", sys.argv[2])
text = text.replace("__ASSET_URL_PLACEHOLDER__", sys.argv[3])
path.write_text(text, encoding="utf-8")
PY
chmod 0755 "${STAGE_DIR}"

# Publish only a complete bundle. Existing non-empty destinations were rejected
# above; an empty destination is removed non-recursively before the atomic move.
if [[ -d "${OUT_DIR}" ]]; then
  rmdir -- "${OUT_DIR}"
fi
mv -T -- "${STAGE_DIR}" "${OUT_DIR}"
STAGE_DIR=""

echo "[OK] Public repo bundle prepared:"
echo "     ${OUT_DIR}"
echo
echo "Files:"
echo "  - README.md"
echo "  - LICENSE"
echo "  - EULA.txt"
echo "  - THIRD_PARTY_LICENSES.md"
echo "  - third_party/"
echo "  - checksums.txt"
echo "  - ${ASSET_NAME}.sig"
echo "  - ${ASSET_NAME}"
