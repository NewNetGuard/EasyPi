#!/usr/bin/env bash
set -euo pipefail
umask 077
export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
unset PYTHONPATH PYTHONHOME BASH_ENV ENV CDPATH GLOBIGNORE

LIB_DIR="/usr/lib/easypi-release"
URL_GUARD="${LIB_DIR}/update_url_guard.py"
ARCHIVE_VALIDATOR="${LIB_DIR}/validate_release_archive.py"
TARGET_DIR="/opt/EasyPi"

usage() {
  cat <<'USAGE'
Install a signed EasyPi release using an independently provisioned trust root.

Usage:
  easypi-install-release --archive-url HTTPS_URL --signature-url HTTPS_URL [options]

Options:
  --trusted-key PATH  Independently provisioned EasyPi release public key
                      (default: /usr/share/keyrings/easypi-release.pub)
  --sha256 HEX        Optional archive checksum (signature remains mandatory)
  -h, --help          Show this help

This bootstrap and its trusted key must come from an authenticated channel
independent of the binary release repository (for example an OS package).
USAGE
}

ARCHIVE_URL=""
SIGNATURE_URL=""
TRUSTED_KEY="/usr/share/keyrings/easypi-release.pub"
EXPECTED_SHA256=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --archive-url) ARCHIVE_URL="${2:-}"; shift 2 ;;
    --signature-url) SIGNATURE_URL="${2:-}"; shift 2 ;;
    --trusted-key) TRUSTED_KEY="${2:-}"; shift 2 ;;
    --sha256) EXPECTED_SHA256="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "[ERROR] Unknown argument: $1" >&2; usage; exit 2 ;;
  esac
done

[[ "${ARCHIVE_URL}" =~ ^https:// && "${SIGNATURE_URL}" =~ ^https:// ]] || {
  echo "[ERROR] Archive and signature URLs must use HTTPS." >&2
  exit 1
}
if [[ -n "${EXPECTED_SHA256}" && ! "${EXPECTED_SHA256}" =~ ^[a-fA-F0-9]{64}$ ]]; then
  echo "[ERROR] Invalid SHA-256 value." >&2
  exit 1
fi
for command_name in curl install mktemp openssl realpath stat python3 tar; do
  command -v "${command_name}" >/dev/null 2>&1 || {
    echo "[ERROR] Required command not found: ${command_name}" >&2
    exit 1
  }
done

trusted_root_file() {
  local path="$1"
  local lexical="" physical="" current="" owner="" mode=""

  [[ -f "${path}" && ! -L "${path}" ]] || return 1
  lexical="$(realpath -sm -- "${path}")" || return 1
  physical="$(realpath -e -- "${path}")" || return 1
  [[ "${lexical}" == "${physical}" ]] || return 1

  current="${physical}"
  while :; do
    owner="$(stat -c '%u' -- "${current}")" || return 1
    mode="$(stat -c '%a' -- "${current}")" || return 1
    [[ "${owner}" == "0" && $((8#${mode} & 8#022)) -eq 0 ]] || return 1
    [[ "${current}" == "/" ]] && break
    current="${current%/*}"
    [[ -n "${current}" ]] || current="/"
  done
}

for helper in "${URL_GUARD}" "${ARCHIVE_VALIDATOR}"; do
  trusted_root_file "${helper}" || {
    echo "[ERROR] Trusted bootstrap helper is missing or unsafe: ${helper}" >&2
    exit 1
  }
done

trusted_root_file "${TRUSTED_KEY}" || {
  echo "[ERROR] Independently provisioned trusted key is missing or unsafe." >&2
  exit 1
}

TMP_DIR="$(mktemp -d /tmp/easypi-install.XXXXXX)"
ARCHIVE_FILE="${TMP_DIR}/easypi.tar.gz"
SIGNATURE_FILE="${TMP_DIR}/easypi.tar.gz.sig"
ROOT_TMP_DIR=""
TARGET_CREATED=0
INSTALL_COMPLETED=0

run_privileged() {
  if [[ "${EUID}" -eq 0 ]]; then
    "$@"
  else
    command -v sudo >/dev/null 2>&1 || {
      echo "[ERROR] sudo is required to install EasyPi." >&2
      exit 1
    }
    sudo -- "$@"
  fi
}

cleanup() {
  local rc=$?
  rm -rf -- "${TMP_DIR}"
  if [[ -n "${ROOT_TMP_DIR}" && "${ROOT_TMP_DIR}" =~ ^/var/tmp/easypi-install-root\.[A-Za-z0-9]+$ ]]; then
    run_privileged rm -rf -- "${ROOT_TMP_DIR}" || true
  fi
  if [[ "${TARGET_CREATED}" -eq 1 && "${INSTALL_COMPLETED}" -ne 1 ]]; then
    echo "[WARN] Installation failed; reverting EasyPi host integration." >&2
    if run_privileged test -f "${TARGET_DIR}/uninstall.sh" \
        && ! run_privileged test -L "${TARGET_DIR}/uninstall.sh"; then
      run_privileged /bin/bash "${TARGET_DIR}/uninstall.sh" \
        --prefix "${TARGET_DIR}" || true
    fi
    echo "[WARN] Removing the newly created installation target." >&2
    run_privileged rm -rf -- "${TARGET_DIR}" || true
  fi
  exit "${rc}"
}
trap cleanup EXIT

safe_https_download() {
  local current_url="$1" destination="$2" timeout="$3" max_bytes="$4"
  local validation normalized_url host port address resolve_address
  local headers body http_code next_url
  local hop=0
  local -a parts=()

  while (( hop <= 5 )); do
    validation="$(python3 "${URL_GUARD}" resolve "${current_url}")" || {
      echo "[ERROR] Release URL must resolve only to public HTTPS addresses." >&2
      return 1
    }
    mapfile -t parts <<<"${validation}"
    [[ "${#parts[@]}" -eq 4 ]] || return 1
    normalized_url="${parts[0]}"
    host="${parts[1]}"
    port="${parts[2]}"
    address="${parts[3]}"
    resolve_address="${address}"
    [[ "${address}" == *:* ]] && resolve_address="[${address}]"
    headers="${TMP_DIR}/download-${hop}.headers"
    body="${TMP_DIR}/download-${hop}.body"
    : > "${headers}"

    http_code="$(curl --disable --silent --show-error --proto '=https' --tlsv1.2 \
      --connect-timeout 10 --max-time "${timeout}" --retry 3 --retry-all-errors \
      --noproxy '*' --max-filesize "${max_bytes}" \
      --resolve "${host}:${port}:${resolve_address}" \
      --dump-header "${headers}" --output "${body}" --write-out '%{http_code}' \
      "${normalized_url}")" || return 1

    case "${http_code}" in
      200)
        mv -f -- "${body}" "${destination}"
        return 0
        ;;
      301|302|303|307|308)
        (( hop < 5 )) || return 1
        next_url="$(python3 "${URL_GUARD}" redirect "${normalized_url}" "${headers}")" \
          || return 1
        rm -f -- "${body}" "${headers}"
        current_url="${next_url}"
        ((hop += 1))
        ;;
      *)
        echo "[ERROR] Release download returned HTTP ${http_code}." >&2
        return 1
        ;;
    esac
  done
  return 1
}

echo "[INFO] Downloading signed release..."
safe_https_download "${ARCHIVE_URL}" "${ARCHIVE_FILE}" 1800 4294967296 || {
  echo "[ERROR] Archive download failed." >&2
  exit 1
}
safe_https_download "${SIGNATURE_URL}" "${SIGNATURE_FILE}" 120 65536 || {
  echo "[ERROR] Signature download failed." >&2
  exit 1
}
[[ "$(stat -c '%s' -- "${ARCHIVE_FILE}")" -le 4294967296 ]] || {
  echo "[ERROR] Release archive exceeds the 4 GiB compressed-size limit." >&2
  exit 1
}
[[ "$(stat -c '%s' -- "${SIGNATURE_FILE}")" -le 65536 ]] || {
  echo "[ERROR] Release signature exceeds the 64 KiB size limit." >&2
  exit 1
}

if [[ -n "${EXPECTED_SHA256}" ]]; then
  command -v sha256sum >/dev/null 2>&1 || {
    echo "[ERROR] sha256sum is required when --sha256 is provided." >&2
    exit 1
  }
  printf '%s  %s\n' "${EXPECTED_SHA256,,}" "${ARCHIVE_FILE}" | sha256sum -c -
fi

echo "[INFO] Verifying EasyPi publisher signature..."
openssl dgst -sha256 -verify "${TRUSTED_KEY}" \
  -signature "${SIGNATURE_FILE}" "${ARCHIVE_FILE}" >/dev/null 2>&1 || {
  echo "[ERROR] SIGNATURE VERIFICATION FAILED — installation rejected." >&2
  exit 1
}

echo "[INFO] Validating signed release contents and manifest..."
python3 "${ARCHIVE_VALIDATOR}" "${ARCHIVE_FILE}" \
  --expected-arch aarch64 --expected-codename trixie

if run_privileged test -e "${TARGET_DIR}" || run_privileged test -L "${TARGET_DIR}"; then
  echo "[ERROR] ${TARGET_DIR} already exists. Use EasyPi's signed updater for an existing installation." >&2
  exit 1
fi

# The downloaded files are owned by the invoking user. Copy them into a
# root-only directory and repeat every authenticity/content check there before
# root opens the archive. This closes the validation-to-extraction race against
# another process running as the invoking user.
ROOT_TMP_DIR="$(run_privileged mktemp -d /var/tmp/easypi-install-root.XXXXXX)"
[[ "${ROOT_TMP_DIR}" =~ ^/var/tmp/easypi-install-root\.[A-Za-z0-9]+$ ]] \
  && run_privileged test -d "${ROOT_TMP_DIR}" \
  && ! run_privileged test -L "${ROOT_TMP_DIR}" \
  && [[ "$(run_privileged stat -c '%u:%a' -- "${ROOT_TMP_DIR}")" == "0:700" ]] || {
    echo "[ERROR] Could not create a trusted root-only staging directory." >&2
    exit 1
  }
ROOT_ARCHIVE_FILE="${ROOT_TMP_DIR}/easypi.tar.gz"
ROOT_SIGNATURE_FILE="${ROOT_TMP_DIR}/easypi.tar.gz.sig"
run_privileged install -o root -g root -m 0600 -- "${ARCHIVE_FILE}" "${ROOT_ARCHIVE_FILE}"
run_privileged install -o root -g root -m 0600 -- "${SIGNATURE_FILE}" "${ROOT_SIGNATURE_FILE}"
if [[ -n "${EXPECTED_SHA256}" ]]; then
  printf '%s  %s\n' "${EXPECTED_SHA256,,}" "${ROOT_ARCHIVE_FILE}" \
    | run_privileged sha256sum -c -
fi
run_privileged openssl dgst -sha256 -verify "${TRUSTED_KEY}" \
  -signature "${ROOT_SIGNATURE_FILE}" "${ROOT_ARCHIVE_FILE}" >/dev/null 2>&1 || {
  echo "[ERROR] Root-staged release signature verification failed." >&2
  exit 1
}
run_privileged python3 "${ARCHIVE_VALIDATOR}" "${ROOT_ARCHIVE_FILE}" \
  --expected-arch aarch64 --expected-codename trixie

echo "[INFO] Installing to ${TARGET_DIR} ..."
run_privileged mkdir -- "${TARGET_DIR}" || {
  echo "[ERROR] Could not create ${TARGET_DIR}; another install may have started." >&2
  exit 1
}
TARGET_CREATED=1
run_privileged chown root:root "${TARGET_DIR}"
run_privileged chmod 0755 "${TARGET_DIR}"
run_privileged tar --extract --gzip --file "${ROOT_ARCHIVE_FILE}" --directory "${TARGET_DIR}" \
  --no-same-owner --no-same-permissions --delay-directory-restore
run_privileged chmod 0755 "${TARGET_DIR}/install.sh" "${TARGET_DIR}/uninstall.sh"
run_privileged "${TARGET_DIR}/install.sh" --binary
INSTALL_COMPLETED=1

echo "[OK] EasyPi installation completed."
