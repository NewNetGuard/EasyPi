#!/usr/bin/env bash
# Refresh the Tor IPv4 policy only from an EasyPi-signed manifest and payload.
set -euo pipefail
umask 077

ACTION="${1:-update}"
[[ $# -le 1 && "${ACTION}" == "update" ]] || {
    echo "Usage: $0 [update]" >&2
    exit 2
}

EASYPI_ROOT="${EASYPI_ROOT:-/opt/EasyPi}"
BUNDLE_PARENT="/var/lib/easypi-security"
BUNDLE_ROOT="${BUNDLE_PARENT}/tor"
VERSIONS_DIR="${BUNDLE_ROOT}/versions"
CURRENT_LINK="${BUNDLE_ROOT}/current"
OUT="${CURRENT_LINK}/tor_ipv4.txt"
TRUSTED_KEY="${EASYPI_TOR_FEED_PUBLIC_KEY:-${EASYPI_ROOT}/scripts/maintenance/update_signing_key.pub}"
FEED_URL="${EASYPI_TOR_FEED_URL:-}"
MANIFEST_URL="${EASYPI_TOR_FEED_MANIFEST_URL:-}"
SIGNATURE_URL="${EASYPI_TOR_FEED_SIGNATURE_URL:-}"
CONFIG_FILE="${EASYPI_TOR_FEED_CONFIG:-/etc/easypi/tor-feed.json}"
RUNTIME_DIR="/run/easypi-feed-update"

if [[ -z "${FEED_URL}" && -f "${CONFIG_FILE}" ]]; then
    [[ ! -L "${CONFIG_FILE}" ]] || {
        echo "ERROR: signed Tor feed configuration must not be a symlink" >&2
        exit 1
    }
    config_uid="$(stat -c '%u' "${CONFIG_FILE}")"
    config_mode="$(stat -c '%a' "${CONFIG_FILE}")"
    [[ "${config_uid}" == "0" && $((8#${config_mode} & 8#022)) -eq 0 ]] || {
        echo "ERROR: signed Tor feed configuration has unsafe ownership or permissions" >&2
        exit 1
    }
    mapfile -t feed_config < <(/usr/bin/python3 - "${CONFIG_FILE}" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    config = json.load(handle)
expected = {"feed_url", "manifest_url", "signature_url"}
if set(config) != expected or not all(isinstance(config[key], str) for key in expected):
    raise SystemExit("invalid signed Tor feed configuration")
for key in ("feed_url", "manifest_url", "signature_url"):
    print(config[key])
PY
    )
    [[ "${#feed_config[@]}" -eq 3 ]] || {
        echo "ERROR: signed Tor feed configuration is invalid" >&2
        exit 1
    }
    FEED_URL="${feed_config[0]}"
    MANIFEST_URL="${feed_config[1]}"
    SIGNATURE_URL="${feed_config[2]}"
fi

if [[ -z "${FEED_URL}" || -z "${MANIFEST_URL}" || -z "${SIGNATURE_URL}" ]]; then
    echo "INFO: no signed Tor feed configured; keeping the last known-good policy" >&2
    exit 3
fi
for url in "${FEED_URL}" "${MANIFEST_URL}" "${SIGNATURE_URL}"; do
    [[ "${url}" =~ ^https:// ]] || {
        echo "ERROR: signed Tor feed URLs must use HTTPS" >&2
        exit 1
    }
done
[[ -f "${TRUSTED_KEY}" && ! -L "${TRUSTED_KEY}" ]] || {
    echo "ERROR: Tor feed trust root is missing or unsafe" >&2
    exit 1
}
key_uid="$(stat -c '%u' "${TRUSTED_KEY}")"
key_mode="$(stat -c '%a' "${TRUSTED_KEY}")"
[[ "${key_uid}" == "0" && $((8#${key_mode} & 8#022)) -eq 0 ]] || {
    echo "ERROR: Tor feed trust root must be root-owned and not writable by group/others" >&2
    exit 1
}
[[ "${EUID}" -eq 0 ]] || {
    echo "ERROR: signed Tor bundle activation requires root" >&2
    exit 1
}

install -d -o root -g root -m 0700 "${RUNTIME_DIR}"
for protected_dir in "${BUNDLE_PARENT}" "${BUNDLE_ROOT}" "${VERSIONS_DIR}"; do
    if [[ -e "${protected_dir}" && -L "${protected_dir}" ]]; then
        echo "ERROR: Tor security state directories must not be symlinks" >&2
        exit 1
    fi
done
install -d -o root -g root -m 0700 "${BUNDLE_PARENT}" "${BUNDLE_ROOT}" "${VERSIONS_DIR}"
parent_uid="$(stat -c '%u' "${BUNDLE_PARENT}")"
parent_mode="$(stat -c '%a' "${BUNDLE_PARENT}")"
bundle_uid="$(stat -c '%u' "${BUNDLE_ROOT}")"
bundle_mode="$(stat -c '%a' "${BUNDLE_ROOT}")"
versions_uid="$(stat -c '%u' "${VERSIONS_DIR}")"
versions_mode="$(stat -c '%a' "${VERSIONS_DIR}")"
[[ "${parent_uid}" == "0" && $((8#${parent_mode} & 8#077)) -eq 0 && \
   "${bundle_uid}" == "0" && $((8#${bundle_mode} & 8#077)) -eq 0 && \
   "${versions_uid}" == "0" && $((8#${versions_mode} & 8#077)) -eq 0 ]] || {
    echo "ERROR: Tor bundle root ownership or permissions are unsafe" >&2
    exit 1
}
command -v flock >/dev/null 2>&1 || {
    echo "ERROR: flock is required for transactional Tor activation" >&2
    exit 1
}
[[ ! -L "${BUNDLE_ROOT}/update.lock" ]] || {
    echo "ERROR: Tor update lock must not be a symlink" >&2
    exit 1
}
exec 9>"${BUNDLE_ROOT}/update.lock"
chmod 0600 "${BUNDLE_ROOT}/update.lock"
flock -x 9

PAYLOAD="$(mktemp "${RUNTIME_DIR}/tor-payload.XXXXXX")"
MANIFEST="$(mktemp "${RUNTIME_DIR}/tor-manifest.XXXXXX")"
SIGNATURE="$(mktemp "${RUNTIME_DIR}/tor-signature.XXXXXX")"
VALIDATED="$(mktemp "${RUNTIME_DIR}/tor-validated.XXXXXX")"
SEQUENCE_FILE="$(mktemp "${RUNTIME_DIR}/tor-sequence.XXXXXX")"
STAGE_DIR=""
trap 'rm -f "${PAYLOAD}" "${MANIFEST}" "${SIGNATURE}" "${VALIDATED}" "${SEQUENCE_FILE}" "${LINK_TMP:-}"; if [[ -n "${STAGE_DIR}" && "${STAGE_DIR}" == "${VERSIONS_DIR}/.stage."* ]]; then rm -rf -- "${STAGE_DIR}"; fi' EXIT

download_https() {
    curl --fail --silent --show-error --location \
        --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --connect-timeout 15 --max-time 120 --retry 2 --retry-all-errors \
        --max-filesize 8388608 --output "$2" "$1"
}

download_https "${FEED_URL}" "${PAYLOAD}" || {
    echo "ERROR: Tor payload download failed; keeping existing policy" >&2
    exit 1
}
download_https "${MANIFEST_URL}" "${MANIFEST}" || {
    echo "ERROR: Tor manifest download failed; keeping existing policy" >&2
    exit 1
}
download_https "${SIGNATURE_URL}" "${SIGNATURE}" || {
    echo "ERROR: Tor manifest signature download failed; keeping existing policy" >&2
    exit 1
}

openssl dgst -sha256 -verify "${TRUSTED_KEY}" \
    -signature "${SIGNATURE}" "${MANIFEST}" >/dev/null 2>&1 || {
    echo "ERROR: Tor feed signature verification failed; keeping existing policy" >&2
    exit 1
}

PAYLOAD="${PAYLOAD}" MANIFEST="${MANIFEST}" CURRENT_LINK="${CURRENT_LINK}" \
VERSIONS_DIR="${VERSIONS_DIR}" VALIDATED="${VALIDATED}" \
SEQUENCE_FILE="${SEQUENCE_FILE}" /usr/bin/python3 - <<'PY'
import hashlib
import ipaddress
import json
import os
import stat
from pathlib import Path

payload = Path(os.environ["PAYLOAD"])
manifest_path = Path(os.environ["MANIFEST"])
validated = Path(os.environ["VALIDATED"])
sequence_file = Path(os.environ["SEQUENCE_FILE"])
current_link = Path(os.environ["CURRENT_LINK"])
versions_dir = Path(os.environ["VERSIONS_DIR"]).resolve(strict=True)

manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
expected_keys = {"schema", "sequence", "generated_at", "payload_sha256", "entry_count"}
if set(manifest) != expected_keys or manifest["schema"] != 1:
    raise SystemExit("invalid Tor feed manifest schema")
sequence = manifest["sequence"]
entry_count = manifest["entry_count"]
if not isinstance(sequence, int) or sequence < 1:
    raise SystemExit("invalid Tor feed sequence")
if not isinstance(entry_count, int) or not 1000 <= entry_count <= 65000:
    raise SystemExit("Tor feed entry count is outside safety bounds")
if not isinstance(manifest["generated_at"], str) or len(manifest["generated_at"]) < 20:
    raise SystemExit("invalid Tor feed timestamp")
expected_hash = manifest["payload_sha256"]
actual_hash = hashlib.sha256(payload.read_bytes()).hexdigest()
if not isinstance(expected_hash, str) or expected_hash != actual_hash:
    raise SystemExit("Tor feed payload hash mismatch")

current_sequence = 0
current_manifest = None
if current_link.exists() or current_link.is_symlink():
    if not current_link.is_symlink():
        raise SystemExit("Tor current pointer is not a symlink")
    try:
        current_version = current_link.resolve(strict=True)
    except OSError as exc:
        raise SystemExit("Tor current pointer is broken") from exc
    if current_version.parent != versions_dir or not current_version.name.isdecimal():
        raise SystemExit("Tor current pointer escapes the version store")
    version_stat = current_version.stat()
    if version_stat.st_uid != 0 or version_stat.st_mode & (stat.S_IWGRP | stat.S_IWOTH):
        raise SystemExit("Tor current version permissions are unsafe")
    current_manifest_path = current_version / "manifest.json"
    if current_manifest_path.is_symlink() or not current_manifest_path.is_file():
        raise SystemExit("Tor current manifest is unsafe")
    try:
        current_manifest = json.loads(current_manifest_path.read_text(encoding="utf-8"))
        current_sequence = int(current_manifest["sequence"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError) as exc:
        raise SystemExit("existing Tor feed anchor is invalid") from exc
if sequence < current_sequence:
    raise SystemExit("Tor feed rollback rejected")
if sequence == current_sequence and current_manifest is not None and manifest != current_manifest:
    raise SystemExit("Tor feed sequence equivocation rejected")

addresses = set()
for raw in payload.read_text(encoding="utf-8", errors="strict").splitlines():
    value = raw.strip()
    if not value or value.startswith("#"):
        continue
    address = ipaddress.ip_address(value)
    if address.version != 4 or not address.is_global:
        raise SystemExit(f"unsafe Tor feed address: {value}")
    addresses.add(str(address))
if len(addresses) != entry_count:
    raise SystemExit("Tor feed count does not match signed manifest")

validated.write_text("".join(f"{value}\n" for value in sorted(addresses)), encoding="ascii")
sequence_file.write_text(f"{sequence}\n", encoding="ascii")
PY

# Payload, signed manifest and signature are installed into one immutable,
# root-owned version. The single symlink rename is the transaction commit and
# also the rollback anchor; an interruption can expose only the old or new
# complete bundle, never a mixed policy/state pair.
SEQUENCE="$(tr -d '\n' < "${SEQUENCE_FILE}")"
[[ "${SEQUENCE}" =~ ^[1-9][0-9]*$ ]] || {
    echo "ERROR: validated Tor sequence is invalid" >&2
    exit 1
}
VERSION_DIR="${VERSIONS_DIR}/${SEQUENCE}"
if [[ -e "${VERSION_DIR}" ]]; then
    [[ -d "${VERSION_DIR}" && ! -L "${VERSION_DIR}" ]] || {
        echo "ERROR: existing Tor version path is unsafe" >&2
        exit 1
    }
    cmp -s "${VALIDATED}" "${VERSION_DIR}/tor_ipv4.txt" && \
        cmp -s "${MANIFEST}" "${VERSION_DIR}/manifest.json" && \
        cmp -s "${SIGNATURE}" "${VERSION_DIR}/manifest.json.sig" || {
        echo "ERROR: Tor sequence already exists with different content" >&2
        exit 1
    }
else
    STAGE_DIR="$(mktemp -d "${VERSIONS_DIR}/.stage.XXXXXX")"
    install -o root -g root -m 0600 "${VALIDATED}" "${STAGE_DIR}/tor_ipv4.txt"
    install -o root -g root -m 0600 "${MANIFEST}" "${STAGE_DIR}/manifest.json"
    install -o root -g root -m 0600 "${SIGNATURE}" "${STAGE_DIR}/manifest.json.sig"
    chmod 0700 "${STAGE_DIR}"
    mv -T -- "${STAGE_DIR}" "${VERSION_DIR}"
    STAGE_DIR=""
fi

LINK_TMP="${BUNDLE_ROOT}/.current.$$"
ln -s "versions/${SEQUENCE}" "${LINK_TMP}"
mv -Tf -- "${LINK_TMP}" "${CURRENT_LINK}"
echo "Tor policy updated from signed feed: ${OUT} ($(wc -l < "${OUT}") addresses)"
