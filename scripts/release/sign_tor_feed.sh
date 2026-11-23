#!/usr/bin/env bash
# Build and sign an authenticated Tor IPv4 snapshot for EasyPi installations.
set -euo pipefail
umask 077

usage() {
  echo "Usage: $0 --input PATH --sequence N --signing-key PATH --output-dir PATH" >&2
}

INPUT=""
SEQUENCE=""
SIGNING_KEY=""
OUTPUT_DIR=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --input) INPUT="${2:-}"; shift 2 ;;
    --sequence) SEQUENCE="${2:-}"; shift 2 ;;
    --signing-key) SIGNING_KEY="${2:-}"; shift 2 ;;
    --output-dir) OUTPUT_DIR="${2:-}"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
done

[[ -f "${INPUT}" && ! -L "${INPUT}" ]] || { echo "ERROR: input is unsafe" >&2; exit 1; }
[[ -f "${SIGNING_KEY}" && ! -L "${SIGNING_KEY}" ]] || { echo "ERROR: signing key is unsafe" >&2; exit 1; }
key_uid="$(stat -c '%u' "${SIGNING_KEY}")"
key_mode="$(stat -c '%a' "${SIGNING_KEY}")"
[[ "${key_uid}" == "$(id -u)" && $((8#${key_mode} & 8#077)) -eq 0 ]] || {
  echo "ERROR: signing key must be owner-only and owned by the signing user" >&2
  exit 1
}
[[ "${SEQUENCE}" =~ ^[1-9][0-9]*$ ]] || { echo "ERROR: sequence must be positive" >&2; exit 1; }
[[ -n "${OUTPUT_DIR}" ]] || { usage; exit 2; }

install -d -m 0700 "${OUTPUT_DIR}"
PAYLOAD="${OUTPUT_DIR}/tor_ipv4.txt"
MANIFEST="${OUTPUT_DIR}/tor_ipv4.manifest.json"
SIGNATURE="${OUTPUT_DIR}/tor_ipv4.manifest.json.sig"

INPUT="${INPUT}" PAYLOAD="${PAYLOAD}" MANIFEST="${MANIFEST}" \
SEQUENCE="${SEQUENCE}" python3 - <<'PY'
import hashlib
import ipaddress
import json
import os
from datetime import datetime, timezone
from pathlib import Path

source = Path(os.environ["INPUT"])
payload = Path(os.environ["PAYLOAD"])
manifest_path = Path(os.environ["MANIFEST"])
addresses = set()
for raw in source.read_text(encoding="utf-8", errors="strict").splitlines():
    value = raw.strip()
    if not value or value.startswith("#"):
        continue
    address = ipaddress.ip_address(value)
    if address.version != 4 or not address.is_global:
        raise SystemExit(f"unsafe Tor address: {value}")
    addresses.add(str(address))
if not 1000 <= len(addresses) <= 65000:
    raise SystemExit(f"Tor snapshot count outside safety bounds: {len(addresses)}")

content = "".join(f"{value}\n" for value in sorted(addresses)).encode("ascii")
payload.write_bytes(content)
manifest = {
    "schema": 1,
    "sequence": int(os.environ["SEQUENCE"]),
    "generated_at": datetime.now(timezone.utc).isoformat(),
    "payload_sha256": hashlib.sha256(content).hexdigest(),
    "entry_count": len(addresses),
}
manifest_path.write_text(
    json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8"
)
PY

openssl dgst -sha256 -sign "${SIGNING_KEY}" -out "${SIGNATURE}" "${MANIFEST}"
chmod 0644 "${PAYLOAD}" "${MANIFEST}" "${SIGNATURE}"
echo "Signed Tor feed written to ${OUTPUT_DIR} (sequence ${SEQUENCE})"
