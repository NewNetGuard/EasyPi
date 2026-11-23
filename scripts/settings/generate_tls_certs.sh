#!/usr/bin/env bash
set -euo pipefail

CERT_DIR_RAW="${1:-/opt/EasyPi/certs}"
CERT_ACTION="${2:-ca-signed}"
CERT_DIR="$(realpath -m "${CERT_DIR_RAW}")"
ALLOWED_DIR="$(realpath -m "/opt/EasyPi/certs")"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
GENERATOR="${ROOT_DIR}/setup/generate_certs.sh"
EASYPI_USER="${EASYPI_USER:-easypi}"
EASYPI_GROUP="${EASYPI_GROUP:-easypi}"

if [[ "${CERT_DIR}" != "${ALLOWED_DIR}" ]]; then
  echo "[ERROR] Certificate directory must be ${ALLOWED_DIR}" >&2
  exit 1
fi

if [[ "${CERT_ACTION}" != "ca-signed" && "${CERT_ACTION}" != "renew" ]]; then
  echo "[ERROR] Certificate action must be ca-signed or renew" >&2
  exit 1
fi

if [[ -L "${ALLOWED_DIR}" ]]; then
  echo "[ERROR] Certificate directory must not be a symlink: ${ALLOWED_DIR}" >&2
  exit 1
fi

if [[ ! -f "${GENERATOR}" ]]; then
  echo "[ERROR] Certificate generator not found: ${GENERATOR}" >&2
  exit 1
fi

export EASYPI_CERT_DIR="${CERT_DIR}"
/bin/bash "${GENERATOR}" "${CERT_ACTION}"

if getent group "${EASYPI_GROUP}" >/dev/null 2>&1; then
  chown "root:${EASYPI_GROUP}" "${CERT_DIR}"
  chown "root:${EASYPI_GROUP}" "${CERT_DIR}/key.pem" "${CERT_DIR}/cert.pem"
  if [[ -f "${CERT_DIR}/ca.pem" ]]; then
    chown "root:${EASYPI_GROUP}" "${CERT_DIR}/ca.pem"
  fi
else
  chown root:root "${CERT_DIR}"
  chown root:root "${CERT_DIR}/key.pem" "${CERT_DIR}/cert.pem"
  if [[ -f "${CERT_DIR}/ca.pem" ]]; then
    chown root:root "${CERT_DIR}/ca.pem"
  fi
fi

chmod 750 "${CERT_DIR}"
chmod 640 "${CERT_DIR}/key.pem"
chmod 644 "${CERT_DIR}/cert.pem"
if [[ -f "${CERT_DIR}/ca.pem" ]]; then
  chmod 644 "${CERT_DIR}/ca.pem"
fi
if [[ -f "${CERT_DIR}/ca-key.pem" ]]; then
  chown root:root "${CERT_DIR}/ca-key.pem"
  chmod 600 "${CERT_DIR}/ca-key.pem"
fi
