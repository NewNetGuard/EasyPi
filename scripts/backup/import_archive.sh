#!/usr/bin/env bash
set -euo pipefail
umask 077

UPLOAD_NAME="${1:-}"
TARGET_NAME="${2:-}"
ROOT="/opt/EasyPi"
IMPORT_DIR="${ROOT}/data/backup-archive-imports"
BACKUP_DIR="${ROOT}/backups"
PYTHON="${ROOT}/backend/.venv/bin/python"
CRYPTO_HELPER="${ROOT}/scripts/utils/backup_crypto.py"
RESTORE_VALIDATOR="${ROOT}/scripts/utils/secure_restore.py"
STAGED_ARCHIVE=""
VALIDATION_FILE=""
COMPLETED=0
DESTINATION=""

die() {
  echo "ERROR: $*" >&2
  exit 1
}

cleanup() {
  local rc=$?
  trap - EXIT
  [[ -z "${VALIDATION_FILE}" ]] || rm -f -- "${VALIDATION_FILE}"
  if (( COMPLETED == 0 )); then
    [[ -z "${STAGED_ARCHIVE}" ]] || rm -f -- "${STAGED_ARCHIVE}"
    [[ -z "${DESTINATION}" ]] || rm -f -- "${DESTINATION}"
  fi
  rm -f -- "${IMPORT_DIR}/${UPLOAD_NAME}"
  exit "${rc}"
}

[[ $# -eq 2 ]] || die "usage: import_archive.sh <upload-name> <backup-name>"
[[ "${UPLOAD_NAME}" =~ ^import-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[.]epibak$ ]] \
  || die "invalid upload name"
[[ "${TARGET_NAME}" =~ ^(config|full|pre-restore)-[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{2}-[0-9]{2}(-[0-9]{2})?[.]epibak$ ]] \
  || die "invalid backup archive name"
[[ -x "${PYTHON}" ]] || die "backup Python runtime is unavailable"
for helper in "${CRYPTO_HELPER}" "${RESTORE_VALIDATOR}"; do
  [[ -f "${helper}" && ! -L "${helper}" ]] || die "backup helper is unavailable"
  helper_uid="$(stat -c '%u' -- "${helper}")"
  helper_mode="$(stat -c '%a' -- "${helper}")"
  [[ "${helper_uid}" == "0" && $((8#${helper_mode} & 8#022)) -eq 0 ]] \
    || die "backup helper ownership or permissions are unsafe"
done

source_path="${IMPORT_DIR}/${UPLOAD_NAME}"
[[ -f "${source_path}" && ! -L "${source_path}" ]] \
  || die "backup upload is missing or unsafe"
source_uid="$(stat -c '%u' -- "${source_path}")"
source_mode="$(stat -c '%a' -- "${source_path}")"
source_size="$(stat -c '%s' -- "${source_path}")"
easypi_uid="$(id -u easypi)"
[[ ("${source_uid}" == "${easypi_uid}" || "${source_uid}" == "0") \
    && $((8#${source_mode} & 8#077)) -eq 0 ]] \
  || die "backup upload ownership or permissions are unsafe"
(( source_size >= 37 && source_size <= 4294967296 )) \
  || die "backup upload size is invalid"

exec 9>/run/easypi-backup.lock
flock -n 9 || die "another backup or restore operation is running"
install -d -o root -g easypi -m 0750 "${BACKUP_DIR}"
destination="${BACKUP_DIR}/${TARGET_NAME}"
DESTINATION="${destination}"
[[ ! -e "${destination}" && ! -L "${destination}" ]] \
  || die "backup archive already exists"

trap cleanup EXIT
STAGED_ARCHIVE="$(mktemp "${BACKUP_DIR}/.import.XXXXXX.epibak")"
install -o root -g root -m 0600 -- "${source_path}" "${STAGED_ARCHIVE}"
# Verify only the root-owned copy. The backend-owned upload may change, but it
# is never reopened after this point.
"${PYTHON}" "${CRYPTO_HELPER}" verify "${STAGED_ARCHIVE}" >/dev/null
VALIDATION_FILE="$(mktemp "${BACKUP_DIR}/.restore.XXXXXX.tar.gz")"
"${PYTHON}" "${CRYPTO_HELPER}" decrypt "${STAGED_ARCHIVE}" "${VALIDATION_FILE}" >/dev/null
chown root:root "${VALIDATION_FILE}"
chmod 0600 "${VALIDATION_FILE}"
/usr/bin/python3 "${RESTORE_VALIDATOR}" --validate-only "${VALIDATION_FILE}" >/dev/null
rm -f -- "${VALIDATION_FILE}"
VALIDATION_FILE=""

mv -- "${STAGED_ARCHIVE}" "${destination}"
STAGED_ARCHIVE=""
chown root:easypi "${destination}"
chmod 0640 "${destination}"
COMPLETED=1
printf 'BACKUP_FILE=%s\n' "${destination}"
