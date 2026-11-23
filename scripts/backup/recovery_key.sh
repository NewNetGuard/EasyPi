#!/usr/bin/env bash
set -euo pipefail
umask 077

ACTION="${1:-}"
NAME="${2:-}"
ROOT="/opt/EasyPi"
EXPORT_DIR="${ROOT}/backups/recovery"
IMPORT_DIR="${ROOT}/data/backup-key-imports"
PYTHON="${ROOT}/backend/.venv/bin/python"
HELPER="${ROOT}/scripts/utils/backup_crypto.py"

die() {
  echo "ERROR: $*" >&2
  exit 1
}

[[ $# -eq 2 && "${ACTION}" =~ ^(export|import|delete)$ ]] \
  || die "usage: recovery_key.sh <export|import|delete> <validated-package-name>"
[[ "${NAME}" =~ ^(recovery-key|import)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}[.]epikey$ ]] \
  || die "invalid recovery-key package name"
if [[ "${ACTION}" != "delete" ]]; then
  [[ -x "${PYTHON}" && -f "${HELPER}" && ! -L "${HELPER}" ]] \
    || die "backup recovery helper is unavailable"

  helper_uid="$(stat -c '%u' -- "${HELPER}")"
  helper_mode="$(stat -c '%a' -- "${HELPER}")"
  [[ "${helper_uid}" == "0" && $((8#${helper_mode} & 8#022)) -eq 0 ]] \
    || die "backup recovery helper ownership or permissions are unsafe"
fi

case "${ACTION}" in
  export)
    [[ "${NAME}" == recovery-key-* ]] || die "invalid export package name"
    install -d -o root -g easypi -m 0750 "${EXPORT_DIR}"
    destination="${EXPORT_DIR}/${NAME}"
    [[ ! -e "${destination}" && ! -L "${destination}" ]] \
      || die "recovery-key export already exists"
    trap 'rm -f -- "${destination:-}"' ERR
    "${PYTHON}" "${HELPER}" export-recovery "${destination}"
    chown root:easypi "${destination}"
    chmod 0640 "${destination}"
    trap - ERR
    printf 'RECOVERY_FILE=%s\n' "${destination}"
    ;;
  import)
    [[ "${NAME}" == import-* ]] || die "invalid import package name"
    source_path="${IMPORT_DIR}/${NAME}"
    [[ -f "${source_path}" && ! -L "${source_path}" ]] \
      || die "recovery-key import is missing or unsafe"
    source_uid="$(stat -c '%u' -- "${source_path}")"
    source_mode="$(stat -c '%a' -- "${source_path}")"
    easypi_uid="$(id -u easypi)"
    [[ ("${source_uid}" == "${easypi_uid}" || "${source_uid}" == "0") \
        && $((8#${source_mode} & 8#077)) -eq 0 ]] \
      || die "recovery-key import ownership or permissions are unsafe"
    install -d -o root -g root -m 0700 /var/lib/easypi/backup
    temporary="$(mktemp /var/lib/easypi/backup/.key-import.XXXXXX.epikey)"
    trap 'rm -f -- "${temporary:-}" "${source_path:-}"' EXIT
    install -o root -g root -m 0600 "${source_path}" "${temporary}"
    "${PYTHON}" "${HELPER}" import-recovery "${temporary}"
    ;;
  delete)
    [[ "${NAME}" == recovery-key-* ]] || die "invalid export package name"
    destination="${EXPORT_DIR}/${NAME}"
    rm -f -- "${destination}"
    printf 'RECOVERY_FILE_DELETED=YES\n'
    ;;
esac
