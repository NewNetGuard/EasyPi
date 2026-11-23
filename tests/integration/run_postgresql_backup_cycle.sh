#!/usr/bin/env bash
set -euo pipefail
umask 077

UPLOAD_DIR="${1:-}"
[[ "${EUID}" -eq 0 ]] || { echo "ERROR: run as root" >&2; exit 1; }
[[ "${UPLOAD_DIR}" == /tmp/easypi-pg-upload-* && -d "${UPLOAD_DIR}" && ! -L "${UPLOAD_DIR}" ]] \
    || { echo "ERROR: unsafe upload directory" >&2; exit 1; }

for required in postgresql_backup_cycle.py postgres_backup.py backup_crypto.py; do
    [[ -f "${UPLOAD_DIR}/${required}" && ! -L "${UPLOAD_DIR}/${required}" ]] \
        || { echo "ERROR: missing test input: ${required}" >&2; exit 1; }
done

SERVER_WAS_INSTALLED=1
POSTGRES_WAS_ACTIVE=0
dpkg-query -W -f='${Status}' postgresql 2>/dev/null | grep -q 'ok installed' \
    || SERVER_WAS_INSTALLED=0
systemctl is-active --quiet postgresql && POSTGRES_WAS_ACTIVE=1

if (( SERVER_WAS_INSTALLED == 0 )); then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq postgresql postgresql-client
fi
systemctl start postgresql

PG_MAJOR="$(pg_config --version | awk '{print $2}' | cut -d. -f1)"
SUFFIX="$(openssl rand -hex 6)"
ROLE="easypi_e2e_${SUFFIX}"
DATABASE="easypi_e2e_${SUFFIX}"
PASSWORD="$(openssl rand -hex 24)"
UNIT="easypi-pg-e2e-${SUFFIX}.service"
WORK_DIR="$(mktemp -d /var/tmp/easypi-pg-e2e.XXXXXX)"

cleanup() {
    local rc=$?
    trap - EXIT
    set +e
    systemctl stop "${UNIT}" >/dev/null 2>&1
    rm -f -- "/run/systemd/system/${UNIT}"
    systemctl daemon-reload >/dev/null 2>&1
    runuser -u postgres -- dropdb --if-exists --force "${DATABASE}" >/dev/null 2>&1
    runuser -u postgres -- psql --no-psqlrc --set ON_ERROR_STOP=1 \
        --command "DROP ROLE IF EXISTS \"${ROLE}\";" >/dev/null 2>&1
    if [[ "${WORK_DIR}" == /var/tmp/easypi-pg-e2e.* && -d "${WORK_DIR}" && ! -L "${WORK_DIR}" ]]; then
        rm -rf -- "${WORK_DIR}"
    fi
    if [[ "${UPLOAD_DIR}" == /tmp/easypi-pg-upload-* && -d "${UPLOAD_DIR}" && ! -L "${UPLOAD_DIR}" ]]; then
        rm -rf -- "${UPLOAD_DIR}"
    fi
    if (( SERVER_WAS_INSTALLED == 0 )); then
        pg_dropcluster --stop "${PG_MAJOR}" main >/dev/null 2>&1 || true
        export DEBIAN_FRONTEND=noninteractive
        apt-get purge -y -qq postgresql "postgresql-${PG_MAJOR}" >/dev/null 2>&1 || true
    elif (( POSTGRES_WAS_ACTIVE == 0 )); then
        systemctl stop postgresql >/dev/null 2>&1 || true
    fi
    exit "${rc}"
}
trap cleanup EXIT

install -o root -g root -m 0700 "${UPLOAD_DIR}/postgresql_backup_cycle.py" "${WORK_DIR}/"
install -o root -g root -m 0600 "${UPLOAD_DIR}/postgres_backup.py" "${WORK_DIR}/"
install -o root -g root -m 0600 "${UPLOAD_DIR}/backup_crypto.py" "${WORK_DIR}/"

runuser -u postgres -- psql --no-psqlrc --set ON_ERROR_STOP=1 \
    --command "CREATE ROLE \"${ROLE}\" LOGIN PASSWORD '${PASSWORD}';"
runuser -u postgres -- createdb --owner="${ROLE}" "${DATABASE}"

ENV_FILE="${WORK_DIR}/database.env"
printf 'DATABASE_URL=postgresql://%s:%s@127.0.0.1:5432/%s\n' \
    "${ROLE}" "${PASSWORD}" "${DATABASE}" > "${ENV_FILE}"
chown root:root "${ENV_FILE}"
chmod 0600 "${ENV_FILE}"

/opt/EasyPi/backend/.venv/bin/python "${WORK_DIR}/postgresql_backup_cycle.py" \
    --env-file "${ENV_FILE}" \
    --work-dir "${WORK_DIR}" \
    --unit "${UNIT}"
