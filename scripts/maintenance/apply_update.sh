#!/usr/bin/env bash
#
# EasyPi signed self-update wrapper (HARDENED: atomic snapshot + health-gated
# auto-rollback). Runs as root via a narrow sudo grant.
#
# SECURITY MODEL:
#   * root-owned, NOT writable by the `easypi` service account.
#   * Before ANY archive content is applied, a detached RSA/SHA-256 signature of
#     the archive is verified against a baked-in PUBLIC key. The private key never
#     lives on the device, so a compromised backend can neither forge an update
#     nor reach root through here. Only signed releases are ever applied.
#
# SAFETY MODEL (code and database rollback on an apply or health-check failure):
#   * A full snapshot of the current code tree AND the databases is taken BEFORE
#     the new files are written. A marker records the in-progress apply.
#   * After the new version is applied the backend is restarted and its /health
#     endpoint is polled. If anything fails (apply error, failed install, backend
#     never becomes healthy) an EXIT trap restores the code/database snapshot and
#     restarts the managed services. Host-wide changes made by an explicitly
#     requested installer hook are outside this snapshot boundary.
#   * If the machine reboots mid-apply, a boot-time oneshot runs `--recover`,
#     which finishes the rollback from the marker + snapshot.
set -euo pipefail
umask 077

PUBKEY="/opt/EasyPi/scripts/maintenance/update_signing_key.pub"
TARGET_DIR="/opt/EasyPi"
URL_GUARD="${TARGET_DIR}/scripts/maintenance/update_url_guard.py"
ARCHIVE_VALIDATOR="${TARGET_DIR}/scripts/release/validate_release_archive.py"
POSTGRES_HELPER="${TARGET_DIR}/scripts/utils/postgres_backup.py"
MARKER="${TARGET_DIR}/.update-in-progress"
LOCK_FILE="/run/lock/easypi-update.lock"
BACKUPS_ROOT="${EASYPI_UPDATE_BACKUPS_ROOT:-/var/backups/easypi/updates}"
HEALTH_URL="http://127.0.0.1:8000/health"
FRONTEND_URL="https://127.0.0.1/"
RUNTIME_HEALTH_CHECK="${TARGET_DIR}/scripts/maintenance/verify_runtime_health.py"
KEEP_SNAPSHOTS=5
BACKEND_STOPPED_FOR_UPDATE=0

# Runtime paths omitted from snapshots and restores because they have dedicated
# handling or are disposable caches.
RSYNC_EXCLUDES=(
  --exclude ".env" --exclude "data/" --exclude "logs/" --exclude ".build/"
  --exclude "backend/.venv/" --exclude "frontend/node_modules/"
  --exclude ".update-backups/" --exclude "backups/" --exclude ".update-in-progress"
)
# The installation CA and TLS private keys are part of the rollback snapshot,
# but a release payload must never replace or delete them. The installer only
# validates/reuses the existing set unless an administrator explicitly renews it.
APPLY_EXCLUDES=("${RSYNC_EXCLUDES[@]}" --exclude "certs/")

GREEN="\033[0;32m"; YELLOW="\033[0;33m"; RED="\033[0;31m"; NC="\033[0m"
info() { echo -e "${GREEN}==>${NC} $1"; }
warn() { echo -e "${YELLOW}==>${NC} $1"; }
die()  { echo -e "${RED}==>${NC} $1" >&2; exit 1; }

[[ "${EUID}" -eq 0 ]] || die "Must run as root"

# Only one signed update or recovery may touch the installation at a time.
# /run/lock is root-controlled, so the backend account cannot redirect the lock.
command -v flock >/dev/null 2>&1 || die "Required command not found: flock"
if [[ -e "${LOCK_FILE}" ]]; then
  [[ ! -L "${LOCK_FILE}" ]] || die "Unsafe update lock: ${LOCK_FILE}"
  LOCK_UID="$(stat -c '%u' -- "${LOCK_FILE}" 2>/dev/null || echo -1)"
  LOCK_MODE="$(stat -c '%a' -- "${LOCK_FILE}" 2>/dev/null || echo 777)"
  [[ "${LOCK_UID}" == "0" && $((8#${LOCK_MODE} & 8#022)) -eq 0 ]] \
    || die "Update lock must be root-owned and not writable outside root"
fi
exec 9>"${LOCK_FILE}"
chmod 0600 "${LOCK_FILE}"
flock -n 9 || die "Another EasyPi update is already running"

secure_target_permissions() {
  # nginx needs traverse-only access to reach the public frontend. 0751 does
  # not permit directory listing; secrets and privileged trees retain their
  # own 0640/0750 permissions.
  chown root:easypi "${TARGET_DIR}"
  chmod 0751 "${TARGET_DIR}"

  # Secrets must never remain writable by the backend service account. Legacy
  # installations may have easypi-owned .env files; every signed update and
  # rollback is an opportunity to repair that boundary without changing data.
  if [[ -f "${TARGET_DIR}/.env" && ! -L "${TARGET_DIR}/.env" ]]; then
    chown root:easypi "${TARGET_DIR}/.env"
    chmod 0640 "${TARGET_DIR}/.env"
  fi

  # Privileged runner targets are root code. Keep directories traversable only
  # by root/easypi and prevent archive source modes from widening access.
  if [[ -d "${TARGET_DIR}/scripts" && ! -L "${TARGET_DIR}/scripts" ]]; then
    chown -R root:easypi "${TARGET_DIR}/scripts"
    find "${TARGET_DIR}/scripts" -type d -exec chmod 0750 {} +
    find "${TARGET_DIR}/scripts" -type f -name '*.sh' -exec chmod 0750 {} +
    [[ -f "${TARGET_DIR}/scripts/runner" && ! -L "${TARGET_DIR}/scripts/runner" ]] \
      && chmod 0750 "${TARGET_DIR}/scripts/runner"
  fi

  if [[ -d "${TARGET_DIR}/frontend/dist" && ! -L "${TARGET_DIR}/frontend/dist" ]]; then
    chown -R root:root "${TARGET_DIR}/frontend/dist"
    find "${TARGET_DIR}/frontend/dist" -type d -exec chmod 0755 {} +
    find "${TARGET_DIR}/frontend/dist" -type f -exec chmod 0644 {} +
  fi
}

secure_sqlite_runtime() {
  local db_dir="${TARGET_DIR}/data/db"
  [[ -d "${db_dir}" && ! -L "${db_dir}" ]] || return 1
  chown -R easypi:easypi "${db_dir}"
  find "${db_dir}" -type d -exec chmod 0750 {} +
  find "${db_dir}" -type f -exec chmod 0640 {} +
}

# --- health check: application, local DNS, routing and fail-closed tunnel state ---
health_ok() {
  local tries="${1:-90}" i code frontend_code   # ~180s: cold start blocks on the netprotection restart
  for ((i = 0; i < tries; i++)); do
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 3 "${HEALTH_URL}" 2>/dev/null || echo 000)"
    frontend_code="$(curl -k -s -o /dev/null -w '%{http_code}' --max-time 3 "${FRONTEND_URL}" 2>/dev/null || echo 000)"
    if [[ "${code}" == "200" && "${frontend_code}" == "200" ]]; then
      # Older rollback snapshots predate the deep checker. New signed releases
      # are required by the archive validator to contain it.
      if [[ ! -f "${RUNTIME_HEALTH_CHECK}" ]] \
          || /usr/bin/python3 "${RUNTIME_HEALTH_CHECK}" >/dev/null 2>&1; then
        return 0
      fi
    fi
    sleep 2
  done
  [[ -f "${RUNTIME_HEALTH_CHECK}" ]] \
    && /usr/bin/python3 "${RUNTIME_HEALTH_CHECK}" || true
  return 1
}

refresh_mobile_link_units() {
  local name="" template="" unit="" agent_user="" agent_group="" staged=""

  # Normal signed updates do not run the full installer. Keep the already
  # installed service definition in sync with its single release template so
  # dependency and restart-policy fixes are applied during ordinary updates.
  for name in \
      easypi-mobile-link-agent.service \
      easypi-mobile-home-tunnel-agent.service \
      easypi-mobile-home-tunnel.service; do
    template="${TARGET_DIR}/templates/systemd/${name}"
    unit="/etc/systemd/system/${name}"
    [[ -f "${template}" && ! -L "${template}" ]] || continue
    agent_user="easypi-mobile-link"
    agent_group="easypi-mobile-link"
    if [[ -f "${unit}" && ! -L "${unit}" ]]; then
      agent_user="$(sed -n 's/^User=//p' "${unit}" | head -n 1)"
      agent_group="$(sed -n 's/^Group=//p' "${unit}" | head -n 1)"
    fi
    [[ "${agent_user}" =~ ^[A-Za-z_][A-Za-z0-9_.-]*$ ]] || agent_user="easypi-mobile-link"
    [[ "${agent_group}" =~ ^[A-Za-z_][A-Za-z0-9_.-]*$ ]] || agent_group="easypi-mobile-link"
    staged="$(mktemp "/etc/systemd/system/.${name}.XXXXXX")"
    install -o root -g root -m 0644 "${template}" "${staged}"
    sed -i "s|/opt/EasyPi|${TARGET_DIR}|g" "${staged}"
    sed -i "s|User=easypi-mobile-link|User=${agent_user}|g" "${staged}"
    sed -i "s|Group=easypi-mobile-link|Group=${agent_group}|g" "${staged}"
    mv -f -- "${staged}" "${unit}"
  done

  if [[ -x "${TARGET_DIR}/chameleon/bin/chameleon-server-arm64" ]]; then
    install -o root -g root -m 0755 \
      "${TARGET_DIR}/chameleon/bin/chameleon-server-arm64" \
      "${TARGET_DIR}/bin/chameleon-server-home"
  fi
}

refresh_taildrop_unit() {
  local name="easypi-taildrop-import.service"
  local template="${TARGET_DIR}/templates/systemd/${name}"
  local unit="/etc/systemd/system/${name}"
  local owner="" group="" staged=""

  # The importer runs as root, so how its unit passes application settings is a
  # privilege boundary. Keep an installed unit in sync with the release
  # template; the importer script and the template always ship together, also
  # when a rollback restores the previous tree. A removed unit is not recreated.
  [[ -f "${template}" && ! -L "${template}" ]] || return 0
  [[ -f "${unit}" && ! -L "${unit}" ]] || return 0
  owner="$(sed -n 's/^ExecStart=.* --owner \([^ ]*\).*/\1/p' "${unit}" | head -n 1)"
  group="$(sed -n 's/^ExecStart=.* --group \([^ ]*\).*/\1/p' "${unit}" | head -n 1)"
  [[ "${owner}" =~ ^[A-Za-z_][A-Za-z0-9_.-]*$ ]] || owner="easypi"
  [[ "${group}" =~ ^[A-Za-z_][A-Za-z0-9_.-]*$ ]] || group="easypi"
  # A rollback runs with errexit suspended, so every step is checked here: a
  # failed render must never replace the installed unit.
  staged="$(mktemp "/etc/systemd/system/.${name}.XXXXXX")" || return 1
  if ! install -o root -g root -m 0644 "${template}" "${staged}" \
      || ! sed -i "s|/opt/EasyPi|${TARGET_DIR}|g" "${staged}" \
      || ! sed -i "s|--owner easypi|--owner ${owner}|g" "${staged}" \
      || ! sed -i "s|--group easypi|--group ${group}|g" "${staged}" \
      || ! grep -q '^ExecStart=' "${staged}" \
      || ! mv -f -- "${staged}" "${unit}"; then
    rm -f -- "${staged}"
    warn "Could not refresh ${name}; the installed unit was kept"
    return 1
  fi
}

refresh_nginx_site() {
  local template="${TARGET_DIR}/templates/nginx/easypi.conf"
  local site="/etc/nginx/sites-available/easypi"
  local rendered="" previous=""

  # The installed site is a verbatim render of its release template; no EasyPi
  # script edits it afterwards. Its request-size and authentication gates are
  # security boundaries that must reach installations updated without the full
  # installer. Only an existing regular file is replaced, and only by a
  # configuration that nginx accepts; otherwise the previous one stays active.
  [[ -f "${template}" && ! -L "${template}" ]] || return 0
  [[ -f "${site}" && ! -L "${site}" ]] || return 0
  command -v nginx >/dev/null 2>&1 || return 0

  # Callers test this function's status, which suspends errexit inside it, so
  # every step is checked here: a failed render must never replace the site.
  rendered="$(mktemp /etc/nginx/sites-available/.easypi.XXXXXX)" || return 1
  if ! install -o root -g root -m 0644 "${template}" "${rendered}" \
      || ! sed -i "s|/opt/EasyPi|${TARGET_DIR}|g" "${rendered}" \
      || [[ ! -s "${rendered}" ]]; then
    rm -f -- "${rendered}"
    return 1
  fi
  if cmp -s -- "${rendered}" "${site}"; then
    rm -f -- "${rendered}"
    return 0
  fi
  previous="$(mktemp /etc/nginx/sites-available/.easypi-previous.XXXXXX)" \
    && cp -a -- "${site}" "${previous}" \
    || { rm -f -- "${rendered}" "${previous}"; return 1; }
  if ! mv -f -- "${rendered}" "${site}" || ! nginx -t >/dev/null 2>&1; then
    mv -f -- "${previous}" "${site}"
    rm -f -- "${rendered}"
    warn "The release nginx configuration failed validation; the previous one was kept"
    return 1
  fi
  rm -f -- "${previous}"
}

restart_enabled_mobile_link_agent() {
  if systemctl is-enabled --quiet easypi-mobile-link-agent.service 2>/dev/null; then
    systemctl reset-failed easypi-mobile-link-agent.service 2>/dev/null || true
    systemctl restart easypi-mobile-link-agent.service 2>/dev/null \
      || warn "Failed to restart easypi-mobile-link-agent"
    if [[ -s /etc/easypi-mobile-link/tunnel-agent.json && -s /etc/easypi-mobile-home/server_config.json ]]; then
      "${TARGET_DIR}/scripts/settings/mobile_link_agent.sh" ensure-home >/dev/null \
        || warn "Failed to restore the configured Mobile Home Tunnel"
      restart_enabled_mobile_home_tunnel
    fi
  fi
}

restart_enabled_mobile_home_tunnel() {
  local svc=""
  # ensure-home only enables and starts the units. An already running process
  # would keep executing the replaced binary, so restart it explicitly here,
  # and only here: per-phone enrolment must never interrupt connected phones.
  for svc in easypi-mobile-home-tunnel.service easypi-mobile-home-tunnel-agent.service; do
    systemctl is-enabled --quiet "${svc}" 2>/dev/null || continue
    systemctl reset-failed "${svc}" 2>/dev/null || true
    systemctl restart "${svc}" 2>/dev/null || warn "Failed to restart ${svc}"
  done
}

restart_services() {
  "${TARGET_DIR}/scripts/settings/mobile_link_agent.sh" ensure-endpoint >/dev/null \
    || die "Could not install the private Mobile Link nginx endpoint"
  refresh_nginx_site \
    || die "Could not install the EasyPi nginx site configuration"
  refresh_mobile_link_units
  refresh_taildrop_unit
  systemctl daemon-reload || true
  for svc in easypi-stealth-guard easypi-stealth-dns easypi-stealth-resume easypi-netprotection easypi-dhcp-observer easypi-taildrop-import nginx easypi-backend; do
    if systemctl list-unit-files "${svc}.service" --no-legend 2>/dev/null | grep -q "${svc}.service"; then
      # Clear any crash-loop start-limit first, or systemd refuses to start the
      # (now rolled-back / fixed) service and the recovery would look "unhealthy".
      systemctl reset-failed "${svc}" 2>/dev/null || true
      systemctl restart "${svc}" 2>/dev/null || warn "Failed to restart ${svc}"
    fi
  done
  # Older installed units used Requires= and stop with the backend. Restore an
  # enabled agent after every update; never start one that was not configured.
  restart_enabled_mobile_link_agent
}

trusted_snapshot_dir() {
  local snap="$1" root_real="" snap_real="" component="" owner="" mode="" db_kind=""

  [[ "${snap}" == /* && -d "${snap}" && ! -L "${snap}" ]] || return 1
  [[ "${snap##*/}" =~ ^[0-9]{8}-[0-9]{6}([.][A-Za-z0-9]{6})?$ ]] || return 1
  root_real="$(realpath -e -- "${BACKUPS_ROOT}")" || return 1
  snap_real="$(realpath -e -- "${snap}")" || return 1
  [[ "$(realpath -sm -- "${snap}")" == "${snap_real}" ]] || return 1
  [[ "${snap_real%/*}" == "${root_real}" ]] || return 1

  for component in "${root_real}" "${snap_real}" "${snap_real}/tree" "${snap_real}/db"; do
    [[ -d "${component}" && ! -L "${component}" ]] || return 1
    owner="$(stat -c '%u' -- "${component}")" || return 1
    mode="$(stat -c '%a' -- "${component}")" || return 1
    [[ "${owner}" == "0" && $((8#${mode} & 8#022)) -eq 0 ]] || return 1
  done
  [[ -f "${snap_real}/database-kind" && ! -L "${snap_real}/database-kind" ]] || return 1
  owner="$(stat -c '%u' -- "${snap_real}/database-kind")" || return 1
  mode="$(stat -c '%a' -- "${snap_real}/database-kind")" || return 1
  [[ "${owner}" == "0" && $((8#${mode} & 8#077)) -eq 0 ]] || return 1
  db_kind="$(cat "${snap_real}/database-kind")" || return 1
  case "${db_kind}" in
    postgresql)
      [[ -f "${snap_real}/postgresql.dump" && ! -L "${snap_real}/postgresql.dump" ]] \
        || return 1
      owner="$(stat -c '%u' -- "${snap_real}/postgresql.dump")" || return 1
      mode="$(stat -c '%a' -- "${snap_real}/postgresql.dump")" || return 1
      [[ "${owner}" == "0" && $((8#${mode} & 8#077)) -eq 0 ]] || return 1
      ;;
    sqlite|missing)
      [[ ! -e "${snap_real}/postgresql.dump" && ! -L "${snap_real}/postgresql.dump" ]] \
        || return 1
      ;;
    *) return 1;;
  esac
  if [[ -e "${snap_real}/.env" || -L "${snap_real}/.env" ]]; then
    [[ -f "${snap_real}/.env" && ! -L "${snap_real}/.env" ]] || return 1
    owner="$(stat -c '%u' -- "${snap_real}/.env")" || return 1
    mode="$(stat -c '%a' -- "${snap_real}/.env")" || return 1
    [[ "${owner}" == "0" && $((8#${mode} & 8#077)) -eq 0 ]] || return 1
  fi
}

# --- restore a snapshot (code tree + databases) and bring services back ---
rollback_from() {
  local snap="$1" reason="$2"
  local restore_failed=0 db_kind=""
  warn "ROLLBACK (${reason})"
  if ! trusted_snapshot_dir "${snap}"; then
    warn "Snapshot is missing or failed ownership/path validation: ${snap}"
    return 1
  fi
  systemctl stop easypi-backend 2>/dev/null || true
  BACKEND_STOPPED_FOR_UPDATE=1
  rsync -a --delete "${RSYNC_EXCLUDES[@]}" "${snap}/tree/" "${TARGET_DIR}/" \
    || restore_failed=1
  if [[ -d "${snap}/db" ]]; then
    mkdir -p "${TARGET_DIR}/data/db"
    # Restore the database directory exactly. Leaving migration-created files
    # behind can make otherwise successful code rollback fail on next start.
    rsync -a --delete "${snap}/db/" "${TARGET_DIR}/data/db/" \
      || restore_failed=1
  fi
  if [[ -f "${snap}/.env" && ! -L "${snap}/.env" ]]; then
    cp -a -- "${snap}/.env" "${TARGET_DIR}/.env" || restore_failed=1
  fi
  secure_target_permissions || restore_failed=1
  db_kind="$(cat "${snap}/database-kind")" || restore_failed=1
  if [[ "${db_kind}" == "sqlite" || "${db_kind}" == "missing" ]]; then
    secure_sqlite_runtime || restore_failed=1
  fi
  if [[ "${db_kind}" == "postgresql" && "${restore_failed}" -eq 0 ]]; then
    "${TARGET_DIR}/backend/.venv/bin/python" "${POSTGRES_HELPER}" \
      restore "${snap}/postgresql.dump" || restore_failed=1
  fi
  if (( restore_failed != 0 )); then
    warn "Rollback state could not be restored completely; services remain stopped"
    return 1
  fi
  restart_services
  BACKEND_STOPPED_FOR_UPDATE=0
  (( restore_failed == 0 ))
}

# ============================================================================
# RECOVER MODE: run at boot by easypi-update-recovery.service when a marker is
# present (an update was interrupted, e.g. by a power cut). Finish the rollback.
# ============================================================================
if [[ "${1:-}" == "--recover" ]]; then
  if [[ ! -f "${MARKER}" ]]; then
    echo "No interrupted update to recover."
    exit 0
  fi
  snap="$(cat "${MARKER}" 2>/dev/null || true)"
  if [[ -n "${snap}" && -d "${snap}/tree" ]]; then
    if rollback_from "${snap}" "interrupted update (reboot)"; then
      rm -f "${MARKER}"
      if health_ok; then info "Recovered the previous working version."; else warn "Recovered, but health check is still failing."; fi
    else
      warn "Rollback was incomplete; retaining the update marker for manual or boot-time recovery."
      exit 1
    fi
  else
    rm -f "${MARKER}"
    warn "Update marker found but its snapshot is missing; nothing to restore."
  fi
  exit 0
fi

# --- environment sanity (normal update run) ---
for c in openssl curl tar rsync sha256sum python3 du df awk flock; do
  command -v "$c" >/dev/null 2>&1 || die "Required command not found: $c"
done
[[ -f "${PUBKEY}" && ! -L "${PUBKEY}" ]] || die "Signing public key missing or unsafe: ${PUBKEY}"
PUBKEY_UID="$(stat -c '%u' -- "${PUBKEY}")"
PUBKEY_MODE="$(stat -c '%a' -- "${PUBKEY}")"
[[ "${PUBKEY_UID}" == "0" && $((8#${PUBKEY_MODE} & 8#022)) -eq 0 ]] \
  || die "Signing public key must be root-owned and not writable outside root"
[[ -f "${URL_GUARD}" && ! -L "${URL_GUARD}" ]] \
  || die "Update URL guard missing or unsafe: ${URL_GUARD}"
URL_GUARD_UID="$(stat -c '%u' -- "${URL_GUARD}")"
URL_GUARD_MODE="$(stat -c '%a' -- "${URL_GUARD}")"
[[ "${URL_GUARD_UID}" == "0" && $((8#${URL_GUARD_MODE} & 8#022)) -eq 0 ]] \
  || die "Update URL guard must be root-owned and not writable outside root"
[[ -f "${ARCHIVE_VALIDATOR}" && ! -L "${ARCHIVE_VALIDATOR}" ]] \
  || die "Release archive validator missing or unsafe: ${ARCHIVE_VALIDATOR}"
ARCHIVE_VALIDATOR_UID="$(stat -c '%u' -- "${ARCHIVE_VALIDATOR}")"
ARCHIVE_VALIDATOR_MODE="$(stat -c '%a' -- "${ARCHIVE_VALIDATOR}")"
[[ "${ARCHIVE_VALIDATOR_UID}" == "0" && $((8#${ARCHIVE_VALIDATOR_MODE} & 8#022)) -eq 0 ]] \
  || die "Release archive validator must be root-owned and not writable outside root"
[[ -f "${POSTGRES_HELPER}" && ! -L "${POSTGRES_HELPER}" ]] \
  || die "PostgreSQL backup helper missing or unsafe: ${POSTGRES_HELPER}"
POSTGRES_HELPER_UID="$(stat -c '%u' -- "${POSTGRES_HELPER}")"
POSTGRES_HELPER_MODE="$(stat -c '%a' -- "${POSTGRES_HELPER}")"
[[ "${POSTGRES_HELPER_UID}" == "0" && $((8#${POSTGRES_HELPER_MODE} & 8#022)) -eq 0 ]] \
  || die "PostgreSQL backup helper must be root-owned and not writable outside root"

MODE=""; URL=""; ARCHIVE_IN=""; SIG_IN=""; SHA256=""
RUN_INSTALL=0; DELETE_OBSOLETE=0; SKIP_RESTART=0; DRY_RUN=0; ALLOW_DOWNGRADE=0
while [[ $# -gt 0 ]]; do
  case "$1" in
    --mode) MODE="${2:-}"; shift 2;;
    --url) URL="${2:-}"; shift 2;;
    --archive) ARCHIVE_IN="${2:-}"; shift 2;;
    --sig) SIG_IN="${2:-}"; shift 2;;
    --sha256) SHA256="${2:-}"; shift 2;;
    --run-install) RUN_INSTALL=1; shift;;
    --delete-obsolete) DELETE_OBSOLETE=1; shift;;
    --skip-restart) SKIP_RESTART=1; shift;;
    --dry-run) DRY_RUN=1; shift;;
    --allow-downgrade) ALLOW_DOWNGRADE=1; shift;;
    *) die "Unknown argument: $1";;
  esac
done

WORK="$(mktemp -d /tmp/easypi-signed-update.XXXXXX)"; chmod 700 "${WORK}"
ARCHIVE="${WORK}/release.tar.gz"
SIG="${WORK}/release.sig"

# EXIT trap: clean temp files; and if we failed AFTER committing to the apply
# (marker present, not yet marked OK), roll the system back to the snapshot.
UPDATE_OK=0
cleanup() {
  local rc=$?
  set +e
  if [[ "${UPDATE_OK}" -ne 1 && -f "${MARKER}" ]]; then
    local snap; snap="$(cat "${MARKER}" 2>/dev/null || true)"
    if [[ -n "${snap}" && -d "${snap}/tree" ]]; then
      if rollback_from "${snap}" "update failed (rc=${rc})"; then
        rm -f "${MARKER}"
        if health_ok; then
          warn "Rolled back to the previous working version — it is healthy."
        else
          warn "Rolled back, but the backend is still unhealthy — manual attention needed."
        fi
      else
        warn "Rollback was incomplete; the update marker was retained for recovery."
      fi
    fi
  elif [[ "${BACKEND_STOPPED_FOR_UPDATE}" -eq 1 ]]; then
    # A failure before the commit marker must not leave the previously working
    # backend stopped merely because no rollback was necessary yet.
    restart_services
    BACKEND_STOPPED_FOR_UPDATE=0
  fi
  rm -rf "${WORK}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

safe_https_download() {
  local url="$1" destination="$2" timeout="$3" max_bytes="$4"
  local current_url="${url}"
  local validation normalized_url host port address resolve_address
  local headers body http_code next_url
  local hop=0
  local -a parts=()

  while (( hop <= 5 )); do
    validation="$(python3 "${URL_GUARD}" resolve "${current_url}")" \
      || die "Update URL must resolve only to public HTTPS addresses"
    mapfile -t parts <<<"${validation}"
    [[ "${#parts[@]}" -eq 4 ]] || die "Could not validate update URL"
    normalized_url="${parts[0]}"
    host="${parts[1]}"
    port="${parts[2]}"
    address="${parts[3]}"
    resolve_address="${address}"
    [[ "${address}" == *:* ]] && resolve_address="[${address}]"

    headers="${WORK}/download-${hop}.headers"
    body="${WORK}/download-${hop}.body"
    : > "${headers}"
    http_code="$(curl --disable --silent --show-error \
      --proto '=https' --tlsv1.2 --connect-timeout 10 --max-time "${timeout}" \
      --retry 3 --retry-all-errors --noproxy '*' --max-filesize "${max_bytes}" \
      --resolve "${host}:${port}:${resolve_address}" \
      --dump-header "${headers}" --output "${body}" \
      --write-out '%{http_code}' "${normalized_url}")" \
      || die "HTTPS update download failed"

    case "${http_code}" in
      200)
        [[ -f "${body}" && ! -L "${body}" ]] || die "Downloaded file is missing"
        mv -f -- "${body}" "${destination}"
        return 0
        ;;
      301|302|303|307|308)
        (( hop < 5 )) || die "HTTPS update redirect limit exceeded"
        next_url="$(python3 "${URL_GUARD}" redirect "${normalized_url}" "${headers}")" \
          || die "Unsafe HTTPS update redirect"
        rm -f -- "${body}" "${headers}"
        current_url="${next_url}"
        ((hop += 1))
        ;;
      *)
        die "HTTPS update download returned HTTP ${http_code}"
        ;;
    esac
  done

  die "HTTPS update redirect limit exceeded"
}

# --- Resolve archive ---
case "${MODE}" in
  url)
    [[ -n "${URL}" ]] || die "--url required for url mode"
    [[ "${URL}" =~ ^https:// ]] || die "Only HTTPS update URLs are allowed"
    info "Downloading archive..."
    safe_https_download "${URL}" "${ARCHIVE}" 1800 4294967296 || die "Archive download failed"
    ;;
  archive)
    [[ -n "${ARCHIVE_IN}" ]] || die "--archive required for archive mode"
    [[ -f "${ARCHIVE_IN}" && ! -L "${ARCHIVE_IN}" ]] \
      || die "Archive must be a regular, non-symlink file: ${ARCHIVE_IN}"
    cp -f "${ARCHIVE_IN}" "${ARCHIVE}"
    ;;
  *) die "--mode must be 'url' or 'archive'";;
esac

# --- Resolve detached signature (URL or local path) ---
[[ -n "${SIG_IN}" ]] || die "--sig (archive signature) is required"
if [[ "${SIG_IN}" =~ ^https:// ]]; then
  info "Downloading signature..."
  safe_https_download "${SIG_IN}" "${SIG}" 60 65536 || die "Signature download failed"
elif [[ -f "${SIG_IN}" && ! -L "${SIG_IN}" ]]; then
  cp -f "${SIG_IN}" "${SIG}"
else
  die "Signature not found: ${SIG_IN}"
fi
[[ "$(stat -c '%s' -- "${ARCHIVE}")" -le 4294967296 ]] \
  || die "Release archive exceeds the 4 GiB compressed-size limit"
[[ "$(stat -c '%s' -- "${SIG}")" -le 65536 ]] \
  || die "Release signature exceeds the 64 KiB size limit"

# --- Optional sha256 (defence in depth; the signature is the real gate) ---
if [[ -n "${SHA256}" ]]; then
  [[ "${SHA256}" =~ ^[A-Fa-f0-9]{64}$ ]] || die "Invalid --sha256"
  actual="$(sha256sum "${ARCHIVE}" | awk '{print $1}')"
  [[ "${actual}" == "${SHA256,,}" ]] || die "SHA-256 mismatch (expected ${SHA256,,}, got ${actual})"
  info "SHA-256 OK"
fi

# --- SECURITY GATE: signature must verify against the baked-in public key ---
info "Verifying release signature..."
openssl dgst -sha256 -verify "${PUBKEY}" -signature "${SIG}" "${ARCHIVE}" >/dev/null 2>&1 \
  || die "SIGNATURE VERIFICATION FAILED — update rejected"
info "Signature verified."

# A valid publisher signature authenticates the bytes; the validator separately
# enforces the release layout, compatibility metadata, safe tar paths, and the
# complete per-file manifest before tar or rsync consumes any archive content.
info "Validating signed release contents and manifest..."
python3 "${ARCHIVE_VALIDATOR}" "${ARCHIVE}" \
  --expected-arch aarch64 --expected-codename trixie \
  || die "SIGNED RELEASE CONTENT VALIDATION FAILED — update rejected"

# --- Extract the validated archive ---
EXTRACT="${WORK}/extract"; mkdir -p "${EXTRACT}"
tar --extract --gzip --file "${ARCHIVE}" --directory "${EXTRACT}" \
  --no-same-owner --no-same-permissions --delay-directory-restore \
  || die "Extraction failed"
PAYLOAD=""
if [[ -f "${EXTRACT}/install.sh" ]]; then
  PAYLOAD="${EXTRACT}"
else
  for d in "${EXTRACT}"/*/; do
    [[ -f "${d}install.sh" ]] && PAYLOAD="${d%/}" && break
  done
fi
[[ -n "${PAYLOAD}" && -f "${PAYLOAD}/install.sh" ]] || die "Invalid archive: install.sh not found"
info "Payload root: ${PAYLOAD}"

# Tar extraction runs with a restrictive umask and never trusts archive mode
# bits. Normalize the signed, validated payload explicitly so rsync cannot make
# the easypi service lose read/execute access or introduce setuid/setgid files.
find "${PAYLOAD}" -type d -exec chmod 0755 {} +
find "${PAYLOAD}" -type f -exec chmod 0644 {} +
chmod 0755 "${PAYLOAD}/install.sh" "${PAYLOAD}/uninstall.sh" \
  "${PAYLOAD}/backend/bin/easypi-backend"
find "${PAYLOAD}/scripts" -type f -name '*.sh' -exec chmod 0755 {} +
chmod 0750 "${PAYLOAD}/scripts/runner"

# --- Downgrade guard (before anything is applied -> always safe) ---
get_ver() {
  # Single source of truth: repo-root VERSION. Fall back to frontend/package.json
  # for archives that predate the VERSION file.
  if [[ -s "$1/VERSION" ]]; then
    tr -d '[:space:]' < "$1/VERSION"
  else
    grep -m1 '"version"' "$1/frontend/package.json" 2>/dev/null | sed -E 's/.*"version"[[:space:]]*:[[:space:]]*"([^"]+)".*/\1/'
  fi
}

# Hash only reviewed Chameleon source inputs. Generated binaries and build
# caches are deliberately excluded: they are outputs of install.sh, not signed
# release inputs. A content digest keeps normal application-only updates fast
# while ensuring a transport change can never leave an old client installed.
chameleon_source_digest() {
  python3 - "$1" <<'PY'
import hashlib
import os
import stat
import sys

root = os.path.abspath(sys.argv[1])
if not os.path.isdir(root) or os.path.islink(root):
    print("missing-or-unsafe")
    raise SystemExit(0)

digest = hashlib.sha256()
for current, directories, filenames in os.walk(root, topdown=True, followlinks=False):
    relative_directory = os.path.relpath(current, root)
    if relative_directory == ".":
        directories[:] = [
            name for name in directories if name not in {"bin", ".build"}
        ]
    directories.sort()
    filenames.sort()

    for name in directories:
        path = os.path.join(current, name)
        if os.path.islink(path):
            print("missing-or-unsafe")
            raise SystemExit(0)

    for name in filenames:
        path = os.path.join(current, name)
        metadata = os.lstat(path)
        if not stat.S_ISREG(metadata.st_mode):
            print("missing-or-unsafe")
            raise SystemExit(0)
        relative_path = os.path.relpath(path, root).replace(os.sep, "/")
        digest.update(relative_path.encode("utf-8"))
        digest.update(b"\0")
        with open(path, "rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)

print(digest.hexdigest())
PY
}

CUR_VER="$(get_ver "${TARGET_DIR}" || true)"
NEW_VER="$(get_ver "${PAYLOAD}" || true)"
if [[ -n "${CUR_VER}" && -n "${NEW_VER}" && "${ALLOW_DOWNGRADE}" -eq 0 && "${NEW_VER}" != "${CUR_VER}" ]]; then
  LOWEST="$(printf '%s\n%s\n' "${CUR_VER}" "${NEW_VER}" | sort -V | head -1)"
  [[ "${LOWEST}" == "${NEW_VER}" ]] \
    && die "Refusing downgrade: installed ${CUR_VER} -> release ${NEW_VER} (use --allow-downgrade to force)"
fi
[[ -n "${NEW_VER}" ]] && info "Release version: ${NEW_VER} (installed: ${CUR_VER:-unknown})"

PAYLOAD_CHAMELEON_DIGEST="$(chameleon_source_digest "${PAYLOAD}/chameleon")"
[[ "${PAYLOAD_CHAMELEON_DIGEST}" =~ ^[a-f0-9]{64}$ ]] \
  || die "Signed release contains missing or unsafe Chameleon sources"
INSTALLED_CHAMELEON_DIGEST="$(chameleon_source_digest "${TARGET_DIR}/chameleon")"
if [[ "${PAYLOAD_CHAMELEON_DIGEST}" != "${INSTALLED_CHAMELEON_DIGEST}" ]]; then
  RUN_INSTALL=1
  info "Chameleon sources changed; the transport binaries will be rebuilt automatically."
fi

# --- Dry run: preview the file changes and stop (no snapshot, no apply) ---
if [[ "${DRY_RUN}" -eq 1 ]]; then
  info "Dry-run: previewing changes (nothing will be written)..."
  RSYNC_ARGS=(-a --dry-run --itemize-changes "${APPLY_EXCLUDES[@]}")
  [[ "${DELETE_OBSOLETE}" -eq 1 ]] && RSYNC_ARGS+=(--delete)
  rsync "${RSYNC_ARGS[@]}" "${PAYLOAD}/" "${TARGET_DIR}/" || true
  info "Dry-run completed."
  UPDATE_OK=1
  exit 0
fi

# --- Free-space pre-check: need room for the snapshot + the new files + margin ---
SNAP_NEED="$(du -sb --exclude=data --exclude=.venv --exclude=node_modules --exclude=.build --exclude=.update-backups --exclude=backups "${TARGET_DIR}" 2>/dev/null | awk '{print $1}')"
PAYLOAD_NEED="$(du -sb "${PAYLOAD}" 2>/dev/null | awk '{print $1}')"
AVAIL="$(df -B1 --output=avail "${TARGET_DIR}" 2>/dev/null | tail -1 | tr -d ' ')"
MARGIN=$((512 * 1024 * 1024))
NEED=$(( ${SNAP_NEED:-0} + ${PAYLOAD_NEED:-0} + MARGIN ))
if [[ -n "${AVAIL}" && "${AVAIL}" -lt "${NEED}" ]]; then
  die "Not enough free disk space: need ~$((NEED / 1024 / 1024)) MB, have $((AVAIL / 1024 / 1024)) MB"
fi

# --- SNAPSHOT the current version (code tree + databases) = known-good ---
install -d -o root -g root -m 0700 "${BACKUPS_ROOT}"
[[ ! -L "${BACKUPS_ROOT}" ]] || die "Update backup root must not be a symbolic link"
BACKUPS_ROOT_UID="$(stat -c '%u' -- "${BACKUPS_ROOT}")"
BACKUPS_ROOT_MODE="$(stat -c '%a' -- "${BACKUPS_ROOT}")"
[[ "${BACKUPS_ROOT_UID}" == "0" && $((8#${BACKUPS_ROOT_MODE} & 8#022)) -eq 0 ]] \
  || die "Update backup root must be root-owned and not writable outside root"
SNAP="$(mktemp -d "${BACKUPS_ROOT}/$(date +%Y%m%d-%H%M%S).XXXXXX")"
chown root:root "${SNAP}"
chmod 0700 "${SNAP}"
install -d -o root -g root -m 0700 "${SNAP}/tree" "${SNAP}/db"
info "Snapshotting current version for rollback -> ${SNAP}"
rsync -a "${RSYNC_EXCLUDES[@]}" "${TARGET_DIR}/" "${SNAP}/tree/" || die "Snapshot failed (nothing applied)"
# rsync -a copies the installation root metadata onto the destination root.
# Restore the root-only snapshot boundary before it can become authoritative.
chown root:root "${SNAP}" "${SNAP}/tree" "${SNAP}/db"
chmod 0700 "${SNAP}" "${SNAP}/tree" "${SNAP}/db"
DB_KIND="$("${TARGET_DIR}/backend/.venv/bin/python" "${POSTGRES_HELPER}" kind)"
case "${DB_KIND}" in
  postgresql|sqlite|missing) ;;
  *) die "Configured database type cannot be snapshotted safely";;
esac
printf '%s\n' "${DB_KIND}" > "${SNAP}/database-kind"
chown root:root "${SNAP}/database-kind"
chmod 0600 "${SNAP}/database-kind"
# The updater runs in its own root-owned systemd unit, so stopping the backend
# cannot terminate this process. Quiesce it before copying SQLite files and
# keep it stopped until the new version (or rollback) is ready to start.
if systemctl list-unit-files easypi-backend.service --no-legend 2>/dev/null \
    | grep -q 'easypi-backend.service'; then
  BACKEND_STOPPED_FOR_UPDATE=1
  systemctl stop easypi-backend.service \
    || die "Could not stop the backend for a consistent database snapshot"
fi
if [[ -d "${TARGET_DIR}/data/db" ]]; then
  rsync -a --delete --exclude 'easypi-postgresql.dump' \
    "${TARGET_DIR}/data/db/" "${SNAP}/db/" \
    || die "Database snapshot failed (nothing applied)"
fi
# The live SQLite directory is service-owned. Snapshot contents must instead be
# immutable to that account; rollback restores the required runtime ownership.
chown -R root:root "${SNAP}/db"
find "${SNAP}/db" -type d -exec chmod 0700 {} +
find "${SNAP}/db" -type f -exec chmod 0600 {} +
if [[ "${DB_KIND}" == "postgresql" ]]; then
  "${TARGET_DIR}/backend/.venv/bin/python" "${POSTGRES_HELPER}" \
    dump "${SNAP}/postgresql.dump" \
    || die "PostgreSQL snapshot failed (nothing applied)"
fi
# prune old snapshots (keep the most recent KEEP_SNAPSHOTS)
if [[ -d "${BACKUPS_ROOT}" ]]; then
  # shellcheck disable=SC2012
  ls -1dt "${BACKUPS_ROOT}"/*/ 2>/dev/null | tail -n +$((KEEP_SNAPSHOTS + 1)) | xargs -r rm -rf || true
fi

# --- Commit point: mark the apply in progress (drives reboot recovery + trap) ---
printf '%s\n' "${SNAP}" > "${MARKER}"
chmod 0600 "${MARKER}"

# --- Also back up the protected user-config files (belt and braces) ---
if [[ -f "${TARGET_DIR}/.env" && ! -L "${TARGET_DIR}/.env" ]]; then
  cp -a "${TARGET_DIR}/.env" "${SNAP}/.env" \
    || die "Environment snapshot failed — rolling back"
  chown root:root "${SNAP}/.env"
  chmod 0600 "${SNAP}/.env"
fi
if [[ -f "${TARGET_DIR}/config/netprotection.toml" ]]; then
  mkdir -p "${SNAP}/config"; cp -a "${TARGET_DIR}/config/netprotection.toml" "${SNAP}/config/netprotection.toml"
fi

# --- Apply the new files (any failure here triggers the rollback trap) ---
RSYNC_ARGS=(-a --chown=root:easypi --chmod=go-w "${APPLY_EXCLUDES[@]}")
[[ "${DELETE_OBSOLETE}" -eq 1 ]] && RSYNC_ARGS+=(--delete)
info "Applying update files..."
rsync "${RSYNC_ARGS[@]}" "${PAYLOAD}/" "${TARGET_DIR}/"
secure_target_permissions

# Never let an update change the protected files even if they slipped into a release.
[[ -f "${SNAP}/.env" ]] && cp -a "${SNAP}/.env" "${TARGET_DIR}/.env" || true
if [[ -f "${SNAP}/config/netprotection.toml" ]]; then
  mkdir -p "${TARGET_DIR}/config"; cp -a "${SNAP}/config/netprotection.toml" "${TARGET_DIR}/config/netprotection.toml"
fi

# --- Fix exec bits and RE-LOCK the privileged script tree to root ---
[[ -f "${TARGET_DIR}/install.sh" ]] && chmod +x "${TARGET_DIR}/install.sh" || true
[[ -f "${TARGET_DIR}/uninstall.sh" ]] && chmod +x "${TARGET_DIR}/uninstall.sh" || true
find "${TARGET_DIR}/scripts" -type f -name "*.sh" -exec chmod +x {} \; 2>/dev/null || true
[[ -f "${TARGET_DIR}/scripts/runner" ]] && chmod +x "${TARGET_DIR}/scripts/runner" || true
chown -R root:easypi "${TARGET_DIR}/scripts" 2>/dev/null || true
chmod 0750 "${TARGET_DIR}/scripts" 2>/dev/null || true
secure_target_permissions

# --- Installer when requested or required by a Chameleon source change.
# Run the TRUSTED extracted copy. FATAL -> rollback. ---
if [[ "${RUN_INSTALL}" -eq 1 ]]; then
  info "Running install.sh --binary ..."
  ( cd "${PAYLOAD}" && bash "${PAYLOAD}/install.sh" --binary ) \
    || die "install.sh failed — rolling back"
fi

# --- Restart services and HEALTH-GATE the result ---
if [[ "${SKIP_RESTART}" -eq 0 ]]; then
  info "Restarting services..."
  restart_services
  BACKEND_STOPPED_FOR_UPDATE=0
  info "Verifying the application, DNS and protected network path..."
  health_ok || die "EasyPi runtime did not become healthy after the update — rolling back"
elif [[ "${BACKEND_STOPPED_FOR_UPDATE}" -eq 1 ]]; then
  # Even an explicitly staged/no-health-check update may not leave the service
  # down after it was quiesced for the database snapshot.
  systemctl start easypi-backend.service \
    || die "Could not restart the backend after the update"
  # --skip-restart suppresses the broad service cycle, not recovery of a
  # configured agent that an older Requires= unit stopped with the backend.
  # The nginx site is refreshed only together with the nginx restart in
  # restart_services, never left staged but unloaded.
  refresh_mobile_link_units
  refresh_taildrop_unit
  systemctl daemon-reload || true
  restart_enabled_mobile_link_agent
  BACKEND_STOPPED_FOR_UPDATE=0
fi

# --- Success: clear the marker so the trap does NOT roll back ---
UPDATE_OK=1
rm -f "${MARKER}"
info "Update completed successfully."
