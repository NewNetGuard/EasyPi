#!/usr/bin/env bash
set -euo pipefail

info() { echo "[netprotection-maintenance] $1"; }
warn() { echo "[netprotection-maintenance][warn] $1"; }

EASYPI_PREFIX="${EASYPI_PREFIX:-/opt/EasyPi}"
DATA_DIR="${EASYPI_PREFIX}/data/netprotection"

SIGNALS_RETENTION_DAYS="${SIGNALS_RETENTION_DAYS:-90}"
FIRST_SEEN_RETENTION_DAYS="${FIRST_SEEN_RETENTION_DAYS:-90}"
SHADOW_HISTORY_RETENTION_DAYS="${SHADOW_HISTORY_RETENTION_DAYS:-90}"
SHADOW_EXPIRED_RETENTION_DAYS="${SHADOW_EXPIRED_RETENTION_DAYS:-30}"
ANOMALY_RETENTION_DAYS="${ANOMALY_RETENTION_DAYS:-30}"
DEVICE_BASELINE_RETENTION_DAYS="${DEVICE_BASELINE_RETENTION_DAYS:-90}"
FLOW_LOG_RETENTION_DAYS="${FLOW_LOG_RETENTION_DAYS:-30}"
SIGNAL_FILE_MAX_AGE_DAYS="${SIGNAL_FILE_MAX_AGE_DAYS:-2}"
AD_GENESIS_LOOKBACK_HOURS="${AD_GENESIS_LOOKBACK_HOURS:-24}"

if [[ ! -d "${DATA_DIR}" ]]; then
  warn "Data directory not found: ${DATA_DIR}"
  exit 0
fi

if ! command -v sqlite3 >/dev/null 2>&1; then
  warn "sqlite3 not installed, skipping maintenance"
  exit 0
fi

sqlite_exec() {
  local db_file="$1"
  local sql="$2"
  sqlite3 "${db_file}" <<SQL
PRAGMA busy_timeout = 5000;
PRAGMA foreign_keys = ON;
${sql}
SQL
}

checkpoint_wal() {
  local db_file="$1"
  sqlite3 "${db_file}" "PRAGMA busy_timeout = 5000; PRAGMA wal_checkpoint(TRUNCATE);" >/dev/null 2>&1 || true
}

cleanup_reload_signals() {
  local removed=0
  local signal
  for signal in ".lists_reload" ".profiles_reload" ".schedules_reload"; do
    if [[ -f "${DATA_DIR}/${signal}" ]]; then
      if find "${DATA_DIR}/${signal}" -mtime +"${SIGNAL_FILE_MAX_AGE_DAYS}" -print -quit | grep -q .; then
        rm -f "${DATA_DIR}/${signal}"
        removed=$((removed + 1))
      fi
    fi
  done
  info "Removed stale signal files: ${removed}"
}

cleanup_signals_db() {
  local db_file="${DATA_DIR}/signals.db"
  [[ -f "${db_file}" ]] || return 0

  sqlite_exec "${db_file}" "
DELETE FROM signals
WHERE timestamp < (strftime('%s','now') - (${SIGNALS_RETENTION_DAYS} * 86400));

DELETE FROM score_cache
WHERE computed_at < (strftime('%s','now') - (7 * 86400));
"

  checkpoint_wal "${db_file}"
  info "Cleaned signals.db"
}

cleanup_first_seen_db() {
  local db_file="${DATA_DIR}/first_seen.db"
  [[ -f "${db_file}" ]] || return 0

  sqlite_exec "${db_file}" "
DELETE FROM first_seen
WHERE last_seen < (strftime('%s','now') - (${FIRST_SEEN_RETENTION_DAYS} * 86400));
"

  checkpoint_wal "${db_file}"
  info "Cleaned first_seen.db"
}

cleanup_shadow_mode_db() {
  local db_file="${DATA_DIR}/shadow_mode.db"
  [[ -f "${db_file}" ]] || return 0

  sqlite_exec "${db_file}" "
DELETE FROM shadow_history
WHERE timestamp < (strftime('%s','now') - (${SHADOW_HISTORY_RETENTION_DAYS} * 86400));

DELETE FROM shadow_domains
WHERE action = 'expired'
  AND last_observed < (strftime('%s','now') - (${SHADOW_EXPIRED_RETENTION_DAYS} * 86400));
"

  checkpoint_wal "${db_file}"
  info "Cleaned shadow_mode.db"
}

cleanup_device_anomaly_db() {
  local db_file="${DATA_DIR}/device_anomaly.db"
  [[ -f "${db_file}" ]] || return 0

  sqlite_exec "${db_file}" "
DELETE FROM device_buckets
WHERE bucket_time < (strftime('%s','now') - (${ANOMALY_RETENTION_DAYS} * 86400));

DELETE FROM anomaly_log
WHERE timestamp < (strftime('%s','now') - (${ANOMALY_RETENTION_DAYS} * 86400));

DELETE FROM device_baselines
WHERE last_updated IS NOT NULL
  AND last_updated < (strftime('%s','now') - (${DEVICE_BASELINE_RETENTION_DAYS} * 86400));
"

  checkpoint_wal "${db_file}"
  info "Cleaned device_anomaly.db"
}

cleanup_flow_log_db() {
  local db_file="${DATA_DIR}/flow_log.db"
  [[ -f "${db_file}" ]] || return 0

  sqlite_exec "${db_file}" "
DELETE FROM flow_log
WHERE julianday(timestamp) < (julianday('now') - ${FLOW_LOG_RETENTION_DAYS});
"

  checkpoint_wal "${db_file}"
  info "Cleaned flow_log.db"
}

# NOTE: the Ad-Genesis behavioural ad-block set (DNS NAI + conntrack flow shape) is
# now rebuilt LIVE in the resolver process (user easypi) every ~80s via
# heuristics.causal_flow.runtime_build. It is deliberately NOT built from this root
# cron any more: doing so re-created ad_genesis_block.json as root, after which the
# easypi service could no longer overwrite it.

info "Starting NetProtection state maintenance in ${DATA_DIR}"

cleanup_reload_signals
cleanup_signals_db
cleanup_first_seen_db
cleanup_shadow_mode_db
cleanup_device_anomaly_db
cleanup_flow_log_db

info "NetProtection state maintenance completed"
