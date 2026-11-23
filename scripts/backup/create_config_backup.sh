#!/bin/bash
set -euo pipefail

# Config Snapshot Script
# Creates a "safe restore point": system config (/etc) plus the EasyPi state you
# would actually want to roll back. Unrelated host secrets are excluded, and
# the remaining sensitive state is authenticated, encrypted, and locked down.

BACKUP_DIR="/opt/EasyPi/backups"
TIMESTAMP=$(date +%Y-%m-%d-%H-%M-%S)
BACKUP_FILE="${BACKUP_DIR}/config-${TIMESTAMP}.epibak"
CRYPTO_PY="/opt/EasyPi/backend/.venv/bin/python"
CRYPTO_HELPER="/opt/EasyPi/scripts/utils/backup_crypto.py"
RESTORE_VALIDATOR="/opt/EasyPi/scripts/utils/secure_restore.py"
SNAPSHOT_HELPER="/opt/EasyPi/scripts/utils/backup_snapshot.py"
POSTGRES_HELPER="/opt/EasyPi/scripts/utils/postgres_backup.py"
POSTGRES_DUMP_REL="opt/EasyPi/data/db/easypi-postgresql.dump"
STEALTH_STATE_MARKER_REL="opt/EasyPi/data/netprotection/.stealth-state-v1"
VALIDATION_FILE=""
SNAPSHOT_DIR=""
BACKUP_COMPLETE=0

cleanup_backup_creation() {
    local rc=$?
    trap - EXIT
    [[ -z "$VALIDATION_FILE" ]] || rm -f -- "$VALIDATION_FILE"
    if [[ -n "$SNAPSHOT_DIR" && "$SNAPSHOT_DIR" == "$BACKUP_DIR"/.snapshot.* ]]; then
        rm -rf -- "$SNAPSHOT_DIR"
    fi
    if (( rc != 0 || BACKUP_COMPLETE == 0 )); then
        rm -f -- "$BACKUP_FILE"
    fi
    exit "$rc"
}

command -v flock >/dev/null 2>&1 || {
    echo "ERROR: flock is required for backup creation" >&2
    exit 69
}
exec 9>/run/easypi-backup.lock
if ! flock -n 9; then
    echo "ERROR: another EasyPi backup or restore operation is running" >&2
    exit 75
fi

# Ensure the backend can enumerate completed archives without making the
# directory or its contents accessible outside the EasyPi service group.
install -d -o root -g easypi -m 0750 "$BACKUP_DIR"
[[ ! -e "$BACKUP_FILE" && ! -L "$BACKUP_FILE" ]] || {
    echo "ERROR: backup name collision; retry in one second" >&2
    exit 1
}
trap cleanup_backup_creation EXIT

echo "Starting config snapshot..."
echo "Backup file: $BACKUP_FILE"

# Check available disk space (require at least 1GB free)
AVAILABLE_SPACE=$(df -BG "$BACKUP_DIR" | awk 'NR==2 {print $4}' | sed 's/G//')
if [ "$AVAILABLE_SPACE" -lt 1 ]; then
    echo "ERROR: Not enough disk space. At least 1GB required." >&2
    exit 1
fi

# Only EasyPi application state and the host identity files are included.
# Archiving all of /etc would expose unrelated service credentials to the
# backend through a download, and root-interpreted configuration (units, SSH,
# kernel parameters, nginx, unbound) is owned by the installer, not by backups.
TARGETS=()
for p in \
    /etc/hostname \
    /etc/hosts \
    /opt/EasyPi/.env \
    /opt/EasyPi/config \
    /opt/EasyPi/data/db \
    /opt/EasyPi/data/netprotection/allowlist.txt \
    /opt/EasyPi/data/netprotection/user_blocklist.txt \
    /opt/EasyPi/data/netprotection/blocklist_config.json \
    /opt/EasyPi/data/netprotection/stealth_meta.json \
    /opt/EasyPi/data/netprotection/stealth_client.conf \
    /opt/EasyPi/data/user/mobile_link.json \
    /var/lib/easypi/stealth-policy ; do
    if [ -e "$p" ]; then
        TARGETS+=("$p")
    fi
done

echo "Creating archive..."
SNAPSHOT_DIR="$(mktemp -d "${BACKUP_DIR}/.snapshot.XXXXXX")"
SNAPSHOT_ARGS=()
STAGED_TARGETS=()
for p in "${TARGETS[@]}"; do
    SNAPSHOT_ARGS+=(--source "$p")
    STAGED_TARGETS+=("${p#/}")
done
SNAPSHOT_ARGS+=(--exclude "/${POSTGRES_DUMP_REL}")
"$CRYPTO_PY" "$SNAPSHOT_HELPER" --root "$SNAPSHOT_DIR" \
    --validate-stealth "${SNAPSHOT_ARGS[@]}"
install -d -o root -g root -m 0700 \
    "$SNAPSHOT_DIR/opt/EasyPi/data/netprotection"
: > "$SNAPSHOT_DIR/$STEALTH_STATE_MARKER_REL"
chmod 0600 "$SNAPSHOT_DIR/$STEALTH_STATE_MARKER_REL"
STAGED_TARGETS+=("$STEALTH_STATE_MARKER_REL")

DB_KIND="$("$CRYPTO_PY" "$POSTGRES_HELPER" kind)"
case "$DB_KIND" in
    postgresql)
        "$CRYPTO_PY" "$POSTGRES_HELPER" dump "$SNAPSHOT_DIR/$POSTGRES_DUMP_REL"
        DUMP_COVERED=0
        for p in "${STAGED_TARGETS[@]}"; do
            if [[ "$POSTGRES_DUMP_REL" == "$p" || "$POSTGRES_DUMP_REL" == "$p"/* ]]; then
                DUMP_COVERED=1
                break
            fi
        done
        (( DUMP_COVERED == 1 )) || STAGED_TARGETS+=("$POSTGRES_DUMP_REL")
        ;;
    sqlite|missing) ;;
    *)
        echo "ERROR: configured database type cannot be backed up safely" >&2
        exit 1
        ;;
esac
tar -C "$SNAPSHOT_DIR" -czf - "${STAGED_TARGETS[@]}" \
    | "$CRYPTO_PY" "$CRYPTO_HELPER" encrypt-stdin "$BACKUP_FILE"
rm -rf -- "$SNAPSHOT_DIR"
SNAPSHOT_DIR=""

# Creation is successful only if the encrypted output can be authenticated,
# fully decompressed, and accepted by the exact restore allowlist. This keeps
# an unusable archive out of both the filesystem and the backup database.
VALIDATION_FILE="$(mktemp "${BACKUP_DIR}/.restore.XXXXXX.tar.gz")"
"$CRYPTO_PY" "$CRYPTO_HELPER" decrypt "$BACKUP_FILE" "$VALIDATION_FILE" >/dev/null
chown root:root "$VALIDATION_FILE"
chmod 600 "$VALIDATION_FILE"
/usr/bin/python3 "$RESTORE_VALIDATOR" --validate-only "$VALIDATION_FILE" >/dev/null
rm -f -- "$VALIDATION_FILE"
VALIDATION_FILE=""

# Lock down the archive: root + the easypi service group only (the backend needs
# group-read for restore/download); never world-readable.
chown root:easypi "$BACKUP_FILE"
chmod 640 "$BACKUP_FILE"
BACKUP_COMPLETE=1

echo "Config backup completed successfully!" >&2
echo "BACKUP_FILE=$BACKUP_FILE"
