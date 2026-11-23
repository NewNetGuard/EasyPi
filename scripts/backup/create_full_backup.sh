#!/bin/bash
set -euo pipefail

# Full EasyPi Backup Script
# Captures restorable EasyPi state without exporting host credentials, private
# keys, user home directories, or arbitrary root-readable files.

BACKUP_DIR="/opt/EasyPi/backups"
TIMESTAMP=$(date +%Y-%m-%d-%H-%M-%S)
BACKUP_FILE="${BACKUP_DIR}/full-${TIMESTAMP}.epibak"
CRYPTO_PY="/opt/EasyPi/backend/.venv/bin/python"
CRYPTO_HELPER="/opt/EasyPi/scripts/utils/backup_crypto.py"
RESTORE_VALIDATOR="/opt/EasyPi/scripts/utils/secure_restore.py"
SNAPSHOT_HELPER="/opt/EasyPi/scripts/utils/backup_snapshot.py"
POSTGRES_HELPER="/opt/EasyPi/scripts/utils/postgres_backup.py"
POSTGRES_DUMP_REL="opt/EasyPi/data/db/easypi-postgresql.dump"
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

# Keep archive discovery available to the backend without granting access to
# users outside the EasyPi service group.
install -d -o root -g easypi -m 0750 "$BACKUP_DIR"
[[ ! -e "$BACKUP_FILE" && ! -L "$BACKUP_FILE" ]] || {
    echo "ERROR: backup name collision; retry in one second" >&2
    exit 1
}
trap cleanup_backup_creation EXIT

echo "Starting full system backup..."
echo "Backup file: $BACKUP_FILE"

# Check available disk space (require at least 5GB free)
AVAILABLE_SPACE=$(df -BG "$BACKUP_DIR" | awk 'NR==2 {print $4}' | sed 's/G//')
if [ "$AVAILABLE_SPACE" -lt 5 ]; then
    echo "ERROR: Not enough disk space. At least 5GB required." >&2
    exit 1
fi

# Create a bounded archive. This is intentionally not a disk image.
echo "Creating archive..."
TARGETS=()
for p in \
    /etc/hostname \
    /etc/hosts \
    /opt/EasyPi/.env \
    /opt/EasyPi/config \
    /opt/EasyPi/data \
    /var/lib/easypi/stealth-policy ; do
    [[ -e "$p" ]] && TARGETS+=("$p")
done

SNAPSHOT_DIR="$(mktemp -d "${BACKUP_DIR}/.snapshot.XXXXXX")"
SNAPSHOT_ARGS=()
STAGED_TARGETS=()
for p in "${TARGETS[@]}"; do
    SNAPSHOT_ARGS+=(--source "$p")
    STAGED_TARGETS+=("${p#/}")
done
for p in \
    /opt/EasyPi/data/installer \
    /opt/EasyPi/data/backup-archive-imports \
    /opt/EasyPi/data/backup-key-imports \
    /opt/EasyPi/data/netprotection/vault \
    /opt/EasyPi/data/netprotection/vapid_private.pem \
    /opt/EasyPi/data/netprotection/adult_domains.txt \
    /opt/EasyPi/data/netprotection/adult_domains.NOTICE.txt \
    /opt/EasyPi/data/netprotection/adult_domains.LICENSE.txt \
    /opt/EasyPi/data/netprotection/adult_domains.sources.json ; do
    SNAPSHOT_ARGS+=(--exclude "$p")
done
SNAPSHOT_ARGS+=(--exclude "/${POSTGRES_DUMP_REL}")
"$CRYPTO_PY" "$SNAPSHOT_HELPER" --root "$SNAPSHOT_DIR" \
    --validate-stealth "${SNAPSHOT_ARGS[@]}"

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

# Enforce the same member, type, allowlist, count, and expanded-size contract
# used by restore before publishing the backup as complete.
VALIDATION_FILE="$(mktemp "${BACKUP_DIR}/.restore.XXXXXX.tar.gz")"
"$CRYPTO_PY" "$CRYPTO_HELPER" decrypt "$BACKUP_FILE" "$VALIDATION_FILE" >/dev/null
chown root:root "$VALIDATION_FILE"
chmod 600 "$VALIDATION_FILE"
/usr/bin/python3 "$RESTORE_VALIDATOR" --validate-only "$VALIDATION_FILE" >/dev/null
rm -f -- "$VALIDATION_FILE"
VALIDATION_FILE=""

chown root:easypi "$BACKUP_FILE"
chmod 640 "$BACKUP_FILE"
BACKUP_COMPLETE=1

echo "Backup completed successfully!" >&2
echo "BACKUP_FILE=$BACKUP_FILE"
