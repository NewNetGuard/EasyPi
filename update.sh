#!/usr/bin/env bash
set -euo pipefail
umask 077

# Compatibility entry point. All update verification, snapshotting, health
# checks, reboot recovery, and rollback live in one hardened implementation.
TARGET_DIR="/opt/EasyPi"
UPDATER="${TARGET_DIR}/scripts/maintenance/apply_update.sh"
MODE=""
SOURCE=""
SIGNATURE="${EASYPI_UPDATE_SIGNATURE:-}"
SHA256="${EASYPI_UPDATE_SHA256:-}"
REQUESTED_TARGET="$TARGET_DIR"
RECOVER=0
declare -a FLAGS=()

die() {
    echo "ERROR: $1" >&2
    exit 1
}

usage() {
    cat <<'USAGE'
EasyPi signed update utility

Archive:
  sudo /opt/EasyPi/update.sh --from-archive RELEASE.tar.gz --signature RELEASE.tar.gz.sig

HTTPS URL:
  sudo /opt/EasyPi/update.sh --from-url https://example/release.tar.gz --signature https://example/release.tar.gz.sig --sha256 HEX

Options:
  --target-dir PATH    Compatibility option; only /opt/EasyPi is accepted
  --from-archive FILE  Update from a local signed release
  --from-url URL       Update from a signed HTTPS release
  --signature PATH|URL Detached RSA/SHA-256 signature (required)
  --sha256 HEX         Optional additional archive checksum
  --delete-obsolete    Delete obsolete code files, never user data
  --run-install        Run install.sh --binary as part of the guarded update
  --skip-restart       Stage files without restart/health gate (explicit opt-out)
  --dry-run            Verify and preview without applying
  --allow-downgrade    Explicitly allow a signed older version
  --recover            Recover an interrupted update from its trusted snapshot
  -h, --help           Show this help
USAGE
}

require_value() {
    [[ $# -ge 2 && -n "$2" ]] || die "$1 requires a value"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --target-dir)
            require_value "$@"
            REQUESTED_TARGET="$2"
            shift 2
            ;;
        --from-archive)
            require_value "$@"
            [[ -z "$MODE" ]] || die "specify exactly one update source"
            MODE="archive"
            SOURCE="$2"
            shift 2
            ;;
        --from-url)
            require_value "$@"
            [[ -z "$MODE" ]] || die "specify exactly one update source"
            MODE="url"
            SOURCE="$2"
            shift 2
            ;;
        --signature)
            require_value "$@"
            SIGNATURE="$2"
            shift 2
            ;;
        --sha256)
            require_value "$@"
            SHA256="$2"
            shift 2
            ;;
        --delete-obsolete|--run-install|--skip-restart|--dry-run|--allow-downgrade)
            FLAGS+=("$1")
            shift
            ;;
        --recover)
            RECOVER=1
            shift
            ;;
        --keep-download)
            die "--keep-download is no longer supported; verified downloads are removed securely"
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            die "unknown argument: $1"
            ;;
    esac
done

[[ "$EUID" -eq 0 ]] || die "run as root"
[[ "$REQUESTED_TARGET" == "$TARGET_DIR" || "$REQUESTED_TARGET" == "$TARGET_DIR/" ]] \
    || die "updates are restricted to $TARGET_DIR"
[[ -d "$TARGET_DIR" && ! -L "$TARGET_DIR" ]] || die "trusted EasyPi installation is missing"

# The wrapper is a root entry point. Refuse delegation if any component of the
# installed updater path can be replaced by the service account or another user.
for trusted in \
    /opt \
    /opt/EasyPi \
    /opt/EasyPi/scripts \
    /opt/EasyPi/scripts/maintenance \
    "$UPDATER"; do
    [[ -e "$trusted" && ! -L "$trusted" ]] || die "unsafe updater path: $trusted"
    uid="$(stat -Lc '%u' -- "$trusted")" || die "cannot inspect updater path"
    mode="$(stat -Lc '%a' -- "$trusted")" || die "cannot inspect updater path"
    [[ "$uid" == "0" && $((8#$mode & 8#022)) -eq 0 ]] \
        || die "updater path must be root-owned and not writable outside root: $trusted"
done
[[ -f "$UPDATER" ]] || die "hardened updater is unavailable"

if (( RECOVER == 1 )); then
    [[ -z "$MODE" && ${#FLAGS[@]} -eq 0 ]] \
        || die "--recover cannot be combined with update options"
    exec /bin/bash "$UPDATER" --recover
fi

[[ -n "$MODE" && -n "$SOURCE" ]] || die "specify --from-archive or --from-url"
[[ -n "$SIGNATURE" ]] || die "--signature is required"

declare -a COMMAND=(/bin/bash "$UPDATER" --mode "$MODE")
if [[ "$MODE" == "archive" ]]; then
    COMMAND+=(--archive "$SOURCE")
else
    COMMAND+=(--url "$SOURCE")
fi
COMMAND+=(--sig "$SIGNATURE")
[[ -z "$SHA256" ]] || COMMAND+=(--sha256 "$SHA256")
COMMAND+=("${FLAGS[@]}")

exec "${COMMAND[@]}"
