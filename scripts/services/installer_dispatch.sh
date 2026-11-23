#!/usr/bin/env bash
set -euo pipefail

JOB_ID="${1:-}"
if [[ -z "${JOB_ID}" ]]; then
  echo "Usage: installer_dispatch.sh <job_id>"
  exit 1
fi

if [[ ! "${JOB_ID}" =~ ^[0-9a-f]{32}$ ]]; then
  echo "Invalid job id: ${JOB_ID}"
  exit 1
fi

EASYPI_ROOT="${EASYPI_ROOT:-/opt/EasyPi}"
JOB_DIR="${EASYPI_ROOT}/data/installer"
JOB_FILE="${JOB_DIR}/${JOB_ID}.json"
LOG_DIR="/var/log/easypi"
LOG_FILE="${LOG_DIR}/installer-${JOB_ID}.log"
TRUSTED_UPDATE_DIR="/var/lib/easypi/updates"
STAGED_UPDATE_DIR="${TRUSTED_UPDATE_DIR}/.staged-${JOB_ID}"

cleanup_update_stage() {
  rm -rf -- "${STAGED_UPDATE_DIR}"
}
trap cleanup_update_stage EXIT

install -d -o root -g easypi -m 0750 "${LOG_DIR}"
if [[ -L "${LOG_FILE}" ]]; then
  echo "Refusing symlink installer log: ${LOG_FILE}"
  exit 1
fi
touch "${LOG_FILE}"
chown root:easypi "${LOG_FILE}"
chmod 640 "${LOG_FILE}" || true

exec > >(tee -a "${LOG_FILE}") 2>&1

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Installer job ${JOB_ID} starting"

if [[ ! -f "${JOB_FILE}" || -L "${JOB_FILE}" ]]; then
  echo "Job file not found: ${JOB_FILE}"
  exit 1
fi

mapfile -d '' -t job_parts < <(python3 - "${JOB_FILE}" "${JOB_ID}" "${EASYPI_ROOT}" "${TRUSTED_UPDATE_DIR}" <<'PY'
import json
import os
import re
import stat
import sys
from pathlib import Path
from urllib.parse import urlsplit

job_path = sys.argv[1]
job_id = sys.argv[2]
easypi_root = Path(sys.argv[3])
trusted_update_dir = Path(sys.argv[4])
flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
fd = os.open(job_path, flags)
try:
    info = os.fstat(fd)
    if not stat.S_ISREG(info.st_mode) or info.st_size > 64 * 1024 or info.st_mode & 0o022:
        raise SystemExit(2)
    job_owner_uid = info.st_uid
    with os.fdopen(fd, "r", encoding="utf-8") as f:
        fd = -1
        data = json.load(f)
finally:
    if fd >= 0:
        os.close(fd)

script = data.get("script")
if not isinstance(script, str) or not script or "\0" in script:
    sys.exit(2)

args = data.get("args") or []
if not isinstance(args, list) or len(args) > 64:
    sys.exit(2)
normalized = []
for arg in args:
    if not isinstance(arg, str):
        arg = str(arg)
    if "\0" in arg or len(arg) > 4096:
        sys.exit(2)
    normalized.append(arg)

if script == "maintenance/apply_update.sh":
    value_options = {"--mode", "--sig", "--archive", "--url", "--sha256"}
    flag_options = {"--run-install", "--delete-obsolete", "--skip-restart", "--dry-run"}
    values = {}
    flags = set()
    index = 0
    while index < len(normalized):
        option = normalized[index]
        if option in value_options:
            if option in values or index + 1 >= len(normalized):
                sys.exit(2)
            value = normalized[index + 1]
            if not value or value.startswith("--"):
                sys.exit(2)
            values[option] = value
            index += 2
            continue
        if option in flag_options:
            if option in flags:
                sys.exit(2)
            flags.add(option)
            index += 1
            continue
        # In particular, the privileged job path never exposes
        # --allow-downgrade or any future updater flag by default.
        sys.exit(2)

    mode = values.get("--mode")
    signature = values.get("--sig")
    if mode not in {"archive", "url"} or not signature:
        sys.exit(2)

    def valid_https_url(value):
        if any(ch.isspace() for ch in value):
            return False
        parsed = urlsplit(value)
        return parsed.scheme.lower() == "https" and bool(parsed.hostname) and not parsed.username and not parsed.password

    def resolved_regular_file(value, root, owner_uid, size_limit):
        candidate = Path(value)
        if not candidate.is_absolute() or candidate.is_symlink():
            sys.exit(2)
        try:
            resolved_root = root.resolve(strict=True)
            resolved = candidate.resolve(strict=True)
            resolved.relative_to(resolved_root)
        except (OSError, ValueError):
            sys.exit(2)
        info = resolved.stat()
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != owner_uid
            or info.st_mode & 0o022
            or info.st_size > size_limit
        ):
            sys.exit(2)
        return resolved

    def require_secure_directory(path, owner_uid):
        if path.is_symlink():
            sys.exit(2)
        try:
            info = path.stat()
        except OSError:
            sys.exit(2)
        if not stat.S_ISDIR(info.st_mode) or info.st_uid != owner_uid or info.st_mode & 0o022:
            sys.exit(2)

    def copy_to_root_stage(source, destination, owner_uid, size_limit):
        source_flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        source_fd = os.open(source, source_flags)
        try:
            before = os.fstat(source_fd)
            if (
                not stat.S_ISREG(before.st_mode)
                or before.st_uid != owner_uid
                or before.st_mode & 0o022
                or before.st_size > size_limit
            ):
                sys.exit(2)
            destination_flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0)
            destination_fd = os.open(destination, destination_flags, 0o600)
            try:
                copied = 0
                while True:
                    chunk = os.read(source_fd, 1024 * 1024)
                    if not chunk:
                        break
                    copied += len(chunk)
                    if copied > size_limit:
                        sys.exit(2)
                    view = memoryview(chunk)
                    while view:
                        written = os.write(destination_fd, view)
                        view = view[written:]
                os.fsync(destination_fd)
            finally:
                os.close(destination_fd)
            after = os.fstat(source_fd)
            if before.st_size != after.st_size or before.st_mtime_ns != after.st_mtime_ns:
                sys.exit(2)
        finally:
            os.close(source_fd)

    def prepare_archive_files(archive_value, signature_value):
        incoming = easypi_root / "data" / "updates"
        require_secure_directory(incoming, job_owner_uid)
        require_secure_directory(trusted_update_dir.parent, 0)
        require_secure_directory(trusted_update_dir, 0)

        archive_source = resolved_regular_file(archive_value, incoming, job_owner_uid, 4 * 1024**3)
        signature_source = resolved_regular_file(signature_value, incoming, job_owner_uid, 64 * 1024)

        stage = trusted_update_dir / f".staged-{job_id}"
        try:
            stage.mkdir(mode=0o700)
        except OSError:
            sys.exit(2)
        archive_stage = stage / "release.tar.gz"
        signature_stage = stage / "release.tar.gz.sig"
        copy_to_root_stage(archive_source, archive_stage, job_owner_uid, 4 * 1024**3)
        copy_to_root_stage(signature_source, signature_stage, job_owner_uid, 64 * 1024)
        return str(archive_stage), str(signature_stage)

    if mode == "archive":
        if set(values) != {"--mode", "--sig", "--archive"}:
            sys.exit(2)
        staged_archive, staged_signature = prepare_archive_files(values["--archive"], signature)
        for index, value in enumerate(normalized[:-1]):
            if value == "--archive":
                normalized[index + 1] = staged_archive
            elif value == "--sig":
                normalized[index + 1] = staged_signature
    else:
        if "--url" not in values or "--archive" in values:
            sys.exit(2)
        if set(values) - {"--mode", "--sig", "--url", "--sha256"}:
            sys.exit(2)
        if not valid_https_url(values["--url"]) or not valid_https_url(signature):
            sys.exit(2)
        checksum = values.get("--sha256")
        if checksum and not re.fullmatch(r"[A-Fa-f0-9]{64}", checksum):
            sys.exit(2)

sys.stdout.write(script + "\0")
for arg in normalized:
    sys.stdout.write(arg + "\0")
PY
)

if [[ ${#job_parts[@]} -lt 1 ]]; then
  echo "Invalid job payload in ${JOB_FILE}"
  exit 1
fi

SCRIPT_REL="${job_parts[0]}"
ARGS=("${job_parts[@]:1}")

case "${SCRIPT_REL}" in
  maintenance/apply_update.sh|services/tailscale.sh|services/wireguard.sh|services/ai.sh|security/update_system.sh)
    ;;
  *)
    echo "Script not allowed: ${SCRIPT_REL}"
    exit 1
    ;;
esac

if [[ "${SCRIPT_REL}" == *".."* ]]; then
  echo "Invalid script path: ${SCRIPT_REL}"
  exit 1
fi

SCRIPT_FULL="${EASYPI_ROOT}/scripts/${SCRIPT_REL}"
if [[ ! -f "${SCRIPT_FULL}" ]]; then
  echo "Script not found: ${SCRIPT_FULL}"
  exit 1
fi

SCRIPT_CANONICAL="$(realpath -e -- "${SCRIPT_FULL}")"
case "${SCRIPT_CANONICAL}" in
  "${EASYPI_ROOT}/scripts/"*) ;;
  *)
    echo "Script escaped the trusted scripts directory"
    exit 1
    ;;
esac
SCRIPT_UID="$(stat -c '%u' -- "${SCRIPT_CANONICAL}")"
SCRIPT_MODE="$(stat -c '%a' -- "${SCRIPT_CANONICAL}")"
if [[ "${SCRIPT_UID}" != "0" || $((8#${SCRIPT_MODE} & 8#022)) -ne 0 ]]; then
  echo "Privileged installer script has unsafe ownership or permissions"
  exit 1
fi

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Running validated installer action"

set +e
if [[ -x "${SCRIPT_CANONICAL}" ]]; then
  "${SCRIPT_CANONICAL}" "${ARGS[@]}"
  EXIT_CODE=$?
else
  /bin/bash "${SCRIPT_CANONICAL}" "${ARGS[@]}"
  EXIT_CODE=$?
fi
set -e

rm -f "${JOB_FILE}" || true

echo "[$(date '+%Y-%m-%d %H:%M:%S')] Installer job ${JOB_ID} finished (exit=${EXIT_CODE})"
exit "${EXIT_CODE}"
