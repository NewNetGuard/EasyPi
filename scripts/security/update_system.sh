#!/bin/bash
set -euo pipefail

ACTION="${1:-}"
export DEBIAN_FRONTEND=noninteractive
readonly PACKAGE_LOCK_FILE="/run/lock/easypi-package-manager.lock"

command -v flock >/dev/null 2>&1 || {
  echo "ERROR: flock is required" >&2
  exit 1
}
[[ -d /run/lock && ! -L /run/lock ]] || {
  echo "ERROR: trusted /run/lock is unavailable" >&2
  exit 1
}
if [[ -e "${PACKAGE_LOCK_FILE}" || -L "${PACKAGE_LOCK_FILE}" ]]; then
  [[ -f "${PACKAGE_LOCK_FILE}" && ! -L "${PACKAGE_LOCK_FILE}" ]] || {
    echo "ERROR: unsafe package-manager lock" >&2
    exit 1
  }
  [[ "$(stat -Lc '%u' -- "${PACKAGE_LOCK_FILE}")" == "0" ]] || {
    echo "ERROR: unsafe package-manager lock owner" >&2
    exit 1
  }
fi
exec 9>"${PACKAGE_LOCK_FILE}"
chmod 0600 "${PACKAGE_LOCK_FILE}"
flock -n 9 || {
  echo "ERROR: another EasyPi package operation is running" >&2
  exit 1
}

# Emit progress lines consumed by backend parser (looks for "NN%")
progress() {
    local pct="${1:-0}"
    shift || true
    local msg="$*"
    if [[ -n "$msg" ]]; then
        echo "[PROGRESS] ${pct}% ${msg}"
    else
        echo "[PROGRESS] ${pct}%"
    fi
}

# PID file for background sync process
SYNC_PID_FILE="/run/easypi-update-sync.pid"

# Function to check if a mountpoint is read-only
is_ro_mount() {
    local mp="$1"
    local opts
    opts=$(awk -v mp="$mp" '$2==mp {print $4}' /proc/mounts | head -n1)
    [[ -n "$opts" ]] && [[ "$opts" == *",ro,"* || "$opts" == ro || "$opts" == ro,* || "$opts" == *,ro ]]
}

# Remount a mountpoint as read-write if it's read-only
remount_rw() {
    local mp="$1"
    if is_ro_mount "$mp"; then
        echo "Mountpoint $mp is read-only, remounting as read-write..."
        sync 2>/dev/null || true
        mount -o remount,rw "$mp" || return 1
        sync
        sleep 1
    fi
    return 0
}

# Function to ensure filesystem is read-write
ensure_rw() {
    local attempts=5
    local i
    for ((i=1; i<=attempts; i++)); do
        local failed=0
        remount_rw "/" || failed=1
        # Some systems have separate /usr or /var mounts; try those too if present
        grep -qs ' /usr ' /proc/mounts && remount_rw "/usr" || true
        grep -qs ' /var ' /proc/mounts && remount_rw "/var" || true

        if [[ $failed -eq 0 ]] && ! is_ro_mount "/"; then
            return 0
        fi
        sleep 2
    done

    # Final check
    if is_ro_mount "/"; then
        echo "ERROR: Failed to remount filesystem as read-write after $attempts attempts" >&2
        echo "This may indicate hardware or filesystem errors. Reboot and run fsck." >&2
        exit 1
    fi
}

# Background sync process - periodically syncs to prevent I/O buildup
start_background_sync() {
    (
        # The child must not keep the package-manager lock alive after its
        # parent exits or is terminated.
        exec 9>&-
        while true; do
            sleep 5
            sync 2>/dev/null || true
            # Also check and remount if needed
            if is_ro_mount "/"; then
                mount -o remount,rw / 2>/dev/null || true
            fi
            if grep -qs ' /usr ' /proc/mounts && is_ro_mount "/usr"; then
                mount -o remount,rw /usr 2>/dev/null || true
            fi
            if grep -qs ' /var ' /proc/mounts && is_ro_mount "/var"; then
                mount -o remount,rw /var 2>/dev/null || true
            fi
        done
    ) &
    echo $! > "$SYNC_PID_FILE"
}

stop_background_sync() {
    if [[ -f "$SYNC_PID_FILE" ]]; then
        local pid
        pid=$(cat "$SYNC_PID_FILE" 2>/dev/null || echo "")
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
        fi
        rm -f "$SYNC_PID_FILE"
    fi
}

# Cleanup on exit
cleanup() {
    stop_background_sync
    sync 2>/dev/null || true
}
trap cleanup EXIT

# Function to run ldconfig safely
safe_ldconfig() {
    ensure_rw
    ldconfig 2>/dev/null || true
}

# Function to safely run apt operations with reduced I/O priority
# ionice -c3 = idle I/O class (only when system is idle)
# nice -n 10 = lower CPU priority
safe_apt() {
    ensure_rw
    sync
    ionice -c3 nice -n 10 "$@"
    local result=$?
    sync
    ensure_rw  # Check again after operation
    return $result
}

case "${ACTION}" in
  update)
    progress 5 "Preparing to update package lists"
    ensure_rw
    start_background_sync
    dpkg --configure -a || true
    sync
    progress 15 "Updating package lists"
    safe_apt apt-get update
    progress 40 "Package lists updated"
    ;;
  upgrade)
    progress 5 "Preparing system upgrade"
    ensure_rw
    start_background_sync
    dpkg --configure -a || true
    sync
    
    progress 15 "Updating package lists"
    safe_apt apt-get update
    progress 30 "Package lists updated"
    
    # Use dist-upgrade to handle held-back packages (like kernel updates)
    progress 40 "Upgrading packages (this can take a while)"
    if ! safe_apt apt-get dist-upgrade -y \
      -o Dpkg::Options::=--force-confdef \
      -o Dpkg::Options::=--force-confold \
      -o APT::Get::Assume-Yes=true \
      -o Dpkg::Use-Pty=0; then
      
      # If failed, try to remount and fix
      echo "Upgrade failed, attempting recovery..."
      progress 55 "Retrying upgrade after recovery steps"
      ensure_rw
      sync
      dpkg --configure -a || true
      sync
      safe_ldconfig
      
      # Retry upgrade with even lower I/O priority
      ionice -c3 nice -n 19 apt-get dist-upgrade -y \
        -o Dpkg::Options::=--force-confdef \
        -o Dpkg::Options::=--force-confold \
        -o APT::Get::Assume-Yes=true \
        -o Dpkg::Use-Pty=0
    fi
    
    # Final cleanup
    progress 90 "Finalizing upgrade"
    sync
    safe_ldconfig

    # Restart user-facing daemons that may still be linked against shared
    # libraries replaced during the upgrade (libc/openssl/nginx). Without this,
    # nginx keeps serving 500s and sshd drops new sessions until a manual reboot.
    # try-restart only acts on units that are currently active; established SSH
    # sessions survive an sshd restart, so this is safe to run mid-job.
    progress 95 "Restarting updated services"
    systemctl try-restart nginx 2>/dev/null || true
    systemctl try-restart ssh 2>/dev/null || true
    systemctl try-restart ssh.socket 2>/dev/null || true

    # A new kernel only takes effect after a reboot — flag it for the UI so the
    # user is told to reboot (the backend surfaces [REBOOT-REQUIRED] in the result).
    if [ -f /run/reboot-required ]; then
      echo "[REBOOT-REQUIRED] $(head -n1 /run/reboot-required 2>/dev/null)"
    else
      # Compare kernel VERSIONS only (strip the +rpt-rpi-<flavor> suffix); the Pi
      # ships modules for several flavors, so a raw dir compare false-flags.
      running_ver="$(uname -r | sed 's/+.*//')"
      newest_ver="$(ls -1 /lib/modules/ 2>/dev/null | sed 's/+.*//' | sort -V | tail -n1)"
      if [ -n "$newest_ver" ] && [ "$newest_ver" != "$running_ver" ]; then
        echo "[REBOOT-REQUIRED] New kernel ${newest_ver} installed (running ${running_ver}); reboot to activate."
      fi
    fi

    progress 100 "Upgrade completed"
    ;;
  list)
    apt list --upgradable
    ;;
  *)
    echo "Usage: $0 {update|upgrade|list}" >&2
    exit 2
    ;;
esac
