#!/bin/bash
set -euo pipefail

# Schedule filesystem check and reboot.
# Attempts to force fsck for root and /usr (if separate) on next boot.

if [[ ${EUID:-0} -ne 0 ]]; then
    echo "ERROR: must run as root" >&2
    exit 1
fi

FSCK_FLAG="/forcefsck"

resolve_device() {
    local src="$1"
    if [[ "$src" == UUID=* ]]; then
        blkid -U "${src#UUID=}" 2>/dev/null || true
        return
    fi
    if [[ "$src" == LABEL=* ]]; then
        blkid -L "${src#LABEL=}" 2>/dev/null || true
        return
    fi
    if [[ "$src" == PARTUUID=* ]]; then
        blkid -U "${src#PARTUUID=}" 2>/dev/null || true
        return
    fi
    echo "$src"
}

force_fsck() {
    local mp="$1"
    local src fstype dev
    src=$(findmnt -no SOURCE -T "$mp" 2>/dev/null || true)
    fstype=$(findmnt -no FSTYPE -T "$mp" 2>/dev/null || true)
    if [[ -z "$src" ]]; then
        echo "WARN: unable to determine device for $mp" >&2
        return 0
    fi
    dev=$(resolve_device "$src")
    if [[ -z "$dev" ]]; then
        echo "WARN: unable to resolve device for $mp ($src)" >&2
        return 0
    fi
    if [[ "$fstype" != "ext4" && "$fstype" != "ext3" && "$fstype" != "ext2" ]]; then
        echo "WARN: $mp uses $fstype; automatic fsck forcing not supported" >&2
        return 0
    fi
    if command -v tune2fs >/dev/null 2>&1; then
        tune2fs -c 1 -C 1 "$dev" >/dev/null 2>&1 || true
        echo "Forced fsck for $mp ($dev)"
    else
        echo "WARN: tune2fs not available; relying on /forcefsck only" >&2
    fi
}

if ! touch "$FSCK_FLAG" 2>/dev/null; then
    echo "WARNING: could not create $FSCK_FLAG (filesystem may be read-only)" >&2
fi

# Force fsck for root and /usr if separate
force_fsck "/"
if findmnt -T /usr >/dev/null 2>&1; then
    force_fsck "/usr"
fi

sync 2>/dev/null || true

# Reboot in 1 minute to allow HTTP response to return
if command -v shutdown >/dev/null 2>&1; then
    shutdown -r +1 "EasyPi: filesystem check scheduled"
else
    systemctl reboot
fi

echo "Filesystem check scheduled. Rebooting soon."
