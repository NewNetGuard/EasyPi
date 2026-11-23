#!/bin/bash

set -euo pipefail

export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
umask 077

die() {
    printf 'ERROR: %s\n' "$1" >&2
    exit "${2:-1}"
}

[[ $EUID -eq 0 ]] || die "must run as root"
[[ $# -eq 2 ]] || die "usage: system_settings.sh set-timezone <timezone>" 2
[[ "$1" == "set-timezone" ]] || die "unsupported action" 2

timezone="$2"
[[ "$timezone" =~ ^[A-Za-z0-9_+./-]{1,64}$ ]] || die "invalid timezone" 2

/usr/bin/timedatectl list-timezones \
    | /usr/bin/grep -Fx -- "$timezone" >/dev/null \
    || die "invalid timezone" 2

/usr/bin/timedatectl set-timezone "$timezone"
