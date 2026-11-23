#!/bin/bash
#
# Narrow password-change helper for EasyPi.
# Reads one password from stdin and changes only a validated non-root user.

set -euo pipefail

USERNAME="${1:-}"

die() {
  echo "ERROR: $*" >&2
  exit 1
}

[[ $# -eq 1 ]] || die "usage: set_user_password.sh username"
[[ "$USERNAME" =~ ^[a-z_][a-z0-9_-]{0,31}$ ]] || die "invalid username"
[[ "$USERNAME" != "root" ]] || die "refusing to change root password"
getent passwd "$USERNAME" >/dev/null || die "user not found"
[[ "$(id -u -- "$USERNAME")" -ne 0 ]] || die "refusing to change uid 0 password"

IFS= read -r PASSWORD || die "password missing on stdin"
[[ -n "$PASSWORD" ]] || die "password must not be empty"
[[ "$PASSWORD" != *$'\n'* ]] || die "password must be a single line"

printf '%s:%s\n' "$USERNAME" "$PASSWORD" | chpasswd
