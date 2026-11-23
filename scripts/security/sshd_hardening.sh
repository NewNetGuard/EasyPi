#!/bin/bash
#
# Narrow SSH hardening helper for EasyPi.
#
# Applies fixed sshd directives so they actually take EFFECT. On modern systems
# the main sshd_config does `Include /etc/ssh/sshd_config.d/*.conf` near the top,
# and drop-ins like 50-cloud-init.conf set PasswordAuthentication yes. Because
# sshd uses the FIRST obtained value, editing the main file (after the Include)
# is silently overridden. We therefore write to a high-priority drop-in
# (00-easypi-hardening.conf) that sorts BEFORE cloud-init, so our value wins.
# Falls back to editing the main config on systems without the Include.

set -euo pipefail

ACTION="${1:-}"
SSHD_CONFIG="/etc/ssh/sshd_config"
DROPIN_DIR="/etc/ssh/sshd_config.d"
DROPIN="${DROPIN_DIR}/00-easypi-hardening.conf"
SSHD_BIN="/usr/sbin/sshd"

die() {
  echo "ERROR: $*" >&2
  exit 1
}

# True if the main config includes the drop-in directory (modern Debian/Ubuntu).
uses_dropins() {
  grep -qiE '^[[:space:]]*Include[[:space:]]+/etc/ssh/sshd_config\.d/\*\.conf' "$SSHD_CONFIG" 2>/dev/null
}

# Set a directive in the main config (fallback for systems without drop-ins).
set_directive_main() {
  local key="$1" value="$2" tmp
  [[ -f "$SSHD_CONFIG" ]] || die "sshd_config not found"
  tmp="$(mktemp)"
  awk -v key="$key" -v value="$value" '
    BEGIN { found = 0 }
    $1 == key { if (!found) { print key " " value; found = 1 } next }
    { print }
    END { if (!found) print key " " value }
  ' "$SSHD_CONFIG" > "$tmp"
  install -o root -g root -m 644 "$tmp" "$SSHD_CONFIG"
  rm -f "$tmp"
}

# Set a directive in the high-priority drop-in (preferred). Preserves any other
# directives we already manage there; replaces this one.
set_directive_dropin() {
  local key="$1" value="$2" tmp existing=""
  mkdir -p "$DROPIN_DIR"
  if [[ -f "$DROPIN" ]]; then
    existing="$(grep -vE '^[[:space:]]*#' "$DROPIN" 2>/dev/null | grep -viE "^[[:space:]]*${key}([[:space:]]|\$)" || true)"
  fi
  tmp="$(mktemp)"
  {
    echo "# Managed by EasyPi security hardening. Do not edit by hand."
    [[ -n "$existing" ]] && printf '%s\n' "$existing"
    echo "${key} ${value}"
  } > "$tmp"
  install -o root -g root -m 644 "$tmp" "$DROPIN"
  rm -f "$tmp"
}

apply_directive() {
  local key="$1" value="$2"
  if uses_dropins; then
    set_directive_dropin "$key" "$value"
    if ! "$SSHD_BIN" -t 2>/dev/null; then
      rm -f "$DROPIN"
      die "resulting sshd config is invalid; rolled back drop-in"
    fi
  else
    local bak
    bak="$(mktemp)"
    cp -a "$SSHD_CONFIG" "$bak"
    set_directive_main "$key" "$value"
    if ! "$SSHD_BIN" -t 2>/dev/null; then
      install -o root -g root -m 644 "$bak" "$SSHD_CONFIG"
      rm -f "$bak"
      die "resulting sshd config is invalid; rolled back main config"
    fi
    rm -f "$bak"
  fi
}

case "$ACTION" in
  disable-root-login)
    [[ $# -eq 1 ]] || die "usage: sshd_hardening.sh disable-root-login"
    apply_directive PermitRootLogin no
    ;;

  disable-password-auth)
    [[ $# -eq 1 ]] || die "usage: sshd_hardening.sh disable-password-auth"
    apply_directive PasswordAuthentication no
    ;;

  *)
    die "unknown action: ${ACTION:-missing}"
    ;;
esac
