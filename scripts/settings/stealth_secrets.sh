#!/bin/bash
# Root-only encrypted credential broker for Stealth. Secrets are accepted on
# stdin and are never placed in argv, the environment, or runner logs.

set -euo pipefail

export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
umask 077

CREDENTIAL_DIR="/etc/easypi/credentials"
PLAINTEXT_DIR="/run/easypi-credentials"

die() {
  echo "$1" >&2
  exit 1
}

[[ "$EUID" -eq 0 ]] || die "root required"
[[ $# -eq 2 ]] || die "usage: stealth_secrets.sh <store|read|exists|delete|mode> <name>"

action="$1"
name="$2"
case "$name" in
  ssh-password|ssh-private-key) ;;
  duckdns-token)
    [[ "$action" == "delete" ]] || die "legacy DuckDNS credential can only be deleted"
    ;;
  *) die "unsupported credential name" ;;
esac

credential_id="easypi-stealth-${name}"
credential_file="${CREDENTIAL_DIR}/${credential_id}.cred"
mode_file="${CREDENTIAL_DIR}/${credential_id}.mode"

install -d -o root -g root -m 0700 "$CREDENTIAL_DIR" "$PLAINTEXT_DIR"
[[ ! -L "$credential_file" && ! -L "$mode_file" ]] || die "credential path must not be a symlink"

case "$action" in
  store)
    plain_file="$(mktemp "${PLAINTEXT_DIR}/.${credential_id}.plain.XXXXXX")"
    encrypted_file="$(mktemp "${CREDENTIAL_DIR}/.${credential_id}.encrypted.XXXXXX")"
    cleanup() {
      rm -f -- "$plain_file" "$encrypted_file"
    }
    trap cleanup EXIT HUP INT TERM
    chmod 0600 "$plain_file" "$encrypted_file"
    head -c 65537 > "$plain_file"
    [[ "$(stat -c %s -- "$plain_file")" -le 65536 ]] || die "credential is too large"

    python3 - "$name" "$plain_file" <<'PY'
import re
import sys
from pathlib import Path

name, path = sys.argv[1], Path(sys.argv[2])
data = path.read_bytes()
if not data or b"\x00" in data:
    raise SystemExit("invalid credential")
try:
    value = data.decode("utf-8")
except UnicodeDecodeError as exc:
    raise SystemExit("credential must be UTF-8") from exc
if name == "duckdns-token":
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,128}", value):
        raise SystemExit("invalid DuckDNS token")
elif name == "ssh-password":
    if len(value) > 4096 or "\n" in value or "\r" in value:
        raise SystemExit("invalid SSH password")
elif name == "ssh-private-key":
    if len(value) > 32768 or not value.startswith("-----BEGIN OPENSSH PRIVATE KEY-----\n"):
        raise SystemExit("invalid SSH private key")
    if not value.rstrip().endswith("-----END OPENSSH PRIVATE KEY-----"):
        raise SystemExit("invalid SSH private key")
PY
    if [[ "$name" == "ssh-private-key" ]]; then
      command -v ssh-keygen >/dev/null 2>&1 || die "ssh-keygen is required"
      ssh-keygen -y -f "$plain_file" >/dev/null 2>&1 || die "invalid SSH private key"
    fi

    command -v systemd-creds >/dev/null 2>&1 || die "systemd-creds is required"
    systemd-creds setup >/dev/null 2>&1
    key_mode="host"
    if [[ -c /dev/tpmrm0 || -c /dev/tpm0 ]]; then
      if systemd-creds encrypt --with-key=host+tpm2 --name="$credential_id" \
          "$plain_file" "$encrypted_file" >/dev/null 2>&1; then
        key_mode="host+tpm2"
      else
        : > "$encrypted_file"
      fi
    fi
    if [[ "$key_mode" == "host" ]]; then
      systemd-creds encrypt --with-key=host --name="$credential_id" \
        "$plain_file" "$encrypted_file" >/dev/null
    fi
    chmod 0600 "$encrypted_file"
    mv -f -- "$encrypted_file" "$credential_file"
    printf '%s\n' "$key_mode" > "$mode_file"
    chmod 0600 "$mode_file"
    ;;
  read)
    [[ -s "$credential_file" ]] || die "credential is not stored"
    systemd-creds decrypt --name="$credential_id" "$credential_file" -
    ;;
  exists)
    if [[ -s "$credential_file" ]]; then printf 'true\n'; else printf 'false\n'; fi
    ;;
  delete)
    rm -f -- "$credential_file" "$mode_file"
    ;;
  mode)
    if [[ -s "$mode_file" ]]; then cat -- "$mode_file"; else printf 'none\n'; fi
    ;;
  *) die "unsupported credential action" ;;
esac
