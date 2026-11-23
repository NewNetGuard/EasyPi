#!/bin/bash
# Root-only credential broker for the outbound OpenVPN client. The API sends a
# JSON object on stdin; credentials never appear in argv, environment variables,
# runner logs, the imported .ovpn file, or API responses.

set -euo pipefail

export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
umask 077

CREDENTIAL_DIR="/etc/easypi/credentials"
PLAINTEXT_DIR="/run/easypi-credentials"
CREDENTIAL_ID="easypi-outbound-vpn-auth"
CREDENTIAL_FILE="${CREDENTIAL_DIR}/${CREDENTIAL_ID}.cred"
MODE_FILE="${CREDENTIAL_DIR}/${CREDENTIAL_ID}.mode"

die() {
  echo "$1" >&2
  exit 1
}

[[ "$EUID" -eq 0 ]] || die "root required"
[[ $# -eq 1 ]] || die "usage: outbound_vpn_secrets.sh <store|read|exists|delete|mode>"

action="$1"
install -d -o root -g root -m 0700 "$CREDENTIAL_DIR" "$PLAINTEXT_DIR"
[[ ! -L "$CREDENTIAL_FILE" && ! -L "$MODE_FILE" ]] || die "credential path must not be a symlink"

case "$action" in
  store)
    request_file="$(mktemp "${PLAINTEXT_DIR}/.${CREDENTIAL_ID}.request.XXXXXX")"
    plain_file="$(mktemp "${PLAINTEXT_DIR}/.${CREDENTIAL_ID}.plain.XXXXXX")"
    encrypted_file="$(mktemp "${CREDENTIAL_DIR}/.${CREDENTIAL_ID}.encrypted.XXXXXX")"
    cleanup() {
      rm -f -- "$request_file" "$plain_file" "$encrypted_file"
    }
    trap cleanup EXIT HUP INT TERM
    chmod 0600 "$request_file" "$plain_file" "$encrypted_file"
    head -c 8705 > "$request_file"
    [[ "$(stat -c %s -- "$request_file")" -le 8704 ]] || die "credential request is too large"

    python3 - "$request_file" "$plain_file" <<'PY'
import json
import os
import sys
from pathlib import Path

request_path, output_path = map(Path, sys.argv[1:])
try:
    payload = json.loads(request_path.read_text(encoding="utf-8"))
except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
    raise SystemExit("invalid credential request") from exc
if not isinstance(payload, dict) or set(payload) != {"username", "password"}:
    raise SystemExit("credential request must contain only username and password")
username = payload.get("username")
password = payload.get("password")
if not isinstance(username, str) or not isinstance(password, str):
    raise SystemExit("credentials must be strings")
if not (1 <= len(username) <= 256) or not (1 <= len(password) <= 4096):
    raise SystemExit("invalid credential length")
if any(ch in username or ch in password for ch in ("\n", "\r", "\x00")):
    raise SystemExit("credentials contain forbidden control characters")
fd = os.open(output_path, os.O_WRONLY | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0))
try:
    os.write(fd, f"{username}\n{password}\n".encode("utf-8"))
    os.fsync(fd)
finally:
    os.close(fd)
PY

    command -v systemd-creds >/dev/null 2>&1 || die "systemd-creds is required"
    systemd-creds setup >/dev/null 2>&1
    key_mode="host"
    if [[ -c /dev/tpmrm0 || -c /dev/tpm0 ]]; then
      if systemd-creds encrypt --with-key=host+tpm2 --name="$CREDENTIAL_ID" \
          "$plain_file" "$encrypted_file" >/dev/null 2>&1; then
        key_mode="host+tpm2"
      else
        : > "$encrypted_file"
      fi
    fi
    if [[ "$key_mode" == "host" ]]; then
      systemd-creds encrypt --with-key=host --name="$CREDENTIAL_ID" \
        "$plain_file" "$encrypted_file" >/dev/null
    fi
    chmod 0600 "$encrypted_file"
    mv -f -- "$encrypted_file" "$CREDENTIAL_FILE"
    printf '%s\n' "$key_mode" > "$MODE_FILE"
    chmod 0600 "$MODE_FILE"
    printf '%s\n' "$key_mode"
    ;;
  read)
    [[ -s "$CREDENTIAL_FILE" ]] || die "OpenVPN credentials are not stored"
    systemd-creds decrypt --name="$CREDENTIAL_ID" "$CREDENTIAL_FILE" -
    ;;
  exists)
    if [[ -s "$CREDENTIAL_FILE" ]]; then printf 'true\n'; else printf 'false\n'; fi
    ;;
  delete)
    rm -f -- "$CREDENTIAL_FILE" "$MODE_FILE"
    ;;
  mode)
    if [[ -s "$MODE_FILE" ]]; then cat -- "$MODE_FILE"; else printf 'none\n'; fi
    ;;
  *) die "unsupported credential action" ;;
esac
