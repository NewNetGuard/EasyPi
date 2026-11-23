#!/usr/bin/env bash
# Validate a privileged install input/output path before root consumes it.
# Reject symlinks in any path component, untrusted ownership, and paths writable
# by group/others. Validate every parent as well as the object itself: checking
# only the final inode leaves a rename/swap race through a writable directory.
set -euo pipefail

kind="${1:-}"
path="${2:-}"
trusted_source_uid="${3:-0}"

case "${kind}" in
  file|directory) ;;
  *) echo "usage: $0 file|directory PATH" >&2; exit 64 ;;
esac
[[ -n "${path}" ]] || { echo "trusted-path: path is empty" >&2; exit 64; }
[[ "${trusted_source_uid}" =~ ^[0-9]+$ ]] || {
  echo "trusted-path: trusted UID must be numeric" >&2
  exit 64
}

if [[ -L "${path}" ]]; then
  echo "trusted-path: symbolic link rejected: ${path}" >&2
  exit 65
fi
if [[ "${kind}" == "file" ]]; then
  [[ -f "${path}" ]] || { echo "trusted-path: not a regular file: ${path}" >&2; exit 66; }
else
  [[ -d "${path}" ]] || { echo "trusted-path: not a directory: ${path}" >&2; exit 66; }
fi

# realpath -s preserves the lexical path while realpath -e follows components.
# A mismatch means an ancestor (or the final component) is a symlink.
lexical="$(realpath -sm -- "${path}")"
physical="$(realpath -e -- "${path}")"
if [[ "${lexical}" != "${physical}" ]]; then
  echo "trusted-path: symbolic-link component rejected: ${path}" >&2
  exit 65
fi

owner_uid="$(stat -c '%u' -- "${path}")"
[[ "${owner_uid}" == "0" || "${owner_uid}" == "${trusted_source_uid}" ]] || {
  echo "trusted-path: untrusted owner rejected: ${path}" >&2
  exit 67
}

mode="$(stat -c '%a' -- "${path}")"
if (( (8#${mode} & 8#022) != 0 )); then
  echo "trusted-path: group/other write permission rejected: ${path}" >&2
  exit 68
fi

# Walk the physical parent chain. A root-owned sticky directory (normally
# /tmp) is safe as a boundary because an unprivileged user cannot rename or
# remove another owner's child there. Ordinary group/other-writable parents
# are rejected even when the final file itself is root-owned and read-only.
parent="$(dirname -- "${physical}")"
while :; do
  parent_owner="$(stat -c '%u' -- "${parent}")"
  parent_mode="$(stat -c '%a' -- "${parent}")"
  [[ "${parent_owner}" == "0" || "${parent_owner}" == "${trusted_source_uid}" ]] || {
    echo "trusted-path: untrusted parent owner rejected: ${parent}" >&2
    exit 69
  }
  if (( (8#${parent_mode} & 8#022) != 0 )); then
    if ! [[ "${parent_owner}" == "0" ]] || (( (8#${parent_mode} & 8#1000) == 0 )); then
      echo "trusted-path: writable parent directory rejected: ${parent}" >&2
      exit 69
    fi
  fi
  [[ "${parent}" == "/" ]] && break
  parent="$(dirname -- "${parent}")"
done
