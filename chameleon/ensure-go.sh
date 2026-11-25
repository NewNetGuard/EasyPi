#!/usr/bin/env bash
# Print the path to the pinned Go 1.27.4 toolchain, provisioning it automatically
# when the build host doesn't have one — the way npm/pip fetch what they need.
#
# Resolution order (first hit wins):
#   1. $GO                     (if set and new enough)
#   2. `go` on PATH            (if new enough)
#   3. cached toolchain        (.build/toolchain from a previous run)
#   4. download the repo-pinned go.dev archive and verify its repo-owned SHA256
#
# Only step 4 needs network, and only once (it is cached under .build/). Every
# diagnostic goes to stderr; the ONLY thing printed to stdout is the go path, so
# callers can do:  GO="$(./ensure-go.sh)"
set -euo pipefail

REQ_MAJOR=1
REQ_MINOR=27
REQ_PATCH=4
PINNED_GO_VERSION=1.27.4
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# Build caches live in .build/ of the project that owns this tree: a Chameleon
# checkout keeps them inside itself; a project that vendors Chameleon (EasyPi)
# keeps them in its own .build/, which its installer and updater manage.
# CHAMELEON_BUILD_ROOT overrides the choice.
if [[ -n "${CHAMELEON_BUILD_ROOT:-}" ]]; then
  BUILD_ROOT="${CHAMELEON_BUILD_ROOT}"
elif [[ -e "${HERE}/.git" ]]; then
  BUILD_ROOT="${HERE}/.build"
else
  BUILD_ROOT="$(cd "${HERE}/.." && pwd)/.build"
fi
CACHE="${EASYPI_GO_CACHE:-${BUILD_ROOT}/toolchain}"

log() { echo "[ensure-go] $*" >&2; }

is_pinned_version() { # $1 = path to a go binary
  local output maj min patch
  output="$(cd "${HERE}" && "$1" version 2>/dev/null)" || return 1
  [[ "${output}" =~ (^|[[:space:]])go([0-9]+)[.]([0-9]+)([.]([0-9]+))?([[:space:]]|$) ]] \
    || return 1
  maj="${BASH_REMATCH[2]}"
  min="${BASH_REMATCH[3]}"
  patch="${BASH_REMATCH[5]:-0}"
  (( maj == REQ_MAJOR && min == REQ_MINOR && patch == REQ_PATCH ))
}

# 1) explicit $GO
if [[ -n "${GO:-}" ]] && is_pinned_version "${GO}"; then echo "${GO}"; exit 0; fi
# 2) system go
if command -v go >/dev/null 2>&1 && is_pinned_version "$(command -v go)"; then command -v go; exit 0; fi
# 3) cached toolchain
if [[ -x "${CACHE}/go/bin/go" ]] && is_pinned_version "${CACHE}/go/bin/go"; then echo "${CACHE}/go/bin/go"; exit 0; fi

# 4) provision from go.dev
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
[[ "${os}" == "linux" ]] || { log "automatic provisioning is supported only on Linux; set GO explicitly"; exit 1; }
case "$(uname -m)" in
  aarch64|arm64)
    arch=arm64
    sum=3392582988a273a87ab5043ee1b2c9c17a2c3c00580bf9326c47a2e0aaaeac92
    ;;
  x86_64|amd64)
    arch=amd64
    sum=7226736c2339719cda28fbf3a54d71aa63bcefe376e98cef00034268dab24840
    ;;
  armv6l|armv7l)
    arch=armv6l
    sum=e50964c41c6e187375387939e2f380de7250eba44e2259dfeb75c540d9d585c3
    ;;
  *) log "unsupported CPU arch $(uname -m)"; exit 1 ;;
esac

command -v curl     >/dev/null 2>&1 || { log "curl is required to fetch Go"; exit 1; }
command -v sha256sum >/dev/null 2>&1 || { log "sha256sum is required to verify Go"; exit 1; }

tarball="go${PINNED_GO_VERSION}.${os}-${arch}.tar.gz"
log "no suitable Go found — fetching pinned ${tarball} (sha256 ${sum:0:12}…)"

mkdir -p "${CACHE}"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
log "downloading ${tarball} ..."
curl -fsSL --max-time 600 -o "${tmp}/${tarball}" "https://go.dev/dl/${tarball}" || { log "download failed"; exit 1; }
log "verifying SHA256 ..."
echo "${sum}  ${tmp}/${tarball}" | sha256sum -c - >/dev/null 2>&1 || { log "CHECKSUM MISMATCH — aborting"; exit 1; }
rm -rf "${CACHE}/go"
tar -C "${CACHE}" -xzf "${tmp}/${tarball}" || { log "extract failed"; exit 1; }
[[ -x "${CACHE}/go/bin/go" ]] && is_pinned_version "${CACHE}/go/bin/go" || { log "provisioned toolchain unusable"; exit 1; }
log "provisioned $("${CACHE}/go/bin/go" version)"
echo "${CACHE}/go/bin/go"
