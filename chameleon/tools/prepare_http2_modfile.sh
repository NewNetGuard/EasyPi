#!/usr/bin/env bash
# Prepare an isolated build copy of pinned x/net and patch only the HTTP/2
# WINDOW_UPDATE batching threshold. No module-cache or tracked dependency files
# are modified.
set -euo pipefail

GO_BINARY="${1:?path to Go binary is required}"
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# Same build-cache location rule as ensure-go.sh.
if [[ -n "${CHAMELEON_BUILD_ROOT:-}" ]]; then
  BUILD_ROOT="${CHAMELEON_BUILD_ROOT}"
elif [[ -e "${ROOT}/.git" ]]; then
  BUILD_ROOT="${ROOT}/.build"
else
  BUILD_ROOT="$(cd "${ROOT}/.." && pwd)/.build"
fi
BUILD_DIR="${BUILD_ROOT}/chameleon-http2-flow"
PATCHED_MODULE="${BUILD_DIR}/xnet"
MODFILE="${BUILD_DIR}/chameleon.mod"
SUMFILE="${BUILD_DIR}/chameleon.sum"
EXPECTED='const inflowMinRefresh = 4 << 10'

cd "${ROOT}"
"${GO_BINARY}" mod download golang.org/x/net
XNET_DIR="$("${GO_BINARY}" list -mod=mod -m -f '{{.Dir}}' golang.org/x/net)"
SOURCE="${XNET_DIR}/http2/flow.go"
[[ -f "${SOURCE}" ]] || { echo "missing x/net/http2 flow source: ${SOURCE}" >&2; exit 1; }
matches="$(grep -Fxc "${EXPECTED}" "${SOURCE}" || true)"
[[ "${matches}" == 1 ]] || {
  echo "x/net/http2 flow threshold changed upstream; refusing a blind patch" >&2
  exit 1
}

mkdir -p "${BUILD_DIR}"
case "${PATCHED_MODULE}" in
  "${BUILD_DIR}/xnet") rm -rf -- "${PATCHED_MODULE}" ;;
  *) echo "unsafe patched module path" >&2; exit 1 ;;
esac
cp -R "${XNET_DIR}" "${PATCHED_MODULE}"
chmod -R u+w "${PATCHED_MODULE}"
sed -i 's/^const inflowMinRefresh = 4 << 10$/const inflowMinRefresh = 8 << 20/' \
  "${PATCHED_MODULE}/http2/flow.go"

cp "${ROOT}/go.mod" "${MODFILE}"
cp "${ROOT}/go.sum" "${SUMFILE}"
printf '\nreplace golang.org/x/net => %s\n' "${PATCHED_MODULE}" >> "${MODFILE}"
echo "${MODFILE}"
