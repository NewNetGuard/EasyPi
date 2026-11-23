#!/usr/bin/env bash
# Build the Chameleon Linux binaries used by EasyPi's Stealth section, from the
# vendored Go source in this directory. Requires exactly Go 1.27.3 (or set $GO).
#
#   ./build.sh            # developer build: server(amd64) + both Linux clients
#   ./build.sh arm64      # install build: servers(amd64+arm64) + arm64 client
#   ./build.sh amd64      # install build: server(amd64) + amd64 client
#
# Outputs (consumed by Stealth and Mobile Link):
#   bin/chameleon-server-amd64   -> VPS (/opt/chameleon-server/chameleon-server)
#   bin/chameleon-server-arm64   -> Pi home-tunnel endpoint
#   bin/chameleon-client-arm64   -> Pi  (/opt/EasyPi/bin/chameleon-client, arm64/Pi 5)
#   bin/chameleon-client-amd64   -> Pi  (/opt/EasyPi/bin/chameleon-client, amd64)
#   bin/chameleon-mobile-link-relay-amd64 -> VPS
#   bin/chameleon-mobile-link-agent-*     -> EasyPi host
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# systemd-run and other non-login installers may intentionally have no HOME.
# Give Go private, per-build caches rather than falling back to a shared or
# caller-controlled location. This also prevents a privileged installation
# from consuming modules or compiled objects selected through inherited env.
GO_BUILD_CACHE="$(mktemp -d "${TMPDIR:-/tmp}/easypi-chameleon-go.XXXXXX")"
# Go keeps its module cache read-only; make it writable again so a build
# without root can remove it.
cleanup() { chmod -R u+w -- "${GO_BUILD_CACHE}" 2>/dev/null; rm -rf -- "${GO_BUILD_CACHE}"; }
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
export GOPATH="${GO_BUILD_CACHE}/gopath"
export GOMODCACHE="${GO_BUILD_CACHE}/gomodcache"
export GOCACHE="${GO_BUILD_CACHE}/gocache"
mkdir -p "${GOPATH}" "${GOMODCACHE}" "${GOCACHE}"

# Resolve a Go toolchain, auto-provisioning one from go.dev if the host has none.
# install.sh deliberately normalizes source files to 0644, so helpers are
# invoked through bash rather than relying on their executable bit.
GO="$(bash "${ROOT}/ensure-go.sh")" || { echo "[build] no usable Go toolchain available" >&2; exit 1; }
FLOW_MODFILE="$(bash "${ROOT}/tools/prepare_http2_modfile.sh" "${GO}")" || {
  echo "[build] failed to prepare browser-like HTTP/2 flow module" >&2
  exit 1
}
OUT="$ROOT/bin"
mkdir -p "$OUT"
cd "$ROOT"

TARGET_ARCH="${1:-all}"
case "$TARGET_ARCH" in
  aarch64|arm64) CLIENT_ARCHES=(arm64) ;;
  x86_64|amd64) CLIENT_ARCHES=(amd64) ;;
  all) CLIENT_ARCHES=(arm64 amd64) ;;
  *) echo "[build] unsupported target architecture: $TARGET_ARCH" >&2; exit 1 ;;
esac

echo "Using: $("$GO" version)"
build() { # $1=goarch $2=outname $3=pkg
  echo "  building $2 ($1)"
  # -buildvcs=false: this is a vendored component inside the EasyPi git repo; do
  # NOT stamp EasyPi's git revision/dirty state into the stealth binaries.
  CGO_ENABLED=0 GOOS=linux GOARCH="$1" "$GO" build -modfile="$FLOW_MODFILE" -trimpath -buildvcs=false -o "$OUT/$2" "$3"
}
rm -f -- "$OUT/chameleon-server-amd64"
build amd64 chameleon-server-amd64 ./server
if [[ " ${CLIENT_ARCHES[*]} " == *" arm64 "* ]]; then
  rm -f -- "$OUT/chameleon-server-arm64"
  build arm64 chameleon-server-arm64 ./server
fi
rm -f -- "$OUT/chameleon-mobile-link-relay-amd64"
build amd64 chameleon-mobile-link-relay-amd64 ./cmd/chameleon-mobile-link-relay
for client_arch in "${CLIENT_ARCHES[@]}"; do
  client_output="chameleon-client-${client_arch}"
  rm -f -- "$OUT/$client_output"
  build "$client_arch" "$client_output" ./cmd/chameleon-client
  mobile_link_output="chameleon-mobile-link-agent-${client_arch}"
  rm -f -- "$OUT/$mobile_link_output"
  build "$client_arch" "$mobile_link_output" ./cmd/chameleon-mobile-link-agent
done
chmod 0755 \
  "$OUT/chameleon-server-amd64" \
  "$OUT/chameleon-mobile-link-relay-amd64" \
  "${CLIENT_ARCHES[@]/#/$OUT/chameleon-client-}" \
  "${CLIENT_ARCHES[@]/#/$OUT/chameleon-mobile-link-agent-}"
if [[ -f "$OUT/chameleon-server-arm64" ]]; then chmod 0755 "$OUT/chameleon-server-arm64"; fi
echo "Done. Binaries in $OUT:"
ls -la \
  "$OUT/chameleon-server-amd64" \
  "$OUT/chameleon-mobile-link-relay-amd64" \
  "${CLIENT_ARCHES[@]/#/$OUT/chameleon-client-}" \
  "${CLIENT_ARCHES[@]/#/$OUT/chameleon-mobile-link-agent-}"
