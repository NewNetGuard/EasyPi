#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
STAGER="${ROOT}/scripts/release/stage_chameleon_source.sh"
INPUT_CHECKER="${ROOT}/scripts/security/verify_chameleon_install_inputs.sh"
TMP="$(mktemp -d)"
trap 'rm -rf -- "${TMP}"' EXIT

FIXTURE="${TMP}/fixture"
mkdir -p "${FIXTURE}"
cp -r "${ROOT}/chameleon" "${FIXTURE}/chameleon"
rm -rf -- "${FIXTURE}/chameleon/bin"
git -C "${FIXTURE}" init -q
git -C "${FIXTURE}" config user.name "EasyPi Test"
git -C "${FIXTURE}" config user.email "test@easypi.invalid"
git -C "${FIXTURE}" add chameleon
git -C "${FIXTURE}" commit -q -m "fixture"

bash "${STAGER}" "${FIXTURE}/chameleon" "${TMP}/payload/chameleon"

[[ ! -e "${TMP}/payload/chameleon/bin" ]]
for forbidden in \
  chameleon-server-amd64 \
  chameleon-client-arm64 \
  chameleon-client-amd64 \
  chameleon-mobile-link-agent-arm64 \
  chameleon-mobile-link-agent-amd64 \
  chameleon-mobile-link-relay-amd64; do
  if find "${TMP}/payload/chameleon" -type f -name "${forbidden}" -print -quit | grep -q .; then
    echo "prebuilt executable entered staged release: ${forbidden}" >&2
    exit 1
  fi
done

for architecture in amd64 arm64; do
  mode="$(bash "${INPUT_CHECKER}" "${TMP}/payload" "${architecture}" "$(id -u)")"
  [[ "${mode}" == "build" ]] || {
    echo "source-only release did not request a build for ${architecture}" >&2
    exit 1
  }
done

[[ -x "${TMP}/payload/chameleon/build.sh" ]]
[[ -x "${TMP}/payload/chameleon/ensure-go.sh" ]]
[[ -x "${TMP}/payload/chameleon/tools/prepare_http2_modfile.sh" ]]

# Untracked or modified source must fail closed rather than enter a root build.
printf 'package server\n' > "${FIXTURE}/chameleon/server/injected.go"
if bash "${STAGER}" "${FIXTURE}/chameleon" "${TMP}/dirty-untracked" \
    >/dev/null 2>&1; then
  echo "untracked Chameleon source was accepted" >&2
  exit 1
fi
rm -f -- "${FIXTURE}/chameleon/server/injected.go"
printf '\n// dirty\n' >> "${FIXTURE}/chameleon/server/main.go"
if bash "${STAGER}" "${FIXTURE}/chameleon" "${TMP}/dirty-tracked" \
    >/dev/null 2>&1; then
  echo "modified tracked Chameleon source was accepted" >&2
  exit 1
fi

# Reproduce install.sh's 0644 source normalization. build.sh must invoke the
# non-executable ensure-go helper through bash and select only the host client.
BUILD_FIXTURE="${TMP}/permission-build"
mkdir -p \
  "${BUILD_FIXTURE}/tools" \
  "${BUILD_FIXTURE}/cmd/chameleon-client" \
  "${BUILD_FIXTURE}/cmd/chameleon-mobile-link-agent" \
  "${BUILD_FIXTURE}/cmd/chameleon-mobile-link-relay" \
  "${BUILD_FIXTURE}/server"
cp "${ROOT}/chameleon/build.sh" "${BUILD_FIXTURE}/build.sh"
cp "${ROOT}/chameleon/ensure-go.sh" "${BUILD_FIXTURE}/ensure-go.sh"
printf 'module fixture\n' > "${BUILD_FIXTURE}/go.mod"
cat > "${BUILD_FIXTURE}/tools/prepare_http2_modfile.sh" <<'SH'
#!/usr/bin/env bash
printf '%s\n' "$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/go.mod"
SH
cat > "${BUILD_FIXTURE}/fake-go" <<'SH'
#!/usr/bin/env bash
set -euo pipefail
[[ -n "${GOPATH:-}" && -d "${GOPATH}" ]]
[[ -n "${GOMODCACHE:-}" && -d "${GOMODCACHE}" ]]
[[ -n "${GOCACHE:-}" && -d "${GOCACHE}" ]]
if [[ "${1:-}" == "version" ]]; then
  echo 'go version go1.27.4 linux/amd64'
  exit 0
fi
output=''
while [[ $# -gt 0 ]]; do
  if [[ "$1" == '-o' ]]; then output="$2"; shift 2; else shift; fi
done
[[ -n "${output}" ]]
printf 'test-binary\n' > "${output}"
SH
chmod 0755 "${BUILD_FIXTURE}/fake-go"
find "${BUILD_FIXTURE}" -type f ! -name fake-go -exec chmod 0644 {} +
env -u HOME -u GOPATH -u GOMODCACHE -u GOCACHE \
  GO="${BUILD_FIXTURE}/fake-go" bash "${BUILD_FIXTURE}/build.sh" arm64 >/dev/null
[[ -s "${BUILD_FIXTURE}/bin/chameleon-server-amd64" ]]
[[ -s "${BUILD_FIXTURE}/bin/chameleon-client-arm64" ]]
[[ -s "${BUILD_FIXTURE}/bin/chameleon-mobile-link-agent-arm64" ]]
[[ -s "${BUILD_FIXTURE}/bin/chameleon-mobile-link-relay-amd64" ]]
[[ ! -e "${BUILD_FIXTURE}/bin/chameleon-client-amd64" ]]
[[ ! -e "${BUILD_FIXTURE}/bin/chameleon-mobile-link-agent-amd64" ]]
echo "source-only Chameleon release staging test passed"
