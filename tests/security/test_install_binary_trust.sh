#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
CHECKER="${ROOT}/scripts/security/verify_trusted_install_path.sh"
INPUT_CHECKER="${ROOT}/scripts/security/verify_chameleon_install_inputs.sh"
TMP="$(mktemp -d)"
trap 'rm -rf -- "${TMP}"' EXIT

expect_rejected() {
  local expected_rc="$1"
  shift
  local rc=0
  bash "${CHECKER}" "$@" >/dev/null 2>&1 || rc=$?
  if [[ "${rc}" != "${expected_rc}" ]]; then
    echo "expected trusted-path rc=${expected_rc}, got rc=${rc}: $*" >&2
    exit 1
  fi
}

mkdir -p "${TMP}/payload-bin" "${TMP}/source/bin"
printf '#!/bin/sh\nexit 0\n' > "${TMP}/payload"
chmod 0755 "${TMP}/payload"

# Destination directory attack: /opt/EasyPi/bin -> attacker-controlled folder.
ln -s "${TMP}/payload-bin" "${TMP}/prefix-bin"
expect_rejected 65 directory "${TMP}/prefix-bin"

# Both privileged source inputs must reject a substituted executable symlink.
ln -s "${TMP}/payload" "${TMP}/source/bin/chameleon-server-amd64"
ln -s "${TMP}/payload" "${TMP}/source/bin/chameleon-client-arm64"
expect_rejected 65 file "${TMP}/source/bin/chameleon-server-amd64"
expect_rejected 65 file "${TMP}/source/bin/chameleon-client-arm64"

# An ancestor symlink must also be rejected, not only the final component.
mkdir -p "${TMP}/real-tree/bin"
printf 'binary' > "${TMP}/real-tree/bin/chameleon-server-amd64"
ln -s "${TMP}/real-tree" "${TMP}/linked-tree"
expect_rejected 65 file "${TMP}/linked-tree/bin/chameleon-server-amd64"

# A read-only, trusted-owner file is still unsafe when any ordinary parent can
# be used by another account to replace it after validation.
mkdir -p "${TMP}/writable-parent/tree"
printf 'binary' > "${TMP}/writable-parent/tree/chameleon-server-amd64"
chmod 0777 "${TMP}/writable-parent"
expect_rejected 69 file \
  "${TMP}/writable-parent/tree/chameleon-server-amd64" "$(id -u)"
chmod 0755 "${TMP}/writable-parent"
bash "${CHECKER}" file \
  "${TMP}/writable-parent/tree/chameleon-server-amd64" "$(id -u)"

# Exercise the same input classifier used by install.sh. A prebuilt-only binary
# release is forbidden: installation must have reviewed source to rebuild.
mkdir -p "${TMP}/binary-release/chameleon/bin"
printf 'server' > "${TMP}/binary-release/chameleon/bin/chameleon-server-amd64"
printf 'client' > "${TMP}/binary-release/chameleon/bin/chameleon-client-amd64"
if bash "${INPUT_CHECKER}" \
    "${TMP}/binary-release" amd64 "$(id -u)" >/dev/null 2>&1; then
  echo "prebuilt-only Chameleon release was accepted" >&2
  exit 1
fi

# A user-owned source checkout is valid when that exact SUDO_UID is explicitly
# trusted. With no binary outputs it must request a fresh build.
mkdir -p \
  "${TMP}/source-checkout/chameleon/bin" \
  "${TMP}/source-checkout/chameleon/clientcore" \
  "${TMP}/source-checkout/chameleon/cmd" \
  "${TMP}/source-checkout/chameleon/mobilelink" \
  "${TMP}/source-checkout/chameleon/server" \
  "${TMP}/source-checkout/chameleon/shared" \
  "${TMP}/source-checkout/chameleon/tools"
printf '#!/usr/bin/env bash\nexit 0\n' > "${TMP}/source-checkout/chameleon/build.sh"
printf '#!/usr/bin/env bash\nexit 0\n' > "${TMP}/source-checkout/chameleon/ensure-go.sh"
printf '#!/usr/bin/env bash\nexit 0\n' > "${TMP}/source-checkout/chameleon/tools/prepare_http2_modfile.sh"
printf 'module test\n' > "${TMP}/source-checkout/chameleon/go.mod"
printf 'checksum\n' > "${TMP}/source-checkout/chameleon/go.sum"
chmod 0755 "${TMP}/source-checkout/chameleon/build.sh"
chmod 0755 "${TMP}/source-checkout/chameleon/ensure-go.sh"
chmod 0755 "${TMP}/source-checkout/chameleon/tools/prepare_http2_modfile.sh"
checkout_uid="$(id -u)"
if [[ "${checkout_uid}" == "0" ]]; then
  # CI commonly runs this test as root. Give the checkout a synthetic
  # non-root SUDO_UID so this remains a real ownership regression test.
  checkout_uid=12345
  chown -R "${checkout_uid}" "${TMP}/source-checkout"
fi
checkout_mode="$(bash "${INPUT_CHECKER}" \
  "${TMP}/source-checkout" amd64 "${checkout_uid}")"
[[ "${checkout_mode}" == "build" ]] || {
  echo "trusted source checkout was not accepted for build" >&2
  exit 1
}
rm "${TMP}/source-checkout/chameleon/build.sh"
expect_rejected 66 file "${TMP}/source-checkout/chameleon/build.sh" "${checkout_uid}"
if bash "${INPUT_CHECKER}" \
    "${TMP}/source-checkout" amd64 "${checkout_uid}" >/dev/null 2>&1; then
  echo "incomplete source checkout was accepted without build.sh" >&2
  exit 1
fi

# Ownership/mode checks are exercised according to the current test identity.
if [[ "$(id -u)" == "0" ]]; then
  chmod 0664 "${TMP}/payload"
  expect_rejected 68 file "${TMP}/payload"
else
  chmod 0644 "${TMP}/payload"
  expect_rejected 67 file "${TMP}/payload"
  # The explicitly selected administrative source owner is accepted, while
  # the default root-only destination policy above still rejects this file.
  bash "${CHECKER}" file "${TMP}/payload" "$(id -u)"
fi

echo "trusted install path and Chameleon input tests passed"
