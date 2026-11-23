#!/usr/bin/env bash
# Validate the Chameleon source and any existing outputs required by the current
# architecture. install.sh always rebuilds from this source; "ready" only means
# existing outputs are safe to replace, while "build" means they are absent.
set -euo pipefail

base_dir="${1:-}"
architecture="${2:-}"
trusted_source_uid="${3:-0}"

[[ -n "${base_dir}" && -n "${architecture}" ]] || {
  echo "usage: $0 BASE_DIR ARCHITECTURE [TRUSTED_SOURCE_UID]" >&2
  exit 64
}
[[ "${trusted_source_uid}" =~ ^[0-9]+$ ]] || {
  echo "chameleon-inputs: trusted UID must be numeric" >&2
  exit 64
}

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
checker="${script_dir}/verify_trusted_install_path.sh"
[[ -f "${checker}" && ! -L "${checker}" ]] || {
  echo "chameleon-inputs: trusted path checker is missing or unsafe" >&2
  exit 65
}

case "${architecture}" in
  aarch64|arm64) client_name="chameleon-client-arm64"; mobile_agent_name="chameleon-mobile-link-agent-arm64" ;;
  x86_64|amd64) client_name="chameleon-client-amd64"; mobile_agent_name="chameleon-mobile-link-agent-amd64" ;;
  *) echo "chameleon-inputs: unsupported architecture: ${architecture}" >&2; exit 66 ;;
esac

chameleon_dir="${base_dir}/chameleon"
bin_dir="${chameleon_dir}/bin"
server_path="${bin_dir}/chameleon-server-amd64"
client_path="${bin_dir}/${client_name}"
mobile_agent_path="${bin_dir}/${mobile_agent_name}"
mobile_relay_path="${bin_dir}/chameleon-mobile-link-relay-amd64"

bash "${checker}" directory "${chameleon_dir}" "${trusted_source_uid}"

# The installer executes the build as root. Validate every source input and
# every path component, and never accept a binary-only release. bin/ is build
# output and is checked separately below.
for required_file in build.sh ensure-go.sh go.mod go.sum tools/prepare_http2_modfile.sh; do
  bash "${checker}" file "${chameleon_dir}/${required_file}" "${trusted_source_uid}"
done
for required_dir in clientcore cmd mobilelink server shared tools; do
  bash "${checker}" directory "${chameleon_dir}/${required_dir}" "${trusted_source_uid}"
done
while IFS= read -r -d '' source_path; do
  case "${source_path}" in
    "${bin_dir}"|"${bin_dir}"/*) continue ;;
  esac
  if [[ -d "${source_path}" && ! -L "${source_path}" ]]; then
    source_kind=directory
  else
    source_kind=file
  fi
  bash "${checker}" "${source_kind}" "${source_path}" "${trusted_source_uid}"
done < <(find "${chameleon_dir}" -mindepth 1 -print0)

ready=1
for binary_path in "${server_path}" "${client_path}" "${mobile_agent_path}" "${mobile_relay_path}"; do
  if [[ -e "${binary_path}" || -L "${binary_path}" ]]; then
    bash "${checker}" file "${binary_path}" "${trusted_source_uid}"
    [[ -s "${binary_path}" ]] || ready=0
  else
    ready=0
  fi
done

if [[ "${ready}" == "1" ]]; then
  printf 'ready\n'
  exit 0
fi

if [[ -e "${bin_dir}" || -L "${bin_dir}" ]]; then
  bash "${checker}" directory "${bin_dir}" "${trusted_source_uid}"
fi
printf 'build\n'
