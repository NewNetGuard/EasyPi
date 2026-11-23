#!/usr/bin/env bash
# Stage only the reviewed Chameleon source needed for an installation-time
# build. Generated executables and local toolchain/module caches are excluded.
set -euo pipefail

source_dir="${1:-}"
destination="${2:-}"
[[ -n "${source_dir}" && -n "${destination}" ]] || {
  echo "usage: $0 CHAMELEON_SOURCE RELEASE_DESTINATION" >&2
  exit 64
}
[[ -d "${source_dir}" && ! -L "${source_dir}" ]] || {
  echo "invalid Chameleon source directory" >&2
  exit 65
}
[[ ! -e "${destination}" && ! -L "${destination}" ]] || {
  echo "Chameleon release destination already exists" >&2
  exit 66
}

repo_root="$(git -C "${source_dir}" rev-parse --show-toplevel 2>/dev/null)" || {
  echo "Chameleon source must belong to a Git checkout" >&2
  exit 67
}
repo_root="$(realpath -e -- "${repo_root}")"
source_dir="$(realpath -e -- "${source_dir}")"
[[ "${source_dir}" == "${repo_root}/chameleon" ]] || {
  echo "Chameleon source must be the checkout's chameleon directory" >&2
  exit 68
}
[[ -z "$(git -C "${repo_root}" status --porcelain=v1 --untracked-files=all)" ]] || {
  echo "refusing to stage Chameleon from a dirty Git working tree" >&2
  exit 69
}
if git -C "${repo_root}" ls-files --stage -- chameleon \
    | awk '$1 == "120000" { found=1 } END { exit(found ? 0 : 1) }'; then
  echo "tracked Chameleon symbolic links are forbidden" >&2
  exit 70
fi

destination_parent="$(dirname -- "${destination}")"
mkdir -p "${destination_parent}"
temporary="$(mktemp -d "${destination}.tmp.XXXXXX")"
cleanup() { rm -rf -- "${temporary}"; }
trap cleanup EXIT HUP INT TERM

# Archive HEAD rather than copying the working directory. This includes only
# committed Git objects and makes the bytes entering the release auditable.
git -C "${repo_root}" archive --format=tar HEAD:chameleon \
  | tar -xf - -C "${temporary}"

for source_file in build.sh ensure-go.sh go.mod go.sum README.md; do
  [[ -f "${temporary}/${source_file}" && ! -L "${temporary}/${source_file}" ]] || {
    echo "required Chameleon source file missing or unsafe: ${source_file}" >&2
    exit 71
  }
done
for source_subdir in clientcore cmd mobilelink server shared tools; do
  [[ -d "${temporary}/${source_subdir}" && ! -L "${temporary}/${source_subdir}" ]] || {
    echo "required Chameleon source directory missing or unsafe: ${source_subdir}" >&2
    exit 72
  }
done

if find "${temporary}" -type l -print -quit | grep -q .; then
  echo "Chameleon source contains a symbolic link" >&2
  exit 73
fi
[[ ! -e "${temporary}/bin" ]] || {
  echo "prebuilt Chameleon binaries entered the release" >&2
  exit 74
}

# Normalize sources copied from Windows or unusual worktrees. The privileged
# installer rejects group/other-writable inputs before compiling them as root.
find "${temporary}" -type d -exec chmod 0755 {} +
find "${temporary}" -type f -exec chmod 0644 {} +
chmod 0755 \
  "${temporary}/build.sh" \
  "${temporary}/ensure-go.sh" \
  "${temporary}/tools/prepare_http2_modfile.sh"
mv -- "${temporary}" "${destination}"
trap - EXIT HUP INT TERM
