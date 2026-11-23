#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

usage() {
  echo "Usage: $0 [-y|--yes]"
}

if [[ "${1:-}" == "-h" || "${1:-}" == "--help" ]]; then
  usage
  exit 0
fi

if [[ "${1:-}" != "-y" && "${1:-}" != "--yes" ]]; then
  cat <<'EOF'
This will remove local data, tokens, and databases from this repo.
It does NOT modify source code.
EOF
  read -r -p "Continue? [y/N] " confirm
  case "$confirm" in
    y|Y|yes|YES) ;;
    *) echo "Canceled."; exit 1 ;;
  esac
fi

info() {
  printf '[clean] %s\n' "$*"
}

clean_dir_except() {
  local dir="$1"
  shift
  local keep_paths=("$@")

  if [[ ! -d "$dir" ]]; then
    return
  fi

  local find_args=(-mindepth 1)
  for keep in "${keep_paths[@]}"; do
    find_args+=( ! -path "$keep" )
  done

  while IFS= read -r -d '' item; do
    rm -rf -- "$item"
    info "Removed $item"
  done < <(find "$dir" "${find_args[@]}" -print0)
}

mkdir -p "$ROOT_DIR/data" "$ROOT_DIR/backend/data" "$ROOT_DIR/backend/app/data" "$ROOT_DIR/logs"

clean_dir_except "$ROOT_DIR/data" "$ROOT_DIR/data/services.json"
clean_dir_except "$ROOT_DIR/backend/data" "$ROOT_DIR/backend/data/services.json" "$ROOT_DIR/backend/data/default_avatar.png"
clean_dir_except "$ROOT_DIR/backend/app/data"
clean_dir_except "$ROOT_DIR/logs"

while IFS= read -r -d '' file; do
  rm -f -- "$file"
  info "Removed $file"
done < <(find "$ROOT_DIR" -type f -name '*.db' -not -path '*/node_modules/*' -print0)

while IFS= read -r -d '' file; do
  rm -f -- "$file"
  info "Removed $file"
done < <(find "$ROOT_DIR" -type f -name '.setup_token' -not -path '*/node_modules/*' -print0)

while IFS= read -r -d '' file; do
  rm -f -- "$file"
  info "Removed $file"
done < <(find "$ROOT_DIR" -type f -name '*.env' ! -name '.env.example' -not -path '*/node_modules/*' -print0)

info "Done."
