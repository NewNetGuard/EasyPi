#!/usr/bin/env bash
set -euo pipefail

# Color helpers for readable output
GREEN="\033[0;32m"
YELLOW="\033[0;33m"
RED="\033[0;31m"
NC="\033[0m"
BACKUP_TIMESTAMP="$(date +%Y%m%d-%H%M%S)"

info() {
  echo -e "${GREEN}==>${NC} $1"
}

warn() {
  echo -e "${YELLOW}==>${NC} $1"
}

error() {
  echo -e "${RED}==>${NC} $1"
}

die() {
  error "$1" >&2
  exit 1
}

# Bootstrap trust check implemented inside the already-running installer.
# It is used before any helper from the checkout is executed, preventing a
# writable parent directory from swapping a checked helper under root.
verify_bootstrap_trusted_file() {
  local path="$1"
  local trusted_uid="${2:-0}"
  local lexical physical current owner mode

  [[ "${trusted_uid}" =~ ^[0-9]+$ ]] || return 64
  [[ -f "${path}" && ! -L "${path}" ]] || return 65
  lexical="$(realpath -sm -- "${path}")" || return 65
  physical="$(realpath -e -- "${path}")" || return 65
  [[ "${lexical}" == "${physical}" ]] || return 65

  current="${physical}"
  while :; do
    owner="$(stat -c '%u' -- "${current}")" || return 66
    mode="$(stat -c '%a' -- "${current}")" || return 66
    [[ "${owner}" == "0" || "${owner}" == "${trusted_uid}" ]] || return 67
    if (( (8#${mode} & 8#022) != 0 )); then
      # Only a root-owned sticky parent such as /tmp is an acceptable writable
      # boundary. The file itself is never allowed to be group/other writable.
      if [[ "${current}" == "${physical}" ]] \
          || [[ "${owner}" != "0" ]] \
          || (( (8#${mode} & 8#1000) == 0 )); then
        return 68
      fi
    fi
    [[ "${current}" == "/" ]] && break
    current="$(dirname -- "${current}")"
  done
}

# Temporary resolv.conf override (for installs where Tailscale DNS breaks resolution).
RESOLV_CONF_BACKUP=""
RESOLV_CONF_LINK_TARGET=""
RESOLV_CONF_TEMP_APPLIED=0

backup_resolv_conf() {
  if [[ -n "${RESOLV_CONF_BACKUP}" ]]; then
    return 0
  fi
  RESOLV_CONF_BACKUP="$(mktemp /tmp/easypi-resolv.XXXXXX)"
  cat /etc/resolv.conf > "${RESOLV_CONF_BACKUP}" 2>/dev/null || true
  if [[ -L /etc/resolv.conf ]]; then
    RESOLV_CONF_LINK_TARGET="$(readlink /etc/resolv.conf 2>/dev/null || true)"
  fi
}

apply_temp_resolv_conf() {
  backup_resolv_conf
  printf "nameserver 1.1.1.1\nnameserver 8.8.8.8\n" > /etc/resolv.conf
  RESOLV_CONF_TEMP_APPLIED=1
}

restore_resolv_conf() {
  if [[ "${RESOLV_CONF_TEMP_APPLIED}" != "1" ]]; then
    return 0
  fi
  if [[ -n "${RESOLV_CONF_LINK_TARGET}" ]]; then
    ln -sf "${RESOLV_CONF_LINK_TARGET}" /etc/resolv.conf || true
    return 0
  fi
  if [[ -n "${RESOLV_CONF_BACKUP}" && -f "${RESOLV_CONF_BACKUP}" ]]; then
    cat "${RESOLV_CONF_BACKUP}" > /etc/resolv.conf || true
  fi
}

trap restore_resolv_conf EXIT

# Ensure DNS works even if Tailscale is managing resolv.conf.
ensure_dns_resolution() {
  local test_host="${DNS_TEST_HOST:-deb.debian.org}"

  if getent hosts "${test_host}" >/dev/null 2>&1; then
    return 0
  fi

  if grep -qi "tailscale" /etc/resolv.conf 2>/dev/null; then
    if command -v tailscale >/dev/null 2>&1; then
      warn "Detected Tailscale DNS override. Disabling accept-dns for install..."
      tailscale set --accept-dns=false >/dev/null 2>&1 || true
      sleep 1
    fi
  fi

  if getent hosts "${test_host}" >/dev/null 2>&1; then
    return 0
  fi

  warn "DNS resolution still failing; applying temporary resolv.conf"
  apply_temp_resolv_conf
}

# Helper to extract values from .env
extract_env() {
  local key=$1
  local default=$2
  local env_file="${EASYPI_PREFIX}/.env"
  if [[ ! -f "${env_file}" ]]; then
    env_file="${BASE_DIR}/backend/.env"
  fi
  
  if [[ -f "${env_file}" ]]; then
    # Use grep -a to handle potential encoding issues and cut carefully
    local val=$(grep "^${key}=" "${env_file}" | cut -d'=' -f2- | sed -e 's/^"//' -e 's/"$//' -e "s/^'//" -e "s/'$//")
    if [[ -n "${val}" ]]; then
      echo "${val}"
      return
    fi
  fi
  echo "${default}"
}

sanitize_env_inline_comments() {
  local env_file="$1"
  if [[ -f "${env_file}" ]]; then
    # Strip inline comments only for numeric values (avoids clobbering secrets/URLs).
    sed -E -i 's/^([A-Z0-9_]+=([0-9]+))[[:space:]]+#.*$/\1/' "${env_file}"
  fi
}

backup_path_if_exists() {
  local path="$1"
  if [[ -e "${path}" || -L "${path}" ]]; then
    local backup_path="${path}.bak-${BACKUP_TIMESTAMP}"
    if [[ ! -e "${backup_path}" && ! -L "${backup_path}" ]]; then
      cp -a "${path}" "${backup_path}"
      info "Backup created: ${backup_path}"
    fi
  fi
}

version_gt() {
  local lhs="$1"
  local rhs="$2"
  [[ "$(printf '%s\n%s\n' "${lhs}" "${rhs}" | sort -V | tail -n1)" == "${lhs}" && "${lhs}" != "${rhs}" ]]
}

canonical_release_arch() {
  case "${1,,}" in
    aarch64|arm64) echo "aarch64" ;;
    *) echo "${1,,}" ;;
  esac
}

read_release_metadata_value() {
  local metadata_file="$1"
  local key="$2"
  awk -v wanted="${key}" '
    index($0, wanted ":") == 1 {
      value = substr($0, length(wanted) + 2)
      sub(/^[[:space:]]+/, "", value)
      sub(/[[:space:]]+$/, "", value)
    }
    END { print value }
  ' "${metadata_file}"
}

check_binary_release_compatibility() {
  if [[ "${BINARY_MODE}" != "true" ]]; then
    return 0
  fi

  local host_arch
  host_arch="$(canonical_release_arch "$(uname -m)")"
  local os_codename="${VERSION_CODENAME:-unknown}"
  os_codename="${os_codename,,}"
  local build_info_file="${BASE_DIR}/BUILD_INFO"
  local version_file="${BASE_DIR}/VERSION"
  local metadata_file=""
  local metadata_kind="none"
  local release_arch=""
  local release_codename=""
  local release_glibc=""

  if [[ "${host_arch}" != "aarch64" ]]; then
    error "Binary release currently supports only aarch64 (ARM64). Detected: ${host_arch}"
    error "Use the matching release artifact for your architecture."
    exit 1
  fi

  if [[ -e "${build_info_file}" || -L "${build_info_file}" ]]; then
    if [[ ! -f "${build_info_file}" || -L "${build_info_file}" ]]; then
      error "Release BUILD_INFO must be a regular, non-symlink file."
      exit 1
    fi
    metadata_file="${build_info_file}"
    metadata_kind="build-info"
  elif [[ -e "${version_file}" || -L "${version_file}" ]]; then
    if [[ ! -f "${version_file}" || -L "${version_file}" ]]; then
      error "Release VERSION must be a regular, non-symlink file."
      exit 1
    fi
    # Backward compatibility for archives created before VERSION became a
    # SemVer-only file and build metadata moved to BUILD_INFO.
    if grep -aqE '^(Architecture|Build distro codename|Build glibc):' "${version_file}"; then
      metadata_file="${version_file}"
      metadata_kind="legacy-version"
      warn "Legacy release metadata found in VERSION; use a release with BUILD_INFO when available."
    else
      warn "Legacy binary release has no BUILD_INFO; declared build compatibility checks are limited."
    fi
  fi

  if [[ -n "${metadata_file}" ]]; then
    release_arch="$(read_release_metadata_value "${metadata_file}" "Architecture")"
    release_codename="$(read_release_metadata_value "${metadata_file}" "Build distro codename")"
    release_glibc="$(read_release_metadata_value "${metadata_file}" "Build glibc")"

    if [[ "${metadata_kind}" == "build-info" ]] \
        && [[ -z "${release_arch}" || -z "${release_codename}" || -z "${release_glibc}" ]]; then
      error "Release BUILD_INFO is incomplete."
      exit 1
    fi
    if [[ -n "${release_arch}" && ! "${release_arch}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
      error "Release BUILD_INFO contains an invalid architecture."
      exit 1
    fi
    if [[ -n "${release_codename}" && ! "${release_codename}" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]]; then
      error "Release BUILD_INFO contains an invalid distro codename."
      exit 1
    fi
    if [[ -n "${release_glibc}" && "${release_glibc}" != "unknown" \
        && ! "${release_glibc}" =~ ^[0-9]+([.][0-9]+)+$ ]]; then
      error "Release BUILD_INFO contains an invalid glibc version."
      exit 1
    fi
  fi

  [[ -n "${release_arch}" ]] && release_arch="$(canonical_release_arch "${release_arch}")"
  release_codename="${release_codename,,}"

  if [[ -n "${release_arch}" && "${release_arch}" != "${host_arch}" ]]; then
    error "Release architecture mismatch: package=${release_arch}, system=${host_arch}"
    exit 1
  fi

  if [[ -n "${release_codename}" && "${release_codename}" != "unknown" && "${os_codename}" != "unknown" && "${release_codename}" != "${os_codename}" ]]; then
    error "OS codename mismatch: package=${release_codename}, system=${os_codename}"
    error "Download the release artifact built for ${os_codename}."
    exit 1
  fi

  local system_glibc=""
  system_glibc="$(ldd --version 2>/dev/null | head -n1 | grep -oE '[0-9]+([.][0-9]+)+' | head -n1 || true)"
  if [[ -n "${release_glibc}" && -n "${system_glibc}" ]] && version_gt "${release_glibc}" "${system_glibc}"; then
    error "glibc mismatch: package requires ${release_glibc}, system has ${system_glibc}"
    error "Download the matching release for your OS codename."
    exit 1
  fi

  local binary_path="${BASE_DIR}/backend/bin/easypi-backend"
  if [[ -f "${binary_path}" ]] && command -v strings >/dev/null 2>&1 && [[ -n "${system_glibc}" ]]; then
    local required_glibc=""
    required_glibc="$(strings "${binary_path}" | grep -oE 'GLIBC_[0-9]+([.][0-9]+)+' | sed 's/GLIBC_//' | sort -V | tail -n1 || true)"
    if [[ -n "${required_glibc}" ]] && version_gt "${required_glibc}" "${system_glibc}"; then
      error "Backend binary requires glibc ${required_glibc}, but system has ${system_glibc}"
      error "Install a release built for your OS (Bookworm vs Trixie)."
      exit 1
    fi
  fi
}

# Helper to wait for HTTP service
wait_for_http() {
  local name=$1
  local url=$2
  local timeout=${3:-30}
  info "Waiting for ${name} at ${url}..."
  for i in $(seq 1 ${timeout}); do
    if curl -s -f "${url}" >/dev/null 2>&1; then
      info "${name} is up!"
      return 0
    fi
    sleep 1
  done
  warn "${name} did not start within ${timeout} seconds"
  return 1
}

secure_runtime_venv() {
  local venv_path="$1"
  [[ -d "${venv_path}" && ! -L "${venv_path}" ]] ||
    die "Runtime virtual environment is missing or unsafe: ${venv_path}"

  # pip runs as root during installation. Keep the environment immutable to the
  # service account while allowing the dedicated EasyPi group to traverse its
  # directories and execute the interpreter and installed entrypoints.
  chown -R root:"${EASYPI_GROUP}" "${venv_path}"
  find "${venv_path}" -type d -exec chmod 0750 {} +
  find "${venv_path}" -type f -exec chmod 0640 {} +
  # A previous installer or interrupted permission sweep may have removed the
  # execute bit from console entrypoints while leaving the venv otherwise
  # valid. Restore Python binaries and shebang entrypoints without making
  # activation snippets and other data files executable.
  local entrypoint entrypoint_name entrypoint_magic
  while IFS= read -r -d '' entrypoint; do
    entrypoint_name="${entrypoint##*/}"
    entrypoint_magic="$(head -c 2 -- "${entrypoint}" 2>/dev/null || true)"
    if [[ "${entrypoint_name}" == "python" \
        || "${entrypoint_name}" =~ ^python[0-9]+([.][0-9]+)?$ \
        || "${entrypoint_magic}" == '#!' ]]; then
      chmod 0750 "${entrypoint}"
    fi
  done < <(find "${venv_path}/bin" -maxdepth 1 -type f -print0)
}

deploy_backend_code() {
  info "Backend code already deployed via deploy_runner_scripts"
}

bootstrap_env() {
  local target_env="${EASYPI_PREFIX}/.env"
  if [[ -f "${target_env}" ]]; then
    backup_path_if_exists "${target_env}"
  fi
  if [[ ! -f "${target_env}" ]]; then
    info "Creating default .env from example"
    if [[ -f "${BASE_DIR}/.env.example" ]]; then
      cp "${BASE_DIR}/.env.example" "${target_env}"
    else
      warn ".env.example not found, creating minimal .env"
      cat <<EOF > "${target_env}"
API_PORT=8000
FRONTEND_PORT=4173
DATABASE_URL=sqlite:///./data/db/easypi.db
SECRET_KEY=$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')
EOF
    fi
  fi

  # Re-apply restrictive permissions on upgrades as well. The deployment
  # permission sweep must never leave existing secrets world-readable.
  chown root:"${EASYPI_GROUP}" "${target_env}"
  chmod 640 "${target_env}"

  sanitize_env_inline_comments "${target_env}"

  # Ensure DATABASE_URL is set (required for backend)
  if ! grep -q "DATABASE_URL=" "${target_env}"; then
    echo "DATABASE_URL=sqlite:///./data/db/easypi.db" >> "${target_env}"
  fi

  # Fix legacy/invalid SQLite path (../data/db) to ensure DB is writable
  local db_url
  db_url="$(extract_env "DATABASE_URL" "")"
  if [[ "${db_url}" == "sqlite:///../data/db/easypi.db" ]]; then
    if grep -q "^DATABASE_URL=" "${target_env}"; then
      sed -i "s|^DATABASE_URL=.*|DATABASE_URL=sqlite:///./data/db/easypi.db|" "${target_env}"
    else
      echo "DATABASE_URL=sqlite:///./data/db/easypi.db" >> "${target_env}"
    fi
    info "Updated DATABASE_URL to sqlite:///./data/db/easypi.db"
  fi

  # Ensure SECRET_KEY is strong enough for production
  local secret_val
  secret_val="$(extract_env "SECRET_KEY" "")"
  if [[ -z "${secret_val}" || "${secret_val}" == "change_me_32_bytes_min" || ${#secret_val} -lt 32 ]]; then
    local new_secret
    new_secret="$(python3 -c 'import secrets; print(secrets.token_urlsafe(32))')"
    if grep -q "^SECRET_KEY=" "${target_env}"; then
      sed -i "s|^SECRET_KEY=.*|SECRET_KEY=${new_secret}|" "${target_env}"
    else
      echo "SECRET_KEY=${new_secret}" >> "${target_env}"
    fi
    info "Generated SECRET_KEY in ${target_env}"
  fi
}

setup_frontend() {
  # Check if pre-built frontend exists (binary release)
  local frontend_dist="${EASYPI_PREFIX}/frontend/dist"
  if [[ -d "${frontend_dist}" && -f "${frontend_dist}/index.html" ]]; then
    info "Pre-built frontend found at ${frontend_dist}, skipping build"
    return 0
  fi
  
  command -v npm >/dev/null 2>&1 || error \
    "Node.js/npm is required when the signed release does not contain frontend/dist."
  command -v runuser >/dev/null 2>&1 || error \
    "runuser is required for the unprivileged frontend build."

  local frontend_dir="${BASE_DIR}/frontend"
  [[ -f "${frontend_dir}/package.json" ]] || error \
    "Frontend package.json is missing from the release."
  [[ -f "${frontend_dir}/package-lock.json" ]] || error \
    "Frontend package-lock.json is mandatory; refusing unpinned dependency resolution."

  local build_user="easypi-build"
  local build_group="easypi-build"
  local created_build_user=0
  if id -u "${build_user}" >/dev/null 2>&1; then
    [[ "$(id -u "${build_user}")" != "0" ]] || error \
      "Refusing unsafe pre-existing ${build_user} account."
    [[ "$(id -nG "${build_user}")" == "${build_group}" ]] || error \
      "Refusing pre-existing ${build_user} account with additional groups."
  else
    getent group "${build_group}" >/dev/null 2>&1 || groupadd --system "${build_group}"
    useradd --system --gid "${build_group}" --home-dir /nonexistent \
      --no-create-home --shell /usr/sbin/nologin "${build_user}"
    created_build_user=1
  fi

  info "Building Frontend from the signed npm lock as ${build_user}..."
  local build_dir
  build_dir="$(mktemp -d /var/tmp/easypi-frontend-build.XXXXXX)"
  # Build from a disposable copy: npm lifecycle scripts cannot modify the
  # signed source tree, and they never execute with root privileges.
  cp -a "${frontend_dir}/." "${build_dir}/"
  rm -rf -- "${build_dir}/node_modules" "${build_dir}/dist"
  chown -R "${build_user}:${build_group}" "${build_dir}"

  if ! runuser -u "${build_user}" -- env \
      HOME="${build_dir}" npm_config_cache="${build_dir}/.npm-cache" \
      npm --prefix "${build_dir}" ci --silent --include=optional; then
    rm -rf -- "${build_dir}"
    if (( created_build_user )); then
      userdel "${build_user}" 2>/dev/null || true
      groupdel "${build_group}" 2>/dev/null || true
    fi
    error "npm ci failed; refusing to alter the signed lock or resolve unpinned dependencies."
  fi

  info "Running vite build..."
  if ! runuser -u "${build_user}" -- env \
      HOME="${build_dir}" npm_config_cache="${build_dir}/.npm-cache" \
      npm --prefix "${build_dir}" run build; then
    rm -rf -- "${build_dir}"
    if (( created_build_user )); then
      userdel "${build_user}" 2>/dev/null || true
      groupdel "${build_group}" 2>/dev/null || true
    fi
    error "Frontend build failed; installation stopped without changing package-lock.json."
  fi
  [[ -f "${build_dir}/dist/index.html" ]] || {
    rm -rf -- "${build_dir}"
    if (( created_build_user )); then
      userdel "${build_user}" 2>/dev/null || true
      groupdel "${build_group}" 2>/dev/null || true
    fi
    error "Frontend build produced no dist/index.html."
  }

  rm -rf -- "${frontend_dir}/dist"
  install -d -o root -g root -m 0755 "${frontend_dir}/dist"
  cp -a "${build_dir}/dist/." "${frontend_dir}/dist/"
  chown -R root:root "${frontend_dir}/dist"
  find "${frontend_dir}/dist" -type d -exec chmod 0755 {} \;
  find "${frontend_dir}/dist" -type f -exec chmod 0644 {} \;
  rm -rf -- "${build_dir}"
  if (( created_build_user )); then
    userdel "${build_user}" 2>/dev/null || true
    groupdel "${build_group}" 2>/dev/null || true
  fi
  info "Frontend built at ${frontend_dir}/dist"
}

setup_nginx() {
  info "Setting up Nginx with HTTPS..."
  
  # Install nginx if not present
  if ! command -v nginx >/dev/null; then
    info "Installing nginx..."
    apt-get install -y nginx
  fi
  
  # Generate SSL certificate. Prefer the local-CA path (per-install Root CA + CA-signed
  # server cert): users import ca.pem once and the panel is trusted (no "Proceed unsafe").
  if [[ -f "${BASE_DIR}/scripts/setup/generate_certs.sh" ]]; then
    info "Generating CA-signed certificate (local EasyPi Root CA)..."
    EASYPI_CERT_DIR="${EASYPI_PREFIX}/certs" bash "${BASE_DIR}/scripts/setup/generate_certs.sh" ca-signed || warn "CA cert generation failed"
    # Publish ca.pem for one-time trust install via https://<pi>/ca.pem
    if [[ ! -f "${EASYPI_PREFIX}/certs/.letsencrypt" \
        && -f "${EASYPI_PREFIX}/certs/ca.pem" \
        && -d "${EASYPI_PREFIX}/frontend/dist" ]]; then
      install -m 0644 "${EASYPI_PREFIX}/certs/ca.pem" "${EASYPI_PREFIX}/frontend/dist/ca.pem" || true
    fi
  elif [[ -f "${BASE_DIR}/scripts/setup/generate_ssl_cert.sh" ]]; then
    info "Generating SSL certificate..."
    bash "${BASE_DIR}/scripts/setup/generate_ssl_cert.sh"
  else
    warn "SSL cert script not found, creating inline..."
    # Inline certificate generation
    if [[ ! -f "/etc/ssl/certs/easypi-selfsigned.crt" ]]; then
      local ssl_days="${EASYPI_SSL_DAYS:-36500}"
      HOSTNAME=$(hostname -f 2>/dev/null || hostname)
      LOCAL_IP=$(hostname -I | awk '{print $1}')
      openssl req -x509 -nodes -days "${ssl_days}" \
        -newkey rsa:2048 \
        -keyout "/etc/ssl/private/easypi-selfsigned.key" \
        -out "/etc/ssl/certs/easypi-selfsigned.crt" \
        -subj "/CN=${HOSTNAME}/O=EasyPi/C=US" \
        -addext "subjectAltName=DNS:${HOSTNAME},DNS:easypi.local,DNS:localhost,IP:${LOCAL_IP},IP:127.0.0.1" 2>/dev/null || true
      chmod 644 /etc/ssl/certs/easypi-selfsigned.crt
      chmod 600 /etc/ssl/private/easypi-selfsigned.key
    fi
  fi

  if [[ -f "${BASE_DIR}/scripts/settings/generate_tls_certs.sh" ]]; then
    info "Ensuring NetProtection TLS certificates..."
    if ! EASYPI_USER="${EASYPI_USER}" EASYPI_GROUP="${EASYPI_GROUP}" \
      bash "${BASE_DIR}/scripts/settings/generate_tls_certs.sh" "/opt/EasyPi/certs"; then
      warn "NetProtection TLS certificate generation failed"
    fi
  fi
  
  # Copy frontend dist to /opt/EasyPi if built elsewhere (skip if already in place)
  local src_frontend="${BASE_DIR}/frontend/dist"
  local dst_frontend="${EASYPI_PREFIX}/frontend/dist"
  
  if [[ -d "${src_frontend}" ]]; then
    if [[ "$(realpath "${src_frontend}" 2>/dev/null)" != "$(realpath "${dst_frontend}" 2>/dev/null)" ]]; then
      info "Deploying frontend files to ${dst_frontend}..."
      mkdir -p "${dst_frontend}"
      cp -rf "${src_frontend}/"* "${dst_frontend}/"
      chmod -R 755 "${EASYPI_PREFIX}/frontend"
      chown -R "${EASYPI_USER}:${EASYPI_GROUP}" "${EASYPI_PREFIX}/frontend"
    else
      info "Frontend already in target location, skipping copy"
    fi
  elif [[ -d "${BASE_DIR}/frontend" ]] && [[ -f "${BASE_DIR}/frontend/index.html" ]]; then
    # Binary release - frontend files directly in frontend folder
    if [[ "$(realpath "${BASE_DIR}/frontend" 2>/dev/null)" != "$(realpath "${dst_frontend}" 2>/dev/null)" ]]; then
      info "Deploying frontend files (binary release) to ${dst_frontend}..."
      mkdir -p "${dst_frontend}"
      cp -rf "${BASE_DIR}/frontend/"* "${dst_frontend}/"
      chmod -R 755 "${EASYPI_PREFIX}/frontend"
      chown -R "${EASYPI_USER}:${EASYPI_GROUP}" "${EASYPI_PREFIX}/frontend"
    else
      info "Frontend already in target location, skipping copy"
    fi
  fi

  local src_help_catalog="${BASE_DIR}/frontend/src/data/helpContent.ts"
  local dst_help_catalog="${EASYPI_PREFIX}/frontend/src/data/helpContent.ts"
  if [[ -f "${src_help_catalog}" ]]; then
    if [[ "$(realpath "${src_help_catalog}" 2>/dev/null)" != "$(realpath "${dst_help_catalog}" 2>/dev/null)" ]]; then
      mkdir -p "$(dirname "${dst_help_catalog}")"
      cp "${src_help_catalog}" "${dst_help_catalog}"
      chmod 644 "${dst_help_catalog}"
      chown "${EASYPI_USER}:${EASYPI_GROUP}" "${dst_help_catalog}"
    fi
  fi
  
  # Deploy nginx configuration
  if [[ -f "${BASE_DIR}/templates/nginx/easypi.conf" ]]; then
    info "Installing nginx configuration..."
    backup_path_if_exists "/etc/nginx/sites-available/easypi"
    cp "${BASE_DIR}/templates/nginx/easypi.conf" "/etc/nginx/sites-available/easypi"
    sed -i "s|/opt/EasyPi|${EASYPI_PREFIX}|g" "/etc/nginx/sites-available/easypi"
    
    # Enable site
    ln -sf /etc/nginx/sites-available/easypi /etc/nginx/sites-enabled/easypi
    
    # Remove default site if exists
    rm -f /etc/nginx/sites-enabled/default 2>/dev/null || true
    
    # Test and reload nginx
    if nginx -t 2>/dev/null; then
      systemctl enable nginx
      systemctl reload nginx || systemctl restart nginx
      info "Nginx configured and running!"
    else
      warn "Nginx configuration test failed. Check: nginx -t"
    fi
  else
    warn "Nginx config template not found at ${BASE_DIR}/templates/nginx/easypi.conf"
  fi
}

if [[ "${EUID}" -ne 0 ]]; then
  error "Please run this script with sudo or as root."
  exit 1
fi

# Parse command line arguments
BINARY_MODE=false
for arg in "$@"; do
  case "$arg" in
    --binary)
      BINARY_MODE=true
      ;;
  esac
done

BASE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="${BASE_DIR}/logs"
mkdir -p "${LOG_DIR}"
LOG_FILE="${LOG_DIR}/install-$(date +%F).log"
EASYPI_USER="easypi"
EASYPI_GROUP="easypi"
CHAMELEON_USER="easypi-chameleon"
CHAMELEON_GROUP="easypi-chameleon"
MOBILE_LINK_USER="easypi-mobile-link"
MOBILE_LINK_GROUP="easypi-mobile-link"
STEALTH_DNS_USER="easypi-stealth-dns"
STEALTH_DNS_GROUP="easypi-stealth-dns"
EASYPI_PREFIX="${EASYPI_PREFIX:-/opt/EasyPi}"
SCRIPTS_DST="${EASYPI_PREFIX}/scripts"
LOGS_DST="${EASYPI_PREFIX}/logs"
TASK_LOGS_DIR="${LOGS_DST}/tasks"
EASYPI_INSTALLATION_PREEXISTED=0
if [[ -f /etc/systemd/system/easypi-backend.service ]]; then
  EASYPI_INSTALLATION_PREEXISTED=1
fi
# Find runner script (with or without .sh extension)
if [[ -f "${BASE_DIR}/scripts/runner" ]]; then
  RUNNER_SRC="${BASE_DIR}/scripts/runner"
elif [[ -f "${BASE_DIR}/scripts/runner.sh" ]]; then
  RUNNER_SRC="${BASE_DIR}/scripts/runner.sh"
else
  RUNNER_SRC="${BASE_DIR}/scripts/runner"  # fallback
fi
SUDOERS_FILE="/etc/sudoers.d/easypi"

# Log everything to file as well as stdout
exec > >(tee -a "${LOG_FILE}") 2>&1

info "Starting EasyPi installation"

if [[ -f /etc/os-release ]]; then
  # shellcheck disable=SC1091
  source /etc/os-release
  OS_ID="${ID:-}"
  OS_ID_LIKE="${ID_LIKE:-}"
else
  error "Cannot detect operating system. /etc/os-release not found."
  exit 1
fi

if [[ "${OS_ID}" != "debian" && "${OS_ID}" != "raspbian" && "${OS_ID_LIKE}" != *debian* ]]; then
  error "Unsupported OS (${OS_ID:-unknown}). Only Debian and Raspberry Pi OS are supported."
  exit 1
fi

check_binary_release_compatibility

info "Updating apt package index"
ensure_dns_resolution
apt-get update -y

info "Installing required packages"
apt-get install -y ca-certificates curl gnupg lsb-release dnsutils openssh-client postgresql-client

info "Installing network tools for Network Toolkit"
apt-get install -y net-tools iproute2 conntrack speedtest-cli ethtool || warn "Some network tools failed to install"

info "Installing NetProtection PRISM policy dependencies"
apt-get install -y ipset python3-cryptography || warn "PRISM policy dependencies failed to install"

# Install arp-scan for better MAC address discovery
if apt-get install -y arp-scan; then
    # Set capabilities so arp-scan works without sudo
    ARP_SCAN_PATH="$(which arp-scan 2>/dev/null || echo '/usr/sbin/arp-scan')"
    if [[ -x "$ARP_SCAN_PATH" ]]; then
        setcap cap_net_raw,cap_net_admin+eip "$ARP_SCAN_PATH" 2>/dev/null && \
            info "Set capabilities on arp-scan for non-root network scanning" || \
            warn "Could not set capabilities on arp-scan (sudo may be required)"
    fi
else
    warn "arp-scan not available - MAC address discovery may be limited"
fi

# Install hostname resolution tools (mDNS/Avahi, NetBIOS/nmblookup)
info "Installing hostname resolution tools (avahi, nmblookup)"
apt-get install -y avahi-utils samba-common-bin || warn "Hostname resolution tools not installed"

info "Installing FFmpeg for camera snapshots and recording"
apt-get install -y ffmpeg || warn "FFmpeg failed to install - camera features will not work"

setup_go2rtc() {
  info "Installing go2rtc for camera streaming"
  if [[ -f "${BASE_DIR}/scripts/setup/install_go2rtc.sh" ]]; then
    if bash "${BASE_DIR}/scripts/setup/install_go2rtc.sh"; then
      info "go2rtc installed successfully"
      if id -u "${EASYPI_USER}" >/dev/null 2>&1 \
          && getent group go2rtc >/dev/null 2>&1; then
        usermod -aG go2rtc "${EASYPI_USER}"
      fi
    else
      warn "go2rtc installation failed - camera live streaming will not work"
      warn "You can install it later with: sudo bash ${BASE_DIR}/scripts/setup/install_go2rtc.sh"
    fi
  else
    warn "go2rtc installer not found - skipping camera streaming setup"
  fi
}

install_tailscale() {
  if command -v tailscale >/dev/null 2>&1; then
    info "Tailscale already installed"
    tailscale set --accept-dns=false >/dev/null 2>&1 || true
    return 0
  fi
  
  info "Installing Tailscale VPN for secure remote access and mobile ad-blocking"
  
  # Use the bundled apt-repository installer. Never pipe a network response
  # directly into a root shell.
  if bash "${BASE_DIR}/scripts/services/tailscale.sh" install; then
    info "Tailscale installed successfully"
  else
    error "Tailscale installation failed - continuing without VPN features"
    return 1
  fi
  
  # Start Tailscale and connect
  info "Starting Tailscale..."
  
  # Use --authkey if provided via environment, otherwise show login URL
  local TAILSCALE_AUTHKEY="${TAILSCALE_AUTHKEY:-}"
  
  if [[ -n "${TAILSCALE_AUTHKEY}" ]]; then
    # Automated setup with auth key
    if tailscale up --authkey="${TAILSCALE_AUTHKEY}" --accept-dns=false --accept-routes --advertise-exit-node; then
      info "Tailscale connected successfully with auth key"
    else
      warn "Tailscale connection failed - check your auth key"
      return 1
    fi
  else
    # Interactive setup - show login URL
    info "Tailscale needs authorization. Starting Tailscale daemon..."
    
    # Start tailscale with flags but don't wait for login
    local tailscale_up_log
    tailscale_up_log="$(mktemp /run/easypi-tailscale-up.XXXXXX)"
    chmod 0600 "${tailscale_up_log}"
    tailscale up --accept-dns=false --accept-routes --advertise-exit-node 2>&1 | tee "${tailscale_up_log}" || true
    
    # Extract and show the login URL
    local LOGIN_URL
    LOGIN_URL="$(grep -oP 'https://login\.tailscale\.com/[^\s]+' "${tailscale_up_log}" || echo "")"
    rm -f -- "${tailscale_up_log}"
    
    if [[ -n "${LOGIN_URL}" ]]; then
      echo ""
      warn "╔═══════════════════════════════════════════════════════════╗"
      warn "║  🔐 Tailscale requires authentication                    ║"
      warn "╚═══════════════════════════════════════════════════════════╝"
      echo ""
      warn "Open this URL in your browser to approve this device:"
      warn "${LOGIN_URL}"
      echo ""
      warn "After approval, run to complete setup:"
      warn "  sudo ${BASE_DIR}/scripts/setup/tailscale_exit_node.sh"
      echo ""
      return 0
    else
      warn "Tailscale started but couldn't extract login URL"
      warn "Visit: https://login.tailscale.com/admin/machines"
      return 0
    fi
  fi
  
  # If we get here, Tailscale is connected
  local TAILSCALE_IP
  TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "unknown")
  
  info "┌─────────────────────────────────────────────────────────┐"
  info "│ Tailscale VPN is ready!                                │"
  info "│ Tailscale IP: ${TAILSCALE_IP}                          │"
  info "│                                                         │"
  info "│ To use on mobile:                                      │"
  info "│ 1. Install Tailscale app on your phone                │"
  info "│ 2. Login with the same account                        │"
  info "│ 3. Set Exit Node: easypi                              │"
  info "│ 4. Set DNS: ${TAILSCALE_IP}                           │"
  info "│                                                         │"
  info "│ Ad-blocking will work everywhere via NetProtection!   │"
  info "└─────────────────────────────────────────────────────────┘"
  
  return 0
}

create_system_user() {
  if ! getent group "${EASYPI_GROUP}" >/dev/null; then
    info "Creating group ${EASYPI_GROUP}"
    groupadd --system "${EASYPI_GROUP}"
  fi

  if ! getent group "${CHAMELEON_GROUP}" >/dev/null; then
    info "Creating restricted Chameleon group ${CHAMELEON_GROUP}"
    groupadd --system "${CHAMELEON_GROUP}"
  fi
  if ! id -u "${CHAMELEON_USER}" >/dev/null 2>&1; then
    info "Creating restricted Chameleon user ${CHAMELEON_USER}"
    useradd --system --home-dir /nonexistent --no-create-home \
      --shell /usr/sbin/nologin --gid "${CHAMELEON_GROUP}" "${CHAMELEON_USER}"
  fi

  if ! getent group "${MOBILE_LINK_GROUP}" >/dev/null; then
    info "Creating restricted Mobile Link group ${MOBILE_LINK_GROUP}"
    groupadd --system "${MOBILE_LINK_GROUP}"
  fi
  if ! id -u "${MOBILE_LINK_USER}" >/dev/null 2>&1; then
    info "Creating restricted Mobile Link user ${MOBILE_LINK_USER}"
    useradd --system --home-dir /nonexistent --no-create-home \
      --shell /usr/sbin/nologin --gid "${MOBILE_LINK_GROUP}" "${MOBILE_LINK_USER}"
  fi

  if ! getent group "${STEALTH_DNS_GROUP}" >/dev/null; then
    info "Creating restricted Chameleon DNS group ${STEALTH_DNS_GROUP}"
    groupadd --system "${STEALTH_DNS_GROUP}"
  fi
  if ! id -u "${STEALTH_DNS_USER}" >/dev/null 2>&1; then
    info "Creating restricted Chameleon DNS user ${STEALTH_DNS_USER}"
    useradd --system --home-dir /nonexistent --no-create-home \
      --shell /usr/sbin/nologin --gid "${STEALTH_DNS_GROUP}" "${STEALTH_DNS_USER}"
  fi

  if ! id -u "${EASYPI_USER}" >/dev/null 2>&1; then
    info "Creating user ${EASYPI_USER}"
    useradd --system --home-dir "${EASYPI_PREFIX}" --create-home \
      --shell /bin/bash --gid "${EASYPI_GROUP}" "${EASYPI_USER}"
  fi
  if getent group go2rtc >/dev/null 2>&1; then
    usermod -aG go2rtc "${EASYPI_USER}"
  fi
  
  # Add current user to easypi group for script access
  local REAL_USER="${SUDO_USER:-${USER:-}}"
  if [[ -n "${REAL_USER}" && "${REAL_USER}" != "root" ]]; then
    if id -u "${REAL_USER}" >/dev/null 2>&1; then
      # Check if user is already in the group
      if id -nG "${REAL_USER}" | grep -qw "${EASYPI_GROUP}"; then
        info "User '${REAL_USER}' already in group '${EASYPI_GROUP}'"
      else
        usermod -aG "${EASYPI_GROUP}" "${REAL_USER}"
        info "Added user '${REAL_USER}' to group '${EASYPI_GROUP}'"
        warn "User '${REAL_USER}' needs to re-login for group changes to take effect"
      fi
    fi
  else
    warn "Could not determine current user. Manually add your user to easypi group:"
    warn "  sudo usermod -aG easypi YOUR_USERNAME"
  fi
}

deploy_runner_scripts() {
  info "Preparing base directory ${EASYPI_PREFIX}"
  mkdir -p "${EASYPI_PREFIX}"
  chown root:"${EASYPI_GROUP}" "${EASYPI_PREFIX}"
  # nginx needs traverse-only access to the installation root in order to
  # serve frontend/dist. Do not grant directory listing to unrelated users.
  chmod 751 "${EASYPI_PREFIX}"

  info "Deploying privileged runner scripts to ${SCRIPTS_DST}"
  install -d -m 0750 "${SCRIPTS_DST}"

  # Copy script categories (skip if source and destination are the same)
  local categories=("services" "stacks" "security" "backup" "settings" "setup" "maintenance" "utils" "sudoers.d")
  for category in "${categories[@]}"; do
    install -d -m 0750 "${SCRIPTS_DST}/${category}"
    if [[ -d "${BASE_DIR}/scripts/${category}" ]]; then
      # Skip copy if source and destination are the same (binary install from /opt/EasyPi)
      if [[ "$(realpath "${BASE_DIR}/scripts/${category}")" != "$(realpath "${SCRIPTS_DST}/${category}")" ]]; then
        cp -a "${BASE_DIR}/scripts/${category}/." "${SCRIPTS_DST}/${category}/"
      fi
    fi
  done

  # Copy standalone scripts from scripts/ root

  if [[ -f "${RUNNER_SRC}" ]]; then
    # Skip if already in place
    if [[ "$(realpath "${RUNNER_SRC}")" != "$(realpath "${SCRIPTS_DST}/runner")" ]]; then
      install -m 0750 "${RUNNER_SRC}" "${SCRIPTS_DST}/runner"
    fi
  else
    warn "Runner source not found, skipping runner install"
  fi

  # Deploy service code and root-executed Prism matchers (skip if same location).
  # prism_dpi must land before the ownership sweep below: setup_app_blocking.sh
  # imports it as root, so the backend account must never own or modify it.
  info "Deploying backend, netprotection, and Prism code to ${EASYPI_PREFIX}"
  if [[ "$(realpath "${BASE_DIR}")" != "$(realpath "${EASYPI_PREFIX}")" ]]; then
    cp -rf "${BASE_DIR}/backend" "${EASYPI_PREFIX}/"
    cp -rf "${BASE_DIR}/easypi_netprotection" "${EASYPI_PREFIX}/"
    cp -rf "${BASE_DIR}/prism_dpi" "${EASYPI_PREFIX}/"
    cp -rf "${BASE_DIR}/prism_tls_bridge" "${EASYPI_PREFIX}/"
    # Also copy config directory
    if [[ -d "${BASE_DIR}/config" ]]; then
      backup_path_if_exists "${EASYPI_PREFIX}/config"
      cp -rf "${BASE_DIR}/config" "${EASYPI_PREFIX}/"
    fi
  else
    info "Skipping code copy (already in target location)"
  fi

  # Copy .env if exists and not already in place
  if [[ -f "${BASE_DIR}/.env" ]] && [[ "$(realpath "${BASE_DIR}")" != "$(realpath "${EASYPI_PREFIX}")" ]]; then
    cp "${BASE_DIR}/.env" "${EASYPI_PREFIX}/"
  elif [[ -f "${BASE_DIR}/backend/.env" ]] && [[ "$(realpath "${BASE_DIR}")" != "$(realpath "${EASYPI_PREFIX}")" ]]; then
    cp "${BASE_DIR}/backend/.env" "${EASYPI_PREFIX}/"
  fi

  # Validate existing privileged Stealth inputs BEFORE the ownership sweep.
  # Otherwise chown would launder an attacker-owned regular file into an
  # apparently trusted root-owned binary before we inspect it.
  local preflight_path_checker="${BASE_DIR}/scripts/security/verify_trusted_install_path.sh"
  local preflight_input_checker="${BASE_DIR}/scripts/security/verify_chameleon_install_inputs.sh"
  local trusted_source_uid="0"
  if [[ "${SUDO_USER:-}" == "${EASYPI_USER}" ]]; then
    die "The EasyPi service account cannot be the trusted installation source owner"
  fi
  if [[ "${SUDO_UID:-}" =~ ^[0-9]+$ && "${SUDO_UID}" != "0" ]]; then
    trusted_source_uid="${SUDO_UID}"
  fi
  verify_bootstrap_trusted_file "${preflight_path_checker}" "${trusted_source_uid}" \
    || die "Trusted install-path verifier or one of its parents is unsafe"
  verify_bootstrap_trusted_file "${preflight_input_checker}" "${trusted_source_uid}" \
    || die "Trusted Chameleon input verifier or one of its parents is unsafe"
  local preflight_chameleon_mode
  preflight_chameleon_mode="$(bash "${preflight_input_checker}" \
    "${BASE_DIR}" "$(uname -m)" "${trusted_source_uid}")" \
    || die "Untrusted or incomplete Stealth installation inputs rejected"
  [[ "${preflight_chameleon_mode}" == "ready" \
     || "${preflight_chameleon_mode}" == "build" ]] \
    || die "Stealth input verifier returned an invalid result"
  if [[ -e "${EASYPI_PREFIX}/bin" || -L "${EASYPI_PREFIX}/bin" ]]; then
    bash "${preflight_path_checker}" directory "${EASYPI_PREFIX}/bin" \
      || die "Unsafe Stealth destination directory rejected"
  fi

  # Deployed code is immutable to the backend account. Only explicit runtime
  # directories below are returned to easypi ownership.
  info "Fixing code ownership and permissions on ${EASYPI_PREFIX}"
  chown -R root:root "${EASYPI_PREFIX}"
  # Do not relax permissions on existing runtime state during an upgrade.
  # Those trees can contain tokens, private keys, backups, and credentials.
  find "${EASYPI_PREFIX}" \
    \( -path "${EASYPI_PREFIX}/data" \
       -o -path "${EASYPI_PREFIX}/backend/data" \
       -o -path "${EASYPI_PREFIX}/backend/.venv" \
       -o -path "${EASYPI_PREFIX}/logs" \
       -o -path "${EASYPI_PREFIX}/cache" \
       -o -path "${EASYPI_PREFIX}/recordings" \
       -o -path "${EASYPI_PREFIX}/config" \
       -o -path "${EASYPI_PREFIX}/backups" \) -prune -o \
    -type d -exec chmod 755 {} \; || true
  # The directory sweep above makes public code directories readable, but the
  # installation root itself remains traverse-only for nginx. Protected child
  # trees and secrets are tightened again below.
  chown root:"${EASYPI_GROUP}" "${EASYPI_PREFIX}"
  chmod 751 "${EASYPI_PREFIX}"
  find "${EASYPI_PREFIX}" \
    \( -path "${EASYPI_PREFIX}/data" \
       -o -path "${EASYPI_PREFIX}/backend/data" \
       -o -path "${EASYPI_PREFIX}/backend/.venv" \
       -o -path "${EASYPI_PREFIX}/logs" \
       -o -path "${EASYPI_PREFIX}/cache" \
       -o -path "${EASYPI_PREFIX}/recordings" \
       -o -path "${EASYPI_PREFIX}/config" \
       -o -path "${EASYPI_PREFIX}/backups" \) -prune -o \
    -type f ! -path "${EASYPI_PREFIX}/.env" -exec chmod 644 {} \; || true
  # The binary archive contains the supported lifecycle entry points at the
  # installation root. The read-only code sweep above intentionally removes
  # arbitrary executable bits, so restore execution only for these reviewed
  # regular files. This keeps the packaged uninstaller usable after install.
  for lifecycle_script in install.sh update.sh uninstall.sh; do
    if [[ -f "${EASYPI_PREFIX}/${lifecycle_script}" \
        && ! -L "${EASYPI_PREFIX}/${lifecycle_script}" ]]; then
      chmod 0755 "${EASYPI_PREFIX}/${lifecycle_script}"
    fi
  done
  if [[ -f "${EASYPI_PREFIX}/.env" ]]; then
    chown root:"${EASYPI_GROUP}" "${EASYPI_PREFIX}/.env"
    chmod 640 "${EASYPI_PREFIX}/.env"
  fi

  # Stealth (Chameleon) binaries: build them from the reviewed source on every
  # installation, then land only the server and this EasyPi architecture's
  # client in ${EASYPI_PREFIX}/bin. Binary releases intentionally contain no
  # prebuilt Chameleon executables (build.sh fetches a pinned Go toolchain).
  # This must also run when the installer itself is launched from /opt/EasyPi;
  # that is the normal clean-install path, not evidence that binaries exist.
  # Use the deployed, root-owned verifier rather than a possibly user-owned
  # source-tree copy. Do not ask an unverified helper to verify itself.
  local trusted_path_checker="${SCRIPTS_DST}/security/verify_trusted_install_path.sh"
  local trusted_input_checker="${SCRIPTS_DST}/security/verify_chameleon_install_inputs.sh"
  verify_bootstrap_trusted_file "${trusted_path_checker}" \
    || die "Deployed install-path verifier or one of its parents is unsafe"
  verify_bootstrap_trusted_file "${trusted_input_checker}" \
    || die "Deployed Chameleon input verifier or one of its parents is unsafe"
  if [[ -e "${EASYPI_PREFIX}/bin" || -L "${EASYPI_PREFIX}/bin" ]]; then
    bash "${trusted_path_checker}" directory "${EASYPI_PREFIX}/bin" \
      || die "Unsafe Stealth destination directory rejected"
  else
    install -d -o root -g root -m 0755 "${EASYPI_PREFIX}/bin"
  fi
  local chameleon_client_source=""
  case "$(uname -m)" in
    aarch64|arm64) chameleon_client_source="${BASE_DIR}/chameleon/bin/chameleon-client-arm64" ;;
    x86_64|amd64) chameleon_client_source="${BASE_DIR}/chameleon/bin/chameleon-client-amd64" ;;
    *) die "Stealth does not support this CPU architecture: $(uname -m)" ;;
  esac
  local chameleon_server_source="${BASE_DIR}/chameleon/bin/chameleon-server-amd64"
  local home_server_source="${BASE_DIR}/chameleon/bin/chameleon-server-${chameleon_client_source##*-}"
  local mobile_link_agent_source="${BASE_DIR}/chameleon/bin/chameleon-mobile-link-agent-${chameleon_client_source##*-}"
  local mobile_link_relay_source="${BASE_DIR}/chameleon/bin/chameleon-mobile-link-relay-amd64"
  local source_bin_dir="${BASE_DIR}/chameleon/bin"
  local source_chameleon_dir="${BASE_DIR}/chameleon"
  local chameleon_input_mode
  chameleon_input_mode="$(bash "${trusted_input_checker}" \
    "${BASE_DIR}" "$(uname -m)" "${trusted_source_uid}")" \
    || die "Untrusted or incomplete Stealth installation inputs rejected"
  if [[ -e "${source_bin_dir}" || -L "${source_bin_dir}" ]]; then
    bash "${trusted_path_checker}" directory "${source_bin_dir}" "${trusted_source_uid}" \
      || die "Unsafe Stealth build output directory rejected"
  else
    install -d -o root -g root -m 0755 "${source_bin_dir}"
  fi
  info "Building fresh Stealth (Chameleon) binaries for $(uname -m) (auto-fetches pinned Go if needed)..."
  env -u GO -u GOPATH -u GOMODCACHE -u GOCACHE \
    bash "${source_chameleon_dir}/build.sh" "$(uname -m)" \
    || die "Stealth build failed; refusing to report an incomplete installation"
  chameleon_input_mode="$(bash "${trusted_input_checker}" \
    "${BASE_DIR}" "$(uname -m)" "${trusted_source_uid}")" \
    || die "Stealth build outputs failed trust verification"
  [[ "${chameleon_input_mode}" == "ready" ]] \
    || die "Stealth binaries are still unavailable after the build step"
  bash "${trusted_path_checker}" directory "${source_bin_dir}" "${trusted_source_uid}" \
    || die "Unsafe Stealth build output directory rejected"
  bash "${trusted_path_checker}" file "${chameleon_server_source}" "${trusted_source_uid}" \
    || die "Untrusted Stealth server binary rejected"
  bash "${trusted_path_checker}" file "${chameleon_client_source}" "${trusted_source_uid}" \
    || die "Untrusted Stealth client binary rejected"
  bash "${trusted_path_checker}" file "${home_server_source}" "${trusted_source_uid}" \
    || die "Untrusted mobile home tunnel server binary rejected"
  bash "${trusted_path_checker}" file "${mobile_link_agent_source}" "${trusted_source_uid}" \
    || die "Untrusted Mobile Link agent binary rejected"
  bash "${trusted_path_checker}" file "${mobile_link_relay_source}" "${trusted_source_uid}" \
    || die "Untrusted Mobile Link relay binary rejected"
  local source_binary
  for source_binary in \
      "${EASYPI_PREFIX}/bin/chameleon-server-amd64" \
      "${EASYPI_PREFIX}/bin/chameleon-server-home" \
      "${EASYPI_PREFIX}/bin/chameleon-client" \
      "${EASYPI_PREFIX}/bin/chameleon-mobile-link-agent" \
      "${EASYPI_PREFIX}/bin/chameleon-mobile-link-relay-amd64"; do
    if [[ -e "${source_binary}" || -L "${source_binary}" ]]; then
      bash "${trusted_path_checker}" file "${source_binary}" \
        || die "Unsafe existing Stealth destination rejected: ${source_binary}"
    fi
  done
  install -o root -g root -m 0755 \
    "${chameleon_server_source}" \
    "${EASYPI_PREFIX}/bin/chameleon-server-amd64"
  install -o root -g root -m 0755 \
    "${home_server_source}" \
    "${EASYPI_PREFIX}/bin/chameleon-server-home"
  install -o root -g root -m 0755 \
    "${chameleon_client_source}" \
    "${EASYPI_PREFIX}/bin/chameleon-client"
  install -o root -g root -m 0755 \
    "${mobile_link_agent_source}" \
    "${EASYPI_PREFIX}/bin/chameleon-mobile-link-agent"
  install -o root -g root -m 0755 \
    "${mobile_link_relay_source}" \
    "${EASYPI_PREFIX}/bin/chameleon-mobile-link-relay-amd64"
  bash "${trusted_path_checker}" file "${EASYPI_PREFIX}/bin/chameleon-server-amd64" \
    || die "Installed Stealth server binary failed trust verification"
  bash "${trusted_path_checker}" file "${EASYPI_PREFIX}/bin/chameleon-client" \
    || die "Installed Stealth client binary failed trust verification"
  bash "${trusted_path_checker}" file "${EASYPI_PREFIX}/bin/chameleon-server-home" \
    || die "Installed mobile home tunnel server failed trust verification"
  bash "${trusted_path_checker}" file "${EASYPI_PREFIX}/bin/chameleon-mobile-link-agent" \
    || die "Installed Mobile Link agent binary failed trust verification"
  bash "${trusted_path_checker}" file "${EASYPI_PREFIX}/bin/chameleon-mobile-link-relay-amd64" \
    || die "Installed Mobile Link relay binary failed trust verification"
  chown -R root:root "${EASYPI_PREFIX}/bin" 2>/dev/null || true
  find "${EASYPI_PREFIX}/bin" -type f -exec chmod 755 {} \; 2>/dev/null || true

  # Explicit runtime state. These are the only project trees writable by the
  # backend service account.
  local mutable_dirs=(
    "${EASYPI_PREFIX}/data"
    "${EASYPI_PREFIX}/backend/data"
    "${EASYPI_PREFIX}/logs"
    "${EASYPI_PREFIX}/cache"
    "${EASYPI_PREFIX}/recordings"
    "${EASYPI_PREFIX}/config"
  )
  local mutable_dir
  for mutable_dir in "${mutable_dirs[@]}"; do
    mkdir -p "${mutable_dir}"
    chown -R "${EASYPI_USER}:${EASYPI_GROUP}" "${mutable_dir}"
    find "${mutable_dir}" -type d -exec chmod 750 {} \; || true
    find "${mutable_dir}" -type f -exec chmod 640 {} \; || true
  done

  # These backend-owned state files contain administrative connection metadata
  # or credentials and are deliberately created as 0600.  The broad mutable
  # tree normalization above must not widen them during an install or update.
  local private_user_state
  for private_user_state in \
      "${EASYPI_PREFIX}/data/user/tailscale_admin.json" \
      "${EASYPI_PREFIX}/data/user/tailscale_relay.json" \
      "${EASYPI_PREFIX}/data/user/mobile_link.json" \
      "${EASYPI_PREFIX}/data/user/mobile_link_relay.json"; do
    if [[ -e "${private_user_state}" || -L "${private_user_state}" ]]; then
      [[ -f "${private_user_state}" && ! -L "${private_user_state}" ]] \
        || die "Unsafe private user-state path rejected: ${private_user_state}"
      chown "${EASYPI_USER}:${EASYPI_GROUP}" "${private_user_state}"
      chmod 0600 "${private_user_state}"
    fi
  done

  # SSH host-key pins are rejected by the backend if either the directory or
  # a stored key is group/world-accessible. Restore their deliberately private
  # modes after the broad mutable-tree normalization above.
  local ssh_trust_dir="${EASYPI_PREFIX}/data/ssh-trust"
  if [[ -e "${ssh_trust_dir}" || -L "${ssh_trust_dir}" ]]; then
    [[ -d "${ssh_trust_dir}" && ! -L "${ssh_trust_dir}" ]] \
      || die "Unsafe SSH trust-store directory rejected: ${ssh_trust_dir}"
    chown "${EASYPI_USER}:${EASYPI_GROUP}" "${ssh_trust_dir}"
    chmod 0700 "${ssh_trust_dir}"
    while IFS= read -r -d '' trust_file; do
      [[ -f "${trust_file}" && ! -L "${trust_file}" ]] \
        || die "Unsafe SSH trust-store path rejected: ${trust_file}"
      chown "${EASYPI_USER}:${EASYPI_GROUP}" "${trust_file}"
      chmod 0600 "${trust_file}"
    done < <(find "${ssh_trust_dir}" -mindepth 1 -maxdepth 1 -print0)
  fi

  # Best-effort: fetch the IEEE OUI (MAC-vendor) database for the network scanner.
  # NON-FATAL by design — on failure (no internet / IEEE unreachable) the scanner falls
  # back to its built-in vendor list, so this must never abort the install/update.
  mkdir -p "${EASYPI_PREFIX}/data/network"
  chown "${EASYPI_USER}:${EASYPI_GROUP}" "${EASYPI_PREFIX}/data/network" 2>/dev/null || true
  if [[ -f "${BASE_DIR}/scripts/utils/fetch_oui_db.py" ]] && command -v python3 >/dev/null 2>&1; then
    info "Fetching MAC-vendor (OUI) database for the scanner (best-effort)..."
    if timeout 90 python3 "${BASE_DIR}/scripts/utils/fetch_oui_db.py" "${EASYPI_PREFIX}/data/network/oui.txt.gz"; then
      chown "${EASYPI_USER}:${EASYPI_GROUP}" "${EASYPI_PREFIX}/data/network/oui.txt.gz" 2>/dev/null || true
    else
      warn "Could not fetch OUI database — scanner will use its built-in vendor list."
    fi
  fi

  # WireGuard state is written by a root runner and read by the backend. Keep it
  # outside the backend-writable data tree so symlink swaps cannot redirect root
  # writes. Migrate only ordinary legacy files, never links or devices.
  local wireguard_state="/var/lib/easypi/wireguard"
  local legacy_wireguard="${EASYPI_PREFIX}/data/wireguard"
  install -d -o root -g "${EASYPI_GROUP}" -m 0750 /var/lib/easypi
  install -d -o root -g "${EASYPI_GROUP}" -m 0750 "${wireguard_state}"
  install -d -o root -g "${EASYPI_GROUP}" -m 0750 "${wireguard_state}/clients"
  local netprotection_state="/var/lib/easypi/netprotection"
  install -d -o root -g "${EASYPI_GROUP}" -m 0750 "${netprotection_state}"
  install -d -o root -g "${EASYPI_GROUP}" -m 0750 /var/lib/easypi/stealth
  install -d -o root -g "${EASYPI_GROUP}" -m 0750 /var/lib/easypi/stealth-policy
  if [[ -f "${legacy_wireguard}/meta.json" && ! -L "${legacy_wireguard}/meta.json" && ! -e "${wireguard_state}/meta.json" ]]; then
    install -o root -g "${EASYPI_GROUP}" -m 0640 \
      "${legacy_wireguard}/meta.json" "${wireguard_state}/meta.json"
  fi
  local legacy_client
  for legacy_client in "${legacy_wireguard}/clients/"*.conf "${legacy_wireguard}/clients/"*.png; do
    [[ -f "${legacy_client}" && ! -L "${legacy_client}" ]] || continue
    [[ -e "${wireguard_state}/clients/$(basename "${legacy_client}")" ]] && continue
    install -o root -g "${EASYPI_GROUP}" -m 0640 \
      "${legacy_client}" "${wireguard_state}/clients/$(basename "${legacy_client}")"
  done
  local legacy_state
  for legacy_state in fail_closed_devices.json whatsapp_block_mode whatsapp_include_meta; do
    if [[ -f "${EASYPI_PREFIX}/data/netprotection/${legacy_state}" &&
          ! -L "${EASYPI_PREFIX}/data/netprotection/${legacy_state}" &&
          ! -e "${netprotection_state}/${legacy_state}" ]]; then
      install -o root -g "${EASYPI_GROUP}" -m 0640 \
        "${EASYPI_PREFIX}/data/netprotection/${legacy_state}" \
        "${netprotection_state}/${legacy_state}"
    fi
  done

  # Backups are readable by the service but never writable by it. Otherwise a
  # compromised backend could replace an archive before a root restore.
  mkdir -p "${EASYPI_PREFIX}/backups"
  chown -R root:"${EASYPI_GROUP}" "${EASYPI_PREFIX}/backups"
  find "${EASYPI_PREFIX}/backups" -type d -exec chmod 750 {} \; || true
  find "${EASYPI_PREFIX}/backups" -type f -exec chmod 640 {} \; || true

  # Installer job spool directory
  mkdir -p "${EASYPI_PREFIX}/data/installer"
  chown "${EASYPI_USER}:${EASYPI_GROUP}" "${EASYPI_PREFIX}/data/installer"
  chmod 750 "${EASYPI_PREFIX}/data/installer"

  # Ensure backend/data directory exists (for threat_monitor_config.json etc.)
  mkdir -p "${EASYPI_PREFIX}/backend/data"
  chown "${EASYPI_USER}:${EASYPI_GROUP}" "${EASYPI_PREFIX}/backend/data"
  chmod 750 "${EASYPI_PREFIX}/backend/data"

  # Enable the Security Monitor by default on a FRESH install only (don't clobber
  # the user's choice on upgrade). Detection is safe — it only watches the logs.
  # Auto-ban stays OFF so nothing is blocked without an explicit opt-in.
  local threat_cfg="${EASYPI_PREFIX}/backend/data/threat_monitor_config.json"
  if [[ ! -f "${threat_cfg}" ]]; then
    cat > "${threat_cfg}" <<'EOF'
{
  "enabled": true,
  "ssh_threshold": 5,
  "auto_ban": false
}
EOF
    chown "${EASYPI_USER}:${EASYPI_GROUP}" "${threat_cfg}"
    chmod 640 "${threat_cfg}"
    info "Security Monitor enabled by default (auto-ban left OFF)"
  fi

  # Ensure data/db directory exists for SQLite
  mkdir -p "${EASYPI_PREFIX}/data/db"
  chown "${EASYPI_USER}:${EASYPI_GROUP}" "${EASYPI_PREFIX}/data/db"
  chmod 750 "${EASYPI_PREFIX}/data/db"

  # Ensure logs directory exists
  mkdir -p "${EASYPI_PREFIX}/logs"
  chown "${EASYPI_USER}:${EASYPI_GROUP}" "${EASYPI_PREFIX}/logs"
  chmod 750 "${EASYPI_PREFIX}/logs"

  chown -R root:${EASYPI_GROUP} "${SCRIPTS_DST}"
  find "${SCRIPTS_DST}" -type f -name "*.sh" -exec chmod 750 {} +
  chmod 750 "${SCRIPTS_DST}/runner"
  # Set correct group ownership on directories
  find "${SCRIPTS_DST}" -type d -exec chmod 750 {} +
  find "${SCRIPTS_DST}" -type d -exec chown root:${EASYPI_GROUP} {} +
  # Normalize line endings (fixes CRLF issues from Windows)
  find "${SCRIPTS_DST}" -type f -name "*.sh" -exec sed -i 's/\r$//' {} + || true
  if [[ -f "${SCRIPTS_DST}/runner" ]]; then
    sed -i 's/\r$//' "${SCRIPTS_DST}/runner" || true
  fi
}

discard_imported_setup_token_on_fresh_install() {
  [[ "${EASYPI_INSTALLATION_PREEXISTED}" == "0" ]] || return 0

  # A source checkout may have been copied directly into /opt/EasyPi. Never
  # accept a setup credential carried by that checkout on a fresh machine.
  # The backend will generate a new cryptographically random token on startup.
  local token_path
  for token_path in \
    "${EASYPI_PREFIX}/data/.setup_token" \
    "${EASYPI_PREFIX}/backend/data/.setup_token"; do
    if [[ -e "${token_path}" || -L "${token_path}" ]]; then
      [[ ! -d "${token_path}" ]] \
        || die "Setup-token path is a directory; refusing fresh installation"
      rm -f -- "${token_path}" \
        || die "Could not discard an imported setup token"
    fi
  done
}

configure_runner_logging() {
  info "Configuring runner log directories"
  install -d -m 0750 "${LOGS_DST}"
  install -d -m 0750 "${TASK_LOGS_DIR}"
  chown -R "${EASYPI_USER}:${EASYPI_GROUP}" "${TASK_LOGS_DIR}"

  install -d -o root -g "${EASYPI_GROUP}" -m 0750 /var/log/easypi
  touch /var/log/easypi/runner.log
  chown root:"${EASYPI_GROUP}" /var/log/easypi /var/log/easypi/runner.log
  chmod 640 /var/log/easypi/runner.log
}

configure_sudoers() {
  info "Configuring sudoers entry for ${EASYPI_USER}"
  
  # Use the full sudoers template from scripts/sudoers.d/easypi if available
  if [[ -f "${SCRIPTS_DST}/sudoers.d/easypi" ]]; then
    info "Installing full sudoers configuration from template"
    backup_path_if_exists "${SUDOERS_FILE}"
    install -m 0440 "${SCRIPTS_DST}/sudoers.d/easypi" "${SUDOERS_FILE}"
  else
    # Fallback to minimal configuration if template not found
    warn "Sudoers template not found, using minimal configuration"
    backup_path_if_exists "${SUDOERS_FILE}"
    cat <<EOF > "${SUDOERS_FILE}"
Cmnd_Alias EASYPI_CMDS = ${SCRIPTS_DST}/runner *
${EASYPI_USER} ALL=(root) NOPASSWD: EASYPI_CMDS
EOF
    chmod 440 "${SUDOERS_FILE}"
  fi
  
  if command -v visudo >/dev/null 2>&1; then
    visudo -cf "${SUDOERS_FILE}" >/dev/null
  else
    warn "visudo not found; sudoers file not validated automatically"
  fi
}

setup_unbound() {
  info "Setting up Unbound recursive DNS resolver for NetProtection"
  if [[ -f "${SCRIPTS_DST}/setup/setup_unbound.sh" ]]; then
    chmod +x "${SCRIPTS_DST}/setup/setup_unbound.sh"
    "${SCRIPTS_DST}/setup/setup_unbound.sh" || warn "Unbound setup failed - NetProtection will use public DNS"
  else
    warn "Unbound setup script not found - skipping"
  fi
}

setup_tailscale_exit_node() {
  # Tailscale must be installed and running
  if ! command -v tailscale >/dev/null 2>&1; then
    warn "Tailscale not installed - skipping exit node configuration"
    return 0
  fi
  
  # Check if Tailscale is running
  if ! tailscale ip -4 >/dev/null 2>&1; then
    warn "Tailscale is not connected - skipping exit node configuration"
    warn "Please approve the device at: https://login.tailscale.com/admin/machines"
    warn "Then run: sudo ${SCRIPTS_DST}/setup/tailscale_exit_node.sh"
    return 0
  fi
  
  info "Configuring Tailscale Exit Node (DNS + firewall + routing)..."
  if [[ -f "${SCRIPTS_DST}/setup/tailscale_exit_node.sh" ]]; then
    chmod +x "${SCRIPTS_DST}/setup/tailscale_exit_node.sh"
    "${SCRIPTS_DST}/setup/tailscale_exit_node.sh" || warn "Tailscale exit node setup failed - you can run it manually later"
  else
    warn "Tailscale exit node setup script not found - skipping"
  fi
}

setup_netprotection() {
  info "Setting up EasyPi NetProtection service"
  if [[ ! -d "${EASYPI_PREFIX}/easypi_netprotection" ]]; then
    warn "easypi_netprotection not found - skipping NetProtection setup"
    return 0
  fi

  # The DNS-shadow bypass detector reads per-flow byte counters from conntrack.
  # nf_conntrack_acct is OFF by default in many kernels; persist it so detection
  # survives reboots (setup_vpn_blocking.sh also enables it at runtime on each sync).
  info "Enabling conntrack byte accounting (nf_conntrack_acct) for bypass detection"
  echo "net.netfilter.nf_conntrack_acct = 1" > /etc/sysctl.d/99-easypi-netprotection.conf
  chown root:root /etc/sysctl.d/99-easypi-netprotection.conf
  chmod 644 /etc/sysctl.d/99-easypi-netprotection.conf
  modprobe nf_conntrack 2>/dev/null || true
  sysctl -w net.netfilter.nf_conntrack_acct=1 >/dev/null 2>&1 || true
  if [[ ! -x "${EASYPI_PREFIX}/backend/.venv/bin/python3" ]]; then
    warn "NetProtection venv not found at ${EASYPI_PREFIX}/backend/.venv - skipping"
    return 0
  fi
  if [[ -f "${SCRIPTS_DST}/services/install_netprotection.sh" ]]; then
    chmod +x "${SCRIPTS_DST}/services/install_netprotection.sh"
    # Export vars for sub-script
    export EASYPI_PREFIX EASYPI_USER EASYPI_GROUP
    "${SCRIPTS_DST}/services/install_netprotection.sh" || {
      error "NetProtection installation failed"
      return 1
    }
  else
    error "NetProtection installation script not found"
    return 1
  fi
}

setup_stealth_strict_services() {
  info "Installing Chameleon early guard, strict DNS, and boot-resume services"
  local stealth_unit
  for stealth_unit in \
    easypi-stealth-guard.service \
    easypi-stealth-dns.service \
    easypi-stealth-resume.service; do
    [[ -f "${BASE_DIR}/templates/systemd/${stealth_unit}" ]] \
      || { error "Missing systemd template: ${stealth_unit}"; return 1; }
    backup_path_if_exists "/etc/systemd/system/${stealth_unit}"
    install -o root -g root -m 0644 \
      "${BASE_DIR}/templates/systemd/${stealth_unit}" \
      "/etc/systemd/system/${stealth_unit}"
    sed -i "s|/opt/EasyPi|${EASYPI_PREFIX}|g" "/etc/systemd/system/${stealth_unit}"
  done
  systemctl daemon-reload
  systemctl enable easypi-stealth-guard.service
  systemctl enable easypi-stealth-dns.service
  systemctl enable easypi-stealth-resume.service
  systemctl restart easypi-stealth-guard.service
  systemctl restart easypi-stealth-dns.service
  systemctl restart easypi-stealth-resume.service
}

initialize_adult_feed() {
  local updater="${SCRIPTS_DST}/settings/update_adult_blocklist.sh"
  if [[ ! -f "${updater}" || -L "${updater}" ]]; then
    warn "Adult-domain feed updater is unavailable; the feed can be downloaded later"
    return 0
  fi

  info "Downloading the optional adult-domain feed and its license notices"
  if ! EASYPI_ROOT="${EASYPI_PREFIX}" bash "${updater}" update; then
    warn "Adult-domain feed download failed; installation will continue"
    warn "Retry later from Parental Controls or with the reviewed updater"
  fi
}

setup_netprotection_state_maintenance() {
  info "Configuring NetProtection state maintenance"

  local script_path="${SCRIPTS_DST}/maintenance/netprotection_state_maintenance.sh"
  local service_src="${BASE_DIR}/templates/systemd/easypi-netprotection-state-maintenance.service"
  local timer_src="${BASE_DIR}/templates/systemd/easypi-netprotection-state-maintenance.timer"
  local service_dst="/etc/systemd/system/easypi-netprotection-state-maintenance.service"
  local timer_dst="/etc/systemd/system/easypi-netprotection-state-maintenance.timer"

  if [[ ! -f "${script_path}" ]]; then
    warn "Maintenance script not found: ${script_path}"
    return 0
  fi
  if [[ ! -f "${service_src}" || ! -f "${timer_src}" ]]; then
    warn "State maintenance systemd templates not found - skipping"
    return 0
  fi

  chmod +x "${script_path}"

  backup_path_if_exists "${service_dst}"
  cp "${service_src}" "${service_dst}"
  sed -i "s|/opt/EasyPi|${EASYPI_PREFIX}|g" "${service_dst}"
  sed -i "s|User=easypi|User=${EASYPI_USER}|g" "${service_dst}"
  sed -i "s|Group=easypi|Group=${EASYPI_GROUP}|g" "${service_dst}"

  backup_path_if_exists "${timer_dst}"
  cp "${timer_src}" "${timer_dst}"

  systemctl daemon-reload
  systemctl enable --now easypi-netprotection-state-maintenance.timer

  if ! systemctl start easypi-netprotection-state-maintenance.service; then
    warn "Initial NetProtection state maintenance run failed"
  fi
}

setup_ipv6_runtime_guard() {
  info "Installing the runtime IPv6 policy guard"

  local script_path="${SCRIPTS_DST}/security/ipv6_policy_guard.sh"
  local service_src="${BASE_DIR}/templates/systemd/easypi-ipv6-policy-guard.service"
  local service_dst="/etc/systemd/system/easypi-ipv6-policy-guard.service"
  local timer_dst="/etc/systemd/system/easypi-ipv6-policy-guard.timer"

  [[ -f "${script_path}" && ! -L "${script_path}" ]] \
    || { error "IPv6 policy guard script is missing or unsafe"; return 1; }
  [[ -f "${service_src}" && ! -L "${service_src}" ]] \
    || { error "IPv6 policy guard systemd template is missing or unsafe"; return 1; }

  chmod 0750 "${script_path}"
  backup_path_if_exists "${service_dst}"
  cp "${service_src}" "${service_dst}"
  sed -i "s|/opt/EasyPi|${EASYPI_PREFIX}|g" "${service_dst}"
  sed -i "s|Group=easypi|Group=${EASYPI_GROUP}|g" "${service_dst}"
  sed -i "s|EASYPI_GROUP=easypi|EASYPI_GROUP=${EASYPI_GROUP}|g" "${service_dst}"
  chown root:root "${service_dst}"
  chmod 0644 "${service_dst}"

  # Retire the timer used by the earlier oneshot implementation. The guard is
  # now a continuously active required service, not a periodic best-effort job.
  systemctl disable --now easypi-ipv6-policy-guard.timer >/dev/null 2>&1 || true
  rm -f "${timer_dst}"

  if [[ -d /etc/NetworkManager/dispatcher.d ]]; then
    local dispatcher_src="${BASE_DIR}/templates/networkmanager/90-easypi-ipv6-policy-guard"
    local dispatcher_dst="/etc/NetworkManager/dispatcher.d/90-easypi-ipv6-policy-guard"
    [[ -f "${dispatcher_src}" && ! -L "${dispatcher_src}" ]] \
      || { error "IPv6 NetworkManager dispatcher is missing or unsafe"; return 1; }
    cp "${dispatcher_src}" "${dispatcher_dst}"
    chown root:root "${dispatcher_dst}"
    chmod 0755 "${dispatcher_dst}"
  fi

  systemctl daemon-reload
  systemctl enable easypi-ipv6-policy-guard.service
  systemctl restart easypi-ipv6-policy-guard.service \
    || { error "Runtime IPv6 policy guard failed to establish"; return 1; }
  systemctl is-active --quiet easypi-ipv6-policy-guard.service \
    || { error "Runtime IPv6 policy guard is not active"; return 1; }
}

setup_prism_flowgraph() {
  info "Configuring PRISM FlowGraph and exact-flow enforcement"
  local setup_script="${SCRIPTS_DST}/settings/setup_prism_flowgraph.sh"
  [[ -f "${setup_script}" && ! -L "${setup_script}" && -x "${setup_script}" ]] \
    || { error "Trusted PRISM FlowGraph setup script is missing"; return 1; }
  "${setup_script}" install \
    || { error "PRISM FlowGraph enforcement could not be established"; return 1; }
}

setup_prism_endpoint_bridge() {
  # Install optional observation units, without starting capture or a listener.
  [[ "${BINARY_MODE}" == "true" ]] || return 0
  local unit template shadow_uid shadow_shell
  if ! getent passwd easypi-prism-tls >/dev/null 2>&1; then
    useradd --system --user-group --no-create-home --home-dir /nonexistent \
      --shell /usr/sbin/nologin easypi-prism-tls \
      || { warn "Optional Prism TLS account could not be created"; return 0; }
  fi
  shadow_uid="$(id -u easypi-prism-tls)"
  [[ "$shadow_uid" =~ ^[0-9]+$ && "$shadow_uid" -gt 0 && "$shadow_uid" -lt 1000 ]] \
    || { warn "Optional Prism TLS requires a dedicated system account"; return 0; }
  shadow_shell="$(getent passwd easypi-prism-tls | cut -d: -f7)"
  [[ "$shadow_shell" == "/usr/sbin/nologin" || "$shadow_shell" == "/sbin/nologin" || "$shadow_shell" == "/bin/false" ]] \
    || { warn "Optional Prism TLS account must not permit login"; return 0; }
  [[ "$(id -gn easypi-prism-tls)" == "easypi-prism-tls" ]] \
    || { warn "Optional Prism TLS account requires its dedicated group"; return 0; }
  for unit in easypi-prism-endpoint-bridge.socket easypi-prism-endpoint-bridge@.service easypi-prism-chrome.service; do
    template="${BASE_DIR}/templates/systemd/${unit}"
    [[ -f "${template}" && ! -L "${template}" ]] \
      || { warn "Optional Prism TLS template is missing"; return 0; }
    backup_path_if_exists "/etc/systemd/system/${unit}"
    install -o root -g root -m 0644 "${template}" "/etc/systemd/system/${unit}" \
      || { warn "Optional Prism TLS unit install failed"; return 0; }
    sed -i "s|/opt/EasyPi|${EASYPI_PREFIX}|g" "/etc/systemd/system/${unit}" \
      || { warn "Optional Prism TLS unit path setup failed"; return 0; }
  done
  systemctl daemon-reload || { warn "Optional Prism TLS unit reload failed"; return 0; }
  info "Prism TLS Endpoint Bridge installed; socket remains opt-in and is not started"
}

retire_prism_experiments() {
  # Lineage and Counterfactual are development-only experiments. Keep their
  # source code, but never leave their NFQUEUE services or firewall hooks in a
  # normal NetProtection installation.
  local setup_script
  for setup_script in \
    "${SCRIPTS_DST}/settings/setup_prism_lineage.sh" \
    "${SCRIPTS_DST}/settings/setup_prism_counterfactual.sh"; do
    if [[ -x "${setup_script}" ]]; then
      "${setup_script}" remove || warn "Failed to retire PRISM experiment: ${setup_script##*/}"
    fi
  done
}

setup_firewall() {
  info "Configuring UFW firewall"
  if [[ ! -f "${SCRIPTS_DST}/security/setup_firewall.sh" ]]; then
    error "Firewall setup script not found; refusing to expose network services"
    systemctl disable --now easypi-netprotection.service >/dev/null 2>&1 || true
    return 1
  fi
  chmod +x "${SCRIPTS_DST}/security/setup_firewall.sh"
  if ! "${SCRIPTS_DST}/security/setup_firewall.sh"; then
    error "Firewall setup failed; NetProtection has been stopped (fail closed)"
    systemctl disable --now easypi-netprotection.service >/dev/null 2>&1 || true
    return 1
  fi
}

setup_python_venv() {
  info "Setting up Python virtual environment in ${EASYPI_PREFIX}"
  local VENV_PATH="${EASYPI_PREFIX}/backend/.venv"
  
  # Ensure the target directory exists
  mkdir -p "${EASYPI_PREFIX}/backend"

  # Validate pip through the interpreter. The generated pip launcher is not a
  # trust boundary and an older installer may have removed its execute bit.
  if [[ -d "${VENV_PATH}" ]] && {
      [[ ! -x "${VENV_PATH}/bin/python" ]] \
        || ! "${VENV_PATH}/bin/python" -m pip --version >/dev/null 2>&1;
    }; then
    warn "Virtual environment at ${VENV_PATH} appears broken, recreating..."
    rm -rf "${VENV_PATH}"
  fi

  if [[ ! -d "${VENV_PATH}" ]]; then
    info "Creating virtual environment at ${VENV_PATH}"
    apt-get install -y python3-venv python3-pip
    python3 -m venv "${VENV_PATH}"
    
    # Check if venv creation succeeded
    if [[ ! -x "${VENV_PATH}/bin/python" ]] \
        || ! "${VENV_PATH}/bin/python" -m pip --version >/dev/null 2>&1; then
        error "Failed to create virtual environment with pip. Checking for python3-pip..."
        apt-get install -y python3-pip
        python3 -m venv --clear "${VENV_PATH}" || {
            error "Could not ensure pip in venv. Critical failure."
            exit 1
        }
    fi
  fi
  
  info "Installing/updating backend requirements"
  if [[ -f "${EASYPI_PREFIX}/backend/requirements.lock" ]]; then
    "${VENV_PATH}/bin/python" -m pip install --require-hashes -r "${EASYPI_PREFIX}/backend/requirements.lock"
  elif [[ -f "${BASE_DIR}/backend/requirements.lock" ]]; then
    "${VENV_PATH}/bin/python" -m pip install --require-hashes -r "${BASE_DIR}/backend/requirements.lock"
  else
    error "Hashed backend runtime lock not found; refusing an unpinned install."
    exit 1
  fi
  
  secure_runtime_venv "${VENV_PATH}"
}

setup_netprotection_venv() {
  local NP_DIR="${EASYPI_PREFIX}/easypi_netprotection"
  if [[ ! -d "${NP_DIR}" ]]; then
    warn "easypi_netprotection not found - skipping NetProtection venv setup"
    return 0
  fi

  info "Setting up NetProtection Python environment in ${EASYPI_PREFIX}"
  local VENV_PATH="${EASYPI_PREFIX}/backend/.venv"

  # Ensure the target directory exists
  mkdir -p "${EASYPI_PREFIX}/backend"

  # Validate pip through the interpreter so a stale launcher mode cannot break
  # a signed update before the environment is secured again.
  if [[ -d "${VENV_PATH}" ]] && {
      [[ ! -x "${VENV_PATH}/bin/python" ]] \
        || ! "${VENV_PATH}/bin/python" -m pip --version >/dev/null 2>&1;
    }; then
    warn "Virtual environment at ${VENV_PATH} appears broken, recreating..."
    rm -rf "${VENV_PATH}"
  fi

  if [[ ! -d "${VENV_PATH}" ]]; then
    info "Creating virtual environment at ${VENV_PATH}"
    apt-get install -y python3-venv python3-pip
    python3 -m venv "${VENV_PATH}"

    if [[ ! -x "${VENV_PATH}/bin/python" ]] \
        || ! "${VENV_PATH}/bin/python" -m pip --version >/dev/null 2>&1; then
      error "Failed to create virtual environment with pip. Checking for python3-pip..."
      apt-get install -y python3-pip
      python3 -m venv --clear "${VENV_PATH}" || {
        error "Could not ensure pip in venv. Critical failure."
        exit 1
      }
    fi
  fi

  info "Installing NetProtection requirements"
  if [[ -f "${EASYPI_PREFIX}/backend/requirements.lock" ]]; then
    # The production lock contains both backend and NetProtection runtime
    # dependencies, so binary and source installations resolve identically.
    "${VENV_PATH}/bin/python" -m pip install --require-hashes -r "${EASYPI_PREFIX}/backend/requirements.lock"
  else
    error "Hashed backend/NetProtection runtime lock not found; refusing an unpinned install."
    return 1
  fi

  secure_runtime_venv "${VENV_PATH}"
}

setup_backend_binary() {
  info "Setting up EasyPi backend from pre-built binary"
  
  local BINARY_SRC="${BASE_DIR}/backend/bin/easypi-backend"
  local BINARY_DST="${EASYPI_PREFIX}/backend/bin/easypi-backend"
  
  if [[ ! -f "${BINARY_SRC}" ]]; then
    error "Binary not found at ${BINARY_SRC}"
    error "Please ensure you're using a binary release or build with:"
    error "  cd backend/packaging && ./build_binary.sh"
    exit 1
  fi
  
  info "Installing binary to ${BINARY_DST}"
  mkdir -p "${EASYPI_PREFIX}/backend/bin"
  # Skip install if source and destination are the same file
  if [[ "$(realpath "${BINARY_SRC}")" != "$(realpath "${BINARY_DST}" 2>/dev/null)" ]]; then
    install -m 0755 "${BINARY_SRC}" "${BINARY_DST}"
  fi
  chown root:root "${BINARY_DST}"
  chmod 0755 "${BINARY_DST}"
  
  # Ensure data directories exist
  mkdir -p "${EASYPI_PREFIX}/data"
  mkdir -p "${EASYPI_PREFIX}/data/db"
  mkdir -p "${EASYPI_PREFIX}/data/user"
  mkdir -p "${EASYPI_PREFIX}/data/netprotection"
  mkdir -p "${EASYPI_PREFIX}/data/installer"
  mkdir -p "${EASYPI_PREFIX}/backend/data"
  mkdir -p "${EASYPI_PREFIX}/logs"
  mkdir -p "${EASYPI_PREFIX}/logs/tasks"
  
  # Copy data files if they exist (skip if same location)
  if [[ -f "${BASE_DIR}/backend/data/services.json" ]]; then
    if [[ "$(realpath "${BASE_DIR}/backend/data")" != "$(realpath "${EASYPI_PREFIX}/backend/data")" ]]; then
      cp "${BASE_DIR}/backend/data/services.json" "${EASYPI_PREFIX}/backend/data/"
    fi
  fi
  
  # Set ownership
  chown -R "${EASYPI_USER}:${EASYPI_GROUP}" "${EASYPI_PREFIX}/data"
  chown -R "${EASYPI_USER}:${EASYPI_GROUP}" "${EASYPI_PREFIX}/backend/data"
  chown -R "${EASYPI_USER}:${EASYPI_GROUP}" "${EASYPI_PREFIX}/logs"
  
  info "Binary backend installation complete"
}

setup_update_staging() {
  # Administrators upload a release archive and its detached signature through
  # Files into this backend-writable inbox. The privileged dispatcher copies
  # both files into the root-owned staging area before invoking the updater.
  local update_inbox="${EASYPI_PREFIX}/data/updates"
  local trusted_update_dir="/var/lib/easypi/updates"

  if [[ -L "${update_inbox}" || -L "/var/lib/easypi" || -L "${trusted_update_dir}" ]]; then
    die "Unsafe update staging symlink detected"
  fi

  install -d -o "${EASYPI_USER}" -g "${EASYPI_GROUP}" -m 0750 "${update_inbox}"
  install -d -o root -g "${EASYPI_GROUP}" -m 0750 /var/lib/easypi
  install -d -o root -g "${EASYPI_GROUP}" -m 0750 "${trusted_update_dir}"
}

# Serialize dual-stack DNS lookups so a router/ISP that drops the parallel AAAA
# query can't stall every resolution by ~5s (the "internet feels slow" symptom,
# especially after NetworkManager regenerates resolv.conf). Installed as an NM
# dispatcher (survives reboot + netplan regen) plus a resolvconf base seed where
# that framework is used.
configure_dns_dualstack() {
  info "Configuring DNS dual-stack resolver option (single-request-reopen)"
  if [[ -d /etc/NetworkManager ]]; then
    mkdir -p /etc/NetworkManager/dispatcher.d
    local disp=/etc/NetworkManager/dispatcher.d/90-easypi-dns-single-request
    cat > "${disp}" <<'DISP_EOF'
#!/bin/sh
# EasyPi: make glibc serialize the A and AAAA lookups it sends in parallel for
# dual-stack names. Some routers/ISPs drop the second parallel query, causing a
# ~5s timeout on every DNS resolution. NetworkManager regenerates resolv.conf on
# network events; re-assert the option after each one.
case "$2" in
  up|dhcp4-change|dhcp6-change|connectivity-change|hostname|reapply) ;;
  *) exit 0 ;;
esac
RC=/etc/resolv.conf
grep -q '^options single-request-reopen' "$RC" 2>/dev/null || \
  printf 'options single-request-reopen\n' >> "$RC"
exit 0
DISP_EOF
    chown root:root "${disp}"
    chmod 755 "${disp}"
    info "Installed NetworkManager DNS dispatcher: ${disp}"
  fi
  if [[ -d /etc/resolvconf/resolv.conf.d ]]; then
    local base=/etc/resolvconf/resolv.conf.d/base
    grep -q '^options single-request-reopen' "${base}" 2>/dev/null || \
      printf 'options single-request-reopen\n' >> "${base}"
    command -v resolvconf >/dev/null 2>&1 && resolvconf -u >/dev/null 2>&1 || true
  fi
}

verify_ipv6_policy_invariant() {
  # EasyPi cannot enforce parental/DNS policy for clients that receive a
  # separate global IPv6 route unless it is also their IPv6 gateway. Refuse a
  # misleading "protected" installation instead of silently allowing bypass.
  # Operators with an intentionally external IPv6 security boundary may opt in
  # explicitly and accept that traffic outside EasyPi is not filtered.
  command -v ip >/dev/null 2>&1 || return 0

  local global_lines
  global_lines="$(ip -o -6 addr show up scope global 2>/dev/null \
    | awk '$2 !~ /^(lo|tailscale0|wg|tun|tap|docker|br-|veth|virbr|lxc)/ {print}' \
    || true)"
  [[ -z "${global_lines}" ]] && return 0

  if [[ "${EASYPI_ALLOW_UNFILTERED_IPV6:-0}" == "1" ]]; then
    warn "Global IPv6 is active outside EasyPi enforcement; explicit override accepted"
    return 0
  fi

  error "Global IPv6 is active but EasyPi is not the IPv6 gateway. Disable IPv6 on the router or provide an IPv6 enforcement gateway. To accept the bypass risk explicitly, set EASYPI_ALLOW_UNFILTERED_IPV6=1."
  return 1
}

# Validate the network security invariant before altering services or deployed
# code, so a rejected dual-stack installation leaves the current system intact.
verify_ipv6_policy_invariant

create_system_user
deploy_runner_scripts
discard_imported_setup_token_on_fresh_install
configure_runner_logging
configure_sudoers
configure_dns_dualstack
bootstrap_env

# Setup backend based on installation mode
if [[ "${BINARY_MODE}" == "true" ]]; then
  info "Binary mode: Installing pre-built backend binary"
  setup_backend_binary
  setup_netprotection_venv
else
  info "Standard mode: Setting up Python virtual environment"
  setup_python_venv
fi

setup_update_staging

  # Unbound Setup (for NetProtection upstream)
  setup_unbound

  # Establish the network boundary before binding DNS on 0.0.0.0:53. A
  # firewall failure is fatal: continuing would create an open resolver.
  setup_firewall

  # go2rtc binds a WebRTC listener on all interfaces. Start it only after the
  # deny-incoming firewall boundary is active, so a partial install never
  # exposes its direct listener to the LAN.
  setup_go2rtc

  # Recheck the IPv6 invariant at boot and after runtime network changes. This
  # is a security boundary, so failure to establish it aborts installation.
  setup_ipv6_runtime_guard

  # NetProtection requires these units so a persisted strict session restores
  # its fail-closed routes before the LAN DNS listener starts.
  setup_stealth_strict_services

  # NetProtection Setup (runs natively)
  setup_netprotection
  initialize_adult_feed
  setup_netprotection_state_maintenance
  setup_prism_flowgraph
  retire_prism_experiments
  setup_prism_endpoint_bridge

  # Install Backend Service...
  info "Installing Backend Service..."
  
  # Create required directories and files for systemd service
  info "Creating required system files for backend service..."
  mkdir -p /etc/wireguard
  touch /etc/sysctl.conf
  chmod 644 /etc/sysctl.conf
  
  if [[ "${BINARY_MODE}" == "true" ]]; then
    # Use binary service template
    backup_path_if_exists "/etc/systemd/system/easypi-backend.service"
    cp "${BASE_DIR}/templates/systemd/easypi-backend-binary.service" "/etc/systemd/system/easypi-backend.service"
  else
    # Use standard venv-based service template
    backup_path_if_exists "/etc/systemd/system/easypi-backend.service"
    cp "${BASE_DIR}/templates/systemd/easypi-backend.service" "/etc/systemd/system/easypi-backend.service"
  fi
  
  sed -i "s|/opt/EasyPi|${EASYPI_PREFIX}|g" "/etc/systemd/system/easypi-backend.service"
  sed -i "s|User=easypi|User=${EASYPI_USER}|g" "/etc/systemd/system/easypi-backend.service"
  sed -i "s|Group=easypi|Group=${EASYPI_GROUP}|g" "/etc/systemd/system/easypi-backend.service"

  # Mobile Link is installed but deliberately not enabled until an administrator
  # provisions a relay endpoint and installation secret.
  info "Installing inactive Mobile Link agent service..."
  install -d -o root -g "${MOBILE_LINK_GROUP}" -m 0750 /etc/easypi-mobile-link
  install -o root -g root -m 0644 \
    "${BASE_DIR}/templates/systemd/easypi-mobile-link-agent.service" \
    "/etc/systemd/system/easypi-mobile-link-agent.service"
  sed -i "s|/opt/EasyPi|${EASYPI_PREFIX}|g" "/etc/systemd/system/easypi-mobile-link-agent.service"
  sed -i "s|User=easypi-mobile-link|User=${MOBILE_LINK_USER}|g" "/etc/systemd/system/easypi-mobile-link-agent.service"
  sed -i "s|Group=easypi-mobile-link|Group=${MOBILE_LINK_GROUP}|g" "/etc/systemd/system/easypi-mobile-link-agent.service"
  for mobile_unit in easypi-mobile-home-tunnel.service easypi-mobile-home-tunnel-agent.service; do
    install -o root -g root -m 0644 \
      "${BASE_DIR}/templates/systemd/${mobile_unit}" "/etc/systemd/system/${mobile_unit}"
    sed -i "s|/opt/EasyPi|${EASYPI_PREFIX}|g" "/etc/systemd/system/${mobile_unit}"
    sed -i "s|User=easypi-mobile-link|User=${MOBILE_LINK_USER}|g" "/etc/systemd/system/${mobile_unit}"
    sed -i "s|Group=easypi-mobile-link|Group=${MOBILE_LINK_GROUP}|g" "/etc/systemd/system/${mobile_unit}"
  done

  # Keep packet capture outside the web process. This service receives only
  # CAP_NET_RAW and writes a bounded identity inventory.
  info "Installing passive DHCP identity observer..."
  backup_path_if_exists "/etc/systemd/system/easypi-dhcp-observer.service"
  cp "${BASE_DIR}/templates/systemd/easypi-dhcp-observer.service" "/etc/systemd/system/easypi-dhcp-observer.service"
  sed -i "s|/opt/EasyPi|${EASYPI_PREFIX}|g" "/etc/systemd/system/easypi-dhcp-observer.service"
  sed -i "s|User=easypi|User=${EASYPI_USER}|g" "/etc/systemd/system/easypi-dhcp-observer.service"
  sed -i "s|Group=easypi|Group=${EASYPI_GROUP}|g" "/etc/systemd/system/easypi-dhcp-observer.service"

  # Apply Tailscale's recommended UDP forwarding offloads whenever an exit
  # node survives a reboot. Enabling Remote Access also applies this setting
  # immediately through the reviewed root runner.
  info "Installing Tailscale exit-node performance service..."
  [[ -f "${BASE_DIR}/templates/systemd/easypi-tailscale-performance.service" \
      && ! -L "${BASE_DIR}/templates/systemd/easypi-tailscale-performance.service" ]] \
    || { error "Tailscale performance systemd template is missing"; exit 1; }
  backup_path_if_exists "/etc/systemd/system/easypi-tailscale-performance.service"
  install -o root -g root -m 0644 \
    "${BASE_DIR}/templates/systemd/easypi-tailscale-performance.service" \
    "/etc/systemd/system/easypi-tailscale-performance.service"
  sed -i "s|/opt/EasyPi|${EASYPI_PREFIX}|g" "/etc/systemd/system/easypi-tailscale-performance.service"

  # Install installer dispatcher service (root-only job runner)
  info "Installing Installer systemd service..."
  backup_path_if_exists "/etc/systemd/system/easypi-installer@.service"
  cp "${BASE_DIR}/templates/systemd/easypi-installer@.service" "/etc/systemd/system/easypi-installer@.service"
  sed -i "s|/opt/EasyPi|${EASYPI_PREFIX}|g" "/etc/systemd/system/easypi-installer@.service"

  # Install Telegram bot service
  info "Installing Telegram bot systemd service..."
  backup_path_if_exists "/etc/systemd/system/easypi-telegram-bot.service"
  cp "${BASE_DIR}/templates/systemd/easypi-telegram-bot.service" "/etc/systemd/system/easypi-telegram-bot.service"
  sed -i "s|/opt/EasyPi|${EASYPI_PREFIX}|g" "/etc/systemd/system/easypi-telegram-bot.service"
  sed -i "s|User=easypi|User=${EASYPI_USER}|g" "/etc/systemd/system/easypi-telegram-bot.service"
  sed -i "s|Group=easypi|Group=${EASYPI_GROUP}|g" "/etc/systemd/system/easypi-telegram-bot.service"

  # Taildrop is streamed from Tailscale's local API. Only complete files that
  # preserve the system disk reserve are published into PiCloud.
  info "Installing PiCloud Taildrop importer..."
  [[ -f "${SCRIPTS_DST}/services/picloud_taildrop_import.py" \
      && ! -L "${SCRIPTS_DST}/services/picloud_taildrop_import.py" ]] \
    || { error "Trusted PiCloud Taildrop importer is missing"; exit 1; }
  [[ -f "${BASE_DIR}/templates/systemd/easypi-taildrop-import.service" \
      && ! -L "${BASE_DIR}/templates/systemd/easypi-taildrop-import.service" ]] \
    || { error "PiCloud Taildrop systemd template is missing"; exit 1; }
  picloud_root="${EASYPI_PREFIX}/backend/data/picloud"
  picloud_folders=(
    .thumbnails
    .meta
    .trash
    Photos
    Videos
    Documents
    Music
    Encrypted
    Files
  )
  for taildrop_path in \
      /var/lib/easypi/taildrop \
      "${picloud_root}" \
      "${picloud_root}/Taildrop"; do
    [[ ! -L "${taildrop_path}" ]] \
      || { error "Refusing symlinked Taildrop path: ${taildrop_path}"; exit 1; }
  done
  for picloud_folder in "${picloud_folders[@]}"; do
    [[ ! -L "${picloud_root}/${picloud_folder}" ]] \
      || { error "Refusing symlinked PiCloud path: ${picloud_root}/${picloud_folder}"; exit 1; }
  done
  install -d -o root -g "${EASYPI_GROUP}" -m 0710 /var/lib/easypi/taildrop
  # Create the PiCloud root explicitly.  If install(1) creates it implicitly
  # while creating a child directory, the intermediate directory keeps
  # root:root ownership and the unprivileged backend cannot create its
  # .thumbnails, .meta, or .trash runtime directories during startup.
  install -d -o "${EASYPI_USER}" -g "${EASYPI_GROUP}" -m 0750 \
    "${picloud_root}"
  for picloud_folder in "${picloud_folders[@]}"; do
    install -d -o "${EASYPI_USER}" -g "${EASYPI_GROUP}" -m 0750 \
      "${picloud_root}/${picloud_folder}"
  done
  [[ "$(stat -c '%U:%G:%a' -- "${picloud_root}")" == \
      "${EASYPI_USER}:${EASYPI_GROUP}:750" ]] \
    || die "PiCloud storage ownership invariant failed"
  backup_path_if_exists "/etc/systemd/system/easypi-taildrop-import.service"
  install -o root -g root -m 0644 \
    "${BASE_DIR}/templates/systemd/easypi-taildrop-import.service" \
    "/etc/systemd/system/easypi-taildrop-import.service"
  sed -i "s|/opt/EasyPi|${EASYPI_PREFIX}|g" "/etc/systemd/system/easypi-taildrop-import.service"
  sed -i "s|--owner easypi|--owner ${EASYPI_USER}|g" "/etc/systemd/system/easypi-taildrop-import.service"
  sed -i "s|--group easypi|--group ${EASYPI_GROUP}|g" "/etc/systemd/system/easypi-taildrop-import.service"

  # Update-recovery oneshot: on next boot, roll back a self-update that was
  # interrupted mid-apply (e.g. a power cut), restoring the previous version.
  info "Installing update-recovery systemd service..."
  backup_path_if_exists "/etc/systemd/system/easypi-update-recovery.service"
  cp "${BASE_DIR}/scripts/maintenance/easypi-update-recovery.service" "/etc/systemd/system/easypi-update-recovery.service"
  sed -i "s|/opt/EasyPi|${EASYPI_PREFIX}|g" "/etc/systemd/system/easypi-update-recovery.service"

  systemctl daemon-reload
  systemctl enable easypi-update-recovery.service
  systemctl enable easypi-tailscale-performance.service
  systemctl restart easypi-tailscale-performance.service \
    || warn "Tailscale exit-node performance optimization could not be applied"
  systemctl enable --now easypi-dhcp-observer.service
  systemctl enable easypi-taildrop-import.service \
    || warn "PiCloud Taildrop importer could not be enabled"
  systemctl restart easypi-taildrop-import.service \
    || warn "PiCloud Taildrop importer could not be started; Tailscale uploads remain queued"
  systemctl enable easypi-backend.service
  systemctl restart easypi-backend.service
  # Older installed units stopped the Mobile Link agent together with the
  # backend. Bring back only an agent that was already enabled; a clean
  # installation remains deliberately inactive until it is configured.
  if systemctl is-enabled --quiet easypi-mobile-link-agent.service 2>/dev/null; then
    systemctl reset-failed easypi-mobile-link-agent.service 2>/dev/null || true
    systemctl restart easypi-mobile-link-agent.service \
      || warn "Mobile Link agent could not be restarted"
  fi

  # Build Frontend
  setup_frontend

  # Setup nginx with HTTPS
  setup_nginx
  # The installed copy: the script renders its nginx template with the EasyPi
  # root it runs from, and the release payload (BASE_DIR) is a temporary
  # directory without the installation's certificates.
  "${SCRIPTS_DST}/settings/mobile_link_agent.sh" ensure-endpoint >/dev/null \
    || error "Could not install the private Mobile Link nginx endpoint"

  info "Services started."
  
  API_PORT="$(extract_env "API_PORT" "8000")"
  FRONTEND_PORT="$(extract_env "FRONTEND_PORT" "4173")"
  
  API_URL="http://localhost:${API_PORT}/healthz"
  
  info "Checking backend health..."
  if wait_for_http "Backend" "${API_URL}" 45 && systemctl is-active --quiet easypi-backend.service; then
    info "Backend is healthy and responding!"
  else
    error "Backend failed to start correctly."
    warn "Diagnostics:"
    warn "  sudo systemctl status easypi-backend.service --no-pager -l"
    warn "  sudo journalctl -u easypi-backend.service -n 120 --no-pager"
    systemctl status easypi-backend.service --no-pager -l || true
    journalctl -u easypi-backend.service -n 120 --no-pager || true
    exit 1
  fi

  if ! systemctl is-active --quiet easypi-netprotection.service; then
    error "NetProtection failed to start correctly."
    warn "Diagnostics:"
    warn "  sudo systemctl status easypi-netprotection.service --no-pager -l"
    warn "  sudo journalctl -u easypi-netprotection.service -n 120 --no-pager"
    systemctl status easypi-netprotection.service --no-pager -l || true
    journalctl -u easypi-netprotection.service -n 120 --no-pager || true
    exit 1
  fi

  # NetProtection, PRISM and the backend insert their FORWARD jumps at the top
  # when they start, which pushes an active Stealth fail-closed guard below
  # them. Put the guard back in front (no client restart) before checking it.
  "${EASYPI_PREFIX}/scripts/runner" settings/stealth_vpn.sh guard >/dev/null \
    || warn "Stealth guard could not be re-applied before the health check"
  info "Checking DNS, gateway and protected tunnel state..."
  if ! /usr/bin/python3 "/opt/EasyPi/scripts/maintenance/verify_runtime_health.py"; then
    error "EasyPi network runtime failed its health check."
    exit 1
  fi

  info "Service status:"
  systemctl is-active --quiet easypi-backend.service && echo "  ✅ easypi-backend: running" || echo "  ⚠️  easypi-backend: not running"
  systemctl is-active --quiet easypi-netprotection.service && echo "  ✅ easypi-netprotection: running" || echo "  ⚠️  easypi-netprotection: not running"


LOCAL_IP=$(hostname -I | awk '{print $1}')

echo ""
echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
echo -e "  ✅ ${GREEN}EasyPi installation completed successfully!${NC}"
echo ""
echo -e "  🌐 Web Interface:"
echo ""
echo -e "     ${GREEN}https://${LOCAL_IP}/${NC}"
echo -e "     or"
echo -e "     ${GREEN}https://easypi.local/${NC}"
echo ""
echo -e "  ℹ️  If ${YELLOW}easypi.local${NC} doesn't resolve immediately, wait 30-90s for mDNS or use the IP URL above."
echo ""

SETUP_TOKEN_FILE="${EASYPI_PREFIX}/data/.setup_token"
SETUP_TOKEN=""
if [[ -f "${SETUP_TOKEN_FILE}" ]]; then
  IFS= read -r SETUP_TOKEN < "${SETUP_TOKEN_FILE}" || true
fi
if [[ -n "${SETUP_TOKEN}" \
    && "${SETUP_TOKEN}" != \{* \
    && "${SETUP_TOKEN}" != setup-token-sha256:* \
    && "${SETUP_TOKEN}" != recovery-token-sha256:* ]]; then
  if [[ ! -c /dev/tty || ! -w /dev/tty ]]; then
    systemctl stop easypi-backend.service >/dev/null 2>&1 || true
    rm -f -- "${SETUP_TOKEN_FILE}"
    unset SETUP_TOKEN
    die "A first installation requires an interactive terminal for the one-time setup token. The backend was stopped and the undisclosed token was removed."
  fi

  SETUP_TOKEN_DIGEST="$(printf '%s' "${SETUP_TOKEN}" | sha256sum | cut -d' ' -f1)"
  if ! (
    umask 077
    token_hash_tmp="$(mktemp "${EASYPI_PREFIX}/data/.setup-token-hash.XXXXXX")"
    trap 'rm -f -- "${token_hash_tmp}"' EXIT
    printf 'setup-token-sha256:%s' "${SETUP_TOKEN_DIGEST}" > "${token_hash_tmp}"
    chown "${EASYPI_USER}:${EASYPI_GROUP}" "${token_hash_tmp}"
    chmod 0600 "${token_hash_tmp}"
    mv -f -- "${token_hash_tmp}" "${SETUP_TOKEN_FILE}"
    trap - EXIT
  ); then
    unset SETUP_TOKEN
    die "Could not seal the first-administrator setup token; refusing to display or retain it."
  fi
  unset SETUP_TOKEN_DIGEST

  # Drop the backend process that generated and cached the plaintext token.
  systemctl restart easypi-backend.service
  if ! wait_for_http "Backend" "${API_URL}" 45 \
      || ! systemctl is-active --quiet easypi-backend.service; then
    unset SETUP_TOKEN
    die "Backend failed after sealing the setup token."
  fi

  # The complete block bypasses stdout and install.log. After this single write
  # only a one-way hash remains on disk, and the restarted backend has no
  # plaintext copy in memory.
  {
    echo -e "  🔐 ${YELLOW}First administrator setup token:${NC}"
    echo ""
    echo -e "     ${YELLOW}${SETUP_TOKEN}${NC}"
    echo ""
    echo -e "  ⚠️  Save this token securely. It is also your recovery token."
    echo -e "      It will not be shown by the web interface or backend logs."
    echo ""
  } > /dev/tty
  unset SETUP_TOKEN
fi

if command -v tailscale >/dev/null 2>&1; then
  TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "")
  if [[ -n "${TAILSCALE_IP}" ]]; then
    echo -e "     Tailscale: ${GREEN}https://${TAILSCALE_IP}/${NC}"
    echo ""
  fi
fi

echo -e "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo ""
