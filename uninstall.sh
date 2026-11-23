#!/usr/bin/env bash
set -euo pipefail

export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
umask 077

readonly GREEN="\033[0;32m"
readonly YELLOW="\033[0;33m"
readonly RED="\033[0;31m"
readonly NC="\033[0m"
readonly DEFAULT_EASYPI_PREFIX="/opt/EasyPi"
readonly UPDATE_LOCK_FILE="/run/lock/easypi-update.lock"
readonly BACKUP_LOCK_FILE="/run/easypi-backup.lock"
readonly PACKAGE_LOCK_FILE="/run/lock/easypi-package-manager.lock"

PURGE=0
ASSUME_YES=0
EASYPI_PREFIX="${EASYPI_PREFIX:-${DEFAULT_EASYPI_PREFIX}}"

# Keep this inventory explicit. Besides the current installer-owned units it
# includes retired EasyPi units so repeated uninstall runs also clean upgrades
# from older releases. No non-EasyPi service is stopped or removed.
readonly -a EASYPI_UNITS=(
  easypi-backend.service
  easypi-chameleon-tcp.socket
  easypi-chameleon-client.service
  easypi-mobile-link-agent.service
  easypi-stealth-guard.service
  easypi-stealth-dns.service
  easypi-stealth-resume.service
  easypi-dhcp-observer.service
  easypi-netprotection.service
  easypi-netprotection-state-maintenance.timer
  easypi-netprotection-state-maintenance.service
  easypi-ipv6-policy-guard.service
  easypi-ipv6-policy-guard.timer
  easypi-prism-shadow.service
  easypi-prism-flowgraph.service
  easypi-prism-endpoint-bridge.socket
  easypi-prism-chrome.service
  easypi-prism-endpoint-bridge@.service
  easypi-prism-lineage.service
  easypi-prism-counterfactual.service
  easypi-telegram-bot.service
  easypi-taildrop-import.service
  easypi-tailscale-performance.service
  easypi-restore.service
  easypi-update-recovery.service
  easypi-gateway-fix.timer
  easypi-gateway-fix.service
  easypi-duckdns.timer
  easypi-duckdns.service
  easypi-installer@.service
  easypi-backup.timer
  easypi-celery.service
)

info() {
  printf '%b==>%b %s\n' "${GREEN}" "${NC}" "$*"
}

warn() {
  printf '%b==>%b %s\n' "${YELLOW}" "${NC}" "$*" >&2
}

die() {
  printf '%bERROR:%b %s\n' "${RED}" "${NC}" "$*" >&2
  exit 2
}

usage() {
  cat <<'EOF'
Usage: sudo bash ./uninstall.sh [OPTIONS]

Remove EasyPi services and host integration while preserving application data.

Options:
  --prefix PATH  EasyPi installation prefix (default: /opt/EasyPi)
  --purge        Also delete the validated installation and EasyPi state data
  --yes          Required confirmation for --purge
  -h, --help     Show this help

By default the installation prefix, /var/lib/easypi,
/var/lib/easypi-security, and /etc/easypi are retained. Purging is deliberately
non-interactive and requires both --purge and --yes so unattended invocations
cannot delete data because stdin happened to contain a confirmation string.
EOF
}

validate_prefix() {
  local candidate="${1:-}"
  local canonical=""
  local basename=""

  [[ -n "${candidate}" ]] || die "EasyPi prefix must not be empty"
  [[ "${candidate}" == /* ]] || die "EasyPi prefix must be an absolute path"
  [[ ${#candidate} -le 240 ]] || die "EasyPi prefix is unreasonably long"
  [[ "${candidate}" != *$'\n'* && "${candidate}" != *$'\r'* && "${candidate}" != *$'\t'* ]] \
    || die "EasyPi prefix contains control characters"

  command -v realpath >/dev/null 2>&1 || die "realpath is required"
  canonical="$(realpath -m -- "${candidate}")" \
    || die "Unable to canonicalize EasyPi prefix"
  [[ -n "${canonical}" && "${candidate}" == "${canonical}" ]] \
    || die "EasyPi prefix must already be canonical (no '..', '.', duplicate, trailing, or symlinked components)"

  case "${canonical}" in
    /|/bin|/boot|/dev|/etc|/home|/lib|/lib64|/media|/mnt|/opt|/proc|/root|/run|/sbin|/srv|/sys|/tmp|/usr|/usr/local|/var|/var/lib|/var/tmp)
      die "Refusing dangerous EasyPi prefix: ${canonical}"
      ;;
  esac

  basename="${canonical##*/}"
  [[ "${basename}" =~ ^[Ee][Aa][Ss][Yy][Pp][Ii]([._-][A-Za-z0-9][A-Za-z0-9._-]*)?$ ]] \
    || die "EasyPi prefix basename must be EasyPi or an easypi-* variant"

  if [[ -e "${canonical}" || -L "${canonical}" ]]; then
    [[ -d "${canonical}" && ! -L "${canonical}" ]] \
      || die "EasyPi prefix must be a real directory, not a file or symbolic link"
  fi

  printf '%s\n' "${canonical}"
}

parse_args() {
  while (( $# > 0 )); do
    case "$1" in
      --prefix)
        (( $# >= 2 )) || die "--prefix requires a path"
        EASYPI_PREFIX="$2"
        shift 2
        ;;
      --purge)
        PURGE=1
        shift
        ;;
      --yes)
        ASSUME_YES=1
        shift
        ;;
      -h|--help)
        usage
        exit 0
        ;;
      --)
        shift
        (( $# == 0 )) || die "Unexpected positional arguments"
        ;;
      *)
        die "Unknown argument: $1"
        ;;
    esac
  done

  EASYPI_PREFIX="$(validate_prefix "${EASYPI_PREFIX}")"

  if (( ASSUME_YES == 1 && PURGE == 0 )); then
    die "--yes is accepted only together with --purge"
  fi
  if (( PURGE == 1 && ASSUME_YES == 0 )); then
    die "Data purge requires both --purge and --yes"
  fi
}

require_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    die "Please run with sudo: sudo bash ./uninstall.sh"
  fi
}

validate_operation_lock() {
  local path="$1"
  local owner=""
  local mode=""

  if [[ -e "${path}" || -L "${path}" ]]; then
    [[ -f "${path}" && ! -L "${path}" ]] \
      || die "Unsafe EasyPi operation lock: ${path}"
    owner="$(stat -Lc '%u' -- "${path}" 2>/dev/null)" \
      || die "Unable to inspect EasyPi operation lock: ${path}"
    mode="$(stat -Lc '%a' -- "${path}" 2>/dev/null)" \
      || die "Unable to inspect EasyPi operation lock: ${path}"
    [[ "${owner}" == "0" && $((8#${mode} & 8#022)) -eq 0 ]] \
      || die "EasyPi operation lock has unsafe ownership or permissions: ${path}"
  fi
}

acquire_operation_locks() {
  command -v flock >/dev/null 2>&1 || die "flock is required"
  [[ -d /run/lock && ! -L /run/lock ]] || die "Trusted /run/lock is unavailable"
  [[ -d /run && ! -L /run ]] || die "Trusted /run is unavailable"
  validate_operation_lock "${UPDATE_LOCK_FILE}"
  validate_operation_lock "${BACKUP_LOCK_FILE}"
  validate_operation_lock "${PACKAGE_LOCK_FILE}"

  exec 7>"${PACKAGE_LOCK_FILE}"
  chmod 0600 "${PACKAGE_LOCK_FILE}"
  flock -n 7 \
    || die "An EasyPi package operation is running; retry uninstall after it finishes"

  exec 8>"${UPDATE_LOCK_FILE}"
  chmod 0600 "${UPDATE_LOCK_FILE}"
  flock -n 8 \
    || die "An EasyPi signed update is running; retry uninstall after it finishes"

  exec 9>"${BACKUP_LOCK_FILE}"
  chmod 0600 "${BACKUP_LOCK_FILE}"
  flock -n 9 \
    || die "An EasyPi backup or restore is running; retry uninstall after it finishes"
}

path_is_root_owned_nonwritable_dir() {
  local path="$1"
  local owner=""
  local permissions=""

  [[ -d "${path}" && ! -L "${path}" ]] || return 1
  owner="$(stat -Lc '%u' -- "${path}" 2>/dev/null)" || return 1
  permissions="$(stat -Lc '%A' -- "${path}" 2>/dev/null)" || return 1
  [[ "${owner}" == "0" ]] || return 1
  [[ "${permissions:5:1}" != "w" && "${permissions:8:1}" != "w" ]]
}

assert_safe_purge_target() {
  local prefix="$1"
  local parent="${prefix%/*}"

  # A missing prefix makes a repeated purge a no-op. Existing targets must
  # match the root-owned layout produced by install.sh before recursive removal.
  [[ -e "${prefix}" || -L "${prefix}" ]] || return 0
  [[ -d "${prefix}" && ! -L "${prefix}" ]] \
    || die "Refusing to purge a non-directory or symbolic-link prefix"
  path_is_root_owned_nonwritable_dir "${parent}" \
    || die "Refusing to purge from a parent directory writable by non-root users"
  path_is_root_owned_nonwritable_dir "${prefix}" \
    || die "Refusing to purge an installation directory writable by non-root users"

  [[ -f "${prefix}/VERSION" && ! -L "${prefix}/VERSION" ]] \
    || die "Refusing to purge a directory without a regular EasyPi VERSION marker"
  [[ -d "${prefix}/scripts" && ! -L "${prefix}/scripts" ]] \
    || die "Refusing to purge a directory without the EasyPi scripts tree"
  [[ -d "${prefix}/backend" && ! -L "${prefix}/backend" ]] \
    || die "Refusing to purge a directory without the EasyPi backend tree"
}

script_is_trusted() {
  local script="$1"
  local owner=""
  local permissions=""

  [[ -f "${script}" && ! -L "${script}" ]] || return 1
  owner="$(stat -Lc '%u' -- "${script}" 2>/dev/null)" || return 1
  permissions="$(stat -Lc '%A' -- "${script}" 2>/dev/null)" || return 1
  [[ "${owner}" == "0" ]] || return 1
  [[ "${permissions:5:1}" != "w" && "${permissions:8:1}" != "w" ]]
}

run_trusted_cleanup() {
  local base_dir="$1"
  local relative="$2"
  local script=""
  shift 2

  script="${base_dir}/${relative}"
  if script_is_trusted "${script}"; then
    EASYPI_LIFECYCLE_MODE=uninstall /bin/bash -- "${script}" "$@" \
      || warn "Runtime cleanup failed: ${relative} $*"
  elif [[ -e "${script}" || -L "${script}" ]]; then
    warn "Skipped untrusted runtime cleanup script: ${script}"
  fi
}

run_runtime_cleanup() {
  local base_dir="$1"
  local relative=""

  info "Removing EasyPi runtime network policies..."

  # These scripts own routing tables and netfilter chains which survive process
  # termination.  Execute only reviewed, root-owned, non-writable installed
  # copies; never flush unrelated firewall state.
  run_trusted_cleanup "${base_dir}" scripts/settings/outbound_vpn.sh down
  run_trusted_cleanup "${base_dir}" scripts/settings/stealth_vpn.sh down
  run_trusted_cleanup "${base_dir}" scripts/settings/setup_app_blocking.sh clear-runtime
  run_trusted_cleanup "${base_dir}" scripts/settings/setup_vpn_blocking.sh clear-runtime
  run_trusted_cleanup "${base_dir}" scripts/settings/tailscale_performance.sh restore
  run_trusted_cleanup "${base_dir}" scripts/security/ipv6_policy_guard.sh --clear
  run_trusted_cleanup "${base_dir}" scripts/security/setup_firewall.sh clear-runtime

  # Lineage, Counterfactual, and Flowgraph can leave NFQUEUE chains behind.
  for relative in \
    scripts/settings/setup_prism_lineage.sh \
    scripts/settings/setup_prism_counterfactual.sh \
    scripts/settings/setup_prism_flowgraph.sh; do
    run_trusted_cleanup "${base_dir}" "${relative}" remove
  done
  run_trusted_cleanup "${base_dir}" scripts/settings/setup_prism_shadow.sh disable
}

collect_installer_instances() {
  local line=""
  local unit=""

  command -v systemctl >/dev/null 2>&1 || return 0
  while IFS= read -r line; do
    unit="${line%%[[:space:]]*}"
    [[ "${unit}" =~ ^easypi-installer@[A-Za-z0-9_.:-]+\.service$ ]] || continue
    printf '%s\n' "${unit}"
  done < <(systemctl list-units --all --full --plain --no-legend \
    'easypi-installer@*.service' 2>/dev/null || true)
}

remove_systemd_units() {
  local unit=""
  local instance=""
  local -a installer_instances=()

  if command -v systemctl >/dev/null 2>&1; then
    mapfile -t installer_instances < <(collect_installer_instances)

    # Stop only this observer's active instances before removing its template.
    while read -r instance _; do
      [[ "$instance" == easypi-prism-endpoint-bridge@*.service ]] || continue
      systemctl stop -- "$instance" >/dev/null 2>&1 || true
    done < <(systemctl list-units 'easypi-prism-endpoint-bridge@*.service' --all --plain --no-legend 2>/dev/null || true)
    info "Stopping and disabling EasyPi systemd units..."
    for instance in "${installer_instances[@]}"; do
      systemctl disable --now -- "${instance}" >/dev/null 2>&1 || true
    done
    for unit in "${EASYPI_UNITS[@]}"; do
      systemctl disable --now -- "${unit}" >/dev/null 2>&1 || true
    done
  else
    warn "systemctl is unavailable; removing unit files without stopping loaded units"
  fi

  for unit in "${EASYPI_UNITS[@]}"; do
    rm -f -- "/etc/systemd/system/${unit}"
  done

  rm -f -- \
    /etc/easypi/chrome-bridge.json \
    /etc/default/easypi-prism-endpoint-bridge \
    /etc/default/easypi-prism-flowgraph \
    /etc/default/easypi-prism-lineage \
    /etc/default/easypi-prism-counterfactual

  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    for instance in "${installer_instances[@]}"; do
      systemctl reset-failed -- "${instance}" >/dev/null 2>&1 || true
    done
    for unit in "${EASYPI_UNITS[@]}"; do
      systemctl reset-failed -- "${unit}" >/dev/null 2>&1 || true
    done
  fi
}

remove_host_integration() {
  info "Removing EasyPi host integration..."

  # EasyPi versions before 1.1 created this dangerously generic restore hook.
  # Remove it only when its complete contents match the old product template;
  # an administrator-owned script at the same path is left untouched.
  local legacy_hook="/etc/network/if-pre-up.d/iptables"
  local legacy_hook_text
  legacy_hook_text=$'#!/bin/bash\n# Restore iptables rules on boot\nif [ -f /etc/iptables/rules.v4 ]; then\n    iptables-restore < /etc/iptables/rules.v4\nfi'
  if [[ -f "${legacy_hook}" && ! -L "${legacy_hook}" ]] \
      && [[ "$(<"${legacy_hook}")" == "${legacy_hook_text}" ]]; then
    rm -f -- "${legacy_hook}"
  fi

  rm -f -- \
    /etc/nginx/sites-enabled/easypi \
    /etc/nginx/sites-available/easypi \
    /etc/nginx/sites-enabled/easypi-mobile-link \
    /etc/nginx/sites-available/easypi-mobile-link \
    /etc/sudoers.d/easypi \
    /etc/NetworkManager/dispatcher.d/90-easypi-ipv6-policy-guard \
    /etc/NetworkManager/dispatcher.d/90-easypi-dns-single-request \
    /etc/sysctl.d/99-easypi-netprotection.conf \
    /etc/sysctl.d/99-easypi-forwarding.conf \
    /etc/sysctl.d/99-easypi-gateway.conf \
    /etc/sysctl.d/99-easypi-ip-forward.conf \
    /etc/sysctl.d/99-easypi-tailscale-exit-node.conf \
    /etc/unbound/unbound.conf.d/easypi-recursive.conf \
    /etc/unbound/unbound.conf.d/easypi.conf \
    /etc/cron.monthly/easypi-cert-renewal \
    /etc/letsencrypt/renewal-hooks/deploy/easypi-doh.sh

  if command -v nginx >/dev/null 2>&1 && nginx -t >/dev/null 2>&1; then
    systemctl reload nginx >/dev/null 2>&1 || true
  fi
  if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet unbound; then
    systemctl try-reload-or-restart unbound >/dev/null 2>&1 || true
  fi
}

remove_managed_go2rtc() {
  local directory="/opt/go2rtc"
  local marker="${directory}/.easypi-managed"
  local owner="" mode="" directory_owner="" directory_mode=""

  # go2rtc uses a generic service name, so never touch it unless the root-only
  # ownership marker created by EasyPi is present and exact. This avoids
  # removing an administrator's independent go2rtc installation.
  if [[ ! -f "${marker}" || -L "${marker}" || -L "${directory}" ]] \
      || [[ "$(cat -- "${marker}" 2>/dev/null || true)" != "easypi-managed-go2rtc-v1" ]]; then
    [[ -e "${directory}" || -e /etc/systemd/system/go2rtc.service ]] \
      && warn "Unmanaged go2rtc installation was preserved."
    return 0
  fi
  owner="$(stat -c '%u' -- "${marker}" 2>/dev/null)" || return 0
  mode="$(stat -c '%a' -- "${marker}" 2>/dev/null)" || return 0
  directory_owner="$(stat -c '%u' -- "${directory}" 2>/dev/null)" || return 0
  directory_mode="$(stat -c '%a' -- "${directory}" 2>/dev/null)" || return 0
  if [[ "${owner}" != 0 || "${directory_owner}" != 0 ]] \
      || (( (8#${mode} & 8#022) != 0 || (8#${directory_mode} & 8#022) != 0 )); then
    warn "Unsafe go2rtc ownership marker was ignored."
    return 0
  fi

  info "Stopping EasyPi-managed go2rtc integration..."
  if command -v systemctl >/dev/null 2>&1; then
    systemctl disable --now go2rtc.service >/dev/null 2>&1 || true
  fi
  rm -f -- /etc/systemd/system/go2rtc.service
  if command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload >/dev/null 2>&1 || true
    systemctl reset-failed go2rtc.service >/dev/null 2>&1 || true
  fi

  if (( PURGE == 1 )); then
    [[ "$(realpath -sm -- "${directory}")" == "${directory}" ]] \
      || die "Refusing unsafe go2rtc purge path"
    rm -rf -- "${directory}"
    info "EasyPi-managed go2rtc state was purged."
  fi
}

purge_state() {
  local prefix="$1"

  assert_safe_purge_target "${prefix}"
  info "Purging validated EasyPi installation and persistent state..."

  # Every recursive target is either the already validated prefix or a fixed,
  # product-owned absolute path. No user input is interpolated into fixed paths.
  rm -rf -- "${prefix}"
  rm -rf -- \
    /var/lib/easypi \
    /var/lib/easypi-security \
    /var/log/easypi \
    /var/backups/easypi \
    /etc/easypi
  rm -rf -- /etc/easypi-mobile-link
  rm -f -- \
    /var/log/easypi-cert-renewal.log \
    /etc/ssl/certs/easypi-selfsigned.crt \
    /etc/ssl/private/easypi-selfsigned.key

  info "EasyPi application data and persistent state were purged."
}

main() {
  parse_args "$@"
  require_root
  acquire_operation_locks

  # Stop/remove units first, then clear their persistent network state. Cleanup
  # runs in lifecycle mode, so `down` cannot recreate the removed services.
  remove_systemd_units
  run_runtime_cleanup "${EASYPI_PREFIX}"
  remove_managed_go2rtc
  remove_host_integration

  if (( PURGE == 1 )); then
    purge_state "${EASYPI_PREFIX}"
  else
    info "EasyPi services were removed; application data was preserved."
    printf '  Retained prefix: %s\n' "${EASYPI_PREFIX}"
    printf '  Retained state:  /var/lib/easypi, /var/lib/easypi-security, /etc/easypi\n'
    printf '  To delete these paths deliberately, rerun with --purge --yes.\n'
  fi

  info "Administrator firewall rules and global UFW policies were preserved."
  info "Existing EasyPi SSH firewall access was retained for remote recovery."

  info "EasyPi uninstallation completed."
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
  main "$@"
fi
