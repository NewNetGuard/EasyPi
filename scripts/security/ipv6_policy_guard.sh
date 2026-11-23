#!/bin/bash
# Persistent fail-closed guard for IPv6 routes outside EasyPi policy.

set -uo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin

readonly CHAIN="EASYPI_IPV6_GUARD"
readonly STAGING="EASYPI_IPV6_GUARD_NEXT"
readonly EMERGENCY="EASYPI_IPV6_EMERGENCY"
readonly STATE_DIR="${EASYPI_IPV6_STATE_DIR:-/var/lib/easypi/security}"
readonly STATE_FILE="${STATE_DIR}/ipv6_policy_guard.json"
readonly LOCK_FILE="${EASYPI_IPV6_LOCK_FILE:-/run/lock/easypi-ipv6-policy.lock}"
readonly CHECK_INTERVAL_SECONDS=15

POLICY_INTERFACES=()
SLEEP_PID=""

log_error() {
    echo "ERROR: $*" >&2
}

wake_monitor() {
    if [[ -n "${SLEEP_PID}" ]]; then
        kill "${SLEEP_PID}" >/dev/null 2>&1 || true
    fi
}

write_state() {
    local status="$1"
    local interfaces="${2:-}"
    local temp
    install -d -o root -g "${EASYPI_GROUP:-easypi}" -m 0750 "${STATE_DIR}" \
        || return 1
    temp="$(mktemp "${STATE_DIR}/.ipv6-policy.XXXXXX")" || return 1
    printf '{"status":"%s","interfaces":"%s","checked_at":%s}\n' \
        "${status}" "${interfaces}" "$(date +%s)" > "${temp}" \
        || { rm -f "${temp}"; return 1; }
    chown "root:${EASYPI_GROUP:-easypi}" "${temp}" \
        || { rm -f "${temp}"; return 1; }
    chmod 0640 "${temp}" || { rm -f "${temp}"; return 1; }
    mv -f "${temp}" "${STATE_FILE}" || { rm -f "${temp}"; return 1; }
}

disable_kernel_forwarding() {
    command -v sysctl >/dev/null 2>&1 || return 1
    sysctl -q -w net.ipv6.conf.all.forwarding=0 >/dev/null 2>&1
}

fail_with_forwarding_disabled() {
    local reason="${1:-emergency-forwarding-disabled}"
    disable_kernel_forwarding || return 1
    write_state "${reason}" "${POLICY_INTERFACES[*]:-}" || true
    # Returning failure is deliberate: Requires/BindsTo must prevent or stop
    # dependent services when netfilter cannot maintain the primary boundary.
    return 1
}

chain_exists() {
    local target="$1"
    ip6tables -w 5 -nL "${target}" >/dev/null 2>&1
}

remove_hooks() {
    local target="$1"
    while ip6tables -w 5 -C FORWARD -j "${target}" >/dev/null 2>&1; do
        ip6tables -w 5 -D FORWARD -j "${target}" || return 1
    done
}

delete_chain() {
    local target="$1"
    remove_hooks "${target}" || return 1
    if chain_exists "${target}"; then
        ip6tables -w 5 -F "${target}" || return 1
        ip6tables -w 5 -X "${target}" || return 1
    fi
}

install_emergency_guard() {
    # If policy inspection or publication fails, block every forwarded IPv6
    # packet. If netfilter itself is unavailable, disabling kernel forwarding
    # is the last fail-closed boundary.
    if ! command -v ip6tables >/dev/null 2>&1; then
        fail_with_forwarding_disabled
        return $?
    fi

    # Every attached emergency chain was populated before attachment. Keep it
    # in place instead of briefly detaching it during repeated error handling.
    if chain_exists "${EMERGENCY}" \
        && ip6tables -w 5 -C FORWARD -j "${EMERGENCY}" >/dev/null 2>&1; then
        write_state "emergency-blocked" "${POLICY_INTERFACES[*]:-}" || true
        return 0
    fi

    remove_hooks "${EMERGENCY}" || {
        fail_with_forwarding_disabled
        return $?
    }
    if chain_exists "${EMERGENCY}"; then
        ip6tables -w 5 -F "${EMERGENCY}" || {
            fail_with_forwarding_disabled
            return $?
        }
    else
        ip6tables -w 5 -N "${EMERGENCY}" || {
            fail_with_forwarding_disabled
            return $?
        }
    fi
    ip6tables -w 5 -A "${EMERGENCY}" -j REJECT \
        --reject-with icmp6-adm-prohibited || {
        fail_with_forwarding_disabled
        return $?
    }
    ip6tables -w 5 -I FORWARD 1 -j "${EMERGENCY}" || {
        fail_with_forwarding_disabled
        return $?
    }
    write_state "emergency-blocked" "${POLICY_INTERFACES[*]:-}" || true
}

inspect_policy_interfaces() {
    local global_addresses default_routes interface_lines interface
    command -v ip >/dev/null 2>&1 || return 1
    global_addresses="$(ip -o -6 addr show up scope global 2>/dev/null)" \
        || return 1
    default_routes="$(ip -o -6 route show default 2>/dev/null)" \
        || return 1

    interface_lines="$({
        awk '{sub(/@.*/, "", $2); print $2}' <<< "${global_addresses}"
        awk '{for (i=1; i<=NF; i++) if ($i == "dev" && i < NF) print $(i+1)}' <<< "${default_routes}"
    } | awk 'NF && $1 !~ /^(lo|tailscale0|wg|tun|tap|docker|br-|veth|virbr|lxc)/' | sort -u)" \
        || return 1

    POLICY_INTERFACES=()
    if [[ -n "${interface_lines}" ]]; then
        mapfile -t POLICY_INTERFACES <<< "${interface_lines}"
    fi
    for interface in "${POLICY_INTERFACES[@]}"; do
        [[ "${interface}" =~ ^[A-Za-z0-9_.:-]{1,32}$ ]] || return 1
    done
}

recover_staging_chain() {
    if ! chain_exists "${STAGING}"; then
        return 0
    fi
    if ip6tables -w 5 -C FORWARD -j "${STAGING}" >/dev/null 2>&1; then
        remove_hooks "${CHAIN}" || return 1
        if chain_exists "${CHAIN}"; then
            ip6tables -w 5 -F "${CHAIN}" || return 1
            ip6tables -w 5 -X "${CHAIN}" || return 1
        fi
        ip6tables -w 5 -E "${STAGING}" "${CHAIN}" || return 1
    else
        ip6tables -w 5 -F "${STAGING}" || return 1
        ip6tables -w 5 -X "${STAGING}" || return 1
    fi
}

publish_runtime_policy() {
    local tunnel interface
    command -v ip6tables >/dev/null 2>&1 || return 1
    recover_staging_chain || return 1

    if [[ "${#POLICY_INTERFACES[@]}" -eq 0 ]]; then
        delete_chain "${STAGING}" || return 1
        delete_chain "${CHAIN}" || return 1
        delete_chain "${EMERGENCY}" || return 1
        write_state "clear" "" || return 1
        return 0
    fi

    ip6tables -w 5 -N "${STAGING}" || return 1
    for tunnel in tailscale0 'wg+' 'tun+' 'tap+' 'docker+' 'br-+' 'virbr+' 'lxc+'; do
        ip6tables -w 5 -A "${STAGING}" -i "${tunnel}" -j RETURN || return 1
    done
    for interface in "${POLICY_INTERFACES[@]}"; do
        # Router-on-a-stick uses one interface in both directions. Only reply
        # direction may pass; original client flows are rejected immediately.
        ip6tables -w 5 -A "${STAGING}" -i "${interface}" \
            -m conntrack --ctdir REPLY -j RETURN || return 1
        ip6tables -w 5 -A "${STAGING}" -i "${interface}" \
            -j REJECT --reject-with icmp6-adm-prohibited || return 1
    done
    ip6tables -w 5 -A "${STAGING}" -j RETURN || return 1

    # The complete policy is attached before the old one and the emergency
    # chain are removed. A partial chain is never the only active boundary.
    ip6tables -w 5 -I FORWARD 1 -j "${STAGING}" || return 1
    remove_hooks "${CHAIN}" || return 1
    if chain_exists "${CHAIN}"; then
        ip6tables -w 5 -F "${CHAIN}" || return 1
        ip6tables -w 5 -X "${CHAIN}" || return 1
    fi
    ip6tables -w 5 -E "${STAGING}" "${CHAIN}" || return 1
    delete_chain "${EMERGENCY}" || return 1
    write_state "blocked" "${POLICY_INTERFACES[*]}" || return 1
}

check_policy() {
    inspect_policy_interfaces || return 1
    publish_runtime_policy || return 1
}

clear_runtime_policy() {
    # Uninstall must not leave a fail-closed chain attached after the service
    # has been disabled.  Recover an interrupted staging swap first so every
    # possible EasyPi-owned chain can then be detached deterministically.
    if command -v ip6tables >/dev/null 2>&1; then
        recover_staging_chain || return 1
        delete_chain "${STAGING}" || return 1
        delete_chain "${CHAIN}" || return 1
        delete_chain "${EMERGENCY}" || return 1
    fi
    write_state "clear" "" || true
}

run_monitor() {
    # Establish a boundary before the first network inspection. Required units
    # cannot start until this process has successfully entered monitor mode.
    install_emergency_guard || return 1

    while true; do
        if ! check_policy; then
            log_error "IPv6 policy verification failed; applying emergency lockdown"
            install_emergency_guard || return 1
        fi
        sleep "${CHECK_INTERVAL_SECONDS}" &
        SLEEP_PID=$!
        wait "${SLEEP_PID}" 2>/dev/null || true
        SLEEP_PID=""
    done
}

[[ "${EUID}" -eq 0 ]] || { log_error "IPv6 policy guard requires root"; exit 1; }
install -d -o root -g root -m 0755 /run/lock || exit 1
exec 9>"${LOCK_FILE}"
flock -n 9 || { log_error "another IPv6 policy guard is running"; exit 1; }

# NetworkManager sends SIGUSR1 to interrupt sleep and request an immediate pass.
trap wake_monitor USR1
trap 'wake_monitor; exit 0' TERM INT

case "${1:-}" in
    --establish)
        install_emergency_guard
        ;;
    --monitor)
        run_monitor
        ;;
    --clear)
        clear_runtime_policy
        ;;
    *)
        log_error "usage: ipv6_policy_guard.sh --establish|--monitor|--clear"
        exit 2
        ;;
esac
