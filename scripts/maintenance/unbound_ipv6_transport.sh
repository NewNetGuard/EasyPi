#!/bin/bash
# Keep Unbound's IPv6 transport in step with real IPv6 reachability.
#
# With do-ip6 enabled on a host that cannot reach the internet over IPv6,
# Unbound still picks IPv6 addresses of nameservers. Every such send fails
# locally, yet it counts against max-global-quota (the per-request budget of
# upstream queries), and Unbound also looks up the AAAA records of every
# nameserver. On a cold cache that exhausts the budget: requests fail with
# SERVFAIL, and when the failed lookup is a zone's DNSKEY the whole zone is
# marked bogus for val-bogus-ttl seconds.
#
# The decision is made from the root servers' answers over each family, not from
# the presence of a route: a route without working IPv6 behaves the same as no
# route. The result is written to a separate Unbound snippet; Unbound is
# reloaded only when the setting changes.
#
# usage: unbound_ipv6_transport.sh [--dry-run | --no-reload]
#   --dry-run    report the decision without changing anything
#   --no-reload  write the snippet but leave reloading to the caller

set -uo pipefail
PATH=/usr/sbin:/usr/bin:/sbin:/bin

readonly SNIPPET="${EASYPI_UNBOUND_TRANSPORT_FILE:-/etc/unbound/unbound.conf.d/easypi-transport.conf}"
# a, k and c root servers: run by three different operators.
readonly V6_PROBES=(2001:503:ba3e::2:30 2001:7fd::1 2001:500:2::c)
readonly V4_PROBES=(198.41.0.4 193.0.14.129 192.33.4.12)

DRY_RUN=0
NO_RELOAD=0
case "${1:-}" in
    --dry-run) DRY_RUN=1 ;;
    --no-reload) NO_RELOAD=1 ;;
esac

log() { printf 'unbound-ipv6-transport: %s\n' "$*"; }

# Count the root servers that answer an SOA query over one address family.
count_answering() {
    local family="$1"; shift
    local address answered=0
    for address in "$@"; do
        if dig "-${family}" +tries=2 +time=2 +norecurse +noall +comments \
                "@${address}" . SOA 2>/dev/null | grep -q 'status: NOERROR'; then
            answered=$((answered + 1))
        fi
    done
    printf '%s\n' "${answered}"
}

current_setting() {
    [[ -f "${SNIPPET}" ]] || { printf 'unset\n'; return; }
    local value
    value="$(sed -nE 's/^[[:space:]]*do-ip6:[[:space:]]*(yes|no)[[:space:]]*$/\1/p' "${SNIPPET}" | tail -n 1)"
    printf '%s\n' "${value:-unset}"
}

write_snippet() {
    local value="$1" dir temp
    dir="$(dirname "${SNIPPET}")"
    temp="$(mktemp "${dir}/.easypi-transport.XXXXXX")" || return 1
    {
        printf '# Managed by EasyPi (unbound_ipv6_transport.sh). Rewritten automatically\n'
        printf '# from the measured IPv6 reachability of the root servers; do not edit.\n'
        printf 'server:\n'
        printf '    do-ip6: %s\n' "${value}"
    } > "${temp}" || { rm -f "${temp}"; return 1; }
    chmod 0644 "${temp}" || { rm -f "${temp}"; return 1; }
    mv -f "${temp}" "${SNIPPET}" || { rm -f "${temp}"; return 1; }
}

reload_unbound() {
    systemctl is-active --quiet unbound || return 0
    # reload_keep_cache (Unbound >= 1.21) re-reads the configuration without
    # discarding the cache; older versions fall back to a plain reload.
    if unbound-control reload_keep_cache >/dev/null 2>&1; then
        return 0
    fi
    systemctl reload-or-restart unbound
}

main() {
    local v4 v6 current decision
    v4="$(count_answering 4 "${V4_PROBES[@]}")"
    if (( v4 == 0 )); then
        # No IPv4 answers either: the host is offline, so the IPv6 result would
        # say nothing about IPv6 itself. Keep the current setting.
        log "no root server answered over IPv4; leaving the transport unchanged"
        return 0
    fi
    v6="$(count_answering 6 "${V6_PROBES[@]}")"
    current="$(current_setting)"

    if (( v6 >= 2 )); then
        decision=yes
    elif (( v6 == 0 )); then
        decision=no
    elif [[ "${current}" != unset ]]; then
        # One answer out of three is inconclusive; do not flap.
        decision="${current}"
    else
        decision=no
    fi

    log "root servers answering: IPv4 ${v4}/${#V4_PROBES[@]}, IPv6 ${v6}/${#V6_PROBES[@]}; do-ip6 ${current} -> ${decision}"
    [[ "${decision}" == "${current}" ]] && return 0
    (( DRY_RUN )) && return 0

    local backup=""
    if [[ -f "${SNIPPET}" ]]; then
        backup="$(mktemp)" && cp -p "${SNIPPET}" "${backup}" || return 1
    fi
    write_snippet "${decision}" || { log "could not write ${SNIPPET}"; rm -f "${backup}"; return 1; }
    if ! unbound-checkconf >/dev/null 2>&1; then
        log "unbound-checkconf rejected the new transport; restoring the previous file"
        if [[ -n "${backup}" ]]; then mv -f "${backup}" "${SNIPPET}"; else rm -f "${SNIPPET}"; fi
        return 1
    fi
    rm -f "${backup}"
    if (( NO_RELOAD )); then
        log "wrote do-ip6: ${decision}; reload left to the caller"
        return 0
    fi
    reload_unbound || { log "Unbound reload failed"; return 1; }
    log "Unbound now runs with do-ip6: ${decision}"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main
fi
