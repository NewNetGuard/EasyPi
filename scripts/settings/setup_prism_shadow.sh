#!/bin/bash
#
# Install Prism shadow rules. Matching packets are counted and recorded by
# default; an explicit short-lived canary can block the exact signature for one
# private LAN address during controlled validation.

set -euo pipefail

export PATH="/usr/sbin:/usr/bin:/sbin:/bin"
umask 077

EASYPI_ROOT="/opt/EasyPi"
PYTHON="/usr/bin/python3"
IPTABLES="/usr/sbin/iptables"
IPSET="/usr/sbin/ipset"
MODPROBE="/usr/sbin/modprobe"
CHAIN="EASYPI_PRISM_SHADOW"
ALL_RECENT_NAME="EP_PRISM_YANDEX_ALL"
BURST_RECENT_NAME="EP_PRISM_YA_BURST"
RAW_MATCH_SET="easypi_prism_raw_recent"
BURST_MATCH_SET="easypi_prism_yandex_burst"
CANARY_SET="easypi_prism_yandex_canary"
FLOW_BLOCK_SET="easypi_prism_flow_drop"
FLOW_RESET_SET="easypi_prism_flow_reset"
CONTEXT_BLOCK_SET="easypi_prism_context"
RAW_MATCH_TTL_SEC=15
BURST_MATCH_TTL_SEC=300
CANARY_TTL_SEC=600
FLOW_BLOCK_TTL_SEC=180
CONTEXT_BLOCK_TTL_SEC=12
BURST_WINDOW_SEC=3
BURST_MIN_PER_NAME=2
BURST_MIN_TOTAL=5

die() {
    echo "setup_prism_shadow: $*" >&2
    exit 1
}

require_root() {
    [[ $EUID -eq 0 ]] || die "root privileges are required"
}

remove_forward_jumps() {
    while "$IPTABLES" -w 5 -C FORWARD -j "$CHAIN" >/dev/null 2>&1; do
        "$IPTABLES" -w 5 -D FORWARD -j "$CHAIN"
    done
}

create_shadow_sets() {
    [[ -x "$IPSET" ]] || die "ipset is not available"
    "$IPSET" create "$RAW_MATCH_SET" hash:ip \
        family inet timeout "$RAW_MATCH_TTL_SEC" maxelem 1024 -exist
    "$IPSET" create "$BURST_MATCH_SET" hash:ip \
        family inet timeout "$BURST_MATCH_TTL_SEC" maxelem 1024 -exist
    "$IPSET" create "$CANARY_SET" hash:ip \
        family inet timeout "$CANARY_TTL_SEC" maxelem 1024 -exist
    "$IPSET" create "$FLOW_BLOCK_SET" hash:ip,port,ip \
        family inet timeout "$FLOW_BLOCK_TTL_SEC" maxelem 4096 -exist
    "$IPSET" create "$FLOW_RESET_SET" hash:ip,port,ip \
        family inet timeout "$FLOW_BLOCK_TTL_SEC" maxelem 4096 -exist
    "$IPSET" create "$CONTEXT_BLOCK_SET" hash:ip \
        family inet timeout "$CONTEXT_BLOCK_TTL_SEC" maxelem 1024 -exist
}

shadow_enforcement_ready() {
    local set_name

    [[ -x "$IPTABLES" && -x "$IPSET" ]] || return 1
    "$IPTABLES" -w 5 -nL "$CHAIN" >/dev/null 2>&1 || return 1
    "$IPTABLES" -w 5 -C FORWARD -j "$CHAIN" >/dev/null 2>&1 || return 1

    for set_name in "$RAW_MATCH_SET" "$BURST_MATCH_SET" "$CANARY_SET" \
        "$FLOW_BLOCK_SET" "$FLOW_RESET_SET" "$CONTEXT_BLOCK_SET"; do
        "$IPSET" list "$set_name" >/dev/null 2>&1 || return 1
    done

    # Validate both directions and both transports. A chain with the right
    # name but without these rules must never be reported as enforcement-ready.
    "$IPTABLES" -w 5 -C "$CHAIN" \
        -p tcp --dport 443 \
        -m set --match-set "$FLOW_BLOCK_SET" src,src,dst -j DROP \
        >/dev/null 2>&1 || return 1
    "$IPTABLES" -w 5 -C "$CHAIN" \
        -p tcp --sport 443 \
        -m set --match-set "$FLOW_BLOCK_SET" dst,dst,src -j DROP \
        >/dev/null 2>&1 || return 1
    "$IPTABLES" -w 5 -C "$CHAIN" \
        -p udp --dport 443 \
        -m set --match-set "$FLOW_BLOCK_SET" src,src,dst -j DROP \
        >/dev/null 2>&1 || return 1
    "$IPTABLES" -w 5 -C "$CHAIN" \
        -p udp --sport 443 \
        -m set --match-set "$FLOW_BLOCK_SET" dst,dst,src -j DROP \
        >/dev/null 2>&1 || return 1
    "$IPTABLES" -w 5 -C "$CHAIN" \
        -p tcp --dport 443 \
        -m set --match-set "$FLOW_RESET_SET" src,src,dst \
        -j REJECT --reject-with tcp-reset >/dev/null 2>&1 || return 1
    "$IPTABLES" -w 5 -C "$CHAIN" \
        -p tcp --sport 443 \
        -m set --match-set "$FLOW_RESET_SET" dst,dst,src \
        -j REJECT --reject-with tcp-reset >/dev/null 2>&1 || return 1
}

enable_shadow() {
    local rule_output matcher port u32_expr hex_pattern server_name
    local recent_name safe_name index context_key
    local installed=0
    local -a ports=() u32_expressions=() hex_patterns=()
    declare -A recent_names=()
    declare -A context_u32_rules=()

    [[ -x "$PYTHON" ]] || die "python3 is not available"
    [[ -x "$IPTABLES" ]] || die "iptables is not available"
    [[ -d "$EASYPI_ROOT/prism_dpi" ]] || die "Prism package is not installed"

    "$MODPROBE" xt_u32 >/dev/null 2>&1 || true
    "$MODPROBE" xt_string >/dev/null 2>&1 || true
    "$MODPROBE" xt_recent >/dev/null 2>&1 || true
    # Raspberry Pi kernels do not always pull the ipset core and hash types in
    # when xt_set loads. Load every set implementation used below explicitly;
    # create_shadow_sets remains the fail-closed capability check.
    "$MODPROBE" ip_set >/dev/null 2>&1 || true
    "$MODPROBE" ip_set_hash_ip >/dev/null 2>&1 || true
    "$MODPROBE" ip_set_hash_ipportip >/dev/null 2>&1 || true
    "$MODPROBE" xt_set >/dev/null 2>&1 || true
    create_shadow_sets
    "$IPSET" flush "$RAW_MATCH_SET"
    "$IPSET" flush "$BURST_MATCH_SET"
    "$IPSET" flush "$FLOW_BLOCK_SET"
    "$IPSET" flush "$FLOW_RESET_SET"
    "$IPSET" flush "$CONTEXT_BLOCK_SET"

    if ! "$IPTABLES" -w 5 -nL "$CHAIN" >/dev/null 2>&1; then
        "$IPTABLES" -w 5 -N "$CHAIN"
    fi
    "$IPTABLES" -w 5 -F "$CHAIN"
    "$IPSET" destroy easypi_prism_ad_signal 2>/dev/null || true
    "$IPSET" destroy easypi_prism_correlated 2>/dev/null || true
    "$IPSET" destroy easypi_prism_yandex_wide_canary 2>/dev/null || true
    "$IPSET" destroy easypi_prism_ya_ctx_canary 2>/dev/null || true
    "$IPSET" destroy easypi_prism_ya_disk_ctx 2>/dev/null || true

    # Confirmed Yandex Ads flows fail fast so the mobile SDK can dismiss its
    # interstitial instead of waiting behind a silent packet-drop timeout.
    "$IPTABLES" -w 5 -A "$CHAIN" \
        -p tcp --dport 443 \
        -m set --match-set "$FLOW_RESET_SET" src,src,dst \
        -j REJECT --reject-with tcp-reset
    "$IPTABLES" -w 5 -A "$CHAIN" \
        -p tcp --sport 443 \
        -m set --match-set "$FLOW_RESET_SET" dst,dst,src \
        -j REJECT --reject-with tcp-reset

    # Keep an active blocked 5-tuple alive in the set while TCP retransmits.
    # Once the flow goes quiet, the bounded timeout removes it automatically.
    "$IPTABLES" -w 5 -A "$CHAIN" \
        -p tcp --dport 443 \
        -m set --match-set "$FLOW_BLOCK_SET" src,src,dst \
        -j SET --add-set "$FLOW_BLOCK_SET" src,src,dst \
            --timeout "$FLOW_BLOCK_TTL_SEC" --exist
    "$IPTABLES" -w 5 -A "$CHAIN" \
        -p tcp --dport 443 \
        -m set --match-set "$FLOW_BLOCK_SET" src,src,dst -j DROP
    "$IPTABLES" -w 5 -A "$CHAIN" \
        -p tcp --sport 443 \
        -m set --match-set "$FLOW_BLOCK_SET" dst,dst,src \
        -j SET --add-set "$FLOW_BLOCK_SET" dst,dst,src \
            --timeout "$FLOW_BLOCK_TTL_SEC" --exist
    "$IPTABLES" -w 5 -A "$CHAIN" \
        -p tcp --sport 443 \
        -m set --match-set "$FLOW_BLOCK_SET" dst,dst,src -j DROP
    "$IPTABLES" -w 5 -A "$CHAIN" \
        -p udp --dport 443 \
        -m set --match-set "$FLOW_BLOCK_SET" src,src,dst \
        -j SET --add-set "$FLOW_BLOCK_SET" src,src,dst \
            --timeout "$FLOW_BLOCK_TTL_SEC" --exist
    "$IPTABLES" -w 5 -A "$CHAIN" \
        -p udp --dport 443 \
        -m set --match-set "$FLOW_BLOCK_SET" src,src,dst -j DROP
    "$IPTABLES" -w 5 -A "$CHAIN" \
        -p udp --sport 443 \
        -m set --match-set "$FLOW_BLOCK_SET" dst,dst,src \
        -j SET --add-set "$FLOW_BLOCK_SET" dst,dst,src \
            --timeout "$FLOW_BLOCK_TTL_SEC" --exist
    "$IPTABLES" -w 5 -A "$CHAIN" \
        -p udp --sport 443 \
        -m set --match-set "$FLOW_BLOCK_SET" dst,dst,src -j DROP

    cd "$EASYPI_ROOT"
    rule_output="$("$PYTHON" -m prism_dpi.rule mobile_ads_yandex)" ||
        die "Prism rule generation failed"

    while IFS=$'\t' read -r matcher port u32_expr hex_pattern server_name; do
        [[ -n "$matcher" ]] || continue
        [[ "$matcher" == "tls-sni-shadow" ]] ||
            die "unsupported Prism shadow matcher"
        [[ "$port" =~ ^[0-9]{1,5}$ ]] || die "invalid destination port"
        ((10#$port >= 1 && 10#$port <= 65535)) || die "destination port out of range"
        [[ "$u32_expr" =~ ^[0-9A-Fx@\>\&\=]+$ ]] || die "invalid u32 expression"
        [[ "$hex_pattern" =~ ^\|[0-9a-f]+\|$ ]] || die "invalid SNI hex pattern"
        (( (${#hex_pattern} - 2) % 2 == 0 )) || die "odd-length SNI hex pattern"
        [[ "$server_name" =~ ^[a-z0-9]+([.-][a-z0-9]+)*$ ]] ||
            die "invalid SNI server name"

        safe_name="${server_name//./_}"
        safe_name="${safe_name//-/_}"
        recent_name="EP_PRISM_${safe_name^^}"
        [[ ${#recent_name} -le 200 ]] || die "recent name is too long"
        recent_names["$server_name"]="$recent_name"
        ports+=("$port")
        u32_expressions+=("$u32_expr")
        hex_patterns+=("$hex_pattern")

        "$IPTABLES" -w 5 -A "$CHAIN" \
            -p tcp --dport "$port" \
            -m u32 --u32 "$u32_expr" \
            -m string --hex-string "$hex_pattern" --algo bm \
            -m recent --name "$recent_name" --rsource --set \
            -m recent --name "$ALL_RECENT_NAME" --rsource --set \
            -j SET --add-set "$RAW_MATCH_SET" src --timeout "$RAW_MATCH_TTL_SEC"
        installed=$((installed + 1))
    done <<< "$rule_output"

    ((installed > 0)) || die "Prism generated no shadow rules"
    [[ -n "${recent_names[yandex.com]:-}" ]] ||
        die "missing yandex.com shadow rule"
    [[ -n "${recent_names[yandex.ru]:-}" ]] ||
        die "missing yandex.ru shadow rule"

    for index in "${!ports[@]}"; do
        "$IPTABLES" -w 5 -A "$CHAIN" \
            -p tcp --dport "${ports[$index]}" \
            -m u32 --u32 "${u32_expressions[$index]}" \
            -m string --hex-string "${hex_patterns[$index]}" --algo bm \
            -m recent --name "${recent_names[yandex.com]}" --rsource \
                --rcheck --seconds "$BURST_WINDOW_SEC" --hitcount "$BURST_MIN_PER_NAME" \
            -m recent --name "${recent_names[yandex.ru]}" --rsource \
                --rcheck --seconds "$BURST_WINDOW_SEC" --hitcount "$BURST_MIN_PER_NAME" \
            -m recent --name "$ALL_RECENT_NAME" --rsource \
                --rcheck --seconds "$BURST_WINDOW_SEC" --hitcount "$BURST_MIN_TOTAL" \
            -m recent --name "$BURST_RECENT_NAME" --rsource --set \
            -j SET --add-set "$BURST_MATCH_SET" src \
                --timeout "$BURST_MATCH_TTL_SEC"
    done

    # Active blocking is opt-in, private-LAN-only, and expires automatically.
    # The canary set is intentionally not flushed when shadow rules are rebuilt.
    for index in "${!ports[@]}"; do
        "$IPTABLES" -w 5 -A "$CHAIN" \
            -p tcp --dport "${ports[$index]}" \
            -m set --match-set "$CANARY_SET" src \
            -m u32 --u32 "${u32_expressions[$index]}" \
            -m string --hex-string "${hex_patterns[$index]}" --algo bm \
            -j DROP
    done

    # A confirmed causal candidate activates this bounded retry guard. It drops
    # only fresh compact ClientHello packets, not established or large-browser
    # TLS flows, and the source membership expires automatically.
    for index in "${!ports[@]}"; do
        context_key="${ports[$index]}:${u32_expressions[$index]}"
        [[ -z "${context_u32_rules[$context_key]+x}" ]] || continue
        context_u32_rules["$context_key"]=1
        "$IPTABLES" -w 5 -A "$CHAIN" \
            -p tcp --dport "${ports[$index]}" \
            -m set --match-set "$CONTEXT_BLOCK_SET" src \
            -m u32 --u32 "${u32_expressions[$index]}" \
            -j DROP
    done

    "$IPTABLES" -w 5 -A "$CHAIN" -j RETURN

    remove_forward_jumps
    "$IPTABLES" -w 5 -I FORWARD 1 -j "$CHAIN"
    echo "Prism shadow enabled with $installed observation rules; burst=${BURST_MIN_PER_NAME}+${BURST_MIN_PER_NAME},total=${BURST_MIN_TOTAL}/${BURST_WINDOW_SEC}s"
}

ensure_shadow_enforcement() {
    if shadow_enforcement_ready; then
        return 0
    fi

    # Keep stdout reserved for the flow-block-stream request/response protocol.
    # Recovery diagnostics and enable_shadow's summary go to stderr.
    echo "setup_prism_shadow: restoring missing Prism enforcement state" >&2
    enable_shadow >&2
    shadow_enforcement_ready ||
        die "Prism enforcement state is incomplete after recovery"
}

disable_shadow() {
    [[ -x "$IPTABLES" ]] || die "iptables is not available"
    remove_forward_jumps
    if "$IPTABLES" -w 5 -nL "$CHAIN" >/dev/null 2>&1; then
        "$IPTABLES" -w 5 -F "$CHAIN"
        "$IPTABLES" -w 5 -X "$CHAIN"
    fi
    if [[ -x "$IPSET" ]]; then
        "$IPSET" destroy "$RAW_MATCH_SET" 2>/dev/null || true
        "$IPSET" destroy "$BURST_MATCH_SET" 2>/dev/null || true
        "$IPSET" destroy "$CANARY_SET" 2>/dev/null || true
        "$IPSET" destroy "$FLOW_BLOCK_SET" 2>/dev/null || true
        "$IPSET" destroy "$FLOW_RESET_SET" 2>/dev/null || true
        "$IPSET" destroy "$CONTEXT_BLOCK_SET" 2>/dev/null || true
    fi
    echo "Prism shadow disabled"
}

is_private_ipv4() {
    local value="$1" a b c d extra octet
    IFS=. read -r a b c d extra <<< "$value"
    [[ -z "${extra:-}" ]] || return 1
    for octet in "$a" "$b" "$c" "$d"; do
        [[ "$octet" =~ ^[0-9]{1,3}$ ]] || return 1
        ((10#$octet <= 255)) || return 1
    done
    if ((10#$a == 10)); then
        return 0
    fi
    if ((10#$a == 192 && 10#$b == 168)); then
        return 0
    fi
    ((10#$a == 172 && 10#$b >= 16 && 10#$b <= 31))
}

is_public_ipv4() {
    local value="$1" a b c d extra octet
    IFS=. read -r a b c d extra <<< "$value"
    [[ -z "${extra:-}" ]] || return 1
    for octet in "$a" "$b" "$c" "$d"; do
        [[ "$octet" =~ ^[0-9]{1,3}$ ]] || return 1
        ((10#$octet <= 255)) || return 1
    done
    ((10#$a != 0 && 10#$a != 10 && 10#$a != 127 && 10#$a < 224)) || return 1
    ((10#$a == 169 && 10#$b == 254)) && return 1
    ((10#$a == 172 && 10#$b >= 16 && 10#$b <= 31)) && return 1
    ((10#$a == 192 && 10#$b == 168)) && return 1
    return 0
}

validate_candidate_flow() {
    local client_ip="$1" client_port="$2" server_ip="$3" protocol="$4" retry_guard="$5"
    local termination="${6:-drop}"
    is_private_ipv4 "$client_ip" || die "flow client must be private IPv4"
    is_public_ipv4 "$server_ip" || die "flow server must be public IPv4"
    [[ "$client_port" =~ ^[0-9]{1,5}$ ]] || die "invalid flow client port"
    ((10#$client_port >= 1024 && 10#$client_port <= 65535)) ||
        die "flow client port out of range"
    [[ "$protocol" == "tcp" || "$protocol" == "udp" ]] ||
        die "flow protocol must be tcp or udp"
    [[ "$retry_guard" == "true" || "$retry_guard" == "false" ]] ||
        die "invalid retry guard"
    [[ "$protocol" == "tcp" || "$retry_guard" == "false" ]] ||
        die "UDP retry guard is unsupported"
    [[ "$termination" == "drop" || "$termination" == "reset" ]] ||
        die "invalid flow termination"
    [[ "$termination" != "reset" || "$protocol" == "tcp" ]] ||
        die "flow reset requires TCP"
    [[ "$termination" != "reset" || "$retry_guard" == "false" ]] ||
        die "flow reset cannot enable retry guard"
}

add_candidate_flow() {
    local client_ip="$1" client_port="$2" server_ip="$3" protocol="$4" retry_guard="$5"
    local termination="${6:-drop}" target_set="$FLOW_BLOCK_SET"
    ensure_shadow_enforcement
    if [[ "$termination" == "reset" ]]; then
        target_set="$FLOW_RESET_SET"
    fi
    "$IPSET" add "$target_set" \
        "$client_ip,$protocol:$client_port,$server_ip" \
        timeout "$FLOW_BLOCK_TTL_SEC" -exist
    if [[ "$retry_guard" == "true" ]]; then
        "$IPSET" add "$CONTEXT_BLOCK_SET" "$client_ip" \
            timeout "$CONTEXT_BLOCK_TTL_SEC" -exist
    fi
}

block_candidate_flow() {
    local client_ip="$1" client_port="$2" server_ip="$3" protocol="$4" retry_guard="$5"
    local termination="${6:-drop}"
    validate_candidate_flow "$client_ip" "$client_port" "$server_ip" "$protocol" "$retry_guard" "$termination"
    create_shadow_sets
    add_candidate_flow "$client_ip" "$client_port" "$server_ip" "$protocol" "$retry_guard" "$termination"
    echo "Prism candidate flow blocked for ${FLOW_BLOCK_TTL_SEC}s; protocol=${protocol}; retry_guard=${retry_guard}; termination=${termination}"
}

flow_block_stream() {
    local client_ip client_port server_ip protocol retry_guard termination extra
    ensure_shadow_enforcement
    while IFS=$'\t' read -r client_ip client_port server_ip protocol retry_guard termination extra; do
        [[ -n "$client_ip" ]] || continue
        termination="${termination:-drop}"
        if [[ -n "${extra:-}" || ( "$retry_guard" != "true" && "$retry_guard" != "false" ) ]]; then
            echo "setup_prism_shadow: rejected malformed stream request" >&2
            printf 'error\n'
            continue
        fi
        if (validate_candidate_flow \
            "$client_ip" "$client_port" "$server_ip" "$protocol" "$retry_guard" "$termination" &&
            add_candidate_flow \
                "$client_ip" "$client_port" "$server_ip" "$protocol" "$retry_guard" "$termination"); then
            printf 'ok\n'
        else
            echo "setup_prism_shadow: rejected invalid stream request" >&2
            printf 'error\n'
        fi
    done
}

enable_canary() {
    local client_ip="$1"
    is_private_ipv4 "$client_ip" || die "canary IP must be private IPv4"
    "$IPTABLES" -w 5 -nL "$CHAIN" >/dev/null 2>&1 ||
        die "Prism shadow must be enabled before canary"
    create_shadow_sets
    "$IPSET" add "$CANARY_SET" "$client_ip" timeout "$CANARY_TTL_SEC" -exist
    echo "Prism canary enabled for $client_ip (${CANARY_TTL_SEC}s)"
}

disable_canary() {
    local client_ip="$1"
    is_private_ipv4 "$client_ip" || die "canary IP must be private IPv4"
    if "$IPSET" list "$CANARY_SET" >/dev/null 2>&1; then
        "$IPSET" del "$CANARY_SET" "$client_ip" 2>/dev/null || true
    fi
    echo "Prism canary disabled for $client_ip"
}

show_status() {
    [[ -x "$IPTABLES" ]] || die "iptables is not available"
    if ! "$IPTABLES" -w 5 -nL "$CHAIN" >/dev/null 2>&1; then
        echo "Prism shadow disabled"
        return 0
    fi

    "$IPTABLES" -w 5 -nL "$CHAIN" -v --line-numbers
    local recent_name
    for recent_name in EP_PRISM_YANDEX_COM EP_PRISM_YANDEX_RU \
        "$ALL_RECENT_NAME" "$BURST_RECENT_NAME"; do
        if [[ -r "/proc/net/xt_recent/$recent_name" ]]; then
            echo
            echo "$recent_name source addresses:"
            /usr/bin/cat "/proc/net/xt_recent/$recent_name"
        fi
    done
    if [[ -x "$IPSET" ]]; then
        local set_name
        for set_name in "$RAW_MATCH_SET" "$BURST_MATCH_SET" "$CANARY_SET" \
            "$FLOW_BLOCK_SET" "$FLOW_RESET_SET" "$CONTEXT_BLOCK_SET"; do
            if "$IPSET" list "$set_name" >/dev/null 2>&1; then
                echo
                "$IPSET" list "$set_name"
            fi
        done
    fi
}

require_root
case "${1:-}" in
    enable)
        [[ $# -eq 1 ]] || die "usage: setup_prism_shadow.sh enable"
        enable_shadow
        ;;
    disable)
        [[ $# -eq 1 ]] || die "usage: setup_prism_shadow.sh disable"
        disable_shadow
        ;;
    status)
        [[ $# -eq 1 ]] || die "usage: setup_prism_shadow.sh status"
        show_status
        ;;
    ensure)
        [[ $# -eq 1 ]] || die "usage: setup_prism_shadow.sh ensure"
        ensure_shadow_enforcement
        echo "Prism enforcement ready"
        ;;
    canary-enable)
        [[ $# -eq 2 ]] || die "usage: setup_prism_shadow.sh canary-enable PRIVATE_IPV4"
        enable_canary "$2"
        ;;
    canary-disable)
        [[ $# -eq 2 ]] || die "usage: setup_prism_shadow.sh canary-disable PRIVATE_IPV4"
        disable_canary "$2"
        ;;
    flow-block)
        [[ $# -eq 5 ]] ||
            die "usage: setup_prism_shadow.sh flow-block PRIVATE_IPV4 CLIENT_PORT PUBLIC_IPV4 PROTOCOL"
        block_candidate_flow "$2" "$3" "$4" "$5" true
        ;;
    flow-block-exact)
        [[ $# -eq 5 ]] ||
            die "usage: setup_prism_shadow.sh flow-block-exact PRIVATE_IPV4 CLIENT_PORT PUBLIC_IPV4 PROTOCOL"
        block_candidate_flow "$2" "$3" "$4" "$5" false
        ;;
    flow-block-stream)
        [[ $# -eq 1 ]] || die "usage: setup_prism_shadow.sh flow-block-stream"
        flow_block_stream
        ;;
    *) die "unsupported action" ;;
esac
