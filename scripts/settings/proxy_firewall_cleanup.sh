#!/usr/bin/env bash
set -euo pipefail

delete_rules() {
    local table="$1"
    local chain="$2"
    local tag="$3"
    iptables -t "$table" -S "$chain" 2>/dev/null | \
        awk -v t="$tag" '$0 ~ t {sub(/^-A /, "-D "); print}' | \
        while read -r rule; do
            iptables -t "$table" $rule 2>/dev/null || true
        done
}

delete_rules nat PREROUTING "easypi-proxy-"
delete_rules filter FORWARD "easypi-proxy-quic"
