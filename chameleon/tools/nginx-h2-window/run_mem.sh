#!/bin/sh
# nginx memory with N concurrent carrier-like streams (TestNginxMemoryBench).
# Fresh nginx and sink per measurement, so VmHWM is the peak of that run only.
# usage: run_mem.sh <test-binary> <out.jsonl> "variant:buf" ...
# Needs ~/ngx/tls-<variant>/objs/nginx and the cert from run_tls.sh. Local only.
set -eu
N="$HOME/ngx"
HERE=$(cd "$(dirname "$0")" && pwd)
BIN="$1"; OUT="$2"; shift 2
: > "$OUT"
python3 -I "$HERE/wan.py" 18491 18443 15 0 & WAN=$!
trap 'kill $WAN 2>/dev/null' EXIT
for cfg in "$@"; do
    variant=${cfg%%:*}; buf=${cfg#*:}
    P="$N/tlsrun-$variant-$buf"   # conf written by run_tls.sh
    for streams in ${STREAMS:-1 10 50 100 128}; do
        for mode in ${MODES:-idle active stalled}; do
            python3 -I "$HERE/sink.py" 18081 & SINK=$!
            : > "$P/error.log"
            "$N/tls-$variant/objs/nginx" -p "$P/" -c conf/nginx.conf & NGX=$!
            sleep 0.7
            NGINX_MEM_ADDR=127.0.0.1:18491 NGINX_MEM_PID=$NGX NGINX_MEM_STREAMS=$streams \
            NGINX_MEM_MODE=$mode NGINX_BENCH_CERT="$N/tls-cert/cert.pem" NGINX_MEM_OUT="$OUT.tmp" \
                "$BIN" -test.run '^TestNginxMemoryBench$' -test.count=1 -test.timeout 5m > /dev/null 2>&1 \
                || echo "FAIL $cfg $streams $mode"
            if [ -s "$OUT.tmp" ]; then
                sed "s/^{/{\"variant\":\"$variant\",\"buf\":\"$buf\",/" "$OUT.tmp" >> "$OUT"
                rm -f "$OUT.tmp"
            fi
            kill $NGX; wait $NGX 2>/dev/null || true
            kill $SINK; wait $SINK 2>/dev/null || true
            grep -E "\[(alert|crit|emerg)\]" "$P/error.log" | head -3 || true
        done
    done
    echo "done $cfg"
done
