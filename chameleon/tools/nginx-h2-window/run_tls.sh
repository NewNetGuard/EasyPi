#!/bin/sh
# TLS bench: nginx (stock / patched) with HTTP/2 over TLS, tunnel-like location,
# behind wan.py; client is the real carrier stack from clientcore
# (TestNginxWindowBench, cross-compiled test binary). Local only.
# usage: run_tls.sh <test-binary> <out-dir> "variant:buf" ...
set -eu
N="$HOME/ngx"
HERE=$(cd "$(dirname "$0")" && pwd)
BIN="$1"; OUT="$2"; shift 2
mkdir -p "$OUT" "$N/tls-cert"
if [ ! -s "$N/tls-cert/cert.pem" ]; then
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3 \
        -subj /CN=bench.local -addext subjectAltName=DNS:bench.local \
        -keyout "$N/tls-cert/key.pem" -out "$N/tls-cert/cert.pem" 2>/dev/null
fi
python3 -I "$HERE/sink.py" 18081 & SINK=$!
python3 -I "$HERE/wan.py" 18490 18443 15 20000000 & WAN1=$!
python3 -I "$HERE/wan.py" 18491 18443 15 0 & WAN2=$!
trap 'kill $SINK $WAN1 $WAN2 2>/dev/null' EXIT
sleep 1
for cfg in "$@"; do
    variant=${cfg%%:*}; buf=${cfg#*:}
    P="$N/tlsrun-$variant-$buf"
    mkdir -p "$P/conf" "$P/logs"
    cat > "$P/conf/nginx.conf" <<EOF
master_process off;
daemon off;
worker_processes 1;
pid nginx.pid;
error_log error.log info;
events { worker_connections 1024; }
http {
    access_log off;
    server {
        listen 127.0.0.1:18443 ssl;
        http2 on;
        ssl_certificate $N/tls-cert/cert.pem;
        ssl_certificate_key $N/tls-cert/key.pem;
        ssl_protocols TLSv1.2 TLSv1.3;
        keepalive_requests 1000000;
        location /up {
            proxy_pass http://127.0.0.1:18081;
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_request_buffering off;
            proxy_buffering off;
            client_body_buffer_size $buf;
            client_max_body_size 0;
            client_body_timeout 24h;
            proxy_read_timeout 24h;
            proxy_send_timeout 24h;
        }
    }
}
EOF
    : > "$P/error.log"
    "$N/tls-$variant/objs/nginx" -p "$P/" -c conf/nginx.conf & NGX=$!
    sleep 0.5
    NGINX_BENCH_ADDR=127.0.0.1:18490 NGINX_BENCH_FREE_ADDR=127.0.0.1:18491 \
    NGINX_BENCH_CERT="$N/tls-cert/cert.pem" NGINX_BENCH_OUT="$OUT/tls-$variant-$buf.json" \
        "$BIN" -test.run '^TestNginxWindowBench$' -test.count=1 -test.timeout 30m > "$OUT/tls-$variant-$buf.log" 2>&1 || echo "test exit $? for $cfg"
    kill $NGX; wait $NGX 2>/dev/null || true
    grep -E "\[(alert|crit|error|emerg)\]" "$P/error.log" | head -5 || true
    echo "done $cfg"
done
