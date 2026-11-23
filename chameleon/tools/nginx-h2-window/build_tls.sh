#!/bin/sh
# Build stock and patched nginx with TLS (h2 over TLS), linked to the system
# libssl.so.3, using OpenSSL headers unpacked from libssl-dev into ~/ngx/ssl-dev.
# Inputs: ~/ngx/nginx-1.28.3 (Ubuntu .12 sources) and ~/ngx/patched (same + patch).
set -eu
N="$HOME/ngx"
HERE=$(cd "$(dirname "$0")" && pwd)
mkdir -p "$N/ssl-lib"
ln -sf /usr/lib/x86_64-linux-gnu/libssl.so.3 "$N/ssl-lib/libssl.so"
ln -sf /usr/lib/x86_64-linux-gnu/libcrypto.so.3 "$N/ssl-lib/libcrypto.so"
for pair in "nginx-1.28.3 tls-stock" "patched tls-patched"; do
    set -- $pair
    rm -rf "${N:?}/$2"
    cp -a "$N/$1" "$N/$2"
    rm -rf "$N/$2/objs" "$N/$2/Makefile"
    EXTRA_CC="-I$N/ssl-dev/usr/include -I$N/ssl-dev/usr/include/x86_64-linux-gnu" \
        python3 -I "$HERE/build.py" "$N/$2" --with-http_ssl_module "--with-ld-opt=-L$N/ssl-lib"
    "$N/$2/objs/nginx" -V 2>&1 | grep -E "built with|TLS SNI"
    ldd "$N/$2/objs/nginx" | grep -E "libssl|libcrypto"
done
diff -ru "$N/tls-stock/src" "$N/tls-patched/src" | sha256sum
