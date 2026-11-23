#!/bin/sh
# Builds /usr/sbin/nginx exactly as Ubuntu's nginx 1.28.3-2ubuntu1.12 package
# configures it (static modules, compiler and linker hardening flags), with and
# without the WINDOW_UPDATE patch. The package's dynamic modules (geoip, image
# filter, perl, xslt, mail, stream) are not built: they are separate packages
# and none is installed on the VPS.
# Inputs: ~/ngx/nginx-1.28.3 (Ubuntu .12 source + package patches),
# ~/ngx/patched (same + h2-unbuffered-window-update-threshold.patch),
# headers unpacked from libssl-dev, libpcre2-dev, zlib1g-dev, libcrypt-dev into ~/ngx/ssl-dev.
set -eu
N="$HOME/ngx"
HERE=$(cd "$(dirname "$0")" && pwd)
INC="-I$N/ssl-dev/usr/include -I$N/ssl-dev/usr/include/x86_64-linux-gnu"
mkdir -p "$N/ssl-lib"
ln -sf /usr/lib/x86_64-linux-gnu/libssl.so.3 "$N/ssl-lib/libssl.so"
ln -sf /usr/lib/x86_64-linux-gnu/libcrypto.so.3 "$N/ssl-lib/libcrypto.so"
ln -sf "$(readlink -f /usr/lib/x86_64-linux-gnu/libpcre2-8.so.0)" "$N/ssl-lib/libpcre2-8.so"
ln -sf "$(readlink -f /usr/lib/x86_64-linux-gnu/libz.so.1)" "$N/ssl-lib/libz.so"
ln -sf "$(readlink -f /usr/lib/x86_64-linux-gnu/libcrypt.so.1)" "$N/ssl-lib/libcrypt.so"
ARGS="$N/ubuntu-configure.args"
cat > "$ARGS" <<EOF
--with-cc-opt=-g -O2 -Werror=implicit-function-declaration -fno-omit-frame-pointer -mno-omit-leaf-frame-pointer -flto=auto -ffat-lto-objects -fstack-protector-strong -fstack-clash-protection -Wformat -Werror=format-security -fcf-protection -fPIC -Wdate-time -D_FORTIFY_SOURCE=3 $INC
--with-ld-opt=-Wl,-Bsymbolic-functions -flto=auto -ffat-lto-objects -Wl,-z,relro -Wl,-z,now -fPIC -L$N/ssl-lib
--prefix=/usr/share/nginx
--conf-path=/etc/nginx/nginx.conf
--http-log-path=/var/log/nginx/access.log
--error-log-path=stderr
--lock-path=/var/lock/nginx.lock
--pid-path=/run/nginx.pid
--modules-path=/usr/lib/nginx/modules
--http-client-body-temp-path=/var/lib/nginx/body
--http-fastcgi-temp-path=/var/lib/nginx/fastcgi
--http-proxy-temp-path=/var/lib/nginx/proxy
--http-scgi-temp-path=/var/lib/nginx/scgi
--http-uwsgi-temp-path=/var/lib/nginx/uwsgi
--with-compat
--with-debug
--with-pcre-jit
--with-http_ssl_module
--with-http_stub_status_module
--with-http_realip_module
--with-http_auth_request_module
--with-http_v2_module
--with-http_v3_module
--with-http_dav_module
--with-http_slice_module
--with-threads
--build=Ubuntu
--with-http_addition_module
--with-http_flv_module
--with-http_gunzip_module
--with-http_gzip_static_module
--with-http_mp4_module
--with-http_random_index_module
--with-http_secure_link_module
--with-http_sub_module
--with-mail_ssl_module
--with-stream_ssl_module
--with-stream_ssl_preread_module
--with-stream_realip_module
EOF
for pair in "nginx-1.28.3 ubuntu-stock" "patched ubuntu-patched"; do
    set -- $pair
    rm -rf "${N:?}/$2"
    cp -a "$N/$1" "$N/$2"
    rm -rf "$N/$2/objs" "$N/$2/Makefile"
    # configure's feature tests must see the unpacked headers too (crypt.h).
    C_INCLUDE_PATH="$N/ssl-dev/usr/include:$N/ssl-dev/usr/include/x86_64-linux-gnu" \
    LIBRARY_PATH="$N/ssl-lib" CONFIGURE_ARGS_FILE="$ARGS" \
        python3 -I "$HERE/build.py" "$N/$2" || exit 1
    grep -q "NGX_HAVE_GNU_CRYPT_R" "$N/$2/objs/ngx_auto_config.h" || { echo "crypt_r not detected"; exit 1; }
    "$N/$2/objs/nginx" -V 2>&1 | head -3
    sha256sum "$N/$2/objs/nginx"
done
diff -ru "$N/ubuntu-stock/src" "$N/ubuntu-patched/src" | sha256sum
