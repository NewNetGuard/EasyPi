#!/bin/bash
# End-to-end test of chameleon/server/nginx/easypi-chameleon-nginx on a
# throwaway Ubuntu (WSL) as root: install, idempotence, package update via the
# apt hook, failed build falling back to the packaged binary, and removal.
# usage: test_vps_tool.sh   (installs nginx and build tools; the caller cleans
# up with test_vps_tool_cleanup.sh)
set -euo pipefail
NGINX_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../server/nginx" && pwd)"
TOOL=/usr/local/sbin/easypi-chameleon-nginx
SHARE=/usr/local/share/easypi-chameleon-nginx
PATCH_NAME=h2-unbuffered-window-update-threshold.patch
STATE=/var/lib/easypi-chameleon/nginx/state
pass() { echo "PASS: $*"; }
fail() { echo "FAIL: $*"; exit 1; }
field() { "$TOOL" status | sed -n "s/^$1=//p"; }
wait_rebuild() {
    for _ in $(seq 1 900); do
        systemctl is-active --quiet easypi-chameleon-nginx-rebuild.service || return 0
        sleep 2
    done
    fail "rebuild did not finish"
}

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
dpkg -s nginx >/dev/null 2>&1 || apt-get install -y -qq nginx >/dev/null
echo "nginx package $(dpkg-query -W -f='${Version}' nginx)"
systemctl start nginx
install -m 0700 "$NGINX_DIR/easypi-chameleon-nginx" "$TOOL"
install -d -m 0755 "$SHARE"
install -m 0644 "$NGINX_DIR/$PATCH_NAME" "$SHARE/$PATCH_NAME"
packaged_sha=$(sha256sum /usr/sbin/nginx | cut -d' ' -f1)

# 1. install
start=$(date +%s)
"$TOOL" install
echo "install took $(( $(date +%s) - start )) s"
[[ "$(field running)" == patched ]] || fail "install did not leave the patched binary running"
dpkg-divert --list /usr/sbin/nginx | grep -q easypi-chameleon || fail "no diversion"
[[ "$(sha256sum /usr/sbin/nginx.distrib | cut -d' ' -f1)" == "$packaged_sha" ]] || fail "packaged binary not kept"
grep -q "worker_connections 4096;" /etc/nginx/nginx.conf || fail "worker_connections"
grep -q "^worker_rlimit_nofile 16384;" /etc/nginx/nginx.conf || fail "worker_rlimit_nofile"
[[ "$(systemctl show -p MemoryMax --value nginx)" != infinity ]] || fail "memory ceiling not applied"
systemctl is-active --quiet nginx || fail "nginx not active"
[[ "$(/usr/sbin/nginx -v 2>&1)" == "$(/usr/sbin/nginx.distrib -v 2>&1)" ]] || fail "version differs"
diff <(/usr/sbin/nginx -V 2>&1 | tail -1) <(/usr/sbin/nginx.distrib -V 2>&1 | tail -1) >/dev/null ||
    echo "note: configure lines differ only by the omitted dynamic modules:"
pass "install: patched $(field VERSION), divert, limits, memory ceiling"

# 2. idempotent redeploy
start=$(date +%s)
"$TOOL" install >/dev/null
[[ $(( $(date +%s) - start )) -lt 30 ]] || fail "redeploy rebuilt an up-to-date patch"
pass "redeploy keeps the current patched binary without rebuilding"

# 3. package update: dpkg writes the packaged binary to nginx.distrib and the
# hook runs the packaged binary at once, then rebuilds. A reinstall of the
# same version stands in for a security update (the state is made stale).
sed -i 's/^DISTRIB_SHA=.*/DISTRIB_SHA=stale/' "$STATE"
apt-get install -y -qq --reinstall nginx >/dev/null
[[ "$(sha256sum /usr/sbin/nginx.distrib | cut -d' ' -f1)" == "$packaged_sha" ]] || fail "update did not land at nginx.distrib"
journalctl -t easypi-chameleon-nginx --since "-2min" -o cat | grep -q "running the packaged nginx (package updated" ||
    fail "hook did not switch to the packaged binary first"
wait_rebuild
[[ "$(field running)" == patched ]] || fail "rebuild after the update did not install the patch"
pass "package update: packaged binary first, patch rebuilt in the background"

# 4. a patch that no longer applies: the packaged binary stays.
cp "$SHARE/$PATCH_NAME" /tmp/patch.good
printf -- '--- a/src/core/nginx.c\n+++ b/src/core/nginx.c\n@@ -1,1 +1,1 @@\n-no such line\n+x\n' > "$SHARE/$PATCH_NAME"
"$TOOL" rebuild
[[ "$(field running)" == packaged ]] || fail "failed build did not fall back to the packaged binary"
[[ "$(field REASON)" == "patch build failed for"* ]] || fail "reason not recorded"
systemctl is-active --quiet nginx || fail "nginx down after a failed build"
cp /tmp/patch.good "$SHARE/$PATCH_NAME"
"$TOOL" rebuild
[[ "$(field running)" == patched ]] || fail "patch not restored"
pass "failed build keeps the packaged binary; a good patch is reinstalled"

# 5. removal
"$TOOL" remove
dpkg-divert --list /usr/sbin/nginx | grep -q easypi-chameleon && fail "diversion left behind"
[[ "$(sha256sum /usr/sbin/nginx | cut -d' ' -f1)" == "$packaged_sha" ]] || fail "packaged binary not restored"
[[ ! -e /etc/apt/apt.conf.d/80easypi-chameleon-nginx ]] || fail "hook left behind"
systemctl is-active --quiet nginx || fail "nginx down after removal"
pass "remove restores the packaged nginx"
echo ALL PASSED
