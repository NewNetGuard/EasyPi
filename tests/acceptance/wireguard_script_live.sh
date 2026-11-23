#!/bin/bash
set -euo pipefail

[[ $EUID -eq 0 ]] || { echo "Run this acceptance test as root" >&2; exit 1; }
[[ $# -eq 1 && -f "$1" ]] || { echo "Usage: $0 /path/to/wireguard.sh" >&2; exit 1; }

SOURCE_SCRIPT="$(realpath "$1")"
TEST_ROOT="$(mktemp -d /tmp/easypi-wireguard-acceptance.XXXXXX)"
trap 'rm -rf -- "$TEST_ROOT"' EXIT
export WG_TEST_ROOT="$TEST_ROOT"

mkdir -p "$TEST_ROOT/mock-bin" "$TEST_ROOT/wireguard" "$TEST_ROOT/state/clients"
cp "$SOURCE_SCRIPT" "$TEST_ROOT/wireguard.sh"
sed -i \
    -e "s#^DATA_DIR=.*#DATA_DIR=\"$TEST_ROOT/state\"#" \
    -e "s#^EASYPI_GROUP=.*#EASYPI_GROUP=\"root\"#" \
    -e "s#^WG_DIR=.*#WG_DIR=\"$TEST_ROOT/wireguard\"#" \
    "$TEST_ROOT/wireguard.sh"
chmod 700 "$TEST_ROOT/wireguard.sh"

cat > "$TEST_ROOT/mock-bin/systemctl" <<'SH'
#!/bin/bash
if [[ "${1:-}" == "is-active" ]]; then
    [[ -f "$WG_TEST_ROOT/active" ]]
    exit
fi
if [[ "${1:-}" == "is-enabled" ]]; then
    [[ -f "$WG_TEST_ROOT/active" ]]
    exit
fi
exit 0
SH

cat > "$TEST_ROOT/mock-bin/wg" <<'SH'
#!/bin/bash
case "${1:-}" in
    genkey)
        tr -d '-' < /proc/sys/kernel/random/uuid
        ;;
    pubkey)
        value="$(cat)"
        printf 'pub-%s\n' "${value:0:20}"
        ;;
    set)
        [[ ! -f "$WG_TEST_ROOT/fail-wg-set" ]]
        ;;
    show)
        printf 'private\tpublic\t51820\toff\n'
        ;;
    *)
        exit 1
        ;;
esac
SH

cat > "$TEST_ROOT/mock-bin/wg-quick" <<'SH'
#!/bin/bash
[[ "${1:-}" == "save" ]]
SH

cat > "$TEST_ROOT/mock-bin/qrencode" <<'SH'
#!/bin/bash
output=""
while [[ $# -gt 0 ]]; do
    if [[ "$1" == "-o" ]]; then
        output="$2"
        shift 2
    else
        shift
    fi
done
[[ -n "$output" ]] || exit 1
cat > "$output"
SH
chmod 700 "$TEST_ROOT/mock-bin/"*
export PATH="$TEST_ROOT/mock-bin:/usr/sbin:/usr/bin:/sbin:/bin"

printf 'server-public-key\n' > "$TEST_ROOT/wireguard/publickey"
printf 'server-private-key\n' > "$TEST_ROOT/wireguard/privatekey"
cat > "$TEST_ROOT/wireguard/wg0.conf" <<'EOF'
[Interface]
Address = 10.8.0.1/24
ListenPort = 51820
PrivateKey = server-private-key
SaveConfig = true
EOF
cat > "$TEST_ROOT/state/meta.json" <<'EOF'
{"port":51820,"cidr":"10.8.0.0/24","dns":"1.1.1.1","endpoint":"vpn.example:51820","peers":[]}
EOF
chown root:root "$TEST_ROOT/state/meta.json"
chmod 640 "$TEST_ROOT/state/meta.json"

# A stopped server must fail before creating a private client artifact.
if "$TEST_ROOT/wireguard.sh" add-peer --name Stopped --allowed 0.0.0.0/0 >/dev/null 2>&1; then
    echo "Stopped WireGuard unexpectedly accepted a peer" >&2
    exit 1
fi
[[ ! -e "$TEST_ROOT/state/clients/Stopped.conf" ]]

# A runtime failure must roll back temporary secrets and metadata.
touch "$TEST_ROOT/active" "$TEST_ROOT/fail-wg-set"
if "$TEST_ROOT/wireguard.sh" add-peer --name Failed --allowed 0.0.0.0/0 >/dev/null 2>&1; then
    echo "Failed wg set unexpectedly accepted a peer" >&2
    exit 1
fi
[[ ! -e "$TEST_ROOT/state/clients/Failed.conf" ]]
[[ "$(jq '.peers | length' "$TEST_ROOT/state/meta.json")" -eq 0 ]]
[[ -z "$(find "$TEST_ROOT/state/clients" -mindepth 1 -maxdepth 1 -print -quit)" ]]
rm -f "$TEST_ROOT/fail-wg-set"

# Parallel additions must serialize and allocate distinct addresses.
"$TEST_ROOT/wireguard.sh" add-peer --name Phone --allowed 0.0.0.0/0 >/dev/null &
first_pid=$!
"$TEST_ROOT/wireguard.sh" add-peer --name Laptop --allowed 0.0.0.0/0 >/dev/null &
second_pid=$!
wait "$first_pid"
wait "$second_pid"
[[ "$(jq '.peers | length' "$TEST_ROOT/state/meta.json")" -eq 2 ]]
[[ "$(jq -r '.peers[].address' "$TEST_ROOT/state/meta.json" | sort -u | wc -l)" -eq 2 ]]
[[ "$(stat -c '%a' "$TEST_ROOT/state/clients/Phone.conf")" == "640" ]]
[[ "$(stat -c '%a' "$TEST_ROOT/state/clients/Phone.png")" == "640" ]]

# Simulate a peer saved in wg0.conf, stop the interface, and revoke it. The
# persistent peer block and all private artifacts must still be removed.
phone_key="$(jq -r '.peers[] | select(.name == "Phone") | .public_key' "$TEST_ROOT/state/meta.json")"
cat >> "$TEST_ROOT/wireguard/wg0.conf" <<EOF

[Peer]
PublicKey = $phone_key
AllowedIPs = 10.8.0.2/32
EOF
rm -f "$TEST_ROOT/active"
"$TEST_ROOT/wireguard.sh" remove-peer --name Phone >/dev/null
! grep -Fq "$phone_key" "$TEST_ROOT/wireguard/wg0.conf"
[[ ! -e "$TEST_ROOT/state/clients/Phone.conf" ]]
[[ ! -e "$TEST_ROOT/state/clients/Phone.png" ]]
[[ "$(jq '[.peers[] | select(.name == "Phone")] | length' "$TEST_ROOT/state/meta.json")" -eq 0 ]]

echo "WIREGUARD_SCRIPT_E2E=PASS"
