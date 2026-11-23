#!/bin/bash
#
# Refresh the runtime-only adult-domain feed used by Parental Controls.
#
# The generated feed is downloaded on the end user's device. It is not part of
# the EasyPi source tree or release archive. Third-party notices and provenance
# are published next to the generated data.
#
# Usage: update_adult_blocklist.sh [update]
#
set -euo pipefail
umask 077

ACTION="${1:-update}"
[[ $# -le 1 && "$ACTION" == "update" ]] || {
    echo "Usage: $0 [update]" >&2
    exit 2
}

EASYPI_ROOT="${EASYPI_ROOT:-/opt/EasyPi}"
DATA_DIR="$EASYPI_ROOT/data/netprotection"
OUT="$DATA_DIR/adult_domains.txt"
NOTICE_OUT="$DATA_DIR/adult_domains.NOTICE.txt"
LICENSE_OUT="$DATA_DIR/adult_domains.LICENSE.txt"
MANIFEST_OUT="$DATA_DIR/adult_domains.sources.json"
DATA_WRITER="$EASYPI_ROOT/scripts/utils/write_easypi_data.py"
BUILDER="$EASYPI_ROOT/scripts/settings/build_adult_blocklist.py"
RUNTIME_DIR="/run/easypi-feed-update"

# A single permissively licensed upstream keeps provenance auditable. The
# generated list currently declares MIT in its header while the repository
# LICENSE is Unlicense. EasyPi preserves both notices and treats the stricter
# MIT notice as applicable. A license-file change stops the update for review.
SOURCE_REVISION="ee3bdbaddf49c756cf3340bb2e6a9dee5282d1c6"
SOURCE_URL="https://raw.githubusercontent.com/blocklistproject/Lists/${SOURCE_REVISION}/porn.txt"
LICENSE_URL="https://raw.githubusercontent.com/blocklistproject/Lists/${SOURCE_REVISION}/LICENSE"
EXPECTED_SOURCE_SHA256="425590c37e3ea624fdf646b14ba661f8b8f38391686adcf02b73f8b2d74b0db1"
EXPECTED_LICENSE_SHA256="6b0382b16279f26ff69014300541967a356a666eb0b91b422f6862f6b7dad17e"

[[ -f "$DATA_WRITER" && ! -L "$DATA_WRITER" ]] || {
    echo "ERROR: secure data writer is missing" >&2
    exit 1
}
[[ -f "$BUILDER" && ! -L "$BUILDER" ]] || {
    echo "ERROR: adult feed builder is missing" >&2
    exit 1
}
[[ -d "$DATA_DIR" && ! -L "$DATA_DIR" ]] || {
    echo "ERROR: NetProtection data directory is unavailable" >&2
    exit 1
}

install -d -o root -g root -m 0700 "$RUNTIME_DIR"

SOURCE_FILE="$(mktemp "$RUNTIME_DIR/adult-source.XXXXXX")"
LICENSE_FILE="$(mktemp "$RUNTIME_DIR/adult-license.XXXXXX")"
GENERATED="$(mktemp "$RUNTIME_DIR/adult-generated.XXXXXX")"
NOTICE="$(mktemp "$RUNTIME_DIR/adult-notice.XXXXXX")"
MANIFEST="$(mktemp "$RUNTIME_DIR/adult-manifest.XXXXXX")"
LICENSE_COPY="$(mktemp "$RUNTIME_DIR/adult-license-copy.XXXXXX")"
trap 'rm -f "$SOURCE_FILE" "$LICENSE_FILE" "$GENERATED" "$NOTICE" "$MANIFEST" "$LICENSE_COPY"' EXIT

download_https() {
    local url="$1"
    local destination="$2"
    curl \
        --fail \
        --silent \
        --show-error \
        --location \
        --proto '=https' \
        --proto-redir '=https' \
        --connect-timeout 15 \
        --max-time 180 \
        --retry 2 \
        --retry-all-errors \
        --max-filesize 67108864 \
        --output "$destination" \
        "$url"
}

if ! download_https "$SOURCE_URL" "$SOURCE_FILE"; then
    echo "ERROR: adult source download failed; keeping existing $OUT" >&2
    exit 1
fi
if ! download_https "$LICENSE_URL" "$LICENSE_FILE"; then
    echo "ERROR: source license download failed; keeping existing $OUT" >&2
    exit 1
fi

ACTUAL_SOURCE_SHA256="$(sha256sum "$SOURCE_FILE" | awk '{print $1}')"
if [[ "$ACTUAL_SOURCE_SHA256" != "$EXPECTED_SOURCE_SHA256" ]]; then
    echo "ERROR: adult source SHA-256 mismatch; keeping existing $OUT" >&2
    exit 1
fi

/usr/bin/python3 "$BUILDER" \
    --source "$SOURCE_FILE" \
    --license "$LICENSE_FILE" \
    --output "$GENERATED" \
    --notice-output "$NOTICE" \
    --license-output "$LICENSE_COPY" \
    --manifest-output "$MANIFEST" \
    --expected-license-sha256 "$EXPECTED_LICENSE_SHA256" \
    --min-domains 500000 \
    --max-domains 2000000

# Publish legal/provenance sidecars first and the active list last. A failed
# validation or write therefore never replaces the last known-good feed.
/usr/bin/python3 "$DATA_WRITER" "$LICENSE_COPY" "$LICENSE_OUT"
/usr/bin/python3 "$DATA_WRITER" "$NOTICE" "$NOTICE_OUT"
/usr/bin/python3 "$DATA_WRITER" "$MANIFEST" "$MANIFEST_OUT"
/usr/bin/python3 "$DATA_WRITER" "$GENERATED" "$OUT"

echo "Adult blocklist updated: $OUT ($(grep -Evc '^(#|$)' "$OUT") domains)"
