#!/bin/bash
#
# Refresh the Newly-Registered Domain (NRD) feed used by NetProtection to block
# freshly-registered phishing/scam domains before they reach normal blocklists.
#
# Usage: update_nrd_list.sh [7|14|30]   (age window in days; default 14)
#
set -euo pipefail
umask 077

WINDOW="${1:-14}"
case "$WINDOW" in 7|14|30) ;; *) WINDOW=14 ;; esac

OUT="/opt/EasyPi/data/netprotection/nrd_domains.txt"
MAX_LINES=3000000   # cap to protect the Pi's RAM (a frozenset of this is loaded)
MIN_LINES=1000      # reject truncated or poisoned empty snapshots
DATA_WRITER="/opt/EasyPi/scripts/utils/write_easypi_data.py"
RUNTIME_DIR="/run/easypi-feed-update"
install -d -o root -g root -m 0700 "$RUNTIME_DIR"

TMP="$(mktemp "$RUNTIME_DIR/nrd-source.XXXXXX")"
GENERATED="$(mktemp "$RUNTIME_DIR/nrd-generated.XXXXXX")"
trap 'rm -f "$TMP" "$GENERATED" "${PART:-}"' EXIT

# Source: hagezi/nrd (domains-only, split by day-range; combine cumulatively).
SOURCE_REVISION="204db7b3153c66a652bf3fe68e0e60110b4cf3ae"
BASE="https://raw.githubusercontent.com/hagezi/nrd/${SOURCE_REVISION}/domains"
declare -Ar EXPECTED_SHA256=(
    [nrd7.txt]="8b83a0556b25b983740a88753b796b909529f422471e8475f51110d436547fee"
    [nrd14-8.txt]="e6e0beedbb6a452167945a4970ab0e6d5f5139aa5082b1e9b4bbbfb341ee4bf7"
    [nrd21-15.txt]="1fd06d7ee7cfddc4dda9b15cb200b5c41e0c6ac67f87068d2cf2f15542c011d3"
    [nrd28-22.txt]="09ad5c577e2f8a592392cfbd9f505b977d5bb9ecf2324d76ef838965e050d4d0"
)
case "$WINDOW" in
    7)  FILES="nrd7.txt" ;;
    14) FILES="nrd7.txt nrd14-8.txt" ;;
    30) FILES="nrd7.txt nrd14-8.txt nrd21-15.txt nrd28-22.txt" ;;
    *)  FILES="nrd7.txt nrd14-8.txt" ;;
esac
for fn in $FILES; do
    PART="$(mktemp "$RUNTIME_DIR/nrd-part.XXXXXX")"
    if ! curl --fail --silent --show-error --location \
        --proto '=https' --proto-redir '=https' --tlsv1.2 \
        --connect-timeout 15 --max-time 180 --retry 2 --retry-all-errors \
        --max-filesize 67108864 --output "$PART" "${BASE}/${fn}"; then
        echo "ERROR: could not download pinned NRD component ${fn}; keeping existing $OUT" >&2
        exit 1
    fi
    actual_sha256="$(sha256sum "$PART" | awk '{print $1}')"
    if [[ "$actual_sha256" != "${EXPECTED_SHA256[$fn]}" ]]; then
        echo "ERROR: NRD component ${fn} SHA-256 mismatch; keeping existing $OUT" >&2
        exit 1
    fi
    cat "$PART" >> "$TMP"
    rm -f "$PART"
done

if [ ! -s "$TMP" ]; then
    echo "ERROR: could not download NRD ${WINDOW}-day feed; keeping existing $OUT" >&2
    exit 1
fi

[[ -d "$(dirname "$OUT")" && ! -L "$(dirname "$OUT")" ]] || {
    echo "ERROR: NetProtection data directory is unavailable" >&2
    exit 1
}

OUT_PATH="$GENERATED" MAXL="$MAX_LINES" MINL="$MIN_LINES" python3 - "$TMP" <<'PY'
import os, re, sys

src = sys.argv[1]
out = os.environ["OUT_PATH"]
maxl = int(os.environ["MAXL"])
minl = int(os.environ["MINL"])

rx = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")
seen = set()
with open(src, encoding="utf-8", errors="ignore") as fh:
    for line in fh:
        line = line.strip().lower()
        if not line or line[0] in "#!":
            continue
        dom = line.split()[-1].strip().rstrip(".")
        if dom and rx.match(dom):
            seen.add(dom)
            if len(seen) >= maxl:
                break

tmp = out + ".tmp"
with open(tmp, "w", encoding="utf-8") as fh:
    for d in seen:
        fh.write(d + "\n")
if len(seen) < minl:
    os.unlink(tmp)
    raise SystemExit(f"NRD feed too small: {len(seen)} < {minl}")
os.replace(tmp, out)
print(f"nrd_domains.txt: {len(seen)} domains")
PY

/usr/bin/python3 "$DATA_WRITER" "$GENERATED" "$OUT"
echo "✓ NRD feed updated: $OUT ($(wc -l < "$OUT") domains, ${WINDOW}-day window)"
