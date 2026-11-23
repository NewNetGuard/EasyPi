#!/bin/bash
#
# Compatibility wrapper for the canonical app blocking script.
#

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TARGET_SCRIPT="$SCRIPT_DIR/scripts/settings/setup_app_blocking.sh"

if [[ ! -f "$TARGET_SCRIPT" ]]; then
    echo "Canonical app blocking script not found: $TARGET_SCRIPT" >&2
    exit 1
fi

exec bash "$TARGET_SCRIPT" "$@"
