#!/usr/bin/env bash
# Run every Chameleon Go test with the repository-pinned toolchain.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO_BIN="$(bash "${ROOT}/ensure-go.sh")"
cd "${ROOT}"
exec "${GO_BIN}" test ./...
