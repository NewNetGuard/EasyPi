"""Command line entry point for the PRISM TLS Lineage Gate."""

from __future__ import annotations

import argparse
from pathlib import Path

from .runtime import LineageGateRuntime


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m prism_dpi.lineage_gate")
    parser.add_argument("command", choices=("live",))
    parser.add_argument("--queue", type=int, default=4242)
    parser.add_argument(
        "--state",
        type=Path,
        default=Path("/var/lib/easypi/prism-lineage/gate.jsonl"),
    )
    args = parser.parse_args()
    return LineageGateRuntime(
        queue_number=args.queue,
        state_path=args.state,
    ).run()


if __name__ == "__main__":
    raise SystemExit(main())
