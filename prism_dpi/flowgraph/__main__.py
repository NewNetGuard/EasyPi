"""Command-line entry point for live and offline PRISM FlowGraph analysis."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from .monitor import DEFAULT_STATE_PATH, replay, run_live


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python3 -m prism_dpi.flowgraph")
    subparsers = parser.add_subparsers(dest="command", required=True)

    live = subparsers.add_parser("live", help="run the metadata-only shadow monitor")
    live.add_argument(
        "--interface",
        default=os.environ.get("PRISM_INTERFACE", "eth0"),
    )
    live.add_argument(
        "--output",
        type=Path,
        default=Path(os.environ.get("PRISM_STATE_PATH", str(DEFAULT_STATE_PATH))),
    )

    replay_parser = subparsers.add_parser("replay", help="analyze a classic pcap file")
    replay_parser.add_argument("capture", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "live":
            return run_live(args.interface, args.output)
        return replay(args.capture)
    except (OSError, ValueError) as exc:
        print(f"prism-flowgraph: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
