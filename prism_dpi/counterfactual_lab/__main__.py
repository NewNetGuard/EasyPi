"""Command line entry point for the PRISM Counterfactual Flow Lab."""

from __future__ import annotations

import argparse
from pathlib import Path

from .runtime import CounterfactualLabRuntime


def main() -> int:
    parser = argparse.ArgumentParser(prog="python -m prism_dpi.counterfactual_lab")
    parser.add_argument("command", choices=("live",))
    parser.add_argument("--queue", type=int, default=4243)
    parser.add_argument(
        "--state",
        type=Path,
        default=Path("/var/lib/easypi/prism-counterfactual/lab.jsonl"),
    )
    parser.add_argument(
        "--plan",
        type=Path,
        default=Path("/var/lib/easypi/prism-counterfactual/plan.json"),
    )
    args = parser.parse_args()
    return CounterfactualLabRuntime(
        queue_number=args.queue,
        state_path=args.state,
        plan_path=args.plan,
    ).run()


if __name__ == "__main__":
    raise SystemExit(main())
