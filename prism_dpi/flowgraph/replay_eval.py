"""Stage-level evaluation of FlowGraph model output against production policy."""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping

from .policy import validate_candidate_event


@dataclass(frozen=True)
class ReplayEvaluation:
    rows: int
    model_candidates: int
    policy_actions: int
    policy_rejections: int
    duplicate_actions: int
    invalid_rows: int
    action_server_names: tuple[str, ...]

    def as_dict(self) -> dict[str, int | list[str]]:
        return {
            "rows": self.rows,
            "model_candidates": self.model_candidates,
            "policy_actions": self.policy_actions,
            "policy_rejections": self.policy_rejections,
            "duplicate_actions": self.duplicate_actions,
            "invalid_rows": self.invalid_rows,
            "action_server_names": list(self.action_server_names),
        }


def evaluate_rows(rows: Iterable[object]) -> ReplayEvaluation:
    """Evaluate decoded replay rows at both model and policy stages.

    Event timestamps are used as each row's evaluation clock. This preserves
    production freshness validation without making an archived replay expire.
    Revisions of an already accepted flow are deduplicated as the live follower
    does, while a flow from a new client remains a distinct action.
    """
    row_count = 0
    model_candidates = 0
    policy_rejections = 0
    duplicate_actions = 0
    invalid_rows = 0
    seen_flows: set[str] = set()
    action_names: list[str] = []

    for value in rows:
        row_count += 1
        if not isinstance(value, Mapping):
            invalid_rows += 1
            continue
        if value.get("event") != "flow_assessment":
            continue
        is_model_candidate = value.get("verdict") == "candidate"
        if is_model_candidate:
            model_candidates += 1
        try:
            event_time = float(value["timestamp"])
        except (KeyError, TypeError, ValueError):
            if is_model_candidate:
                policy_rejections += 1
            continue
        candidate = validate_candidate_event(dict(value), now=event_time)
        if candidate is None:
            if is_model_candidate:
                policy_rejections += 1
            continue
        if candidate.flow_id in seen_flows:
            duplicate_actions += 1
            continue
        seen_flows.add(candidate.flow_id)
        server_name = value.get("server_name")
        action_names.append(server_name if isinstance(server_name, str) else "")

    return ReplayEvaluation(
        rows=row_count,
        model_candidates=model_candidates,
        policy_actions=len(seen_flows),
        policy_rejections=policy_rejections,
        duplicate_actions=duplicate_actions,
        invalid_rows=invalid_rows,
        action_server_names=tuple(action_names),
    )


def evaluate_jsonl(path: str | Path) -> ReplayEvaluation:
    """Evaluate a replay JSONL artifact without loading it all into memory."""

    def decoded_rows() -> Iterable[object]:
        with Path(path).open("r", encoding="utf-8-sig") as source:
            for line in source:
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    yield None

    return evaluate_rows(decoded_rows())


def main(argv: list[str] | None = None) -> int:
    paths = [Path(value) for value in (sys.argv[1:] if argv is None else argv)]
    if not paths:
        print("usage: python -m prism_dpi.flowgraph.replay_eval REPLAY.jsonl [...]", file=sys.stderr)
        return 2
    for path in paths:
        print(json.dumps({"path": str(path), **evaluate_jsonl(path).as_dict()}))
    return 0


__all__ = ["ReplayEvaluation", "evaluate_jsonl", "evaluate_rows", "main"]


if __name__ == "__main__":
    raise SystemExit(main())
