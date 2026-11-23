"""NFQUEUE runtime for bounded counterfactual flow experiments."""

from __future__ import annotations

import errno
import json
import os
import signal
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from prism_dpi.flowgraph.monitor import JsonlWriter
from prism_dpi.lineage_gate.packet import parse_queued_ipv4_transport

from .decision import (
    CounterfactualFlowLab,
    ExperimentPlan,
    InterventionVerdict,
)


MAX_PLAN_BYTES = 4_096


@dataclass(frozen=True)
class LoadedExperimentPlan:
    generation: int
    plan: ExperimentPlan | None


def load_experiment_plan(path: Path) -> LoadedExperimentPlan:
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise ValueError("plan must be a regular file")
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise ValueError("plan ownership or mode is unsafe")
        if metadata.st_size > MAX_PLAN_BYTES:
            raise ValueError("plan is too large")
        raw = os.read(descriptor, MAX_PLAN_BYTES + 1)
    finally:
        os.close(descriptor)
    value = json.loads(raw.decode("utf-8"))
    if not isinstance(value, dict):
        raise ValueError("plan must be a JSON object")
    generation = _strict_int(value.get("generation"), "generation")
    armed = value.get("armed")
    if not isinstance(armed, bool):
        raise ValueError("armed must be boolean")
    if not armed:
        if set(value) != {"armed", "generation"}:
            raise ValueError("disarmed plan contains unexpected fields")
        return LoadedExperimentPlan(generation, None)
    expected = {
        "armed",
        "generation",
        "client_ip",
        "protocol",
        "selection",
        "target_ordinal",
        "target_server_ip",
        "intervention_ms",
        "max_drops",
        "discovery_ms",
    }
    if set(value) != expected:
        raise ValueError("armed plan fields are invalid")
    intervention_ms = _strict_int(value["intervention_ms"], "intervention_ms")
    discovery_ms = _strict_int(value["discovery_ms"], "discovery_ms")
    return LoadedExperimentPlan(
        generation,
        ExperimentPlan(
            generation=generation,
            client_ip=str(value["client_ip"]),
            protocol=str(value["protocol"]),
            target_ordinal=_strict_int(value["target_ordinal"], "target_ordinal"),
            intervention_seconds=intervention_ms / 1_000.0,
            max_drops=_strict_int(value["max_drops"], "max_drops"),
            discovery_seconds=discovery_ms / 1_000.0,
            selection=str(value["selection"]),
            target_server_ip=str(value["target_server_ip"]),
        ),
    )


class CounterfactualLabRuntime:
    def __init__(
        self,
        *,
        queue_number: int,
        state_path: Path,
        plan_path: Path | None,
        lab: CounterfactualFlowLab | None = None,
    ) -> None:
        if not 0 <= queue_number <= 65_535:
            raise ValueError("queue number must be between 0 and 65535")
        self.queue_number = queue_number
        self.writer = JsonlWriter(state_path)
        self.plan_path = plan_path
        self.lab = lab or CounterfactualFlowLab()
        self._last_generation = -1
        self._last_plan_error = ""
        self._last_reason = ""
        self._stopped = False
        self.accepted = 0
        self.dropped = 0
        self.errors = 0

    def run(self) -> int:
        try:
            from netfilterqueue import COPY_PACKET, NetfilterQueue
        except ImportError as exc:
            raise RuntimeError("python3-netfilterqueue is required") from exc

        queue = NetfilterQueue()
        queue.bind(
            self.queue_number,
            self._handle_packet,
            max_len=512,
            mode=COPY_PACKET,
            range=2048,
        )
        signal.signal(signal.SIGTERM, self._stop)
        signal.signal(signal.SIGINT, self._stop)
        self._write_event("counterfactual_lab_started")
        next_heartbeat = time.monotonic() + 30.0
        try:
            while not self._stopped:
                try:
                    queue.run(block=False)
                except OSError as exc:
                    if exc.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                        raise
                now = time.monotonic()
                if now >= next_heartbeat:
                    self._write_event("counterfactual_lab_heartbeat")
                    next_heartbeat = now + 30.0
                time.sleep(0.005)
        finally:
            self.lab.disarm()
            queue.unbind()
            self._write_event("counterfactual_lab_stopped")
        return 0

    def _handle_packet(self, packet: Any, *, now: float | None = None) -> None:
        try:
            current_time = time.monotonic() if now is None else now
            self._reload_plan(current_time)
            transport = parse_queued_ipv4_transport(packet.get_payload())
            if transport is None:
                packet.accept()
                self.accepted += 1
                return
            decision = self.lab.observe(transport, now=current_time)
            if decision.verdict is InterventionVerdict.DROP:
                packet.drop()
                self.dropped += 1
                self._write_event(
                    "counterfactual_packet_resolved",
                    verdict="drop",
                    reason=decision.reason,
                    flow=decision.flow.id() if decision.flow else "",
                    ordinal=decision.ordinal,
                    experiment_drops=decision.dropped_count,
                    target_server_name=self.lab.target_server_name,
                )
                return
            packet.accept()
            self.accepted += 1
            if decision.reason != self._last_reason and decision.reason in {
                "discovery_timeout",
                "intervention_complete",
                "observed_flow_limit",
            }:
                self._write_event(
                    "counterfactual_experiment_state",
                    reason=decision.reason,
                    ordinal=decision.ordinal,
                    experiment_drops=decision.dropped_count,
                )
            self._last_reason = decision.reason
        except Exception as exc:
            self.errors += 1
            self.lab.disarm()
            try:
                packet.accept()
                self.accepted += 1
            except Exception:
                pass
            self._write_event(
                "counterfactual_lab_error",
                error=type(exc).__name__,
            )

    def _reload_plan(self, now: float) -> None:
        if self.plan_path is None:
            return
        try:
            loaded = load_experiment_plan(self.plan_path)
        except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
            signature = type(exc).__name__
            self.lab.disarm()
            self._last_generation = -1
            if signature != self._last_plan_error:
                self._write_event("counterfactual_plan_rejected", error=signature)
                self._last_plan_error = signature
            return
        self._last_plan_error = ""
        if loaded.generation == self._last_generation:
            return
        self._last_generation = loaded.generation
        self._last_reason = ""
        if loaded.plan is None:
            self.lab.disarm()
            self._write_event(
                "counterfactual_plan_loaded",
                armed=False,
                generation=loaded.generation,
            )
            return
        self.lab.arm(loaded.plan, now=now)
        self._write_event(
            "counterfactual_plan_loaded",
            armed=True,
            generation=loaded.generation,
            client_ip=loaded.plan.client_ip,
            protocol=loaded.plan.protocol,
            selection=loaded.plan.selection,
            target_ordinal=loaded.plan.target_ordinal,
            target_server_ip=loaded.plan.target_server_ip,
            intervention_ms=round(loaded.plan.intervention_seconds * 1_000),
            max_drops=loaded.plan.max_drops,
        )

    def _stop(self, _signum: int, _frame: object) -> None:
        self._stopped = True

    def _write_event(self, event: str, **fields: object) -> None:
        try:
            self.writer.write(
                {
                    "event": event,
                    "timestamp": time.time(),
                    "queue": self.queue_number,
                    "accepted": self.accepted,
                    "dropped": self.dropped,
                    "errors": self.errors,
                    "armed": self.lab.armed,
                    "generation": self.lab.generation,
                    "observed_flows": self.lab.observed_flow_count,
                    "pending_reassemblies": self.lab.pending_reassembly_count,
                    "target_server_name": self.lab.target_server_name,
                    **fields,
                }
            )
        except OSError:
            self.errors += 1


def _strict_int(value: object, field: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{field} must be integer")
    return value


__all__ = [
    "CounterfactualLabRuntime",
    "LoadedExperimentPlan",
    "load_experiment_plan",
]
