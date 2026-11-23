"""Runtime orchestration and bounded JSONL telemetry for PRISM FlowGraph."""

from __future__ import annotations

import json
import os
import signal
import sys
import time
from pathlib import Path
from typing import TextIO

from .model import FlowGraphEngine
from .packet import parse_link_packet
from .source import PcapReader, RawSocketSource


DEFAULT_STATE_PATH = Path("/var/lib/easypi/prism/flowgraph.jsonl")
MAX_LOG_BYTES = 20 * 1024 * 1024


class JsonlWriter:
    def __init__(self, path: Path, *, max_bytes: int = MAX_LOG_BYTES) -> None:
        self.path = path
        self.max_bytes = max_bytes

    def write(self, value: dict[str, object]) -> None:
        self._rotate_if_needed()
        line = json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n"
        flags = os.O_APPEND | os.O_CREAT | os.O_WRONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(self.path, flags, 0o640)
        try:
            os.write(descriptor, line.encode("utf-8"))
        finally:
            os.close(descriptor)

    def _rotate_if_needed(self) -> None:
        try:
            size = self.path.stat().st_size
        except FileNotFoundError:
            return
        if size < self.max_bytes:
            return
        previous = self.path.with_suffix(self.path.suffix + ".1")
        try:
            previous.unlink()
        except FileNotFoundError:
            pass
        self.path.replace(previous)


class FlowGraphMonitor:
    def __init__(
        self,
        engine: FlowGraphEngine | None = None,
        *,
        ignored_client_ips: frozenset[str] = frozenset(),
    ) -> None:
        self.engine = engine or FlowGraphEngine()
        self.ignored_client_ips = ignored_client_ips

    def process(self, timestamp: float, frame: bytes, link_type: int) -> list[dict[str, object]]:
        event = parse_link_packet(
            timestamp,
            frame,
            link_type=link_type,
            ignored_client_ips=self.ignored_client_ips,
        )
        if event is None:
            return []
        return [assessment.to_dict() for assessment in self.engine.ingest(event)]

    def finalize(self, *, completion_reason: str) -> list[dict[str, object]]:
        return [
            observation.to_dict()
            for observation in self.engine.finalize(
                completion_reason=completion_reason,
            )
        ]


def run_live(interface: str, output: Path) -> int:
    output.parent.mkdir(parents=True, exist_ok=True)
    writer = JsonlWriter(output)
    source = RawSocketSource(interface)
    monitor = FlowGraphMonitor(ignored_client_ips=source.local_addresses)
    stopped = False

    def stop(_signum: int, _frame: object) -> None:
        nonlocal stopped
        stopped = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    writer.write(
        {
            "event": "flowgraph_started",
            "interface": interface,
            "ignored_client_ips": sorted(source.local_addresses),
            "mode": "shadow",
            "timestamp": time.time(),
        }
    )
    next_heartbeat = time.monotonic() + 30.0
    try:
        while not stopped:
            packet = source.receive()
            if packet is not None:
                timestamp, frame = packet
                for assessment in monitor.process(timestamp, frame, source.link_type):
                    assessment.setdefault("event", "flow_assessment")
                    writer.write(assessment)
            if time.monotonic() >= next_heartbeat:
                writer.write(
                    {
                        "event": "flowgraph_heartbeat",
                        "interface": interface,
                        "mode": "shadow",
                        "timestamp": time.time(),
                        **monitor.engine.snapshot(),
                    }
                )
                next_heartbeat = time.monotonic() + 30.0
    finally:
        source.close()
        for observation in monitor.finalize(completion_reason="monitor_stopped"):
            writer.write(observation)
        writer.write(
            {
                "event": "flowgraph_stopped",
                "timestamp": time.time(),
                **monitor.engine.snapshot(),
            }
        )
    return 0


def replay(path: Path, output: TextIO = sys.stdout) -> int:
    monitor = FlowGraphMonitor()
    for timestamp, frame, link_type in PcapReader(path):
        for assessment in monitor.process(timestamp, frame, link_type):
            output.write(json.dumps(assessment, sort_keys=True) + "\n")
    for observation in monitor.finalize(completion_reason="replay_complete"):
        output.write(json.dumps(observation, sort_keys=True) + "\n")
    summary = {"event": "replay_complete", **monitor.engine.snapshot()}
    output.write(json.dumps(summary, sort_keys=True) + "\n")
    return 0


__all__ = [
    "DEFAULT_STATE_PATH",
    "FlowGraphMonitor",
    "JsonlWriter",
    "replay",
    "run_live",
]
