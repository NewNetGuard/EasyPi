"""Linux NFQUEUE adapter for the bounded TLS Lineage Gate."""

from __future__ import annotations

import errno
import signal
import time
from pathlib import Path
from typing import Any

from prism_dpi.flowgraph.monitor import JsonlWriter

from .decision import GateResolution, LineageGate, ResolutionVerdict
from .packet import parse_queued_ipv4_client_hello, parse_queued_ipv4_transport


class LineageGateRuntime:
    def __init__(
        self,
        *,
        queue_number: int,
        state_path: Path,
        gate: LineageGate | None = None,
    ) -> None:
        if not 0 <= queue_number <= 65_535:
            raise ValueError("queue number must be between 0 and 65535")
        self.queue_number = queue_number
        self.writer = JsonlWriter(state_path)
        self.gate = gate or LineageGate()
        self._packets: dict[int, Any] = {}
        self._next_token = 1
        self._stopped = False
        self.accepted = 0
        self.dropped = 0
        self.held = 0
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
            max_len=256,
            mode=COPY_PACKET,
            range=2048,
        )
        signal.signal(signal.SIGTERM, self._stop)
        signal.signal(signal.SIGINT, self._stop)
        self._write_event("lineage_gate_started")
        next_heartbeat = time.monotonic() + 30.0
        try:
            while not self._stopped:
                try:
                    queue.run(block=False)
                except OSError as exc:
                    if exc.errno not in (errno.EAGAIN, errno.EWOULDBLOCK):
                        raise
                self._apply(self.gate.expire(time.monotonic()))
                now = time.monotonic()
                if now >= next_heartbeat:
                    self._write_event("lineage_gate_heartbeat")
                    next_heartbeat = now + 30.0
                deadline = self.gate.next_deadline()
                delay = 0.01 if deadline is None else min(0.01, max(0.001, deadline - now))
                time.sleep(delay)
        finally:
            self._apply(self.gate.release_all())
            queue.unbind()
            self._write_event("lineage_gate_stopped")
        return 0

    def _handle_packet(self, packet: Any, *, now: float | None = None) -> None:
        token: int | None = None
        try:
            current_time = time.monotonic() if now is None else now
            transport = parse_queued_ipv4_transport(packet.get_payload())
            if transport is not None and transport.flow.protocol == "udp":
                if self.gate.should_drop_quic(
                    transport.flow.client_ip,
                    now=current_time,
                ):
                    packet.drop()
                    self.dropped += 1
                    self._write_event(
                        "lineage_quic_resolved",
                        verdict="drop",
                        reason="confirmed_lineage_transport_quarantine",
                        client_ip=transport.flow.client_ip,
                    )
                else:
                    packet.accept()
                    self.accepted += 1
                return
            parsed = parse_queued_ipv4_client_hello(packet.get_payload())
            if parsed is None or not parsed.hello.psk_identity_lengths:
                packet.accept()
                self.accepted += 1
                return
            token = self._next_token
            self._next_token += 1
            packet.retain()
            self._packets[token] = packet
            resolutions = self.gate.offer(
                token,
                now=current_time,
                flow=parsed.flow,
                hello=parsed.hello,
            )
            if not any(item.token == token for item in resolutions):
                self.held += 1
                self._write_event(
                    "lineage_flow_held",
                    client_ip=parsed.flow.client_ip,
                    server_name=parsed.hello.server_name,
                    lineage=parsed.hello.lineage_fingerprint,
                )
            self._apply(resolutions)
        except Exception as exc:
            self.errors += 1
            if token is not None:
                self._packets.pop(token, None)
                self.gate.cancel(token)
            try:
                packet.accept()
                self.accepted += 1
            except Exception:
                pass
            self._write_event(
                "lineage_gate_error",
                error=type(exc).__name__,
            )

    def _apply(self, resolutions: tuple[GateResolution, ...]) -> None:
        for resolution in resolutions:
            if not isinstance(resolution.token, int):
                continue
            packet = self._packets.pop(resolution.token, None)
            if packet is None:
                continue
            try:
                if resolution.verdict is ResolutionVerdict.DROP:
                    packet.drop()
                    self.dropped += 1
                else:
                    packet.accept()
                    self.accepted += 1
            except Exception:
                self.errors += 1
                try:
                    packet.accept()
                    self.accepted += 1
                except Exception:
                    pass
            self._write_event(
                "lineage_flow_resolved",
                verdict=resolution.verdict.value,
                reason=resolution.reason,
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
                    "held": self.held,
                    "errors": self.errors,
                    "pending": self.gate.pending_count,
                    "blocked_lineages": self.gate.blocked_lineage_count,
                    "quarantined_clients": self.gate.quarantined_client_count,
                    **fields,
                }
            )
        except OSError:
            self.errors += 1


__all__ = ["LineageGateRuntime"]
