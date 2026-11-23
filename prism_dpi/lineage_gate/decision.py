"""Pure decision state for the PRISM TLS Lineage Gate."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Hashable

from prism_dpi.flowgraph.events import FlowKey, TlsClientHello


class ResolutionVerdict(str, Enum):
    ACCEPT = "accept"
    DROP = "drop"


@dataclass(frozen=True)
class GateResolution:
    token: Hashable
    verdict: ResolutionVerdict
    reason: str


@dataclass(frozen=True)
class _LineageKey:
    client_ip: str
    server_name: str
    fingerprint: str


@dataclass(frozen=True)
class _PendingFlow:
    tokens: tuple[Hashable, ...]
    flow: FlowKey
    deadline: float


class LineageGate:
    """Hold one PSK flow briefly and drop only a matching concurrent pair."""

    def __init__(
        self,
        *,
        pair_window_seconds: float = 0.2,
        block_seconds: float = 30.0,
        transport_quarantine_seconds: float = 30.0,
        max_pending: int = 128,
    ) -> None:
        if not 0.01 <= pair_window_seconds <= 1.0:
            raise ValueError("pair window must be between 10ms and 1s")
        if not 1.0 <= block_seconds <= 300.0:
            raise ValueError("block duration must be between 1s and 300s")
        if not 1.0 <= transport_quarantine_seconds <= 60.0:
            raise ValueError("transport quarantine must be between 1s and 60s")
        if not 1 <= max_pending <= 4096:
            raise ValueError("max pending must be between 1 and 4096")
        self.pair_window_seconds = pair_window_seconds
        self.block_seconds = block_seconds
        self.transport_quarantine_seconds = transport_quarantine_seconds
        self.max_pending = max_pending
        self._pending: dict[_LineageKey, _PendingFlow] = {}
        self._pending_token_count = 0
        self._blocked_until: dict[_LineageKey, float] = {}
        self._quarantined_until: dict[str, float] = {}

    def offer(
        self,
        token: Hashable,
        *,
        now: float,
        flow: FlowKey,
        hello: TlsClientHello,
    ) -> tuple[GateResolution, ...]:
        resolutions = list(self.expire(now))
        key = self._key(flow, hello)
        if key is None:
            resolutions.append(
                GateResolution(token, ResolutionVerdict.ACCEPT, "not_resumption")
            )
            return tuple(resolutions)

        if self._blocked_until.get(key, 0.0) > now:
            self._quarantine_client(flow.client_ip, now)
            resolutions.append(
                GateResolution(token, ResolutionVerdict.DROP, "confirmed_lineage")
            )
            return tuple(resolutions)

        pending = self._pending.get(key)
        if pending is not None:
            if pending.flow != flow and pending.deadline >= now:
                del self._pending[key]
                self._pending_token_count -= len(pending.tokens)
                self._blocked_until[key] = now + self.block_seconds
                self._quarantine_client(flow.client_ip, now)
                resolutions.extend(
                    GateResolution(
                        pending_token,
                        ResolutionVerdict.DROP,
                        "resumption_pair",
                    )
                    for pending_token in (*pending.tokens, token)
                )
                return tuple(resolutions)
            if self._pending_token_count >= self.max_pending:
                resolutions.append(
                    GateResolution(token, ResolutionVerdict.ACCEPT, "pending_limit")
                )
                return tuple(resolutions)
            self._pending[key] = _PendingFlow(
                tokens=(*pending.tokens, token),
                flow=pending.flow,
                deadline=pending.deadline,
            )
            self._pending_token_count += 1
            return tuple(resolutions)

        if self._pending_token_count >= self.max_pending:
            resolutions.append(
                GateResolution(token, ResolutionVerdict.ACCEPT, "pending_limit")
            )
            return tuple(resolutions)

        self._pending[key] = _PendingFlow(
            tokens=(token,),
            flow=flow,
            deadline=now + self.pair_window_seconds,
        )
        self._pending_token_count += 1
        return tuple(resolutions)

    def expire(self, now: float) -> tuple[GateResolution, ...]:
        resolutions: list[GateResolution] = []
        for key, pending in list(self._pending.items()):
            if pending.deadline <= now:
                del self._pending[key]
                self._pending_token_count -= len(pending.tokens)
                resolutions.extend(
                    GateResolution(
                        pending_token,
                        ResolutionVerdict.ACCEPT,
                        "pair_timeout",
                    )
                    for pending_token in pending.tokens
                )
        for key, deadline in list(self._blocked_until.items()):
            if deadline <= now:
                del self._blocked_until[key]
        for client_ip, deadline in list(self._quarantined_until.items()):
            if deadline <= now:
                del self._quarantined_until[client_ip]
        return tuple(resolutions)

    def release_all(self) -> tuple[GateResolution, ...]:
        resolutions = tuple(
            GateResolution(
                token,
                ResolutionVerdict.ACCEPT,
                "gate_shutdown",
            )
            for pending in self._pending.values()
            for token in pending.tokens
        )
        self._pending.clear()
        self._pending_token_count = 0
        self._blocked_until.clear()
        self._quarantined_until.clear()
        return resolutions

    def cancel(self, token: Hashable) -> None:
        """Forget an unresolved packet after the adapter has accepted it fail-open."""
        for key, pending in list(self._pending.items()):
            if token not in pending.tokens:
                continue
            remaining = tuple(item for item in pending.tokens if item != token)
            self._pending_token_count -= 1
            if remaining:
                self._pending[key] = _PendingFlow(
                    tokens=remaining,
                    flow=pending.flow,
                    deadline=pending.deadline,
                )
            else:
                del self._pending[key]
            return

    def should_drop_quic(self, client_ip: str, *, now: float) -> bool:
        deadline = self._quarantined_until.get(client_ip, 0.0)
        if deadline <= now:
            self._quarantined_until.pop(client_ip, None)
            return False
        return True

    def _quarantine_client(self, client_ip: str, now: float) -> None:
        deadline = now + self.transport_quarantine_seconds
        self._quarantined_until[client_ip] = max(
            deadline,
            self._quarantined_until.get(client_ip, 0.0),
        )

    @property
    def pending_count(self) -> int:
        return self._pending_token_count

    @property
    def blocked_lineage_count(self) -> int:
        return len(self._blocked_until)

    @property
    def quarantined_client_count(self) -> int:
        return len(self._quarantined_until)

    def next_deadline(self) -> float | None:
        if not self._pending:
            return None
        return min(item.deadline for item in self._pending.values())

    @staticmethod
    def _key(flow: FlowKey, hello: TlsClientHello) -> _LineageKey | None:
        if hello.record_length > 640 or not hello.psk_identity_lengths:
            return None
        return _LineageKey(
            client_ip=flow.client_ip,
            server_name=hello.server_name,
            fingerprint=hello.lineage_fingerprint,
        )


__all__ = ["GateResolution", "LineageGate", "ResolutionVerdict"]
