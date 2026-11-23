"""Bounded fail-open gate for compact TLS resumption lineages."""

from .decision import GateResolution, LineageGate, ResolutionVerdict
from .packet import (
    QueuedClientHello,
    QueuedTransportPacket,
    parse_queued_ipv4_client_hello,
    parse_queued_ipv4_transport,
)

__all__ = [
    "GateResolution",
    "LineageGate",
    "QueuedClientHello",
    "QueuedTransportPacket",
    "ResolutionVerdict",
    "parse_queued_ipv4_client_hello",
    "parse_queued_ipv4_transport",
]
