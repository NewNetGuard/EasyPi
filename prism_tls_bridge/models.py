"""Public, secret-free contracts for an observation-only bridge."""

from dataclasses import dataclass
from enum import Enum
import ipaddress
import math
from .qpack_budget import quic_envelope


class InspectionState(str, Enum):
    DECRYPTED = "Decrypted"
    METADATA = "Metadata only"
    UNKNOWN = "Unknown"


@dataclass(frozen=True)
class Endpoint:
    address: str
    port: int

    def __post_init__(self):
        object.__setattr__(self, "address", str(ipaddress.ip_address(self.address)))
        if not 1 <= self.port <= 65535:
            raise ValueError("invalid endpoint port")


@dataclass(frozen=True)
class Provenance:
    endpoint_id: str
    capture_point: str
    key_source: str
    tls_leg: str
    opt_in: bool = False

    def __post_init__(self):
        if not isinstance(self.opt_in, bool):
            raise ValueError("opt-in must be explicit boolean consent")
        for name in ("endpoint_id", "capture_point", "key_source", "tls_leg"):
            value = getattr(self, name)
            if (
                not isinstance(value, str)
                or not 1 <= len(value) <= 64
                or any(ord(c) < 32 for c in value)
            ):
                raise ValueError("invalid provenance identifier")


@dataclass(frozen=True)
class Limits:
    max_connections: int = 16
    global_bytes: int = 32 * 1024 * 1024
    per_connection_bytes: int = 1024 * 1024
    decoder_buffer_bytes: int = 65536
    reassembly_bytes: int = 65536
    history_bytes: int = 8192
    max_segments: int = 128
    max_streams: int = 8
    stream_bytes: int = 16384
    header_bytes: int = 16384
    max_header_fields: int = 64
    max_packets: int = 1024
    max_keys: int = 8
    max_events: int = 128
    event_bytes: int = 4096
    max_closed: int = 64
    idle_seconds: float = 30
    gap_seconds: float = 3
    keys_wait_seconds: float = 5
    key_lease_seconds: float = 60
    previous_quic_key_seconds: float = 3

    def __post_init__(self):
        positive = (
            "max_connections",
            "global_bytes",
            "per_connection_bytes",
            "decoder_buffer_bytes",
            "reassembly_bytes",
            "history_bytes",
            "max_segments",
            "max_streams",
            "stream_bytes",
            "header_bytes",
            "max_header_fields",
            "max_packets",
            "max_keys",
            "max_events",
            "event_bytes",
            "max_closed",
        )
        if any(
            not isinstance(getattr(self, n), int) or getattr(self, n) <= 0
            for n in positive
        ):
            raise ValueError("limits must be positive integers")
        if (
            self.reassembly_bytes >= 1 << 30
            or self.history_bytes > self.reassembly_bytes
        ):
            raise ValueError("invalid TCP sequence window")
        if any(
            not math.isfinite(getattr(self, n)) or getattr(self, n) <= 0
            for n in (
                "idle_seconds",
                "gap_seconds",
                "keys_wait_seconds",
                "key_lease_seconds",
                "previous_quic_key_seconds",
            )
        ):
            raise ValueError("timeouts must be positive")
        if (
            self.per_connection_bytes
            < 8 * self.decoder_buffer_bytes
            + 3 * self.max_streams * self.stream_bytes
            + self.history_bytes * 2
        ):
            raise ValueError(
                "per-connection envelope is too small for configured buffers"
            )
        if self.fixed_bytes + self.per_connection_bytes > self.global_bytes:
            raise ValueError("global budget cannot admit a connection")
        if quic_envelope(self) > self.per_connection_bytes:
            raise ValueError("per-connection envelope is too small for QPACK and QUIC buffers")

    @property
    def fixed_bytes(self):
        return self.max_events * self.event_bytes + self.max_closed * 1024


@dataclass(frozen=True)
class Snapshot:
    flow_id: str
    transport: str
    state: InspectionState
    reason: str
    provenance: Provenance
    coverage: str = "none"
    direction: str = "client"
    request_headers_complete: bool = False
    body_inspected: bool = False
    diagnostic: str = "missing_key"
    transport_closed: bool = False
    client_key_generation: int = 0
    server_key_generation: int = 0
    decoder_code: str = "none"
    quic_authenticated_packets: int = 0
    decoder_requested_bytes: int | None = None
    decoder_limit_bytes: int | None = None
