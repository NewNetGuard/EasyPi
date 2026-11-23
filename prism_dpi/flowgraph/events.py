"""Typed metadata events used by the PRISM FlowGraph analyzer."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any


class Direction(str, Enum):
    CLIENT_TO_SERVER = "client_to_server"
    SERVER_TO_CLIENT = "server_to_client"


class Verdict(str, Enum):
    ALLOW = "allow"
    AMBIGUOUS = "ambiguous"
    CANDIDATE = "candidate"


@dataclass(frozen=True, order=True)
class FlowKey:
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    protocol: str = "tcp"

    def id(self) -> str:
        return (
            f"{self.protocol}:{self.client_ip}:{self.client_port}>"
            f"{self.server_ip}:{self.server_port}"
        )


@dataclass(frozen=True)
class TlsClientHello:
    server_name: str
    record_length: int
    fingerprint: str
    alpn: tuple[str, ...]
    extension_ids: tuple[int, ...]
    session_id_length: int
    psk_identity_lengths: tuple[int, ...]
    psk_binder_lengths: tuple[int, ...]
    key_share_groups: tuple[int, ...]
    supported_versions: tuple[int, ...]
    lineage_fingerprint: str


@dataclass(frozen=True)
class DnsEvent:
    timestamp: float
    client_ip: str
    query_name: str
    blocked: bool


@dataclass(frozen=True)
class FlowAssessment:
    timestamp: float
    flow: FlowKey
    session_id: int
    server_name: str
    verdict: Verdict
    confidence: float
    revision: int
    evidence: tuple[str, ...]
    features: dict[str, int | float | str | bool]

    def to_dict(self) -> dict[str, Any]:
        value = asdict(self)
        value["event"] = "flow_assessment"
        value["flow"] = self.flow.id()
        value["client_ip"] = self.flow.client_ip
        value["client_port"] = self.flow.client_port
        value["server_ip"] = self.flow.server_ip
        value["server_port"] = self.flow.server_port
        value["verdict"] = self.verdict.value
        return value


@dataclass(frozen=True)
class QuicInitialObservation:
    timestamp: float
    flow: FlowKey
    version: int
    destination_connection_id_length: int
    hello: TlsClientHello

    def to_dict(self) -> dict[str, Any]:
        return {
            "event": "quic_initial_observation",
            "timestamp": self.timestamp,
            "flow": self.flow.id(),
            "client_ip": self.flow.client_ip,
            "client_port": self.flow.client_port,
            "server_ip": self.flow.server_ip,
            "server_port": self.flow.server_port,
            "server_name": self.hello.server_name,
            "quic_version": f"0x{self.version:08x}",
            "destination_connection_id_length": self.destination_connection_id_length,
            "tls_fingerprint": self.hello.fingerprint,
            "tls_lineage_fingerprint": self.hello.lineage_fingerprint,
            "tls_psk_identity_count": len(self.hello.psk_identity_lengths),
            "tls_alpn": ",".join(self.hello.alpn),
            "mode": "shadow",
        }


@dataclass(frozen=True)
class OpaqueQuicFlowObservation:
    timestamp: float
    flow: FlowKey
    datagram_bytes: int
    header_form: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "event": "opaque_quic_flow_observation",
            "timestamp": self.timestamp,
            "flow": self.flow.id(),
            "client_ip": self.flow.client_ip,
            "client_port": self.flow.client_port,
            "server_ip": self.flow.server_ip,
            "server_port": self.flow.server_port,
            "datagram_bytes": self.datagram_bytes,
            "quic_fixed_bit": True,
            "quic_header_form": self.header_form,
            "mode": "shadow",
        }


@dataclass(frozen=True)
class Udp443FlowObservation:
    timestamp: float
    flow: FlowKey
    datagram_bytes: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "event": "udp_443_flow_observation",
            "timestamp": self.timestamp,
            "flow": self.flow.id(),
            "client_ip": self.flow.client_ip,
            "client_port": self.flow.client_port,
            "server_ip": self.flow.server_ip,
            "server_port": self.flow.server_port,
            "datagram_bytes": self.datagram_bytes,
            "mode": "shadow",
        }


@dataclass(frozen=True)
class TlsExchangeObservation:
    timestamp: float
    flow: FlowKey
    server_name: str
    tls_fingerprint: str
    exchange_index: int
    request_record_count: int
    request_bytes: int
    response_record_count: int
    response_bytes: int
    first_response_delay_ms: int
    next_request_delay_ms: int | None
    flow_age_ms: int
    previous_response_bytes: int
    previous_next_request_delay_ms: int
    response_step_ratio: float
    completion_reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "event": "tls_exchange_observation",
            "timestamp": self.timestamp,
            "flow": self.flow.id(),
            "client_ip": self.flow.client_ip,
            "client_port": self.flow.client_port,
            "server_ip": self.flow.server_ip,
            "server_port": self.flow.server_port,
            "server_name": self.server_name,
            "tls_fingerprint": self.tls_fingerprint,
            "exchange_index": self.exchange_index,
            "request_record_count": self.request_record_count,
            "request_bytes": self.request_bytes,
            "response_record_count": self.response_record_count,
            "response_bytes": self.response_bytes,
            "first_response_delay_ms": self.first_response_delay_ms,
            "next_request_delay_ms": self.next_request_delay_ms,
            "flow_age_ms": self.flow_age_ms,
            "previous_response_bytes": self.previous_response_bytes,
            "previous_next_request_delay_ms": (self.previous_next_request_delay_ms),
            "response_step_ratio": self.response_step_ratio,
            "completion_reason": self.completion_reason,
            "mode": "shadow",
        }


@dataclass(frozen=True)
class TlsRecordSequenceObservation:
    timestamp: float
    flow: FlowKey
    server_name: str
    tls_fingerprint: str
    record_directions: tuple[Direction, ...]
    record_lengths: tuple[int, ...]
    interarrival_ms: tuple[int, ...]
    duration_ms: int
    completion_reason: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "event": "tls_record_sequence_observation",
            "timestamp": self.timestamp,
            "flow": self.flow.id(),
            "client_ip": self.flow.client_ip,
            "client_port": self.flow.client_port,
            "server_ip": self.flow.server_ip,
            "server_port": self.flow.server_port,
            "server_name": self.server_name,
            "tls_fingerprint": self.tls_fingerprint,
            "record_directions": [value.value for value in self.record_directions],
            "record_lengths": list(self.record_lengths),
            "interarrival_ms": list(self.interarrival_ms),
            "record_count": len(self.record_lengths),
            "duration_ms": self.duration_ms,
            "completion_reason": self.completion_reason,
            "mode": "shadow",
        }


__all__ = [
    "Direction",
    "DnsEvent",
    "FlowAssessment",
    "FlowKey",
    "OpaqueQuicFlowObservation",
    "QuicInitialObservation",
    "TlsExchangeObservation",
    "TlsRecordSequenceObservation",
    "TlsClientHello",
    "Udp443FlowObservation",
    "Verdict",
]
