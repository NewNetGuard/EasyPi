"""Acyclic constants, state and helpers for the encrypted flow graph."""

from __future__ import annotations

import ipaddress
import math
from collections import defaultdict, deque
from dataclasses import dataclass, field

from .events import (
    Direction,
    DnsEvent,
    FlowAssessment,
    FlowKey,
    OpaqueQuicFlowObservation,
    QuicInitialObservation,
    TlsExchangeObservation,
    TlsClientHello,
    TlsRecordSequenceObservation,
    Udp443FlowObservation,
    Verdict,
)
from .packet import (
    DnsMessage,
    OpaqueQuicFlowPacket,
    QuicInitialPacket,
    TcpPacket,
    UnclassifiedUdp443Packet,
)
from .tls import TlsRecordDecoder, parse_client_hello
from .tls import TlsRecord


FLOW_IDLE_SECONDS = 90.0
GRAPH_WINDOW_SECONDS = 6.0
DNS_EVIDENCE_SECONDS = 5.0
BURST_WINDOW_SECONDS = 3.0
ROOT_TO_SUBDOMAIN_WINDOW_SECONDS = 1.5
ROOT_PROFILE_TRANSITION_WINDOW_SECONDS = 3.0
DENSE_PROFILE_TRANSITION_MIN_SUBDOMAINS = 8
LINEAGE_PAIR_WINDOW_SECONDS = 0.25
CAUSAL_ROOT_FANOUT_WINDOW_SECONDS = 6.0
CAUSAL_ROOT_MIN_DISTINCT_SUBDOMAINS = 2
CROSS_SESSION_ROOT_FANOUT_WINDOW_SECONDS = 3.0
CROSS_SESSION_ROOT_MIN_DISTINCT_SUBDOMAINS = 3
CROSS_SESSION_ROOT_MIN_DISTINCT_SESSIONS = 2
LARGE_ROOT_RETRY_WINDOW_SECONDS = 3.0
DELAYED_LARGE_ROOT_RETRY_WINDOW_SECONDS = 6.0
CONFIRMED_ROOT_CONTINUATION_WINDOW_SECONDS = 45.0
ACTIVE_FAMILY_REQUEST_WINDOW_SECONDS = 1.0
ROOT_EXCHANGE_CONVEYOR_WINDOW_SECONDS = 10.0
ROOT_EXCHANGE_CONVEYOR_MIN_FLOWS = 8
ROOT_EXCHANGE_RAPID_WINDOW_SECONDS = 1.0
ROOT_EXCHANGE_RAPID_MIN_FLOWS = 3
ROOT_EXCHANGE_REQUEST_SPREAD_MAX = 0.20
ROOT_EXCHANGE_RESPONSE_SPREAD_MAX = 0.10
UNIFORM_ROOT_COMPANION_WINDOW_SECONDS = 3.0
UNIFORM_ROOT_COMPANION_HELLO_DELTA_SECONDS = 2.0
UNIFORM_ROOT_CROSS_ENDPOINT_WINDOW_SECONDS = 3.0
UNIFORM_ROOT_CROSS_ENDPOINT_HELLO_DELTA_SECONDS = 3.0
UNIFORM_ROOT_SETUP_WINDOW_SECONDS = 2.0
UNIFORM_ROOT_SETUP_MIN_FLOWS = 2
UNIFORM_ROOT_SETUP_CONTEXT_WINDOW_SECONDS = 6.0
SETUP_RESUMPTION_PAIR_WINDOW_SECONDS = 0.25
SETUP_RESUMPTION_MIN_FLOWS = 2
UNIFORM_ROOT_SUCCESSOR_WINDOW_SECONDS = 30.0
SUCCESSOR_EXCHANGE_WINDOW_SECONDS = 4.0
SUCCESSOR_EXCHANGE_COUNT = 4
SUCCESSOR_REQUEST_MIN_BYTES = 800
SUCCESSOR_REQUEST_MAX_BYTES = 4_000
SUCCESSOR_SMALL_RESPONSE_MIN_BYTES = 1_500
SUCCESSOR_SMALL_RESPONSE_MAX_BYTES = 5_000
SUCCESSOR_SMALL_RESPONSE_MIN_COUNT = 3
SUCCESSOR_LARGE_RESPONSE_MIN_BYTES = 20_000
SUCCESSOR_LARGE_RESPONSE_MIN_COUNT = 1
SUCCESSOR_RESUMPTION_CONTEXT_WINDOW_SECONDS = 10.0
SUCCESSOR_RESUMPTION_PAIR_WINDOW_SECONDS = 0.25
SUCCESSOR_RESUMPTION_MIN_FLOWS = 2
ROOT_PROFILE_CYCLE_PHASE_WINDOW_SECONDS = 6.0
ROOT_PROFILE_CYCLE_PAIR_WINDOW_SECONDS = 0.25
ROOT_PROFILE_CYCLE_CONTEXT_WINDOW_SECONDS = 10.0
ROOT_PROFILE_CYCLE_MIN_FLOWS = 2
PAIRED_ROOT_PAIR_WINDOW_SECONDS = 0.4
PAIRED_ROOT_INITIAL_RESUMPTION_WINDOW_SECONDS = 10.0
PAIRED_ROOT_CONTEXT_WINDOW_SECONDS = 45.0
PAIRED_ROOT_RENEWAL_MIN_DESCENDANTS = 3
PAIRED_ROOT_REQUEST_MIN_BYTES = 800
PAIRED_ROOT_REQUEST_MAX_BYTES = 4_000
PAIRED_ROOT_RESPONSE_MIN_BYTES = 1_500
PAIRED_ROOT_LARGE_RESPONSE_MIN_BYTES = 10_000
UNIFORM_ROOT_MULTIPLEX_WINDOW_SECONDS = 1.0
UNIFORM_ROOT_MULTIPLEX_MIN_EXCHANGES = 1
UNIFORM_ROOT_MULTIPLEX_MIN_ENDPOINT_FLOWS = 3
UNIFORM_ROOT_MULTIPLEX_MIN_DISTINCT_NAMES = 2
MIRRORED_ROOT_PAIR_WINDOW_SECONDS = 0.25
MIRRORED_ROOT_TRANSITION_WINDOW_SECONDS = 1.0
YANDEX_MAIL_CONTEXT_MIN_AGE_SECONDS = 5.0
YANDEX_MAIL_CONTEXT_MAX_AGE_SECONDS = 120.0
YANDEX_MAIL_ROOT_BURST_WINDOW_SECONDS = 1.0
YANDEX_MAIL_ROOT_BURST_MIN_FLOWS = 5
YANDEX_MAIL_DESKTOP_MIN_CONTEXT_FLOWS = 4
YANDEX_MAIL_DESKTOP_MIN_CONTEXT_AGE_SECONDS = 1.0
YANDEX_MAIL_DZEN_MIN_BURST_FLOWS = 5
YANDEX_MAIL_INLINE_MIN_CONTEXT_FLOWS = 4
YANDEX_MAIL_INLINE_PREVIOUS_REQUEST_MIN_BYTES = 3_400
YANDEX_MAIL_INLINE_PREVIOUS_REQUEST_MAX_BYTES = 4_300
YANDEX_MAIL_INLINE_PREVIOUS_RESPONSE_MIN_BYTES = 1_200
YANDEX_MAIL_INLINE_PREVIOUS_RESPONSE_MAX_BYTES = 1_650
YANDEX_MAIL_INLINE_REQUEST_MIN_BYTES = 1_900
YANDEX_MAIL_INLINE_REQUEST_MAX_BYTES = 2_400
YANDEX_MAIL_INLINE_FLOW_AGE_MIN_MS = 2_500
YANDEX_MAIL_INLINE_FLOW_AGE_MAX_MS = 6_500
YANDEX_MAIL_INLINE_FIRST_RESPONSE_DELAY_MIN_MS = 80
YANDEX_MAIL_INLINE_FIRST_RESPONSE_DELAY_MAX_MS = 250
YANDEX_MAIL_INLINE_NEXT_REQUEST_DELAY_MIN_MS = 100
YANDEX_MAIL_INLINE_NEXT_REQUEST_DELAY_MAX_MS = 500
YANDEX_MAIL_INLINE_FIRST_TLS_FINGERPRINT = "d9c5b4b26de42707"
YANDEX_MAIL_INLINE_FIRST_TLS_LINEAGE_FINGERPRINT = "e49e77cbc38230eb"
YANDEX_MAIL_INLINE_FIRST_HELLO_MIN_BYTES = 1_900
YANDEX_MAIL_INLINE_FIRST_HELLO_MAX_BYTES = 2_150
YANDEX_MAIL_INLINE_FIRST_REQUEST_MIN_BYTES = 2_100
YANDEX_MAIL_INLINE_FIRST_REQUEST_MAX_BYTES = 2_200
YANDEX_MAIL_INLINE_FIRST_CLIENT_PAYLOAD_MIN_BYTES = 4_200
YANDEX_MAIL_INLINE_FIRST_CLIENT_PAYLOAD_MAX_BYTES = 4_400
YANDEX_MAIL_INLINE_FIRST_SERVER_PAYLOAD_MIN_BYTES = 5_000
YANDEX_MAIL_INLINE_FIRST_SERVER_PAYLOAD_MAX_BYTES = 5_500
YANDEX_MAIL_INLINE_FIRST_REQUEST_DELAY_MIN_MS = 70
YANDEX_MAIL_INLINE_FIRST_REQUEST_DELAY_MAX_MS = 130
YANDEX_MAIL_INLINE_FIRST_HANDSHAKE_DELAY_MIN_MS = 40
YANDEX_MAIL_INLINE_FIRST_HANDSHAKE_DELAY_MAX_MS = 90
YANDEX_MAIL_INLINE_FIRST_CONTEXT_MAX_AGE_MS = 1_500
YANDEX_MAIL_INLINE_FIRST_CONTEXT_MAX_IDLE_MS = 250
YANDEX_MAIL_INLINE_FIRST_MIN_BURST_FLOWS = 7
YANDEX_MAIL_INLINE_FIRST_MIN_SESSION_FLOWS = 4
YANDEX_MAIL_INLINE_FIRST_MIN_FAMILY_REQUESTS = 2
YANDEX_MAIL_INLINE_BOOTSTRAP_REQUEST_MIN_BYTES = 6_000
YANDEX_MAIL_INLINE_BOOTSTRAP_REQUEST_MAX_BYTES = 8_000
YANDEX_MAIL_INLINE_BOOTSTRAP_MIN_BURST_FLOWS = 10
YANDEX_MAIL_INLINE_BOOTSTRAP_MIN_SESSION_FLOWS = 5
YANDEX_MAIL_INLINE_OUTLIER_RESPONSE_MIN_BYTES = 16_000
YANDEX_MAIL_INLINE_OUTLIER_REQUEST_MIN_BYTES = 1_900
YANDEX_MAIL_INLINE_OUTLIER_REQUEST_MAX_BYTES = 8_000
YANDEX_MAIL_INLINE_OUTLIER_PEER_REQUEST_MIN_BYTES = 1_800
YANDEX_MAIL_INLINE_OUTLIER_PEER_REQUEST_MAX_BYTES = 5_000
YANDEX_MAIL_INLINE_OUTLIER_PEER_RESPONSE_MIN_BYTES = 500
YANDEX_MAIL_INLINE_OUTLIER_PEER_RESPONSE_MAX_BYTES = 5_000
YANDEX_MAIL_INLINE_OUTLIER_MIN_PEERS = 2
YANDEX_MAIL_INLINE_OUTLIER_PEER_WINDOW_SECONDS = 1.5
YANDEX_MAIL_INLINE_OUTLIER_MAX_FLOW_AGE_MS = 2_500
YANDEX_MAIL_INLINE_OUTLIER_MAX_FIRST_RESPONSE_DELAY_MS = 150
YANDEX_MAIL_INLINE_PAYLOAD_REQUEST_MIN_BYTES = 2_050
YANDEX_MAIL_INLINE_PAYLOAD_REQUEST_MAX_BYTES = 2_200
YANDEX_MAIL_INLINE_PAYLOAD_RESPONSE_MIN_BYTES = 32_000
YANDEX_MAIL_INLINE_PAYLOAD_MIN_RESPONSE_RECORDS = 2
YANDEX_MAIL_INLINE_PAYLOAD_MAX_FLOW_AGE_MS = 10_000
YANDEX_MAIL_INLINE_PAYLOAD_MAX_FIRST_RESPONSE_DELAY_MS = 250
YANDEX_MAIL_INLINE_AD_DNA_PREVIOUS_REQUEST_MIN_BYTES = 2_200
YANDEX_MAIL_INLINE_AD_DNA_PREVIOUS_REQUEST_MAX_BYTES = 4_200
YANDEX_MAIL_INLINE_AD_DNA_PREVIOUS_RESPONSE_MIN_BYTES = 500
YANDEX_MAIL_INLINE_AD_DNA_PREVIOUS_RESPONSE_MAX_BYTES = 1_500
YANDEX_MAIL_INLINE_AD_DNA_PREVIOUS_RESPONSE_DELAY_MIN_MS = 30
YANDEX_MAIL_INLINE_AD_DNA_PREVIOUS_RESPONSE_DELAY_MAX_MS = 200
YANDEX_MAIL_INLINE_AD_DNA_NEXT_REQUEST_DELAY_MAX_MS = 100
YANDEX_MAIL_INLINE_AD_DNA_REQUEST_MIN_BYTES = 6_000
YANDEX_MAIL_INLINE_AD_DNA_REQUEST_MAX_BYTES = 12_500
YANDEX_MAIL_INLINE_AD_DNA_FLOW_AGE_MIN_MS = 800
YANDEX_MAIL_INLINE_AD_DNA_FLOW_AGE_MAX_MS = 15_000
MAX_FLOW_RECORDS = 16
MAX_ACTIVE_FLOWS = 8_192
MAX_GRAPH_NODES_PER_CLIENT = 1_024
MAX_PENDING_DNS_QUERIES = 8_192
MAX_QUIC_CRYPTO_STATES = 1_024
QUIC_CRYPTO_IDLE_SECONDS = 5.0
MAX_OPAQUE_QUIC_STATES = 4_096
OPAQUE_QUIC_IDLE_SECONDS = 10.0
OPAQUE_QUIC_OBSERVATION_INTERVAL_SECONDS = 1.0
MAX_OPAQUE_QUIC_OBSERVATIONS_PER_FLOW = 6
MAX_UDP443_STATES = 4_096
UDP443_IDLE_SECONDS = 10.0
UDP443_OBSERVATION_INTERVAL_SECONDS = 1.0
MAX_UDP443_OBSERVATIONS_PER_FLOW = 6
MAX_TLS_EXCHANGES_PER_FLOW = 64
MAX_TLS_RECORD_SEQUENCE = 96
MAX_REASSESSED_ROOT_PEERS = 32
MAX_CONFIRMED_ROOTS_PER_CLIENT = 128
MAX_CONFIRMED_UNIFORM_CONVEYORS_PER_CLIENT = 128
MAX_CONFIRMED_SETUP_CONTEXTS_PER_CLIENT = 128
MAX_CONFIRMED_SUCCESSOR_CONTEXTS_PER_CLIENT = 128
MAX_CONFIRMED_PROFILE_CYCLE_CONTEXTS_PER_CLIENT = 128
MAX_CONFIRMED_PAIRED_ROOT_CONTEXTS_PER_CLIENT = 128
MAX_ROOT_EXCHANGES_PER_CLIENT = 512


class TcpSequenceAssembler:
    """Emit an in-order, bounded TCP byte stream and ignore retransmissions."""

    def __init__(self, *, max_pending_bytes: int = 65_536) -> None:
        self._next_sequence: int | None = None
        self._pending: dict[int, bytes] = {}
        self._pending_bytes = 0
        self._max_pending_bytes = max_pending_bytes

    def feed(self, sequence: int, payload: bytes, *, syn: bool = False) -> bytes:
        if syn and self._next_sequence is None:
            self._next_sequence = (sequence + 1) & 0xFFFFFFFF
        if not payload:
            return b""
        if self._next_sequence is None:
            self._next_sequence = sequence

        expected = self._next_sequence
        if sequence < expected:
            overlap = expected - sequence
            if overlap >= len(payload):
                return b""
            payload = payload[overlap:]
            sequence = expected
        if sequence > expected:
            if sequence not in self._pending:
                self._pending[sequence] = payload
                self._pending_bytes += len(payload)
            if self._pending_bytes > self._max_pending_bytes:
                self._pending.clear()
                self._pending_bytes = 0
            return b""

        output = bytearray(payload)
        self._next_sequence = (expected + len(payload)) & 0xFFFFFFFF
        while self._next_sequence in self._pending:
            chunk = self._pending.pop(self._next_sequence)
            self._pending_bytes -= len(chunk)
            output.extend(chunk)
            self._next_sequence = (self._next_sequence + len(chunk)) & 0xFFFFFFFF
        return bytes(output)


@dataclass
class _DirectionState:
    assembler: TcpSequenceAssembler = field(default_factory=TcpSequenceAssembler)
    decoder: TlsRecordDecoder = field(default_factory=TlsRecordDecoder)
    payload_bytes: int = 0
    record_lengths: list[int] = field(default_factory=list)
    record_times: list[float] = field(default_factory=list)


@dataclass
class _FlowState:
    flow: FlowKey
    created_at: float
    last_seen: float
    client: _DirectionState = field(default_factory=_DirectionState)
    server: _DirectionState = field(default_factory=_DirectionState)
    hello: TlsClientHello | None = None
    hello_at: float = 0.0
    session_id: int = 0
    causal_edge_score: float = 0.0
    revision: int = 0
    last_signature: tuple[object, ...] | None = None
    exchange: _TlsExchangeState | None = None
    next_exchange_index: int = 1
    last_completed_exchange: TlsExchangeObservation | None = None
    completed_exchanges: deque[TlsExchangeObservation] = field(
        default_factory=lambda: deque(maxlen=8)
    )
    successor_exchange_conveyor_emitted: bool = False
    setup_resumption_descendant_emitted: bool = False
    successor_resumption_descendant_emitted: bool = False
    profile_cycle_conveyor_emitted: bool = False
    profile_cycle_resumption_descendant_emitted: bool = False
    paired_root_conveyor_emitted: bool = False
    paired_root_setup_descendant_emitted: bool = False
    paired_root_resumption_descendant_emitted: bool = False
    yandex_mail_inline_response_outlier_emitted: bool = False
    record_sequence: list[tuple[Direction, int, int]] = field(default_factory=list)
    record_sequence_started_at: float = 0.0
    record_sequence_last_at: float = 0.0
    record_sequence_emitted: bool = False


@dataclass
class _TlsExchangeState:
    index: int
    started_at: float
    request_record_count: int = 0
    request_bytes: int = 0
    response_record_count: int = 0
    response_bytes: int = 0
    first_response_at: float = 0.0
    last_response_at: float = 0.0


@dataclass(frozen=True)
class _GraphNode:
    timestamp: float
    flow: FlowKey
    hello: TlsClientHello
    session_id: int


@dataclass(frozen=True)
class _ConfirmedLargeRoot:
    timestamp: float
    flow: FlowKey
    server_name: str
    session_id: int


@dataclass(frozen=True)
class _CompletedRootExchange:
    timestamp: float
    flow: FlowKey
    server_name: str
    tls_fingerprint: str
    request_bytes: int
    response_bytes: int


@dataclass(frozen=True)
class _ConfirmedUniformRootConveyor:
    timestamp: float
    flow: FlowKey
    server_name: str
    tls_fingerprint: str
    tls_lineage_fingerprint: str


@dataclass(frozen=True)
class _ConfirmedUniformRootSetupContext:
    timestamp: float
    flow: FlowKey
    server_name: str
    tls_fingerprint: str
    tls_lineage_fingerprint: str


@dataclass
class _ConfirmedUniformRootSuccessorContext:
    timestamp: float
    flow: FlowKey
    server_name: str
    tls_fingerprint: str
    tls_lineage_fingerprint: str
    resumed_fingerprint: str = ""
    resumed_lineage_fingerprint: str = ""
    resumed_pair_flows: tuple[FlowKey, ...] = ()
    resumed_distinct_endpoint_count: int = 0
    resumed_pair_hello_delta_ms: int = 0


@dataclass(frozen=True)
class _RootProfileCycleMatch:
    prior_setup_count: int = 0
    resumed_pair_count: int = 0
    returned_setup_pair_count: int = 0
    setup_to_resumed_ms: int = 0
    resumed_to_return_ms: int = 0
    resumed_pair_delta_ms: int = 0
    returned_setup_pair_delta_ms: int = 0
    resumed_fingerprint: str = ""
    resumed_lineage_fingerprint: str = ""


@dataclass(frozen=True)
class _ConfirmedCompactRootProfileCycle:
    timestamp: float
    flow: FlowKey
    server_name: str
    setup_fingerprint: str
    setup_lineage_fingerprint: str
    resumed_fingerprint: str
    resumed_lineage_fingerprint: str


@dataclass(frozen=True)
class _PairedRootExchangeSnapshot:
    timestamp: float = 0.0
    request_bytes: int = 0
    response_bytes: int = 0
    completed: bool = False


@dataclass(frozen=True)
class _PairedRootFirstExchangeMatch:
    flow_count: int = 0
    distinct_endpoint_count: int = 0
    completed_exchange_count: int = 0
    hello_delta_ms: int = 0
    exchange_delta_ms: int = 0
    request_min_bytes: int = 0
    request_max_bytes: int = 0
    response_min_bytes: int = 0
    response_max_bytes: int = 0
    response_ratio: float = 0.0


@dataclass
class _ConfirmedPairedRootConveyor:
    timestamp: float
    flow: FlowKey
    server_name: str
    setup_fingerprint: str
    setup_lineage_fingerprint: str
    setup_distinct_endpoint_count: int
    resumed_fingerprint: str = ""
    resumed_lineage_fingerprint: str = ""
    descendant_count: int = 0
    last_descendant_at: float = 0.0

    @property
    def active_at(self) -> float:
        if self.descendant_count >= PAIRED_ROOT_RENEWAL_MIN_DESCENDANTS:
            return self.last_descendant_at
        return self.timestamp


@dataclass
class _QuicCryptoState:
    last_seen: float
    fragments: dict[int, bytes] = field(default_factory=dict)
    total_bytes: int = 0


@dataclass
class _OpaqueQuicState:
    last_seen: float
    last_emitted: float = 0.0
    observations_emitted: int = 0


@dataclass
class _Udp443State:
    last_seen: float
    last_emitted: float = 0.0
    observations_emitted: int = 0


def _edge_score(
    timestamp: float,
    flow: FlowKey,
    hello: TlsClientHello,
    node: _GraphNode,
) -> float:
    delta = max(0.0, timestamp - node.timestamp)
    score = 0.30 * math.exp(-delta / 1.5)
    if hello.fingerprint == node.hello.fingerprint:
        score += 0.35
    if _domain_family(hello.server_name) == _domain_family(node.hello.server_name):
        score += 0.20
    if _network_prefix(flow.server_ip) == _network_prefix(node.flow.server_ip):
        score += 0.08
    port_delta = abs(flow.client_port - node.flow.client_port)
    if port_delta <= 32:
        score += 0.18
    elif port_delta <= 256:
        score += 0.08
    return min(score, 1.0)


def _domain_family(server_name: str) -> str:
    labels = server_name.rstrip(".").split(".")
    return ".".join(labels[-2:]) if len(labels) >= 2 else server_name


def _is_root_server_name(server_name: str) -> bool:
    return len(server_name.rstrip(".").split(".")) == 2


def _network_prefix(value: str) -> str:
    address = ipaddress.ip_address(value)
    prefix = 24 if address.version == 4 else 64
    return str(ipaddress.ip_network(f"{address}/{prefix}", strict=False))


def _first_application_record(lengths: list[int]) -> int | None:
    # TLS 1.3 emits ClientHello, ChangeCipherSpec, encrypted Finished, then data.
    if len(lengths) < 4:
        return None
    return lengths[3]


def _relative_distance(left: int, right: int) -> float:
    return abs(left - right) / max(left, right, 1)


def _relative_spread(values: list[int]) -> float:
    return (max(values) - min(values)) / max(max(values), 1)


def _record_delay_ms(record_times: list[float], hello_at: float) -> int:
    if len(record_times) < 4 or not hello_at:
        return 0
    return max(0, round((record_times[3] - hello_at) * 1000))


__all__ = [
    "ACTIVE_FAMILY_REQUEST_WINDOW_SECONDS",
    "BURST_WINDOW_SECONDS",
    "CAUSAL_ROOT_FANOUT_WINDOW_SECONDS",
    "CAUSAL_ROOT_MIN_DISTINCT_SUBDOMAINS",
    "CONFIRMED_ROOT_CONTINUATION_WINDOW_SECONDS",
    "CROSS_SESSION_ROOT_FANOUT_WINDOW_SECONDS",
    "CROSS_SESSION_ROOT_MIN_DISTINCT_SESSIONS",
    "CROSS_SESSION_ROOT_MIN_DISTINCT_SUBDOMAINS",
    "DELAYED_LARGE_ROOT_RETRY_WINDOW_SECONDS",
    "DENSE_PROFILE_TRANSITION_MIN_SUBDOMAINS",
    "DNS_EVIDENCE_SECONDS",
    "Direction",
    "DnsEvent",
    "DnsMessage",
    "FLOW_IDLE_SECONDS",
    "FlowAssessment",
    "FlowKey",
    "GRAPH_WINDOW_SECONDS",
    "LARGE_ROOT_RETRY_WINDOW_SECONDS",
    "LINEAGE_PAIR_WINDOW_SECONDS",
    "MAX_ACTIVE_FLOWS",
    "MAX_CONFIRMED_PAIRED_ROOT_CONTEXTS_PER_CLIENT",
    "MAX_CONFIRMED_PROFILE_CYCLE_CONTEXTS_PER_CLIENT",
    "MAX_CONFIRMED_ROOTS_PER_CLIENT",
    "MAX_CONFIRMED_SETUP_CONTEXTS_PER_CLIENT",
    "MAX_CONFIRMED_SUCCESSOR_CONTEXTS_PER_CLIENT",
    "MAX_CONFIRMED_UNIFORM_CONVEYORS_PER_CLIENT",
    "MAX_FLOW_RECORDS",
    "MAX_GRAPH_NODES_PER_CLIENT",
    "MAX_OPAQUE_QUIC_OBSERVATIONS_PER_FLOW",
    "MAX_OPAQUE_QUIC_STATES",
    "MAX_PENDING_DNS_QUERIES",
    "MAX_QUIC_CRYPTO_STATES",
    "MAX_REASSESSED_ROOT_PEERS",
    "MAX_ROOT_EXCHANGES_PER_CLIENT",
    "MAX_TLS_EXCHANGES_PER_FLOW",
    "MAX_TLS_RECORD_SEQUENCE",
    "MAX_UDP443_OBSERVATIONS_PER_FLOW",
    "MAX_UDP443_STATES",
    "MIRRORED_ROOT_PAIR_WINDOW_SECONDS",
    "MIRRORED_ROOT_TRANSITION_WINDOW_SECONDS",
    "OPAQUE_QUIC_IDLE_SECONDS",
    "OPAQUE_QUIC_OBSERVATION_INTERVAL_SECONDS",
    "OpaqueQuicFlowObservation",
    "OpaqueQuicFlowPacket",
    "PAIRED_ROOT_CONTEXT_WINDOW_SECONDS",
    "PAIRED_ROOT_INITIAL_RESUMPTION_WINDOW_SECONDS",
    "PAIRED_ROOT_LARGE_RESPONSE_MIN_BYTES",
    "PAIRED_ROOT_PAIR_WINDOW_SECONDS",
    "PAIRED_ROOT_RENEWAL_MIN_DESCENDANTS",
    "PAIRED_ROOT_REQUEST_MAX_BYTES",
    "PAIRED_ROOT_REQUEST_MIN_BYTES",
    "PAIRED_ROOT_RESPONSE_MIN_BYTES",
    "QUIC_CRYPTO_IDLE_SECONDS",
    "QuicInitialObservation",
    "QuicInitialPacket",
    "ROOT_EXCHANGE_CONVEYOR_MIN_FLOWS",
    "ROOT_EXCHANGE_CONVEYOR_WINDOW_SECONDS",
    "ROOT_EXCHANGE_RAPID_MIN_FLOWS",
    "ROOT_EXCHANGE_RAPID_WINDOW_SECONDS",
    "ROOT_EXCHANGE_REQUEST_SPREAD_MAX",
    "ROOT_EXCHANGE_RESPONSE_SPREAD_MAX",
    "ROOT_PROFILE_CYCLE_CONTEXT_WINDOW_SECONDS",
    "ROOT_PROFILE_CYCLE_MIN_FLOWS",
    "ROOT_PROFILE_CYCLE_PAIR_WINDOW_SECONDS",
    "ROOT_PROFILE_CYCLE_PHASE_WINDOW_SECONDS",
    "ROOT_PROFILE_TRANSITION_WINDOW_SECONDS",
    "ROOT_TO_SUBDOMAIN_WINDOW_SECONDS",
    "SETUP_RESUMPTION_MIN_FLOWS",
    "SETUP_RESUMPTION_PAIR_WINDOW_SECONDS",
    "SUCCESSOR_EXCHANGE_COUNT",
    "SUCCESSOR_EXCHANGE_WINDOW_SECONDS",
    "SUCCESSOR_LARGE_RESPONSE_MIN_BYTES",
    "SUCCESSOR_LARGE_RESPONSE_MIN_COUNT",
    "SUCCESSOR_REQUEST_MAX_BYTES",
    "SUCCESSOR_REQUEST_MIN_BYTES",
    "SUCCESSOR_RESUMPTION_CONTEXT_WINDOW_SECONDS",
    "SUCCESSOR_RESUMPTION_MIN_FLOWS",
    "SUCCESSOR_RESUMPTION_PAIR_WINDOW_SECONDS",
    "SUCCESSOR_SMALL_RESPONSE_MAX_BYTES",
    "SUCCESSOR_SMALL_RESPONSE_MIN_BYTES",
    "SUCCESSOR_SMALL_RESPONSE_MIN_COUNT",
    "TcpPacket",
    "TcpSequenceAssembler",
    "TlsClientHello",
    "TlsExchangeObservation",
    "TlsRecord",
    "TlsRecordDecoder",
    "TlsRecordSequenceObservation",
    "UDP443_IDLE_SECONDS",
    "UDP443_OBSERVATION_INTERVAL_SECONDS",
    "UNIFORM_ROOT_COMPANION_HELLO_DELTA_SECONDS",
    "UNIFORM_ROOT_COMPANION_WINDOW_SECONDS",
    "UNIFORM_ROOT_CROSS_ENDPOINT_HELLO_DELTA_SECONDS",
    "UNIFORM_ROOT_CROSS_ENDPOINT_WINDOW_SECONDS",
    "UNIFORM_ROOT_MULTIPLEX_MIN_DISTINCT_NAMES",
    "UNIFORM_ROOT_MULTIPLEX_MIN_ENDPOINT_FLOWS",
    "UNIFORM_ROOT_MULTIPLEX_MIN_EXCHANGES",
    "UNIFORM_ROOT_MULTIPLEX_WINDOW_SECONDS",
    "UNIFORM_ROOT_SETUP_CONTEXT_WINDOW_SECONDS",
    "UNIFORM_ROOT_SETUP_MIN_FLOWS",
    "UNIFORM_ROOT_SETUP_WINDOW_SECONDS",
    "UNIFORM_ROOT_SUCCESSOR_WINDOW_SECONDS",
    "Udp443FlowObservation",
    "UnclassifiedUdp443Packet",
    "Verdict",
    "YANDEX_MAIL_CONTEXT_MAX_AGE_SECONDS",
    "YANDEX_MAIL_CONTEXT_MIN_AGE_SECONDS",
    "YANDEX_MAIL_DESKTOP_MIN_CONTEXT_AGE_SECONDS",
    "YANDEX_MAIL_DESKTOP_MIN_CONTEXT_FLOWS",
    "YANDEX_MAIL_DZEN_MIN_BURST_FLOWS",
    "YANDEX_MAIL_INLINE_AD_DNA_FLOW_AGE_MAX_MS",
    "YANDEX_MAIL_INLINE_AD_DNA_FLOW_AGE_MIN_MS",
    "YANDEX_MAIL_INLINE_AD_DNA_NEXT_REQUEST_DELAY_MAX_MS",
    "YANDEX_MAIL_INLINE_AD_DNA_PREVIOUS_REQUEST_MAX_BYTES",
    "YANDEX_MAIL_INLINE_AD_DNA_PREVIOUS_REQUEST_MIN_BYTES",
    "YANDEX_MAIL_INLINE_AD_DNA_PREVIOUS_RESPONSE_DELAY_MAX_MS",
    "YANDEX_MAIL_INLINE_AD_DNA_PREVIOUS_RESPONSE_DELAY_MIN_MS",
    "YANDEX_MAIL_INLINE_AD_DNA_PREVIOUS_RESPONSE_MAX_BYTES",
    "YANDEX_MAIL_INLINE_AD_DNA_PREVIOUS_RESPONSE_MIN_BYTES",
    "YANDEX_MAIL_INLINE_AD_DNA_REQUEST_MAX_BYTES",
    "YANDEX_MAIL_INLINE_AD_DNA_REQUEST_MIN_BYTES",
    "YANDEX_MAIL_INLINE_BOOTSTRAP_MIN_BURST_FLOWS",
    "YANDEX_MAIL_INLINE_BOOTSTRAP_MIN_SESSION_FLOWS",
    "YANDEX_MAIL_INLINE_BOOTSTRAP_REQUEST_MAX_BYTES",
    "YANDEX_MAIL_INLINE_BOOTSTRAP_REQUEST_MIN_BYTES",
    "YANDEX_MAIL_INLINE_FIRST_CLIENT_PAYLOAD_MAX_BYTES",
    "YANDEX_MAIL_INLINE_FIRST_CLIENT_PAYLOAD_MIN_BYTES",
    "YANDEX_MAIL_INLINE_FIRST_CONTEXT_MAX_AGE_MS",
    "YANDEX_MAIL_INLINE_FIRST_CONTEXT_MAX_IDLE_MS",
    "YANDEX_MAIL_INLINE_FIRST_HANDSHAKE_DELAY_MAX_MS",
    "YANDEX_MAIL_INLINE_FIRST_HANDSHAKE_DELAY_MIN_MS",
    "YANDEX_MAIL_INLINE_FIRST_HELLO_MAX_BYTES",
    "YANDEX_MAIL_INLINE_FIRST_HELLO_MIN_BYTES",
    "YANDEX_MAIL_INLINE_FIRST_MIN_BURST_FLOWS",
    "YANDEX_MAIL_INLINE_FIRST_MIN_FAMILY_REQUESTS",
    "YANDEX_MAIL_INLINE_FIRST_MIN_SESSION_FLOWS",
    "YANDEX_MAIL_INLINE_FIRST_REQUEST_DELAY_MAX_MS",
    "YANDEX_MAIL_INLINE_FIRST_REQUEST_DELAY_MIN_MS",
    "YANDEX_MAIL_INLINE_FIRST_REQUEST_MAX_BYTES",
    "YANDEX_MAIL_INLINE_FIRST_REQUEST_MIN_BYTES",
    "YANDEX_MAIL_INLINE_FIRST_RESPONSE_DELAY_MAX_MS",
    "YANDEX_MAIL_INLINE_FIRST_RESPONSE_DELAY_MIN_MS",
    "YANDEX_MAIL_INLINE_FIRST_SERVER_PAYLOAD_MAX_BYTES",
    "YANDEX_MAIL_INLINE_FIRST_SERVER_PAYLOAD_MIN_BYTES",
    "YANDEX_MAIL_INLINE_FIRST_TLS_FINGERPRINT",
    "YANDEX_MAIL_INLINE_FIRST_TLS_LINEAGE_FINGERPRINT",
    "YANDEX_MAIL_INLINE_FLOW_AGE_MAX_MS",
    "YANDEX_MAIL_INLINE_FLOW_AGE_MIN_MS",
    "YANDEX_MAIL_INLINE_MIN_CONTEXT_FLOWS",
    "YANDEX_MAIL_INLINE_NEXT_REQUEST_DELAY_MAX_MS",
    "YANDEX_MAIL_INLINE_NEXT_REQUEST_DELAY_MIN_MS",
    "YANDEX_MAIL_INLINE_OUTLIER_MAX_FIRST_RESPONSE_DELAY_MS",
    "YANDEX_MAIL_INLINE_OUTLIER_MAX_FLOW_AGE_MS",
    "YANDEX_MAIL_INLINE_OUTLIER_MIN_PEERS",
    "YANDEX_MAIL_INLINE_OUTLIER_PEER_REQUEST_MAX_BYTES",
    "YANDEX_MAIL_INLINE_OUTLIER_PEER_REQUEST_MIN_BYTES",
    "YANDEX_MAIL_INLINE_OUTLIER_PEER_RESPONSE_MAX_BYTES",
    "YANDEX_MAIL_INLINE_OUTLIER_PEER_RESPONSE_MIN_BYTES",
    "YANDEX_MAIL_INLINE_OUTLIER_PEER_WINDOW_SECONDS",
    "YANDEX_MAIL_INLINE_OUTLIER_REQUEST_MAX_BYTES",
    "YANDEX_MAIL_INLINE_OUTLIER_REQUEST_MIN_BYTES",
    "YANDEX_MAIL_INLINE_OUTLIER_RESPONSE_MIN_BYTES",
    "YANDEX_MAIL_INLINE_PAYLOAD_MAX_FIRST_RESPONSE_DELAY_MS",
    "YANDEX_MAIL_INLINE_PAYLOAD_MAX_FLOW_AGE_MS",
    "YANDEX_MAIL_INLINE_PAYLOAD_MIN_RESPONSE_RECORDS",
    "YANDEX_MAIL_INLINE_PAYLOAD_REQUEST_MAX_BYTES",
    "YANDEX_MAIL_INLINE_PAYLOAD_REQUEST_MIN_BYTES",
    "YANDEX_MAIL_INLINE_PAYLOAD_RESPONSE_MIN_BYTES",
    "YANDEX_MAIL_INLINE_PREVIOUS_REQUEST_MAX_BYTES",
    "YANDEX_MAIL_INLINE_PREVIOUS_REQUEST_MIN_BYTES",
    "YANDEX_MAIL_INLINE_PREVIOUS_RESPONSE_MAX_BYTES",
    "YANDEX_MAIL_INLINE_PREVIOUS_RESPONSE_MIN_BYTES",
    "YANDEX_MAIL_INLINE_REQUEST_MAX_BYTES",
    "YANDEX_MAIL_INLINE_REQUEST_MIN_BYTES",
    "YANDEX_MAIL_ROOT_BURST_MIN_FLOWS",
    "YANDEX_MAIL_ROOT_BURST_WINDOW_SECONDS",
    "_CompletedRootExchange",
    "_ConfirmedCompactRootProfileCycle",
    "_ConfirmedLargeRoot",
    "_ConfirmedPairedRootConveyor",
    "_ConfirmedUniformRootConveyor",
    "_ConfirmedUniformRootSetupContext",
    "_ConfirmedUniformRootSuccessorContext",
    "_DirectionState",
    "_FlowState",
    "_GraphNode",
    "_OpaqueQuicState",
    "_PairedRootExchangeSnapshot",
    "_PairedRootFirstExchangeMatch",
    "_QuicCryptoState",
    "_RootProfileCycleMatch",
    "_TlsExchangeState",
    "_Udp443State",
    "_domain_family",
    "_edge_score",
    "_first_application_record",
    "_is_root_server_name",
    "_network_prefix",
    "_record_delay_ms",
    "_relative_distance",
    "_relative_spread",
    "dataclass",
    "defaultdict",
    "deque",
    "field",
    "ipaddress",
    "math",
    "parse_client_hello",
]
