"""Stateful, fail-open causal flow graph for encrypted traffic metadata.

The public import surface remains here; implementation primitives live in the
acyclic :mod:`prism_dpi.flowgraph.foundation` module.
"""

# ruff: noqa: F401

from prism_dpi.flowgraph.foundation import (
    ACTIVE_FAMILY_REQUEST_WINDOW_SECONDS,
    BURST_WINDOW_SECONDS,
    CAUSAL_ROOT_FANOUT_WINDOW_SECONDS,
    CAUSAL_ROOT_MIN_DISTINCT_SUBDOMAINS,
    CONFIRMED_ROOT_CONTINUATION_WINDOW_SECONDS,
    CROSS_SESSION_ROOT_FANOUT_WINDOW_SECONDS,
    CROSS_SESSION_ROOT_MIN_DISTINCT_SESSIONS,
    CROSS_SESSION_ROOT_MIN_DISTINCT_SUBDOMAINS,
    DELAYED_LARGE_ROOT_RETRY_WINDOW_SECONDS,
    DENSE_PROFILE_TRANSITION_MIN_SUBDOMAINS,
    DNS_EVIDENCE_SECONDS,
    Direction,
    DnsEvent,
    DnsMessage,
    FLOW_IDLE_SECONDS,
    FlowAssessment,
    FlowKey,
    GRAPH_WINDOW_SECONDS,
    LARGE_ROOT_RETRY_WINDOW_SECONDS,
    LINEAGE_PAIR_WINDOW_SECONDS,
    MAX_ACTIVE_FLOWS,
    MAX_CONFIRMED_PAIRED_ROOT_CONTEXTS_PER_CLIENT,
    MAX_CONFIRMED_PROFILE_CYCLE_CONTEXTS_PER_CLIENT,
    MAX_CONFIRMED_ROOTS_PER_CLIENT,
    MAX_CONFIRMED_SETUP_CONTEXTS_PER_CLIENT,
    MAX_CONFIRMED_SUCCESSOR_CONTEXTS_PER_CLIENT,
    MAX_CONFIRMED_UNIFORM_CONVEYORS_PER_CLIENT,
    MAX_FLOW_RECORDS,
    MAX_GRAPH_NODES_PER_CLIENT,
    MAX_OPAQUE_QUIC_OBSERVATIONS_PER_FLOW,
    MAX_OPAQUE_QUIC_STATES,
    MAX_PENDING_DNS_QUERIES,
    MAX_QUIC_CRYPTO_STATES,
    MAX_REASSESSED_ROOT_PEERS,
    MAX_ROOT_EXCHANGES_PER_CLIENT,
    MAX_TLS_EXCHANGES_PER_FLOW,
    MAX_TLS_RECORD_SEQUENCE,
    MAX_UDP443_OBSERVATIONS_PER_FLOW,
    MAX_UDP443_STATES,
    MIRRORED_ROOT_PAIR_WINDOW_SECONDS,
    MIRRORED_ROOT_TRANSITION_WINDOW_SECONDS,
    OPAQUE_QUIC_IDLE_SECONDS,
    OPAQUE_QUIC_OBSERVATION_INTERVAL_SECONDS,
    OpaqueQuicFlowObservation,
    OpaqueQuicFlowPacket,
    PAIRED_ROOT_CONTEXT_WINDOW_SECONDS,
    PAIRED_ROOT_INITIAL_RESUMPTION_WINDOW_SECONDS,
    PAIRED_ROOT_LARGE_RESPONSE_MIN_BYTES,
    PAIRED_ROOT_PAIR_WINDOW_SECONDS,
    PAIRED_ROOT_RENEWAL_MIN_DESCENDANTS,
    PAIRED_ROOT_REQUEST_MAX_BYTES,
    PAIRED_ROOT_REQUEST_MIN_BYTES,
    PAIRED_ROOT_RESPONSE_MIN_BYTES,
    QUIC_CRYPTO_IDLE_SECONDS,
    QuicInitialObservation,
    QuicInitialPacket,
    ROOT_EXCHANGE_CONVEYOR_MIN_FLOWS,
    ROOT_EXCHANGE_CONVEYOR_WINDOW_SECONDS,
    ROOT_EXCHANGE_RAPID_MIN_FLOWS,
    ROOT_EXCHANGE_RAPID_WINDOW_SECONDS,
    ROOT_EXCHANGE_REQUEST_SPREAD_MAX,
    ROOT_EXCHANGE_RESPONSE_SPREAD_MAX,
    ROOT_PROFILE_CYCLE_CONTEXT_WINDOW_SECONDS,
    ROOT_PROFILE_CYCLE_MIN_FLOWS,
    ROOT_PROFILE_CYCLE_PAIR_WINDOW_SECONDS,
    ROOT_PROFILE_CYCLE_PHASE_WINDOW_SECONDS,
    ROOT_PROFILE_TRANSITION_WINDOW_SECONDS,
    ROOT_TO_SUBDOMAIN_WINDOW_SECONDS,
    SETUP_RESUMPTION_MIN_FLOWS,
    SETUP_RESUMPTION_PAIR_WINDOW_SECONDS,
    SUCCESSOR_EXCHANGE_COUNT,
    SUCCESSOR_EXCHANGE_WINDOW_SECONDS,
    SUCCESSOR_LARGE_RESPONSE_MIN_BYTES,
    SUCCESSOR_LARGE_RESPONSE_MIN_COUNT,
    SUCCESSOR_REQUEST_MAX_BYTES,
    SUCCESSOR_REQUEST_MIN_BYTES,
    SUCCESSOR_RESUMPTION_CONTEXT_WINDOW_SECONDS,
    SUCCESSOR_RESUMPTION_MIN_FLOWS,
    SUCCESSOR_RESUMPTION_PAIR_WINDOW_SECONDS,
    SUCCESSOR_SMALL_RESPONSE_MAX_BYTES,
    SUCCESSOR_SMALL_RESPONSE_MIN_BYTES,
    SUCCESSOR_SMALL_RESPONSE_MIN_COUNT,
    TcpPacket,
    TcpSequenceAssembler,
    TlsClientHello,
    TlsExchangeObservation,
    TlsRecord,
    TlsRecordDecoder,
    TlsRecordSequenceObservation,
    UDP443_IDLE_SECONDS,
    UDP443_OBSERVATION_INTERVAL_SECONDS,
    UNIFORM_ROOT_COMPANION_HELLO_DELTA_SECONDS,
    UNIFORM_ROOT_COMPANION_WINDOW_SECONDS,
    UNIFORM_ROOT_CROSS_ENDPOINT_HELLO_DELTA_SECONDS,
    UNIFORM_ROOT_CROSS_ENDPOINT_WINDOW_SECONDS,
    UNIFORM_ROOT_MULTIPLEX_MIN_DISTINCT_NAMES,
    UNIFORM_ROOT_MULTIPLEX_MIN_ENDPOINT_FLOWS,
    UNIFORM_ROOT_MULTIPLEX_MIN_EXCHANGES,
    UNIFORM_ROOT_MULTIPLEX_WINDOW_SECONDS,
    UNIFORM_ROOT_SETUP_CONTEXT_WINDOW_SECONDS,
    UNIFORM_ROOT_SETUP_MIN_FLOWS,
    UNIFORM_ROOT_SETUP_WINDOW_SECONDS,
    UNIFORM_ROOT_SUCCESSOR_WINDOW_SECONDS,
    Udp443FlowObservation,
    UnclassifiedUdp443Packet,
    Verdict,
    YANDEX_MAIL_CONTEXT_MAX_AGE_SECONDS,
    YANDEX_MAIL_CONTEXT_MIN_AGE_SECONDS,
    YANDEX_MAIL_DESKTOP_MIN_CONTEXT_AGE_SECONDS,
    YANDEX_MAIL_DESKTOP_MIN_CONTEXT_FLOWS,
    YANDEX_MAIL_DZEN_MIN_BURST_FLOWS,
    YANDEX_MAIL_INLINE_AD_DNA_FLOW_AGE_MAX_MS,
    YANDEX_MAIL_INLINE_AD_DNA_FLOW_AGE_MIN_MS,
    YANDEX_MAIL_INLINE_AD_DNA_NEXT_REQUEST_DELAY_MAX_MS,
    YANDEX_MAIL_INLINE_AD_DNA_PREVIOUS_REQUEST_MAX_BYTES,
    YANDEX_MAIL_INLINE_AD_DNA_PREVIOUS_REQUEST_MIN_BYTES,
    YANDEX_MAIL_INLINE_AD_DNA_PREVIOUS_RESPONSE_DELAY_MAX_MS,
    YANDEX_MAIL_INLINE_AD_DNA_PREVIOUS_RESPONSE_DELAY_MIN_MS,
    YANDEX_MAIL_INLINE_AD_DNA_PREVIOUS_RESPONSE_MAX_BYTES,
    YANDEX_MAIL_INLINE_AD_DNA_PREVIOUS_RESPONSE_MIN_BYTES,
    YANDEX_MAIL_INLINE_AD_DNA_REQUEST_MAX_BYTES,
    YANDEX_MAIL_INLINE_AD_DNA_REQUEST_MIN_BYTES,
    YANDEX_MAIL_INLINE_BOOTSTRAP_MIN_BURST_FLOWS,
    YANDEX_MAIL_INLINE_BOOTSTRAP_MIN_SESSION_FLOWS,
    YANDEX_MAIL_INLINE_BOOTSTRAP_REQUEST_MAX_BYTES,
    YANDEX_MAIL_INLINE_BOOTSTRAP_REQUEST_MIN_BYTES,
    YANDEX_MAIL_INLINE_FIRST_CLIENT_PAYLOAD_MAX_BYTES,
    YANDEX_MAIL_INLINE_FIRST_CLIENT_PAYLOAD_MIN_BYTES,
    YANDEX_MAIL_INLINE_FIRST_CONTEXT_MAX_AGE_MS,
    YANDEX_MAIL_INLINE_FIRST_CONTEXT_MAX_IDLE_MS,
    YANDEX_MAIL_INLINE_FIRST_HANDSHAKE_DELAY_MAX_MS,
    YANDEX_MAIL_INLINE_FIRST_HANDSHAKE_DELAY_MIN_MS,
    YANDEX_MAIL_INLINE_FIRST_HELLO_MAX_BYTES,
    YANDEX_MAIL_INLINE_FIRST_HELLO_MIN_BYTES,
    YANDEX_MAIL_INLINE_FIRST_MIN_BURST_FLOWS,
    YANDEX_MAIL_INLINE_FIRST_MIN_FAMILY_REQUESTS,
    YANDEX_MAIL_INLINE_FIRST_MIN_SESSION_FLOWS,
    YANDEX_MAIL_INLINE_FIRST_REQUEST_DELAY_MAX_MS,
    YANDEX_MAIL_INLINE_FIRST_REQUEST_DELAY_MIN_MS,
    YANDEX_MAIL_INLINE_FIRST_REQUEST_MAX_BYTES,
    YANDEX_MAIL_INLINE_FIRST_REQUEST_MIN_BYTES,
    YANDEX_MAIL_INLINE_FIRST_RESPONSE_DELAY_MAX_MS,
    YANDEX_MAIL_INLINE_FIRST_RESPONSE_DELAY_MIN_MS,
    YANDEX_MAIL_INLINE_FIRST_SERVER_PAYLOAD_MAX_BYTES,
    YANDEX_MAIL_INLINE_FIRST_SERVER_PAYLOAD_MIN_BYTES,
    YANDEX_MAIL_INLINE_FIRST_TLS_FINGERPRINT,
    YANDEX_MAIL_INLINE_FIRST_TLS_LINEAGE_FINGERPRINT,
    YANDEX_MAIL_INLINE_FLOW_AGE_MAX_MS,
    YANDEX_MAIL_INLINE_FLOW_AGE_MIN_MS,
    YANDEX_MAIL_INLINE_MIN_CONTEXT_FLOWS,
    YANDEX_MAIL_INLINE_NEXT_REQUEST_DELAY_MAX_MS,
    YANDEX_MAIL_INLINE_NEXT_REQUEST_DELAY_MIN_MS,
    YANDEX_MAIL_INLINE_OUTLIER_MAX_FIRST_RESPONSE_DELAY_MS,
    YANDEX_MAIL_INLINE_OUTLIER_MAX_FLOW_AGE_MS,
    YANDEX_MAIL_INLINE_OUTLIER_MIN_PEERS,
    YANDEX_MAIL_INLINE_OUTLIER_PEER_REQUEST_MAX_BYTES,
    YANDEX_MAIL_INLINE_OUTLIER_PEER_REQUEST_MIN_BYTES,
    YANDEX_MAIL_INLINE_OUTLIER_PEER_RESPONSE_MAX_BYTES,
    YANDEX_MAIL_INLINE_OUTLIER_PEER_RESPONSE_MIN_BYTES,
    YANDEX_MAIL_INLINE_OUTLIER_PEER_WINDOW_SECONDS,
    YANDEX_MAIL_INLINE_OUTLIER_REQUEST_MAX_BYTES,
    YANDEX_MAIL_INLINE_OUTLIER_REQUEST_MIN_BYTES,
    YANDEX_MAIL_INLINE_OUTLIER_RESPONSE_MIN_BYTES,
    YANDEX_MAIL_INLINE_PAYLOAD_MAX_FIRST_RESPONSE_DELAY_MS,
    YANDEX_MAIL_INLINE_PAYLOAD_MAX_FLOW_AGE_MS,
    YANDEX_MAIL_INLINE_PAYLOAD_MIN_RESPONSE_RECORDS,
    YANDEX_MAIL_INLINE_PAYLOAD_REQUEST_MAX_BYTES,
    YANDEX_MAIL_INLINE_PAYLOAD_REQUEST_MIN_BYTES,
    YANDEX_MAIL_INLINE_PAYLOAD_RESPONSE_MIN_BYTES,
    YANDEX_MAIL_INLINE_PREVIOUS_REQUEST_MAX_BYTES,
    YANDEX_MAIL_INLINE_PREVIOUS_REQUEST_MIN_BYTES,
    YANDEX_MAIL_INLINE_PREVIOUS_RESPONSE_MAX_BYTES,
    YANDEX_MAIL_INLINE_PREVIOUS_RESPONSE_MIN_BYTES,
    YANDEX_MAIL_INLINE_REQUEST_MAX_BYTES,
    YANDEX_MAIL_INLINE_REQUEST_MIN_BYTES,
    YANDEX_MAIL_ROOT_BURST_MIN_FLOWS,
    YANDEX_MAIL_ROOT_BURST_WINDOW_SECONDS,
    _CompletedRootExchange,
    _ConfirmedCompactRootProfileCycle,
    _ConfirmedLargeRoot,
    _ConfirmedPairedRootConveyor,
    _ConfirmedUniformRootConveyor,
    _ConfirmedUniformRootSetupContext,
    _ConfirmedUniformRootSuccessorContext,
    _DirectionState,
    _FlowState,
    _GraphNode,
    _OpaqueQuicState,
    _PairedRootExchangeSnapshot,
    _PairedRootFirstExchangeMatch,
    _QuicCryptoState,
    _RootProfileCycleMatch,
    _TlsExchangeState,
    _Udp443State,
    _domain_family,
    _edge_score,
    _first_application_record,
    _is_root_server_name,
    _network_prefix,
    _record_delay_ms,
    _relative_distance,
    _relative_spread,
    dataclass,
    defaultdict,
    deque,
    field,
    ipaddress,
    math,
    parse_client_hello,
)

from prism_dpi.flowgraph.components.assessment import AssessmentMixin  # noqa: E402
from prism_dpi.flowgraph.components.correlation import CorrelationMixin  # noqa: E402
from prism_dpi.flowgraph.components.ingestion import IngestionMixin  # noqa: E402
from prism_dpi.flowgraph.components.tls_analysis import TlsAnalysisMixin  # noqa: E402


class FlowGraphEngine(
    IngestionMixin,
    CorrelationMixin,
    TlsAnalysisMixin,
    AssessmentMixin,
):
    """Build per-flow causal sessions and emit shadow-only assessments.

    The engine has no packet-blocking API. A candidate verdict is evidence for a
    later controlled policy, never permission to modify firewall state.
    """

    def __init__(self) -> None:
        self._flows: dict[FlowKey, _FlowState] = {}
        self._nodes: dict[str, deque[_GraphNode]] = defaultdict(deque)
        self._blocked_dns: dict[str, deque[DnsEvent]] = defaultdict(deque)
        self._confirmed_large_roots: dict[str, deque[_ConfirmedLargeRoot]] = (
            defaultdict(deque)
        )
        self._completed_root_exchanges: dict[str, deque[_CompletedRootExchange]] = (
            defaultdict(deque)
        )
        self._confirmed_uniform_root_conveyors: dict[
            str, deque[_ConfirmedUniformRootConveyor]
        ] = defaultdict(deque)
        self._confirmed_uniform_root_setup_contexts: dict[
            str, deque[_ConfirmedUniformRootSetupContext]
        ] = defaultdict(deque)
        self._confirmed_uniform_root_successor_contexts: dict[
            str, deque[_ConfirmedUniformRootSuccessorContext]
        ] = defaultdict(deque)
        self._confirmed_root_profile_cycles: dict[
            str, deque[_ConfirmedCompactRootProfileCycle]
        ] = defaultdict(deque)
        self._confirmed_paired_root_conveyors: dict[
            str, deque[_ConfirmedPairedRootConveyor]
        ] = defaultdict(deque)
        self._dns_queries: dict[tuple[str, int], tuple[float, str]] = {}
        self._quic_crypto: dict[tuple[FlowKey, int, bytes], _QuicCryptoState] = {}
        self._opaque_quic: dict[FlowKey, _OpaqueQuicState] = {}
        self._udp443: dict[FlowKey, _Udp443State] = {}
        self._next_session_id = 1
        self.packets_seen = 0
        self.tls_hellos_seen = 0
        self.quic_hellos_seen = 0
        self.opaque_quic_flows_seen = 0
        self.opaque_quic_observations_emitted = 0
        self.udp_443_flows_seen = 0
        self.udp_443_observations_emitted = 0
        self.tls_exchanges_seen = 0
        self.tls_record_sequences_seen = 0
        self.blocked_dns_seen = 0
        self.assessments_emitted = 0
        self.candidate_assessments = 0


__all__ = ["FlowGraphEngine", "TcpSequenceAssembler"]
