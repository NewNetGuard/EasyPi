"""Assessment behavior for FlowGraphEngine."""

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
    FlowAssessment,
    LARGE_ROOT_RETRY_WINDOW_SECONDS,
    LINEAGE_PAIR_WINDOW_SECONDS,
    MAX_CONFIRMED_PAIRED_ROOT_CONTEXTS_PER_CLIENT,
    MAX_CONFIRMED_PROFILE_CYCLE_CONTEXTS_PER_CLIENT,
    MAX_CONFIRMED_ROOTS_PER_CLIENT,
    MAX_CONFIRMED_SETUP_CONTEXTS_PER_CLIENT,
    MAX_CONFIRMED_SUCCESSOR_CONTEXTS_PER_CLIENT,
    MAX_CONFIRMED_UNIFORM_CONVEYORS_PER_CLIENT,
    PAIRED_ROOT_CONTEXT_WINDOW_SECONDS,
    PAIRED_ROOT_INITIAL_RESUMPTION_WINDOW_SECONDS,
    PAIRED_ROOT_LARGE_RESPONSE_MIN_BYTES,
    PAIRED_ROOT_PAIR_WINDOW_SECONDS,
    PAIRED_ROOT_REQUEST_MAX_BYTES,
    PAIRED_ROOT_REQUEST_MIN_BYTES,
    PAIRED_ROOT_RESPONSE_MIN_BYTES,
    ROOT_EXCHANGE_CONVEYOR_MIN_FLOWS,
    ROOT_EXCHANGE_RAPID_MIN_FLOWS,
    ROOT_EXCHANGE_RAPID_WINDOW_SECONDS,
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
    Verdict,
    YANDEX_MAIL_CONTEXT_MAX_AGE_SECONDS,
    YANDEX_MAIL_CONTEXT_MIN_AGE_SECONDS,
    YANDEX_MAIL_DESKTOP_MIN_CONTEXT_AGE_SECONDS,
    YANDEX_MAIL_DESKTOP_MIN_CONTEXT_FLOWS,
    YANDEX_MAIL_DZEN_MIN_BURST_FLOWS,
    YANDEX_MAIL_INLINE_BOOTSTRAP_MIN_BURST_FLOWS,
    YANDEX_MAIL_INLINE_BOOTSTRAP_MIN_SESSION_FLOWS,
    YANDEX_MAIL_INLINE_BOOTSTRAP_REQUEST_MAX_BYTES,
    YANDEX_MAIL_INLINE_BOOTSTRAP_REQUEST_MIN_BYTES,
    YANDEX_MAIL_INLINE_FIRST_CONTEXT_MAX_AGE_MS,
    YANDEX_MAIL_INLINE_FIRST_CONTEXT_MAX_IDLE_MS,
    YANDEX_MAIL_INLINE_FIRST_HANDSHAKE_DELAY_MIN_MS,
    YANDEX_MAIL_INLINE_FIRST_MIN_BURST_FLOWS,
    YANDEX_MAIL_INLINE_FIRST_MIN_FAMILY_REQUESTS,
    YANDEX_MAIL_INLINE_FIRST_MIN_SESSION_FLOWS,
    YANDEX_MAIL_INLINE_FIRST_REQUEST_DELAY_MAX_MS,
    YANDEX_MAIL_INLINE_FIRST_SERVER_PAYLOAD_MAX_BYTES,
    YANDEX_MAIL_INLINE_FIRST_SERVER_PAYLOAD_MIN_BYTES,
    YANDEX_MAIL_INLINE_MIN_CONTEXT_FLOWS,
    YANDEX_MAIL_ROOT_BURST_MIN_FLOWS,
    YANDEX_MAIL_ROOT_BURST_WINDOW_SECONDS,
    _ConfirmedCompactRootProfileCycle,
    _ConfirmedLargeRoot,
    _ConfirmedPairedRootConveyor,
    _ConfirmedUniformRootConveyor,
    _ConfirmedUniformRootSetupContext,
    _ConfirmedUniformRootSuccessorContext,
    _FlowState,
    _domain_family,
    _first_application_record,
    _is_root_server_name,
    _record_delay_ms,
    defaultdict,
)


class AssessmentMixin:
    """Internal behavior mixed into the stable engine facade."""

    def _assess(self, timestamp: float, state: _FlowState) -> FlowAssessment | None:
        hello = state.hello
        if hello is None:
            return None
        nodes = self._nodes[state.flow.client_ip]
        burst_nodes = [
            node for node in nodes if node.timestamp >= timestamp - BURST_WINDOW_SECONDS
        ]
        session_nodes = [node for node in nodes if node.session_id == state.session_id]
        same_fingerprint = sum(
            node.hello.fingerprint == hello.fingerprint for node in burst_nodes
        )
        compact_hello = hello.record_length <= 640
        root_name = _is_root_server_name(hello.server_name)
        distinct_names = len({node.hello.server_name for node in session_nodes})
        compact_root_nodes = [
            node
            for node in session_nodes
            if node.hello.record_length <= 640
            and _is_root_server_name(node.hello.server_name)
        ]
        compact_subdomain_nodes = [
            node
            for node in session_nodes
            if node.hello.record_length <= 640
            and not _is_root_server_name(node.hello.server_name)
        ]
        compact_root_counts: dict[str, int] = defaultdict(int)
        for node in compact_root_nodes:
            compact_root_counts[node.hello.server_name] += 1
        compact_root_flow_count = max(compact_root_counts.values(), default=0)
        compact_root_to_subdomain = compact_root_flow_count >= 4 and bool(
            compact_subdomain_nodes
        )
        recent_compact_root_nodes = [
            node
            for node in session_nodes
            if node.timestamp >= timestamp - ROOT_TO_SUBDOMAIN_WINDOW_SECONDS
            and node.hello.record_length <= 640
            and _is_root_server_name(node.hello.server_name)
        ]
        compact_root_to_subdomain_transition = (
            compact_hello
            and not root_name
            and len(recent_compact_root_nodes) >= 2
            and state.causal_edge_score >= 0.42
        )
        recent_prior_compact_nodes = [
            node
            for node in nodes
            if node.flow != state.flow
            and node.timestamp >= timestamp - ROOT_PROFILE_TRANSITION_WINDOW_SECONDS
            and node.hello.record_length <= 640
        ]
        prior_same_root_nodes = [
            node
            for node in recent_prior_compact_nodes
            if node.hello.server_name == hello.server_name
            and _is_root_server_name(node.hello.server_name)
        ]
        prior_root_fingerprints: dict[str, int] = defaultdict(int)
        for node in prior_same_root_nodes:
            prior_root_fingerprints[node.hello.fingerprint] += 1
        repeated_prior_root_fingerprints = {
            fingerprint
            for fingerprint, count in prior_root_fingerprints.items()
            if count >= 2
        }
        current_domain_family = _domain_family(hello.server_name)
        active_yandex_mail_states = [
            peer
            for peer in self._flows.values()
            if peer.flow != state.flow
            and peer.flow.client_ip == state.flow.client_ip
            and peer.hello is not None
            and peer.hello.server_name == "mail.yandex.ru"
            and peer.server.payload_bytes > 0
            and 0 <= timestamp - peer.last_seen <= YANDEX_MAIL_CONTEXT_MAX_AGE_SECONDS
        ]
        latest_yandex_mail_hello_at = max(
            (peer.hello_at for peer in active_yandex_mail_states),
            default=timestamp,
        )
        yandex_mail_context_age_ms = max(
            0,
            round((timestamp - latest_yandex_mail_hello_at) * 1_000),
        )
        yandex_mail_context_idle_ms = min(
            (
                max(0, round((timestamp - peer.last_seen) * 1_000))
                for peer in active_yandex_mail_states
            ),
            default=0,
        )
        yandex_mail_root_burst_nodes = [
            node
            for node in nodes
            if node.hello.server_name == "yandex.ru"
            and node.hello.record_length > 640
            and node.timestamp >= timestamp - YANDEX_MAIL_ROOT_BURST_WINDOW_SECONDS
        ]
        yandex_mail_browser_root_burst = (
            hello.server_name == "yandex.ru"
            and not compact_hello
            and root_name
            and bool(active_yandex_mail_states)
            and yandex_mail_context_age_ms
            >= round(YANDEX_MAIL_CONTEXT_MIN_AGE_SECONDS * 1_000)
            and len(yandex_mail_root_burst_nodes) >= YANDEX_MAIL_ROOT_BURST_MIN_FLOWS
        )
        yandex_mail_browser_serial_root = (
            hello.server_name == "yandex.ru"
            and not compact_hello
            and root_name
            and len(active_yandex_mail_states) >= YANDEX_MAIL_DESKTOP_MIN_CONTEXT_FLOWS
            and yandex_mail_context_age_ms
            >= round(YANDEX_MAIL_DESKTOP_MIN_CONTEXT_AGE_SECONDS * 1_000)
        )
        yandex_mail_browser_dzen_root = (
            hello.server_name == "dzen.ru"
            and not compact_hello
            and root_name
            and state.server.payload_bytes == 0
            and len(active_yandex_mail_states) >= YANDEX_MAIL_DESKTOP_MIN_CONTEXT_FLOWS
            and yandex_mail_context_age_ms
            >= round(YANDEX_MAIL_DESKTOP_MIN_CONTEXT_AGE_SECONDS * 1_000)
            and len(burst_nodes) >= YANDEX_MAIL_DZEN_MIN_BURST_FLOWS
        )
        pending_exchange = state.exchange
        previous_exchange = state.last_completed_exchange
        yandex_mail_inline_ad_request = (
            previous_exchange is not None
            and self._could_assess_yandex_mail_inline_ad_request(
                state,
                previous_exchange,
            )
            and len(active_yandex_mail_states) >= YANDEX_MAIL_INLINE_MIN_CONTEXT_FLOWS
            and yandex_mail_context_age_ms
            >= round(YANDEX_MAIL_DESKTOP_MIN_CONTEXT_AGE_SECONDS * 1_000)
        )
        yandex_mail_inline_ad_dna_request = (
            previous_exchange is not None
            and self._could_assess_yandex_mail_inline_ad_dna_request(
                state,
                previous_exchange,
            )
            and len(active_yandex_mail_states) >= 1
            and len(burst_nodes) >= 4
        )
        yandex_mail_inline_bootstrap_large_request = bool(
            hello.server_name == "mail.yandex.ru"
            and bool(hello.psk_identity_lengths)
            and previous_exchange is None
            and pending_exchange is not None
            and pending_exchange.index == 1
            and pending_exchange.request_record_count == 1
            and YANDEX_MAIL_INLINE_BOOTSTRAP_REQUEST_MIN_BYTES
            <= pending_exchange.request_bytes
            <= YANDEX_MAIL_INLINE_BOOTSTRAP_REQUEST_MAX_BYTES
            and pending_exchange.response_record_count == 0
            and YANDEX_MAIL_INLINE_FIRST_SERVER_PAYLOAD_MIN_BYTES
            <= state.server.payload_bytes
            <= YANDEX_MAIL_INLINE_FIRST_SERVER_PAYLOAD_MAX_BYTES
            and len(burst_nodes) >= YANDEX_MAIL_INLINE_BOOTSTRAP_MIN_BURST_FLOWS
            and len(session_nodes) >= YANDEX_MAIL_INLINE_BOOTSTRAP_MIN_SESSION_FLOWS
            and 30
            <= _record_delay_ms(state.client.record_times, state.hello_at)
            <= YANDEX_MAIL_INLINE_FIRST_REQUEST_DELAY_MAX_MS
            and YANDEX_MAIL_INLINE_FIRST_HANDSHAKE_DELAY_MIN_MS
            <= _record_delay_ms(state.server.record_times, state.hello_at)
            <= 130
        )
        yandex_mail_inline_small_peer_count = self._yandex_mail_inline_small_peer_count(
            timestamp, state
        )
        yandex_mail_inline_response_outlier = (
            self._could_assess_yandex_mail_inline_response_outlier(
                timestamp,
                state,
            )
            or (
                self._could_assess_yandex_mail_inline_payload_dna(
                    timestamp,
                    state,
                )
                and len(active_yandex_mail_states)
                >= YANDEX_MAIL_INLINE_MIN_CONTEXT_FLOWS
                and len(burst_nodes) >= 4
            )
        )
        prior_compact_subdomain_count = sum(
            not _is_root_server_name(node.hello.server_name)
            and _domain_family(node.hello.server_name) == current_domain_family
            for node in recent_prior_compact_nodes
        )
        repeated_setup_profile_transition = (
            hello.fingerprint not in repeated_prior_root_fingerprints
            and bool(repeated_prior_root_fingerprints)
            and prior_compact_subdomain_count >= 4
        )
        dense_single_setup_profile_transition = (
            len(prior_same_root_nodes) >= 1
            and any(
                node.hello.fingerprint != hello.fingerprint
                for node in prior_same_root_nodes
            )
            and prior_compact_subdomain_count >= DENSE_PROFILE_TRANSITION_MIN_SUBDOMAINS
        )
        compact_root_profile_transition = (
            compact_hello
            and root_name
            and (
                repeated_setup_profile_transition
                or dense_single_setup_profile_transition
            )
        )
        prior_lineage_nodes = [
            node
            for node in recent_prior_compact_nodes
            if node.timestamp >= timestamp - LINEAGE_PAIR_WINDOW_SECONDS
            and node.hello.server_name == hello.server_name
            and node.hello.lineage_fingerprint == hello.lineage_fingerprint
            and bool(node.hello.psk_identity_lengths)
        ]
        compact_root_resumption_pair = (
            compact_hello
            and root_name
            and bool(hello.psk_identity_lengths)
            and bool(prior_lineage_nodes)
        )
        root_suffix = f".{hello.server_name.rstrip('.')}"
        same_family_subdomain_names = {
            node.hello.server_name
            for node in session_nodes
            if node.flow != state.flow
            and node.timestamp >= timestamp - CAUSAL_ROOT_FANOUT_WINDOW_SECONDS
            and node.hello.server_name != hello.server_name
            and node.hello.server_name.endswith(root_suffix)
        }
        cross_session_subdomain_nodes = [
            node
            for node in nodes
            if node.flow != state.flow
            and node.timestamp >= timestamp - CROSS_SESSION_ROOT_FANOUT_WINDOW_SECONDS
            and node.hello.record_length > 640
            and not _is_root_server_name(node.hello.server_name)
            and _domain_family(node.hello.server_name) == current_domain_family
        ]
        cross_session_subdomain_names = {
            node.hello.server_name for node in cross_session_subdomain_nodes
        }
        cross_session_ids = {node.session_id for node in cross_session_subdomain_nodes}
        large_root_after_subdomain_fanout = (
            not compact_hello
            and root_name
            and state.causal_edge_score >= 0.42
            and len(same_family_subdomain_names) >= CAUSAL_ROOT_MIN_DISTINCT_SUBDOMAINS
        )
        large_root_after_cross_session_fanout = (
            not compact_hello
            and root_name
            and len(cross_session_subdomain_names)
            >= CROSS_SESSION_ROOT_MIN_DISTINCT_SUBDOMAINS
            and len(cross_session_ids) >= CROSS_SESSION_ROOT_MIN_DISTINCT_SESSIONS
        )
        confirmed_large_roots = [
            item
            for item in self._confirmed_large_roots.get(state.flow.client_ip, ())
            if item.flow != state.flow
            and timestamp - LARGE_ROOT_RETRY_WINDOW_SECONDS
            <= item.timestamp
            <= timestamp
            and item.flow.server_ip == state.flow.server_ip
            and item.flow.server_port == state.flow.server_port
            and item.server_name == hello.server_name
            and item.session_id == state.session_id
        ]
        confirmed_large_endpoint_roots = [
            item
            for item in self._confirmed_large_roots.get(state.flow.client_ip, ())
            if item.flow != state.flow
            and timestamp - DELAYED_LARGE_ROOT_RETRY_WINDOW_SECONDS
            <= item.timestamp
            <= timestamp
            and item.flow.server_ip == state.flow.server_ip
            and item.flow.server_port == state.flow.server_port
            and item.server_name == hello.server_name
        ]
        confirmed_continuation_roots = [
            item
            for item in self._confirmed_large_roots.get(state.flow.client_ip, ())
            if item.flow != state.flow
            and timestamp - CONFIRMED_ROOT_CONTINUATION_WINDOW_SECONDS
            <= item.timestamp
            <= timestamp
            and item.flow.server_ip == state.flow.server_ip
            and item.flow.server_port == state.flow.server_port
            and item.server_name == hello.server_name
        ]
        recent_family_request_states = [
            peer
            for peer in self._flows.values()
            if peer.flow != state.flow
            and peer.flow.client_ip == state.flow.client_ip
            and peer.hello is not None
            and not _is_root_server_name(peer.hello.server_name)
            and _domain_family(peer.hello.server_name) == current_domain_family
            and peer.last_completed_exchange is not None
            and timestamp - ACTIVE_FAMILY_REQUEST_WINDOW_SECONDS
            <= peer.last_completed_exchange.timestamp
            <= timestamp
        ]
        yandex_mail_inline_first_ad_request = (
            self._could_assess_yandex_mail_inline_first_ad_request(state)
            and len(active_yandex_mail_states) >= YANDEX_MAIL_INLINE_MIN_CONTEXT_FLOWS
            and 0
            <= yandex_mail_context_age_ms
            <= YANDEX_MAIL_INLINE_FIRST_CONTEXT_MAX_AGE_MS
            and 0
            <= yandex_mail_context_idle_ms
            <= YANDEX_MAIL_INLINE_FIRST_CONTEXT_MAX_IDLE_MS
            and len(burst_nodes) >= YANDEX_MAIL_INLINE_FIRST_MIN_BURST_FLOWS
            and len(session_nodes) >= YANDEX_MAIL_INLINE_FIRST_MIN_SESSION_FLOWS
            and len(recent_family_request_states)
            >= YANDEX_MAIL_INLINE_FIRST_MIN_FAMILY_REQUESTS
        )
        compact_root_causal_retry = (
            compact_hello
            and root_name
            and state.causal_edge_score >= 0.42
            and len(same_family_subdomain_names) >= CAUSAL_ROOT_MIN_DISTINCT_SUBDOMAINS
            and bool(confirmed_large_roots)
        )
        large_root_causal_retry = (
            not compact_hello and root_name and bool(confirmed_large_endpoint_roots)
        )
        large_root_active_family_continuation = (
            not compact_hello
            and root_name
            and bool(confirmed_continuation_roots)
            and bool(recent_family_request_states)
        )
        (
            uniform_root_exchange_count,
            uniform_root_exchange_window_ms,
            uniform_root_request_spread,
            uniform_root_response_spread,
        ) = self._uniform_root_exchange_cluster(timestamp, state)
        sustained_uniform_root_exchange_conveyor = (
            uniform_root_exchange_count >= ROOT_EXCHANGE_CONVEYOR_MIN_FLOWS
        )
        rapid_uniform_root_exchange_conveyor = (
            uniform_root_exchange_count >= ROOT_EXCHANGE_RAPID_MIN_FLOWS
            and uniform_root_exchange_window_ms
            <= round(ROOT_EXCHANGE_RAPID_WINDOW_SECONDS * 1_000)
        )
        uniform_root_exchange_conveyor = (
            sustained_uniform_root_exchange_conveyor
            or rapid_uniform_root_exchange_conveyor
        )
        uniform_root_endpoint_peers = [
            peer
            for peer in self._flows.values()
            if peer.flow != state.flow
            and peer.flow.client_ip == state.flow.client_ip
            and peer.flow.server_ip == state.flow.server_ip
            and peer.flow.server_port == state.flow.server_port
            and peer.hello is not None
            and peer.hello.record_length <= 640
            and _is_root_server_name(peer.hello.server_name)
            and peer.hello_at >= timestamp - UNIFORM_ROOT_MULTIPLEX_WINDOW_SECONDS
        ]
        uniform_root_endpoint_names = {
            hello.server_name,
            *(peer.hello.server_name for peer in uniform_root_endpoint_peers),
        }
        uniform_root_endpoint_peer_count = len(uniform_root_endpoint_peers) + 1
        uniform_root_endpoint_seed_exchanges = [
            item
            for item in self._completed_root_exchanges.get(state.flow.client_ip, ())
            if item.flow != state.flow
            and timestamp - UNIFORM_ROOT_MULTIPLEX_WINDOW_SECONDS
            <= item.timestamp
            <= timestamp
            and item.flow.server_ip == state.flow.server_ip
            and item.flow.server_port == state.flow.server_port
        ]
        latest_uniform_root_endpoint_seed = max(
            uniform_root_endpoint_seed_exchanges,
            key=lambda item: item.timestamp,
            default=None,
        )
        uniform_root_endpoint_seed_age_ms = (
            max(
                0,
                round(
                    (timestamp - latest_uniform_root_endpoint_seed.timestamp) * 1_000
                ),
            )
            if latest_uniform_root_endpoint_seed is not None
            else 0
        )
        uniform_root_endpoint_multiplex = (
            compact_hello
            and root_name
            and len(uniform_root_endpoint_seed_exchanges)
            >= UNIFORM_ROOT_MULTIPLEX_MIN_EXCHANGES
            and uniform_root_endpoint_seed_age_ms
            <= round(UNIFORM_ROOT_MULTIPLEX_WINDOW_SECONDS * 1_000)
            and uniform_root_endpoint_peer_count
            >= UNIFORM_ROOT_MULTIPLEX_MIN_ENDPOINT_FLOWS
            and len(uniform_root_endpoint_names)
            >= UNIFORM_ROOT_MULTIPLEX_MIN_DISTINCT_NAMES
        )
        confirmed_uniform_conveyors = [
            item
            for item in self._confirmed_uniform_root_conveyors.get(
                state.flow.client_ip, ()
            )
            if item.flow != state.flow
            and timestamp - UNIFORM_ROOT_COMPANION_WINDOW_SECONDS
            <= item.timestamp
            <= timestamp
            and item.flow.server_ip == state.flow.server_ip
            and item.flow.server_port == state.flow.server_port
        ]
        closest_uniform_conveyor = max(
            confirmed_uniform_conveyors,
            key=lambda item: item.timestamp,
            default=None,
        )
        uniform_root_companion_confirmation_age_ms = (
            max(0, round((timestamp - closest_uniform_conveyor.timestamp) * 1_000))
            if closest_uniform_conveyor is not None
            else 0
        )
        uniform_root_companion_hello_delta_ms = (
            abs(round((state.hello_at - closest_uniform_conveyor.timestamp) * 1_000))
            if closest_uniform_conveyor is not None
            else 0
        )
        uniform_root_endpoint_companion = (
            compact_hello
            and root_name
            and bool(confirmed_uniform_conveyors)
            and uniform_root_companion_hello_delta_ms
            <= round(UNIFORM_ROOT_COMPANION_HELLO_DELTA_SECONDS * 1_000)
        )
        confirmed_cross_endpoint_conveyors = [
            item
            for item in self._confirmed_uniform_root_conveyors.get(
                state.flow.client_ip, ()
            )
            if item.flow != state.flow
            and timestamp - UNIFORM_ROOT_CROSS_ENDPOINT_WINDOW_SECONDS
            <= item.timestamp
            <= timestamp
            and item.flow.server_ip != state.flow.server_ip
            and item.flow.server_port == state.flow.server_port
            and item.tls_fingerprint == hello.fingerprint
            and item.tls_lineage_fingerprint == hello.lineage_fingerprint
        ]
        closest_cross_endpoint_conveyor = max(
            confirmed_cross_endpoint_conveyors,
            key=lambda item: item.timestamp,
            default=None,
        )
        uniform_root_cross_confirmation_age_ms = (
            max(
                0,
                round((timestamp - closest_cross_endpoint_conveyor.timestamp) * 1_000),
            )
            if closest_cross_endpoint_conveyor is not None
            else 0
        )
        uniform_root_cross_hello_delta_ms = (
            abs(
                round(
                    (state.hello_at - closest_cross_endpoint_conveyor.timestamp) * 1_000
                )
            )
            if closest_cross_endpoint_conveyor is not None
            else 0
        )
        uniform_root_cross_endpoint_companion = (
            compact_hello
            and root_name
            and bool(confirmed_cross_endpoint_conveyors)
            and uniform_root_cross_hello_delta_ms
            <= round(UNIFORM_ROOT_CROSS_ENDPOINT_HELLO_DELTA_SECONDS * 1_000)
        )
        confirmed_setup_conveyors = [
            item
            for item in self._confirmed_uniform_root_conveyors.get(
                state.flow.client_ip, ()
            )
            if item.flow != state.flow
            and timestamp - UNIFORM_ROOT_SETUP_WINDOW_SECONDS
            <= item.timestamp
            <= timestamp
            and item.flow.server_ip != state.flow.server_ip
            and item.flow.server_port == state.flow.server_port
            and item.server_name != hello.server_name
            and item.tls_fingerprint != hello.fingerprint
        ]
        closest_setup_conveyor = max(
            confirmed_setup_conveyors,
            key=lambda item: item.timestamp,
            default=None,
        )
        uniform_root_setup_confirmation_age_ms = (
            max(0, round((timestamp - closest_setup_conveyor.timestamp) * 1_000))
            if closest_setup_conveyor is not None
            else 0
        )
        uniform_root_setup_hello_age_ms = max(
            0, round((timestamp - state.hello_at) * 1_000)
        )
        uniform_root_setup_peers = [
            peer
            for peer in self._flows.values()
            if peer.flow.client_ip == state.flow.client_ip
            and peer.flow.server_ip == state.flow.server_ip
            and peer.flow.server_port == state.flow.server_port
            and peer.hello is not None
            and peer.hello.server_name == hello.server_name
            and peer.hello.fingerprint == hello.fingerprint
            and peer.hello.lineage_fingerprint == hello.lineage_fingerprint
            and peer.hello.record_length <= 640
            and not peer.hello.psk_identity_lengths
            and 0 <= timestamp - peer.hello_at <= UNIFORM_ROOT_SETUP_WINDOW_SECONDS
        ]
        uniform_root_setup_companion = (
            compact_hello
            and root_name
            and not hello.psk_identity_lengths
            and bool(confirmed_setup_conveyors)
            and len(uniform_root_setup_peers) >= UNIFORM_ROOT_SETUP_MIN_FLOWS
            and uniform_root_setup_hello_age_ms
            <= round(UNIFORM_ROOT_SETUP_WINDOW_SECONDS * 1_000)
        )
        eligible_setup_contexts = [
            item
            for item in self._confirmed_uniform_root_setup_contexts.get(
                state.flow.client_ip, ()
            )
            if timestamp - UNIFORM_ROOT_SETUP_CONTEXT_WINDOW_SECONDS
            <= item.timestamp
            <= timestamp
            and item.flow.server_ip == state.flow.server_ip
            and item.flow.server_port == state.flow.server_port
            and item.server_name == hello.server_name
            and item.tls_fingerprint != hello.fingerprint
        ]
        setup_context_groups: dict[
            tuple[str, str], list[_ConfirmedUniformRootSetupContext]
        ] = defaultdict(list)
        for item in eligible_setup_contexts:
            setup_context_groups[
                (item.tls_fingerprint, item.tls_lineage_fingerprint)
            ].append(item)
        confirmed_setup_contexts = max(
            setup_context_groups.values(),
            key=len,
            default=[],
        )
        closest_setup_context = max(
            confirmed_setup_contexts,
            key=lambda item: item.timestamp,
            default=None,
        )
        uniform_root_setup_context_age_ms = (
            max(0, round((timestamp - closest_setup_context.timestamp) * 1_000))
            if closest_setup_context is not None
            else 0
        )
        setup_resumption_peers = [
            peer
            for peer in self._flows.values()
            if peer.flow.client_ip == state.flow.client_ip
            and peer.flow.server_ip == state.flow.server_ip
            and peer.flow.server_port == state.flow.server_port
            and peer.hello is not None
            and peer.hello.server_name == hello.server_name
            and peer.hello.record_length <= 640
            and bool(peer.hello.psk_identity_lengths)
            and peer.hello.fingerprint == hello.fingerprint
            and peer.hello.lineage_fingerprint == hello.lineage_fingerprint
            and peer.server.payload_bytes == 0
            and abs(peer.hello_at - state.hello_at)
            <= SETUP_RESUMPTION_PAIR_WINDOW_SECONDS
        ]
        setup_resumption_hello_delta_ms = (
            max(
                0,
                round(
                    (
                        max(peer.hello_at for peer in setup_resumption_peers)
                        - min(peer.hello_at for peer in setup_resumption_peers)
                    )
                    * 1_000
                ),
            )
            if setup_resumption_peers
            else 0
        )
        uniform_root_setup_resumption_descendant = (
            not state.setup_resumption_descendant_emitted
            and compact_hello
            and root_name
            and bool(hello.psk_identity_lengths)
            and len(confirmed_setup_contexts) >= UNIFORM_ROOT_SETUP_MIN_FLOWS
            and len(setup_resumption_peers) >= SETUP_RESUMPTION_MIN_FLOWS
            and setup_resumption_hello_delta_ms
            <= round(SETUP_RESUMPTION_PAIR_WINDOW_SECONDS * 1_000)
            and state.server.payload_bytes == 0
        )
        confirmed_successor_conveyors = [
            item
            for item in self._confirmed_uniform_root_conveyors.get(
                state.flow.client_ip, ()
            )
            if item.flow != state.flow
            and state.hello_at - UNIFORM_ROOT_SUCCESSOR_WINDOW_SECONDS
            <= item.timestamp
            <= state.hello_at
            and item.flow.server_ip == state.flow.server_ip
            and item.flow.server_port == state.flow.server_port
            and item.server_name != hello.server_name
            and item.tls_fingerprint != hello.fingerprint
        ]
        closest_successor_conveyor = max(
            confirmed_successor_conveyors,
            key=lambda item: item.timestamp,
            default=None,
        )
        uniform_root_successor_confirmation_age_ms = (
            max(
                0,
                round((state.hello_at - closest_successor_conveyor.timestamp) * 1_000),
            )
            if closest_successor_conveyor is not None
            else 0
        )
        successor_exchanges = list(state.completed_exchanges)[
            -SUCCESSOR_EXCHANGE_COUNT:
        ]
        successor_exchange_window_ms = (
            max(
                0,
                round(
                    (
                        successor_exchanges[-1].timestamp
                        - successor_exchanges[0].timestamp
                    )
                    * 1_000
                ),
            )
            if len(successor_exchanges) == SUCCESSOR_EXCHANGE_COUNT
            else 0
        )
        successor_requests = [item.request_bytes for item in successor_exchanges]
        successor_responses = [item.response_bytes for item in successor_exchanges]
        successor_request_min_bytes = min(successor_requests, default=0)
        successor_request_max_bytes = max(successor_requests, default=0)
        successor_small_response_count = sum(
            SUCCESSOR_SMALL_RESPONSE_MIN_BYTES
            <= value
            <= SUCCESSOR_SMALL_RESPONSE_MAX_BYTES
            for value in successor_responses
        )
        successor_large_response_count = sum(
            value >= SUCCESSOR_LARGE_RESPONSE_MIN_BYTES for value in successor_responses
        )
        uniform_root_successor_exchange_conveyor = (
            not state.successor_exchange_conveyor_emitted
            and compact_hello
            and root_name
            and not hello.psk_identity_lengths
            and bool(confirmed_successor_conveyors)
            and len(successor_exchanges) == SUCCESSOR_EXCHANGE_COUNT
            and all(
                item.completion_reason == "next_request" for item in successor_exchanges
            )
            and successor_exchange_window_ms
            <= round(SUCCESSOR_EXCHANGE_WINDOW_SECONDS * 1_000)
            and successor_request_min_bytes >= SUCCESSOR_REQUEST_MIN_BYTES
            and successor_request_max_bytes <= SUCCESSOR_REQUEST_MAX_BYTES
            and successor_small_response_count >= SUCCESSOR_SMALL_RESPONSE_MIN_COUNT
            and successor_large_response_count >= SUCCESSOR_LARGE_RESPONSE_MIN_COUNT
        )
        eligible_successor_contexts = [
            item
            for item in self._confirmed_uniform_root_successor_contexts.get(
                state.flow.client_ip, ()
            )
            if item.flow != state.flow
            and timestamp - SUCCESSOR_RESUMPTION_CONTEXT_WINDOW_SECONDS
            <= item.timestamp
            <= timestamp
            and item.flow.server_ip != state.flow.server_ip
            and item.flow.server_port == state.flow.server_port
            and item.server_name == hello.server_name
            and item.tls_fingerprint != hello.fingerprint
            and item.tls_lineage_fingerprint != hello.lineage_fingerprint
        ]
        successor_resumption_context = max(
            eligible_successor_contexts,
            key=lambda item: item.timestamp,
            default=None,
        )
        successor_resumption_context_age_ms = (
            max(
                0,
                round((timestamp - successor_resumption_context.timestamp) * 1_000),
            )
            if successor_resumption_context is not None
            else 0
        )
        successor_resumption_peers = [
            peer
            for peer in self._flows.values()
            if successor_resumption_context is not None
            and peer.flow.client_ip == state.flow.client_ip
            and peer.flow.server_ip != successor_resumption_context.flow.server_ip
            and peer.flow.server_port == state.flow.server_port
            and peer.hello is not None
            and peer.hello.server_name == hello.server_name
            and peer.hello.record_length <= 640
            and bool(peer.hello.psk_identity_lengths)
            and peer.hello.fingerprint == hello.fingerprint
            and peer.hello.lineage_fingerprint == hello.lineage_fingerprint
            and peer.server.payload_bytes == 0
            and successor_resumption_context.timestamp <= peer.hello_at
            and peer.hello_at
            <= successor_resumption_context.timestamp
            + SUCCESSOR_RESUMPTION_CONTEXT_WINDOW_SECONDS
            and abs(peer.hello_at - state.hello_at)
            <= SUCCESSOR_RESUMPTION_PAIR_WINDOW_SECONDS
        ]
        successor_resumption_pair_peers: list[_FlowState] = []
        if state in successor_resumption_peers:
            companion = min(
                (
                    peer
                    for peer in successor_resumption_peers
                    if peer.flow != state.flow
                    and peer.flow.server_ip != state.flow.server_ip
                ),
                key=lambda peer: abs(peer.hello_at - state.hello_at),
                default=None,
            )
            if companion is not None:
                successor_resumption_pair_peers = [state, companion]
        successor_resumption_pair_delta_ms = (
            max(
                0,
                round(
                    (
                        max(peer.hello_at for peer in successor_resumption_pair_peers)
                        - min(peer.hello_at for peer in successor_resumption_pair_peers)
                    )
                    * 1_000
                ),
            )
            if successor_resumption_pair_peers
            else 0
        )
        successor_resumption_pair_was_established = bool(
            successor_resumption_context
            and successor_resumption_context.resumed_pair_flows
        )
        if (
            successor_resumption_context is not None
            and not successor_resumption_pair_was_established
            and len(successor_resumption_pair_peers) >= SUCCESSOR_RESUMPTION_MIN_FLOWS
            and successor_resumption_pair_delta_ms
            <= round(SUCCESSOR_RESUMPTION_PAIR_WINDOW_SECONDS * 1_000)
        ):
            successor_resumption_context.resumed_fingerprint = hello.fingerprint
            successor_resumption_context.resumed_lineage_fingerprint = (
                hello.lineage_fingerprint
            )
            successor_resumption_context.resumed_pair_flows = tuple(
                peer.flow for peer in successor_resumption_pair_peers
            )
            successor_resumption_context.resumed_distinct_endpoint_count = 2
            successor_resumption_context.resumed_pair_hello_delta_ms = (
                successor_resumption_pair_delta_ms
            )
        successor_resumption_pair_established = bool(
            successor_resumption_context
            and successor_resumption_context.resumed_pair_flows
        )
        successor_resumption_fingerprint_match = bool(
            successor_resumption_context
            and successor_resumption_context.resumed_fingerprint == hello.fingerprint
        )
        successor_resumption_lineage_match = bool(
            successor_resumption_context
            and successor_resumption_context.resumed_lineage_fingerprint
            == hello.lineage_fingerprint
        )
        successor_resumption_context_continuation = bool(
            successor_resumption_pair_was_established
            and successor_resumption_context
            and state.flow not in successor_resumption_context.resumed_pair_flows
        )
        uniform_root_successor_resumption_descendant = (
            not state.successor_resumption_descendant_emitted
            and compact_hello
            and root_name
            and bool(hello.psk_identity_lengths)
            and successor_resumption_pair_established
            and successor_resumption_fingerprint_match
            and successor_resumption_lineage_match
            and state.server.payload_bytes == 0
        )
        profile_cycle = self._root_profile_cycle(state)
        compact_root_profile_cycle_conveyor = (
            not state.profile_cycle_conveyor_emitted
            and compact_hello
            and root_name
            and not hello.psk_identity_lengths
            and profile_cycle.prior_setup_count >= 1
            and profile_cycle.resumed_pair_count >= ROOT_PROFILE_CYCLE_MIN_FLOWS
            and profile_cycle.returned_setup_pair_count >= ROOT_PROFILE_CYCLE_MIN_FLOWS
            and 0
            <= profile_cycle.setup_to_resumed_ms
            <= round(ROOT_PROFILE_CYCLE_PHASE_WINDOW_SECONDS * 1_000)
            and 0
            <= profile_cycle.resumed_to_return_ms
            <= round(ROOT_PROFILE_CYCLE_PHASE_WINDOW_SECONDS * 1_000)
            and profile_cycle.resumed_pair_delta_ms
            <= round(ROOT_PROFILE_CYCLE_PAIR_WINDOW_SECONDS * 1_000)
            and profile_cycle.returned_setup_pair_delta_ms
            <= round(ROOT_PROFILE_CYCLE_PAIR_WINDOW_SECONDS * 1_000)
            and bool(profile_cycle.resumed_fingerprint)
            and bool(profile_cycle.resumed_lineage_fingerprint)
            and state.server.payload_bytes == 0
        )
        eligible_profile_cycle_contexts = [
            item
            for item in self._confirmed_root_profile_cycles.get(
                state.flow.client_ip, ()
            )
            if item.flow != state.flow
            and timestamp - ROOT_PROFILE_CYCLE_CONTEXT_WINDOW_SECONDS
            <= item.timestamp
            <= timestamp
            and item.flow.server_ip == state.flow.server_ip
            and item.flow.server_port == state.flow.server_port
            and item.server_name == hello.server_name
            and item.setup_fingerprint != hello.fingerprint
            and item.setup_lineage_fingerprint != hello.lineage_fingerprint
            and item.resumed_fingerprint == hello.fingerprint
            and item.resumed_lineage_fingerprint == hello.lineage_fingerprint
        ]
        closest_profile_cycle_context = max(
            eligible_profile_cycle_contexts,
            key=lambda item: item.timestamp,
            default=None,
        )
        profile_cycle_context_age_ms = (
            max(
                0,
                round((timestamp - closest_profile_cycle_context.timestamp) * 1_000),
            )
            if closest_profile_cycle_context is not None
            else 0
        )
        compact_root_profile_cycle_resumption_descendant = (
            not state.profile_cycle_resumption_descendant_emitted
            and compact_hello
            and root_name
            and bool(hello.psk_identity_lengths)
            and bool(eligible_profile_cycle_contexts)
            and state.server.payload_bytes == 0
        )
        paired_root = self._paired_root_first_exchange(state)
        paired_root_first_exchange_conveyor = (
            not state.paired_root_conveyor_emitted
            and compact_hello
            and root_name
            and not hello.psk_identity_lengths
            and paired_root.flow_count == 2
            and paired_root.hello_delta_ms
            <= round(PAIRED_ROOT_PAIR_WINDOW_SECONDS * 1_000)
            and paired_root.exchange_delta_ms
            <= round(PAIRED_ROOT_PAIR_WINDOW_SECONDS * 1_000)
            and paired_root.request_min_bytes >= PAIRED_ROOT_REQUEST_MIN_BYTES
            and paired_root.request_max_bytes <= PAIRED_ROOT_REQUEST_MAX_BYTES
            and paired_root.response_min_bytes >= PAIRED_ROOT_RESPONSE_MIN_BYTES
            and paired_root.response_max_bytes >= PAIRED_ROOT_LARGE_RESPONSE_MIN_BYTES
        )
        paired_root_resumption_shape = (
            compact_hello and root_name and bool(hello.psk_identity_lengths)
        )
        paired_root_setup_contexts = [
            item
            for item in self._confirmed_paired_root_conveyors.get(
                state.flow.client_ip, ()
            )
            if item.flow != state.flow
            and timestamp - PAIRED_ROOT_CONTEXT_WINDOW_SECONDS
            <= item.active_at
            <= timestamp
            and item.flow.server_port == state.flow.server_port
            and item.server_name == hello.server_name
            and item.setup_fingerprint == hello.fingerprint
            and item.setup_lineage_fingerprint == hello.lineage_fingerprint
        ]
        closest_paired_root_setup_context = max(
            paired_root_setup_contexts,
            key=lambda item: item.active_at,
            default=None,
        )
        paired_root_setup_context_origin_age_ms = (
            max(
                0,
                round(
                    (timestamp - closest_paired_root_setup_context.timestamp) * 1_000
                ),
            )
            if closest_paired_root_setup_context is not None
            else 0
        )
        paired_root_setup_context_age_ms = (
            max(
                0,
                round(
                    (timestamp - closest_paired_root_setup_context.active_at) * 1_000
                ),
            )
            if closest_paired_root_setup_context is not None
            else 0
        )
        paired_root_setup_descendant = (
            not state.paired_root_setup_descendant_emitted
            and compact_hello
            and root_name
            and not hello.psk_identity_lengths
            and bool(closest_paired_root_setup_context)
            and state.server.payload_bytes == 0
        )
        recent_paired_root_contexts = [
            item
            for item in (
                self._confirmed_paired_root_conveyors.get(state.flow.client_ip, ())
                if paired_root_resumption_shape
                else ()
            )
            if item.flow != state.flow
            and timestamp - PAIRED_ROOT_CONTEXT_WINDOW_SECONDS
            <= item.active_at
            <= timestamp
            and item.flow.server_port == state.flow.server_port
            and item.server_name == hello.server_name
            and item.setup_fingerprint != hello.fingerprint
            and item.setup_lineage_fingerprint != hello.lineage_fingerprint
        ]
        established_paired_root_contexts = [
            item
            for item in recent_paired_root_contexts
            if item.resumed_fingerprint == hello.fingerprint
            and item.resumed_lineage_fingerprint == hello.lineage_fingerprint
        ]
        initial_paired_root_contexts = [
            item
            for item in recent_paired_root_contexts
            if not item.resumed_fingerprint
            and not item.resumed_lineage_fingerprint
            and (
                item.setup_distinct_endpoint_count == 2
                or item.flow.server_ip == state.flow.server_ip
            )
            and timestamp - PAIRED_ROOT_INITIAL_RESUMPTION_WINDOW_SECONDS
            <= item.timestamp
        ]
        closest_paired_root_context = max(
            established_paired_root_contexts or initial_paired_root_contexts,
            key=lambda item: item.active_at,
            default=None,
        )
        paired_root_resumption_initial = bool(
            closest_paired_root_context
            and not closest_paired_root_context.resumed_fingerprint
        )
        if paired_root_resumption_initial and closest_paired_root_context is not None:
            closest_paired_root_context.resumed_fingerprint = hello.fingerprint
            closest_paired_root_context.resumed_lineage_fingerprint = (
                hello.lineage_fingerprint
            )
        paired_root_context_age_ms = (
            max(
                0,
                round((timestamp - closest_paired_root_context.active_at) * 1_000),
            )
            if closest_paired_root_context is not None
            else 0
        )
        paired_root_context_origin_age_ms = (
            max(
                0,
                round((timestamp - closest_paired_root_context.timestamp) * 1_000),
            )
            if closest_paired_root_context is not None
            else 0
        )
        paired_root_resumption_fingerprint_match = bool(
            closest_paired_root_context
            and closest_paired_root_context.resumed_fingerprint == hello.fingerprint
        )
        paired_root_resumption_lineage_match = bool(
            closest_paired_root_context
            and closest_paired_root_context.resumed_lineage_fingerprint
            == hello.lineage_fingerprint
        )
        paired_root_resumption_descendant = (
            not state.paired_root_resumption_descendant_emitted
            and paired_root_resumption_shape
            and bool(closest_paired_root_context)
            and paired_root_resumption_fingerprint_match
            and paired_root_resumption_lineage_match
            and state.server.payload_bytes == 0
        )
        matched_paired_root_context = (
            closest_paired_root_setup_context
            if paired_root_setup_descendant
            else closest_paired_root_context
            if paired_root_resumption_descendant
            else None
        )
        if matched_paired_root_context is not None:
            matched_paired_root_context.descendant_count += 1
            matched_paired_root_context.last_descendant_at = timestamp
        (
            mirrored_root_setup_pair_count,
            mirrored_root_resumed_pair_count,
            mirrored_root_distinct_name_count,
            mirrored_root_distinct_endpoint_count,
            mirrored_root_setup_delta_ms,
            mirrored_root_resumed_delta_ms,
            mirrored_root_transition_window_ms,
            mirrored_root_profile_changed,
        ) = self._mirrored_root_transition(timestamp, state)
        mirrored_root_transition = (
            mirrored_root_setup_pair_count >= 2
            and mirrored_root_resumed_pair_count >= 2
            and mirrored_root_distinct_name_count >= 2
            and mirrored_root_distinct_endpoint_count >= 2
            and mirrored_root_profile_changed
        )
        if uniform_root_exchange_conveyor or uniform_root_endpoint_multiplex:
            conveyors = self._confirmed_uniform_root_conveyors[state.flow.client_ip]
            if not any(item.flow == state.flow for item in conveyors):
                conveyors.append(
                    _ConfirmedUniformRootConveyor(
                        timestamp=timestamp,
                        flow=state.flow,
                        server_name=hello.server_name,
                        tls_fingerprint=hello.fingerprint,
                        tls_lineage_fingerprint=hello.lineage_fingerprint,
                    )
                )
                while len(conveyors) > MAX_CONFIRMED_UNIFORM_CONVEYORS_PER_CLIENT:
                    conveyors.popleft()
        if uniform_root_setup_companion:
            contexts = self._confirmed_uniform_root_setup_contexts[state.flow.client_ip]
            if not any(item.flow == state.flow for item in contexts):
                contexts.append(
                    _ConfirmedUniformRootSetupContext(
                        timestamp=timestamp,
                        flow=state.flow,
                        server_name=hello.server_name,
                        tls_fingerprint=hello.fingerprint,
                        tls_lineage_fingerprint=hello.lineage_fingerprint,
                    )
                )
                while len(contexts) > MAX_CONFIRMED_SETUP_CONTEXTS_PER_CLIENT:
                    contexts.popleft()
        if uniform_root_successor_exchange_conveyor:
            contexts = self._confirmed_uniform_root_successor_contexts[
                state.flow.client_ip
            ]
            if not any(item.flow == state.flow for item in contexts):
                contexts.append(
                    _ConfirmedUniformRootSuccessorContext(
                        timestamp=timestamp,
                        flow=state.flow,
                        server_name=hello.server_name,
                        tls_fingerprint=hello.fingerprint,
                        tls_lineage_fingerprint=hello.lineage_fingerprint,
                    )
                )
                while len(contexts) > MAX_CONFIRMED_SUCCESSOR_CONTEXTS_PER_CLIENT:
                    contexts.popleft()
        if compact_root_profile_cycle_conveyor:
            contexts = self._confirmed_root_profile_cycles[state.flow.client_ip]
            if not any(
                item.flow.server_ip == state.flow.server_ip
                and item.flow.server_port == state.flow.server_port
                and item.server_name == hello.server_name
                and item.setup_fingerprint == hello.fingerprint
                and item.setup_lineage_fingerprint == hello.lineage_fingerprint
                and item.resumed_fingerprint == profile_cycle.resumed_fingerprint
                and item.resumed_lineage_fingerprint
                == profile_cycle.resumed_lineage_fingerprint
                and abs(item.timestamp - timestamp)
                <= ROOT_PROFILE_CYCLE_PAIR_WINDOW_SECONDS
                for item in contexts
            ):
                contexts.append(
                    _ConfirmedCompactRootProfileCycle(
                        timestamp=timestamp,
                        flow=state.flow,
                        server_name=hello.server_name,
                        setup_fingerprint=hello.fingerprint,
                        setup_lineage_fingerprint=(hello.lineage_fingerprint),
                        resumed_fingerprint=profile_cycle.resumed_fingerprint,
                        resumed_lineage_fingerprint=(
                            profile_cycle.resumed_lineage_fingerprint
                        ),
                    )
                )
                while len(contexts) > MAX_CONFIRMED_PROFILE_CYCLE_CONTEXTS_PER_CLIENT:
                    contexts.popleft()
        if paired_root_first_exchange_conveyor:
            contexts = self._confirmed_paired_root_conveyors[state.flow.client_ip]
            if not any(
                item.flow.server_ip == state.flow.server_ip
                and item.flow.server_port == state.flow.server_port
                and item.server_name == hello.server_name
                and item.setup_fingerprint == hello.fingerprint
                and item.setup_lineage_fingerprint == hello.lineage_fingerprint
                and abs(item.timestamp - timestamp) <= PAIRED_ROOT_PAIR_WINDOW_SECONDS
                for item in contexts
            ):
                contexts.append(
                    _ConfirmedPairedRootConveyor(
                        timestamp=timestamp,
                        flow=state.flow,
                        server_name=hello.server_name,
                        setup_fingerprint=hello.fingerprint,
                        setup_lineage_fingerprint=(hello.lineage_fingerprint),
                        setup_distinct_endpoint_count=(
                            paired_root.distinct_endpoint_count
                        ),
                    )
                )
                while len(contexts) > MAX_CONFIRMED_PAIRED_ROOT_CONTEXTS_PER_CLIENT:
                    contexts.popleft()
        if large_root_after_subdomain_fanout or large_root_after_cross_session_fanout:
            roots = self._confirmed_large_roots[state.flow.client_ip]
            if not any(item.flow == state.flow for item in roots):
                roots.append(
                    _ConfirmedLargeRoot(
                        timestamp=timestamp,
                        flow=state.flow,
                        server_name=hello.server_name,
                        session_id=state.session_id,
                    )
                )
                while len(roots) > MAX_CONFIRMED_ROOTS_PER_CLIENT:
                    roots.popleft()
        denied = [
            event
            for event in self._blocked_dns.get(state.flow.client_ip, ())
            if timestamp - DNS_EVIDENCE_SECONDS <= event.timestamp <= timestamp
        ]
        first_request = _first_application_record(state.client.record_lengths)
        first_response = _first_application_record(state.server.record_lengths)

        confidence, verdict, evidence = self._score_assessment(locals())
        return self._finalize_assessment(locals(), timestamp, state)

    def _score_assessment(
        self, values: dict[str, object]
    ) -> tuple[float, Verdict, list[str]]:
        score = 0.0
        evidence: list[str] = []
        if values["compact_hello"]:
            score += 0.2
            evidence.append("compact_client_hello")
        else:
            score -= 0.28
            evidence.append("large_client_hello_safety")
        if values["root_name"] and values["compact_hello"]:
            score += 0.08
            evidence.append("compact_root_sni")
        if values["same_fingerprint"] >= 2:
            score += 0.15
            evidence.append("repeated_tls_fingerprint")
        if len(values["session_nodes"]) >= 4:
            score += 0.12
            evidence.append("causal_session_fanout")
        if len(values["burst_nodes"]) >= 5:
            score += 0.1
            evidence.append("dense_connection_burst")
        if values["compact_root_to_subdomain_transition"]:
            score += 0.4
            evidence.append("compact_root_to_subdomain_causal")
        elif values["compact_root_to_subdomain"]:
            score += 0.1
            evidence.append("compact_root_subdomain_fanout")
        if values["compact_root_profile_transition"]:
            score += 0.45
            evidence.append("compact_root_profile_transition_causal")
        if values["hello"].psk_identity_lengths:
            evidence.append("tls_session_resumption")
        if values["compact_root_resumption_pair"]:
            score += 0.55
            evidence.append("compact_root_resumption_pair_causal")
        if values["large_root_after_subdomain_fanout"]:
            evidence.append("large_root_after_subdomain_fanout_causal")
        if values["large_root_after_cross_session_fanout"]:
            evidence.append("large_root_after_cross_session_fanout_causal")
        if values["compact_root_causal_retry"]:
            evidence.append("compact_root_retry_after_large_causal_root")
        if values["large_root_causal_retry"]:
            evidence.append("large_root_retry_after_causal_root")
        if values["large_root_active_family_continuation"]:
            evidence.append("large_root_after_active_family_request")
        if values["uniform_root_exchange_conveyor"]:
            evidence.append("uniform_root_exchange_conveyor")
        if values["uniform_root_endpoint_multiplex"]:
            evidence.append("uniform_root_endpoint_multiplex")
        if values["uniform_root_endpoint_companion"]:
            evidence.append("uniform_root_endpoint_companion")
        if values["uniform_root_cross_endpoint_companion"]:
            evidence.append("uniform_root_cross_endpoint_companion")
        if values["uniform_root_setup_companion"]:
            evidence.append("uniform_root_setup_companion")
        if values["uniform_root_setup_resumption_descendant"]:
            evidence.append("uniform_root_setup_resumption_descendant")
        if values["uniform_root_successor_exchange_conveyor"]:
            evidence.append("uniform_root_successor_exchange_conveyor")
        if values["uniform_root_successor_resumption_descendant"]:
            evidence.append("uniform_root_successor_resumption_descendant")
        if values["compact_root_profile_cycle_conveyor"]:
            evidence.append("compact_root_profile_cycle_conveyor")
        if values["compact_root_profile_cycle_resumption_descendant"]:
            evidence.append("compact_root_profile_cycle_resumption_descendant")
        if values["paired_root_first_exchange_conveyor"]:
            evidence.append("paired_root_first_exchange_conveyor")
        if values["paired_root_setup_descendant"]:
            evidence.append("paired_root_setup_descendant")
        if values["paired_root_resumption_descendant"]:
            evidence.append("paired_root_resumption_descendant")
        if values["mirrored_root_transition"]:
            evidence.append("mirrored_root_resumption_transition")
        if values["yandex_mail_browser_root_burst"]:
            evidence.append("yandex_mail_browser_root_burst")
        if values["yandex_mail_browser_serial_root"]:
            evidence.append("yandex_mail_browser_serial_root")
        if values["yandex_mail_browser_dzen_root"]:
            evidence.append("yandex_mail_browser_dzen_root")
        if values["yandex_mail_inline_ad_request"]:
            evidence.append("yandex_mail_inline_ad_request")
        if values["yandex_mail_inline_first_ad_request"]:
            evidence.append("yandex_mail_inline_first_ad_request")
        if values["yandex_mail_inline_bootstrap_large_request"]:
            evidence.append("yandex_mail_inline_bootstrap_large_request")
        if values["yandex_mail_inline_response_outlier"]:
            evidence.append("yandex_mail_inline_response_outlier")
        if values["yandex_mail_inline_ad_dna_request"]:
            evidence.append("yandex_mail_inline_ad_dna_request")
        if values["denied"]:
            score += 0.18
            evidence.append("nearby_blocked_dns")
        if values["first_request"] is not None and values["first_request"] <= 2200:
            score += 0.05
            evidence.append("small_first_request")
        if not values["compact_hello"] and (not values["denied"]):
            score -= 0.12
            evidence.append("no_causal_dns_for_large_flow")
        confidence = round(max(0.0, min(1.0, score)), 3)
        if values["large_root_after_subdomain_fanout"]:
            confidence = max(confidence, 0.82)
        if values["large_root_after_cross_session_fanout"]:
            confidence = max(confidence, 0.82)
        if values["compact_root_causal_retry"]:
            confidence = max(confidence, 0.82)
        if values["large_root_causal_retry"]:
            confidence = max(confidence, 0.82)
        if values["large_root_active_family_continuation"]:
            confidence = max(confidence, 0.82)
        if values["uniform_root_exchange_conveyor"]:
            confidence = max(confidence, 0.82)
        if values["uniform_root_endpoint_multiplex"]:
            confidence = max(confidence, 0.82)
        if values["uniform_root_endpoint_companion"]:
            confidence = max(confidence, 0.82)
        if values["uniform_root_cross_endpoint_companion"]:
            confidence = max(confidence, 0.82)
        if values["uniform_root_setup_companion"]:
            confidence = max(confidence, 0.82)
        if values["uniform_root_setup_resumption_descendant"]:
            confidence = max(confidence, 0.82)
        if values["uniform_root_successor_exchange_conveyor"]:
            confidence = max(confidence, 0.82)
        if values["uniform_root_successor_resumption_descendant"]:
            confidence = max(confidence, 0.82)
        if values["compact_root_profile_cycle_conveyor"]:
            confidence = max(confidence, 0.82)
        if values["compact_root_profile_cycle_resumption_descendant"]:
            confidence = max(confidence, 0.82)
        if values["paired_root_first_exchange_conveyor"]:
            confidence = max(confidence, 0.82)
        if values["paired_root_setup_descendant"]:
            confidence = max(confidence, 0.82)
        if values["paired_root_resumption_descendant"]:
            confidence = max(confidence, 0.82)
        if values["mirrored_root_transition"]:
            confidence = max(confidence, 0.82)
        if values["yandex_mail_browser_root_burst"]:
            confidence = max(confidence, 0.82)
        if values["yandex_mail_browser_serial_root"]:
            confidence = max(confidence, 0.82)
        if values["yandex_mail_browser_dzen_root"]:
            confidence = max(confidence, 0.82)
        if values["yandex_mail_inline_ad_request"]:
            confidence = max(confidence, 0.96)
        if values["yandex_mail_inline_first_ad_request"]:
            confidence = max(confidence, 0.98)
        if values["yandex_mail_inline_bootstrap_large_request"]:
            confidence = max(confidence, 0.96)
        if values["yandex_mail_inline_response_outlier"]:
            confidence = max(confidence, 0.98)
        if values["yandex_mail_inline_ad_dna_request"]:
            confidence = max(confidence, 0.99)
        if confidence >= 0.75:
            verdict = Verdict.CANDIDATE
        elif confidence <= 0.2:
            verdict = Verdict.ALLOW
        else:
            verdict = Verdict.AMBIGUOUS
        return confidence, verdict, evidence

    def _finalize_assessment(
        self, values: dict[str, object], timestamp: float, state: _FlowState
    ) -> FlowAssessment | None:
        features = self._build_assessment_features(values, timestamp, state)
        if values["uniform_root_successor_exchange_conveyor"]:
            state.successor_exchange_conveyor_emitted = True
        if values["uniform_root_setup_resumption_descendant"]:
            state.setup_resumption_descendant_emitted = True
        if values["uniform_root_successor_resumption_descendant"]:
            state.successor_resumption_descendant_emitted = True
        if values["compact_root_profile_cycle_conveyor"]:
            state.profile_cycle_conveyor_emitted = True
        if values["compact_root_profile_cycle_resumption_descendant"]:
            state.profile_cycle_resumption_descendant_emitted = True
        if values["paired_root_first_exchange_conveyor"]:
            state.paired_root_conveyor_emitted = True
        if values["paired_root_setup_descendant"]:
            state.paired_root_setup_descendant_emitted = True
        if values["paired_root_resumption_descendant"]:
            state.paired_root_resumption_descendant_emitted = True
        if values["yandex_mail_inline_response_outlier"]:
            state.yandex_mail_inline_response_outlier_emitted = True
        signature = (
            values["verdict"],
            values["confidence"],
            tuple(values["evidence"]),
            tuple(features.items()),
        )
        if signature == state.last_signature:
            return None
        state.last_signature = signature
        state.revision += 1
        return FlowAssessment(
            timestamp=timestamp,
            flow=state.flow,
            session_id=state.session_id,
            server_name=values["hello"].server_name,
            verdict=values["verdict"],
            confidence=values["confidence"],
            revision=state.revision,
            evidence=tuple(values["evidence"]),
            features=features,
        )

    @staticmethod
    def _build_assessment_features(
        values: dict[str, object],
        timestamp: float,
        state: _FlowState,
    ) -> dict[str, int | float | str | bool]:
        features: dict[str, int | float | str | bool] = {
            "tls_record_length": values["hello"].record_length,
            "tls_fingerprint": values["hello"].fingerprint,
            "tls_lineage_fingerprint": values["hello"].lineage_fingerprint,
            "tls_session_id_length": values["hello"].session_id_length,
            "tls_psk_identity_count": len(values["hello"].psk_identity_lengths),
            "tls_psk_identity_lengths": ",".join(
                map(str, values["hello"].psk_identity_lengths)
            ),
            "tls_psk_binder_lengths": ",".join(
                map(str, values["hello"].psk_binder_lengths)
            ),
            "tls_key_share_groups": ",".join(
                map(str, values["hello"].key_share_groups)
            ),
            "tls_supported_versions": ",".join(
                map(str, values["hello"].supported_versions)
            ),
            "compact_client_hello": values["compact_hello"],
            "root_server_name": values["root_name"],
            "yandex_mail_context_flow_count": len(values["active_yandex_mail_states"]),
            "yandex_mail_context_age_ms": values["yandex_mail_context_age_ms"],
            "yandex_mail_context_idle_ms": values["yandex_mail_context_idle_ms"],
            "yandex_mail_root_burst_count": len(values["yandex_mail_root_burst_nodes"]),
            "yandex_mail_browser_root_burst": values["yandex_mail_browser_root_burst"],
            "yandex_mail_browser_serial_root": values[
                "yandex_mail_browser_serial_root"
            ],
            "yandex_mail_browser_dzen_root": values["yandex_mail_browser_dzen_root"],
            "yandex_mail_inline_ad_request": values["yandex_mail_inline_ad_request"],
            "yandex_mail_inline_first_ad_request": values[
                "yandex_mail_inline_first_ad_request"
            ],
            "yandex_mail_inline_bootstrap_large_request": values[
                "yandex_mail_inline_bootstrap_large_request"
            ],
            "yandex_mail_inline_response_outlier": values[
                "yandex_mail_inline_response_outlier"
            ],
            "yandex_mail_inline_ad_dna_request": values[
                "yandex_mail_inline_ad_dna_request"
            ],
            "yandex_mail_inline_small_peer_count": values[
                "yandex_mail_inline_small_peer_count"
            ],
            "yandex_mail_pending_exchange_index": values["pending_exchange"].index
            if values["pending_exchange"] is not None
            else 0,
            "yandex_mail_pending_request_record_count": values[
                "pending_exchange"
            ].request_record_count
            if values["pending_exchange"] is not None
            else 0,
            "yandex_mail_pending_request_bytes": values[
                "pending_exchange"
            ].request_bytes
            if values["pending_exchange"] is not None
            else 0,
            "yandex_mail_pending_response_record_count": values[
                "pending_exchange"
            ].response_record_count
            if values["pending_exchange"] is not None
            else 0,
            "yandex_mail_pending_response_bytes": values[
                "pending_exchange"
            ].response_bytes
            if values["pending_exchange"] is not None
            else 0,
            "yandex_mail_pending_first_response_delay_ms": max(
                0,
                round(
                    (
                        values["pending_exchange"].first_response_at
                        - values["pending_exchange"].started_at
                    )
                    * 1000
                ),
            )
            if values["pending_exchange"] is not None
            and values["pending_exchange"].first_response_at
            else 0,
            "yandex_mail_current_flow_age_ms": max(
                0, round((timestamp - state.hello_at) * 1000)
            ),
            "yandex_mail_previous_exchange_index": values[
                "previous_exchange"
            ].exchange_index
            if values["previous_exchange"] is not None
            else 0,
            "yandex_mail_previous_request_bytes": values[
                "previous_exchange"
            ].request_bytes
            if values["previous_exchange"] is not None
            else 0,
            "yandex_mail_previous_response_bytes": values[
                "previous_exchange"
            ].response_bytes
            if values["previous_exchange"] is not None
            else 0,
            "yandex_mail_previous_first_response_delay_ms": values[
                "previous_exchange"
            ].first_response_delay_ms
            if values["previous_exchange"] is not None
            else 0,
            "yandex_mail_previous_next_request_delay_ms": values[
                "previous_exchange"
            ].next_request_delay_ms
            if values["previous_exchange"] is not None
            and values["previous_exchange"].next_request_delay_ms is not None
            else 0,
            "yandex_mail_previous_flow_age_ms": values["previous_exchange"].flow_age_ms
            if values["previous_exchange"] is not None
            else 0,
            "burst_flow_count": len(values["burst_nodes"]),
            "session_flow_count": len(values["session_nodes"]),
            "session_distinct_sni": values["distinct_names"],
            "session_server_names": ",".join(
                sorted({node.hello.server_name for node in values["session_nodes"]})[
                    :16
                ]
            ),
            "causal_edge_score": round(state.causal_edge_score, 3),
            "same_fingerprint_count": values["same_fingerprint"],
            "compact_root_flow_count": values["compact_root_flow_count"],
            "compact_subdomain_flow_count": len(values["compact_subdomain_nodes"]),
            "compact_root_to_subdomain_fanout": values["compact_root_to_subdomain"],
            "recent_compact_root_flow_count": len(values["recent_compact_root_nodes"]),
            "compact_root_to_subdomain_transition": values[
                "compact_root_to_subdomain_transition"
            ],
            "prior_same_root_flow_count": len(values["prior_same_root_nodes"]),
            "prior_compact_subdomain_count": values["prior_compact_subdomain_count"],
            "dense_single_setup_profile_transition": values[
                "dense_single_setup_profile_transition"
            ],
            "compact_root_profile_transition": values[
                "compact_root_profile_transition"
            ],
            "prior_lineage_flow_count": len(values["prior_lineage_nodes"]),
            "compact_root_resumption_pair": values["compact_root_resumption_pair"],
            "same_family_subdomain_count": len(values["same_family_subdomain_names"]),
            "large_root_after_subdomain_fanout": values[
                "large_root_after_subdomain_fanout"
            ],
            "cross_session_same_family_subdomain_count": len(
                values["cross_session_subdomain_names"]
            ),
            "cross_session_distinct_session_count": len(values["cross_session_ids"]),
            "large_root_after_cross_session_fanout": values[
                "large_root_after_cross_session_fanout"
            ],
            "prior_large_causal_root_count": len(values["confirmed_large_roots"]),
            "compact_root_causal_retry": values["compact_root_causal_retry"],
            "prior_large_endpoint_root_count": len(
                values["confirmed_large_endpoint_roots"]
            ),
            "large_root_causal_retry": values["large_root_causal_retry"],
            "prior_confirmed_endpoint_root_count": len(
                values["confirmed_continuation_roots"]
            ),
            "recent_family_request_flow_count": len(
                values["recent_family_request_states"]
            ),
            "large_root_active_family_continuation": values[
                "large_root_active_family_continuation"
            ],
            "uniform_root_exchange_count": values["uniform_root_exchange_count"],
            "uniform_root_distinct_flow_count": values["uniform_root_exchange_count"],
            "uniform_root_exchange_window_ms": values[
                "uniform_root_exchange_window_ms"
            ],
            "uniform_root_request_spread": values["uniform_root_request_spread"],
            "uniform_root_response_spread": values["uniform_root_response_spread"],
            "uniform_root_exact_endpoint": values["uniform_root_exchange_conveyor"],
            "uniform_root_endpoint_peer_count": values[
                "uniform_root_endpoint_peer_count"
            ],
            "uniform_root_endpoint_distinct_name_count": len(
                values["uniform_root_endpoint_names"]
            ),
            "uniform_root_endpoint_seed_exchange_count": len(
                values["uniform_root_endpoint_seed_exchanges"]
            ),
            "uniform_root_endpoint_seed_age_ms": values[
                "uniform_root_endpoint_seed_age_ms"
            ],
            "uniform_root_endpoint_multiplex": values[
                "uniform_root_endpoint_multiplex"
            ],
            "prior_uniform_root_conveyor_count": len(
                values["confirmed_uniform_conveyors"]
            ),
            "uniform_root_companion_confirmation_age_ms": values[
                "uniform_root_companion_confirmation_age_ms"
            ],
            "uniform_root_companion_hello_delta_ms": values[
                "uniform_root_companion_hello_delta_ms"
            ],
            "uniform_root_companion_exact_endpoint": values[
                "uniform_root_endpoint_companion"
            ],
            "prior_uniform_root_cross_lineage_count": len(
                values["confirmed_cross_endpoint_conveyors"]
            ),
            "uniform_root_cross_confirmation_age_ms": values[
                "uniform_root_cross_confirmation_age_ms"
            ],
            "uniform_root_cross_hello_delta_ms": values[
                "uniform_root_cross_hello_delta_ms"
            ],
            "uniform_root_cross_endpoint": values[
                "uniform_root_cross_endpoint_companion"
            ],
            "uniform_root_cross_fingerprint_match": bool(
                values["confirmed_cross_endpoint_conveyors"]
            ),
            "uniform_root_cross_lineage_match": bool(
                values["confirmed_cross_endpoint_conveyors"]
            ),
            "prior_uniform_root_setup_conveyor_count": len(
                values["confirmed_setup_conveyors"]
            ),
            "uniform_root_setup_peer_count": len(values["uniform_root_setup_peers"]),
            "uniform_root_setup_confirmation_age_ms": values[
                "uniform_root_setup_confirmation_age_ms"
            ],
            "uniform_root_setup_hello_age_ms": values[
                "uniform_root_setup_hello_age_ms"
            ],
            "uniform_root_setup_exact_endpoint": bool(
                values["uniform_root_setup_peers"]
            ),
            "uniform_root_setup_distinct_endpoint": bool(
                values["confirmed_setup_conveyors"]
            ),
            "uniform_root_setup_distinct_name": bool(
                values["confirmed_setup_conveyors"]
            ),
            "uniform_root_setup_profile_changed": bool(
                values["confirmed_setup_conveyors"]
            ),
            "prior_uniform_root_setup_context_count": len(
                values["confirmed_setup_contexts"]
            ),
            "uniform_root_setup_context_age_ms": values[
                "uniform_root_setup_context_age_ms"
            ],
            "setup_resumption_peer_count": len(values["setup_resumption_peers"]),
            "setup_resumption_hello_delta_ms": values[
                "setup_resumption_hello_delta_ms"
            ],
            "uniform_root_setup_context_exact_endpoint": bool(
                values["confirmed_setup_contexts"]
            ),
            "uniform_root_setup_context_exact_name": bool(
                values["confirmed_setup_contexts"]
            ),
            "uniform_root_setup_context_profile_match": len(
                values["confirmed_setup_contexts"]
            )
            >= UNIFORM_ROOT_SETUP_MIN_FLOWS,
            "uniform_root_setup_resumption_profile_changed": bool(
                values["confirmed_setup_contexts"]
            ),
            "uniform_root_setup_resumption_fingerprint_match": len(
                values["setup_resumption_peers"]
            )
            >= SETUP_RESUMPTION_MIN_FLOWS,
            "uniform_root_setup_resumption_lineage_match": len(
                values["setup_resumption_peers"]
            )
            >= SETUP_RESUMPTION_MIN_FLOWS,
            "prior_uniform_root_successor_conveyor_count": len(
                values["confirmed_successor_conveyors"]
            ),
            "uniform_root_successor_confirmation_age_ms": values[
                "uniform_root_successor_confirmation_age_ms"
            ],
            "successor_exchange_count": len(values["successor_exchanges"]),
            "successor_exchange_window_ms": values["successor_exchange_window_ms"],
            "successor_request_min_bytes": values["successor_request_min_bytes"],
            "successor_request_max_bytes": values["successor_request_max_bytes"],
            "successor_small_response_count": values["successor_small_response_count"],
            "successor_large_response_count": values["successor_large_response_count"],
            "uniform_root_successor_exact_endpoint": bool(
                values["confirmed_successor_conveyors"]
            ),
            "uniform_root_successor_distinct_name": bool(
                values["confirmed_successor_conveyors"]
            ),
            "uniform_root_successor_profile_changed": bool(
                values["confirmed_successor_conveyors"]
            ),
            "prior_uniform_root_successor_context_count": len(
                values["eligible_successor_contexts"]
            ),
            "successor_resumption_context_age_ms": values[
                "successor_resumption_context_age_ms"
            ],
            "successor_resumption_pair_flow_count": len(
                values["successor_resumption_context"].resumed_pair_flows
            )
            if values["successor_resumption_context"] is not None
            else 0,
            "successor_resumption_distinct_endpoint_count": values[
                "successor_resumption_context"
            ].resumed_distinct_endpoint_count
            if values["successor_resumption_context"] is not None
            else 0,
            "successor_resumption_pair_hello_delta_ms": values[
                "successor_resumption_context"
            ].resumed_pair_hello_delta_ms
            if values["successor_resumption_context"] is not None
            else 0,
            "successor_resumption_pair_established": values[
                "successor_resumption_pair_established"
            ],
            "successor_resumption_context_continuation": values[
                "successor_resumption_context_continuation"
            ],
            "successor_resumption_exact_name": bool(
                values["successor_resumption_context"]
            ),
            "successor_resumption_distinct_origin_endpoint": bool(
                values["successor_resumption_context"]
            ),
            "successor_resumption_origin_profile_changed": bool(
                values["successor_resumption_context"]
            ),
            "successor_resumption_fingerprint_match": values[
                "successor_resumption_fingerprint_match"
            ],
            "successor_resumption_lineage_match": values[
                "successor_resumption_lineage_match"
            ],
            "profile_cycle_prior_setup_count": values[
                "profile_cycle"
            ].prior_setup_count,
            "profile_cycle_resumed_pair_count": values[
                "profile_cycle"
            ].resumed_pair_count,
            "profile_cycle_returned_setup_pair_count": values[
                "profile_cycle"
            ].returned_setup_pair_count,
            "profile_cycle_setup_to_resumed_ms": values[
                "profile_cycle"
            ].setup_to_resumed_ms,
            "profile_cycle_resumed_to_return_ms": values[
                "profile_cycle"
            ].resumed_to_return_ms,
            "profile_cycle_resumed_pair_delta_ms": values[
                "profile_cycle"
            ].resumed_pair_delta_ms,
            "profile_cycle_returned_setup_pair_delta_ms": values[
                "profile_cycle"
            ].returned_setup_pair_delta_ms,
            "profile_cycle_exact_endpoint": bool(
                values["profile_cycle"].prior_setup_count
            ),
            "profile_cycle_exact_name": bool(values["profile_cycle"].prior_setup_count),
            "profile_cycle_setup_profile_returned": bool(
                values["profile_cycle"].prior_setup_count
            ),
            "profile_cycle_resumed_profile_changed": bool(
                values["profile_cycle"].resumed_fingerprint
                and values["profile_cycle"].resumed_lineage_fingerprint
            ),
            "prior_profile_cycle_context_count": len(
                values["eligible_profile_cycle_contexts"]
            ),
            "profile_cycle_context_age_ms": values["profile_cycle_context_age_ms"],
            "profile_cycle_context_exact_endpoint": bool(
                values["closest_profile_cycle_context"]
            ),
            "profile_cycle_context_exact_name": bool(
                values["closest_profile_cycle_context"]
            ),
            "profile_cycle_context_profile_changed": bool(
                values["closest_profile_cycle_context"]
            ),
            "profile_cycle_context_fingerprint_match": bool(
                values["closest_profile_cycle_context"]
            ),
            "profile_cycle_context_lineage_match": bool(
                values["closest_profile_cycle_context"]
            ),
            "paired_root_flow_count": values["paired_root"].flow_count,
            "paired_root_distinct_endpoint_count": values[
                "paired_root"
            ].distinct_endpoint_count,
            "paired_root_completed_exchange_count": values[
                "paired_root"
            ].completed_exchange_count,
            "paired_root_hello_delta_ms": values["paired_root"].hello_delta_ms,
            "paired_root_exchange_delta_ms": values["paired_root"].exchange_delta_ms,
            "paired_root_request_min_bytes": values["paired_root"].request_min_bytes,
            "paired_root_request_max_bytes": values["paired_root"].request_max_bytes,
            "paired_root_response_min_bytes": values["paired_root"].response_min_bytes,
            "paired_root_response_max_bytes": values["paired_root"].response_max_bytes,
            "paired_root_response_ratio": values["paired_root"].response_ratio,
            "paired_root_exact_endpoint": values["paired_root"].distinct_endpoint_count
            == 1,
            "paired_root_exact_name": values["paired_root"].flow_count == 2,
            "paired_root_setup_profile_match": values["paired_root"].flow_count == 2,
            "prior_paired_root_setup_context_count": len(
                values["paired_root_setup_contexts"]
            ),
            "paired_root_setup_context_age_ms": values[
                "paired_root_setup_context_age_ms"
            ],
            "paired_root_setup_context_origin_age_ms": values[
                "paired_root_setup_context_origin_age_ms"
            ],
            "paired_root_setup_context_descendant_count": values[
                "closest_paired_root_setup_context"
            ].descendant_count
            if values["closest_paired_root_setup_context"] is not None
            else 0,
            "paired_root_setup_context_exact_name": bool(
                values["closest_paired_root_setup_context"]
            ),
            "paired_root_setup_context_exact_port": bool(
                values["closest_paired_root_setup_context"]
            ),
            "paired_root_setup_context_fingerprint_match": bool(
                values["closest_paired_root_setup_context"]
            ),
            "paired_root_setup_context_lineage_match": bool(
                values["closest_paired_root_setup_context"]
            ),
            "prior_paired_root_context_count": len(
                values["recent_paired_root_contexts"]
            ),
            "paired_root_context_age_ms": values["paired_root_context_age_ms"],
            "paired_root_context_origin_age_ms": values[
                "paired_root_context_origin_age_ms"
            ],
            "paired_root_context_descendant_count": values[
                "closest_paired_root_context"
            ].descendant_count
            if values["closest_paired_root_context"] is not None
            else 0,
            "paired_root_resumption_initial": values["paired_root_resumption_initial"],
            "paired_root_context_origin_endpoint_count": values[
                "closest_paired_root_context"
            ].setup_distinct_endpoint_count
            if values["closest_paired_root_context"] is not None
            else 0,
            "paired_root_initial_endpoint_scope_match": bool(
                values["closest_paired_root_context"]
                and (
                    values["closest_paired_root_context"].setup_distinct_endpoint_count
                    == 2
                    or values["closest_paired_root_context"].flow.server_ip
                    == state.flow.server_ip
                )
            ),
            "paired_root_context_exact_name": bool(
                values["closest_paired_root_context"]
            ),
            "paired_root_context_exact_port": bool(
                values["closest_paired_root_context"]
            ),
            "paired_root_resumption_profile_established": bool(
                values["closest_paired_root_context"]
                and values["closest_paired_root_context"].resumed_fingerprint
                and values["closest_paired_root_context"].resumed_lineage_fingerprint
            ),
            "paired_root_resumption_fingerprint_match": values[
                "paired_root_resumption_fingerprint_match"
            ],
            "paired_root_resumption_lineage_match": values[
                "paired_root_resumption_lineage_match"
            ],
            "mirrored_root_setup_pair_count": values["mirrored_root_setup_pair_count"],
            "mirrored_root_resumed_pair_count": values[
                "mirrored_root_resumed_pair_count"
            ],
            "mirrored_root_distinct_name_count": values[
                "mirrored_root_distinct_name_count"
            ],
            "mirrored_root_distinct_endpoint_count": values[
                "mirrored_root_distinct_endpoint_count"
            ],
            "mirrored_root_setup_delta_ms": values["mirrored_root_setup_delta_ms"],
            "mirrored_root_resumed_delta_ms": values["mirrored_root_resumed_delta_ms"],
            "mirrored_root_transition_window_ms": values[
                "mirrored_root_transition_window_ms"
            ],
            "mirrored_root_profile_changed": values["mirrored_root_profile_changed"],
            "mirrored_root_transition": values["mirrored_root_transition"],
            "blocked_dns_count": len(values["denied"]),
            "blocked_dns_names": ",".join(
                sorted({event.query_name for event in values["denied"]})[:8]
            ),
            "first_client_application_record": values["first_request"] or 0,
            "first_server_application_record": values["first_response"] or 0,
            "client_tls_record_lengths": ",".join(
                map(str, state.client.record_lengths)
            ),
            "server_tls_record_lengths": ",".join(
                map(str, state.server.record_lengths)
            ),
            "first_request_delay_ms": _record_delay_ms(
                state.client.record_times, state.hello_at
            ),
            "first_response_delay_ms": _record_delay_ms(
                state.server.record_times, state.hello_at
            ),
            "client_payload_bytes": state.client.payload_bytes,
            "server_payload_bytes": state.server.payload_bytes,
        }
        return features
