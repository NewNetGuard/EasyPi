"""Correlation behavior for FlowGraphEngine."""

from prism_dpi.flowgraph.foundation import (
    CAUSAL_ROOT_FANOUT_WINDOW_SECONDS,
    FlowAssessment,
    MAX_REASSESSED_ROOT_PEERS,
    MIRRORED_ROOT_PAIR_WINDOW_SECONDS,
    MIRRORED_ROOT_TRANSITION_WINDOW_SECONDS,
    PAIRED_ROOT_LARGE_RESPONSE_MIN_BYTES,
    PAIRED_ROOT_PAIR_WINDOW_SECONDS,
    PAIRED_ROOT_REQUEST_MAX_BYTES,
    PAIRED_ROOT_REQUEST_MIN_BYTES,
    PAIRED_ROOT_RESPONSE_MIN_BYTES,
    ROOT_PROFILE_CYCLE_MIN_FLOWS,
    ROOT_PROFILE_CYCLE_PAIR_WINDOW_SECONDS,
    ROOT_PROFILE_CYCLE_PHASE_WINDOW_SECONDS,
    SETUP_RESUMPTION_PAIR_WINDOW_SECONDS,
    SUCCESSOR_RESUMPTION_PAIR_WINDOW_SECONDS,
    UNIFORM_ROOT_COMPANION_HELLO_DELTA_SECONDS,
    UNIFORM_ROOT_CROSS_ENDPOINT_HELLO_DELTA_SECONDS,
    UNIFORM_ROOT_SETUP_WINDOW_SECONDS,
    YANDEX_MAIL_ROOT_BURST_WINDOW_SECONDS,
    _FlowState,
    _PairedRootExchangeSnapshot,
    _PairedRootFirstExchangeMatch,
    _RootProfileCycleMatch,
    _domain_family,
    _is_root_server_name,
)


class CorrelationMixin:
    """Internal behavior mixed into the stable engine facade."""

    def _reassess_root_peers(
        self,
        timestamp: float,
        new_state: _FlowState,
    ) -> list[FlowAssessment]:
        hello = new_state.hello
        if hello is None or _is_root_server_name(hello.server_name):
            return []
        family = _domain_family(hello.server_name)
        peers = [
            state
            for state in self._flows.values()
            if state.flow != new_state.flow
            and state.hello is not None
            and state.flow.client_ip == new_state.flow.client_ip
            and (state.session_id == new_state.session_id or hello.record_length > 640)
            and state.hello_at >= timestamp - CAUSAL_ROOT_FANOUT_WINDOW_SECONDS
            and _is_root_server_name(state.hello.server_name)
            and _domain_family(state.hello.server_name) == family
        ]
        peers.sort(key=lambda state: state.hello.record_length <= 640)
        assessments: list[FlowAssessment] = []
        for peer in peers[:MAX_REASSESSED_ROOT_PEERS]:
            assessment = self._assess(timestamp, peer)
            if assessment is not None:
                assessments.append(assessment)
        return assessments

    def _reassess_yandex_mail_browser_root_peers(
        self,
        timestamp: float,
        trigger: _FlowState,
    ) -> list[FlowAssessment]:
        peers = [
            state
            for state in self._flows.values()
            if state.flow != trigger.flow
            and state.flow.client_ip == trigger.flow.client_ip
            and state.hello is not None
            and state.hello.server_name == "yandex.ru"
            and state.hello.record_length > 640
            and 0 <= timestamp - state.hello_at <= YANDEX_MAIL_ROOT_BURST_WINDOW_SECONDS
        ]
        peers.sort(key=lambda state: state.hello_at, reverse=True)
        assessments: list[FlowAssessment] = []
        for peer in peers[:MAX_REASSESSED_ROOT_PEERS]:
            assessment = self._assess(timestamp, peer)
            if assessment is not None:
                assessments.append(assessment)
        return assessments

    def _reassess_uniform_root_endpoint_peers(
        self,
        timestamp: float,
        trigger: _FlowState,
    ) -> list[FlowAssessment]:
        peers = [
            state
            for state in self._flows.values()
            if state.flow != trigger.flow
            and state.flow.client_ip == trigger.flow.client_ip
            and state.flow.server_ip == trigger.flow.server_ip
            and state.flow.server_port == trigger.flow.server_port
            and state.hello is not None
            and state.hello.record_length <= 640
            and _is_root_server_name(state.hello.server_name)
            and abs(state.hello_at - timestamp)
            <= UNIFORM_ROOT_COMPANION_HELLO_DELTA_SECONDS
        ]
        peers.sort(key=lambda state: state.hello_at, reverse=True)
        assessments: list[FlowAssessment] = []
        for peer in peers[:MAX_REASSESSED_ROOT_PEERS]:
            assessment = self._assess(timestamp, peer)
            if assessment is not None:
                assessments.append(assessment)
        return assessments

    def _reassess_uniform_root_lineage_peers(
        self,
        timestamp: float,
        trigger: _FlowState,
    ) -> list[FlowAssessment]:
        trigger_hello = trigger.hello
        if trigger_hello is None:
            return []
        peers = [
            state
            for state in self._flows.values()
            if state.flow != trigger.flow
            and state.flow.client_ip == trigger.flow.client_ip
            and state.flow.server_ip != trigger.flow.server_ip
            and state.flow.server_port == trigger.flow.server_port
            and state.hello is not None
            and state.hello.record_length <= 640
            and _is_root_server_name(state.hello.server_name)
            and state.hello.fingerprint == trigger_hello.fingerprint
            and (state.hello.lineage_fingerprint == trigger_hello.lineage_fingerprint)
            and abs(state.hello_at - timestamp)
            <= UNIFORM_ROOT_CROSS_ENDPOINT_HELLO_DELTA_SECONDS
        ]
        peers.sort(key=lambda state: state.hello_at, reverse=True)
        assessments: list[FlowAssessment] = []
        for peer in peers[:MAX_REASSESSED_ROOT_PEERS]:
            assessment = self._assess(timestamp, peer)
            if assessment is not None:
                assessments.append(assessment)
        return assessments

    def _reassess_uniform_root_setup_peers(
        self,
        timestamp: float,
        trigger: _FlowState,
    ) -> list[FlowAssessment]:
        trigger_hello = trigger.hello
        if trigger_hello is None:
            return []
        peers = [
            state
            for state in self._flows.values()
            if state.flow != trigger.flow
            and state.flow.client_ip == trigger.flow.client_ip
            and state.flow.server_ip != trigger.flow.server_ip
            and state.flow.server_port == trigger.flow.server_port
            and state.hello is not None
            and state.hello.record_length <= 640
            and not state.hello.psk_identity_lengths
            and _is_root_server_name(state.hello.server_name)
            and state.hello.server_name != trigger_hello.server_name
            and state.hello.fingerprint != trigger_hello.fingerprint
            and 0 <= timestamp - state.hello_at <= UNIFORM_ROOT_SETUP_WINDOW_SECONDS
        ]
        peers.sort(key=lambda state: state.hello_at, reverse=True)
        assessments: list[FlowAssessment] = []
        for peer in peers[:MAX_REASSESSED_ROOT_PEERS]:
            assessment = self._assess(timestamp, peer)
            if assessment is not None:
                assessments.append(assessment)
        return assessments

    def _reassess_mirrored_root_peers(
        self,
        timestamp: float,
        trigger: _FlowState,
    ) -> list[FlowAssessment]:
        trigger_hello = trigger.hello
        if trigger_hello is None or not trigger_hello.psk_identity_lengths:
            return []
        peers = [
            state
            for state in self._flows.values()
            if state.flow != trigger.flow
            and state.flow.client_ip == trigger.flow.client_ip
            and state.flow.server_ip != trigger.flow.server_ip
            and state.flow.server_port == trigger.flow.server_port
            and state.hello is not None
            and state.hello.record_length <= 640
            and _is_root_server_name(state.hello.server_name)
            and state.hello.server_name != trigger_hello.server_name
            and bool(state.hello.psk_identity_lengths)
            and state.hello.fingerprint == trigger_hello.fingerprint
            and (state.hello.lineage_fingerprint == trigger_hello.lineage_fingerprint)
            and abs(state.hello_at - trigger.hello_at)
            <= MIRRORED_ROOT_PAIR_WINDOW_SECONDS
        ]
        peers.sort(key=lambda state: state.hello_at, reverse=True)
        assessments: list[FlowAssessment] = []
        for peer in peers[:MAX_REASSESSED_ROOT_PEERS]:
            assessment = self._assess(timestamp, peer)
            if assessment is not None:
                assessments.append(assessment)
        return assessments

    def _reassess_uniform_root_setup_resumption_peers(
        self,
        timestamp: float,
        trigger: _FlowState,
    ) -> list[FlowAssessment]:
        trigger_hello = trigger.hello
        if trigger_hello is None:
            return []
        peers = [
            state
            for state in self._flows.values()
            if state.flow != trigger.flow
            and state.flow.client_ip == trigger.flow.client_ip
            and state.flow.server_ip == trigger.flow.server_ip
            and state.flow.server_port == trigger.flow.server_port
            and state.hello is not None
            and state.hello.server_name == trigger_hello.server_name
            and state.hello.record_length <= 640
            and bool(state.hello.psk_identity_lengths)
            and state.hello.fingerprint == trigger_hello.fingerprint
            and (state.hello.lineage_fingerprint == trigger_hello.lineage_fingerprint)
            and state.server.payload_bytes == 0
            and abs(state.hello_at - trigger.hello_at)
            <= SETUP_RESUMPTION_PAIR_WINDOW_SECONDS
        ]
        peers.sort(key=lambda state: state.hello_at, reverse=True)
        assessments: list[FlowAssessment] = []
        for peer in peers[:MAX_REASSESSED_ROOT_PEERS]:
            assessment = self._assess(timestamp, peer)
            if assessment is not None:
                assessments.append(assessment)
        return assessments

    def _reassess_uniform_root_successor_resumption_peers(
        self,
        timestamp: float,
        trigger: _FlowState,
    ) -> list[FlowAssessment]:
        trigger_hello = trigger.hello
        if trigger_hello is None:
            return []
        peers = [
            state
            for state in self._flows.values()
            if state.flow != trigger.flow
            and state.flow.client_ip == trigger.flow.client_ip
            and state.flow.server_ip != trigger.flow.server_ip
            and state.flow.server_port == trigger.flow.server_port
            and state.hello is not None
            and state.hello.server_name == trigger_hello.server_name
            and state.hello.record_length <= 640
            and bool(state.hello.psk_identity_lengths)
            and state.hello.fingerprint == trigger_hello.fingerprint
            and (state.hello.lineage_fingerprint == trigger_hello.lineage_fingerprint)
            and state.server.payload_bytes == 0
            and abs(state.hello_at - trigger.hello_at)
            <= SUCCESSOR_RESUMPTION_PAIR_WINDOW_SECONDS
        ]
        peers.sort(key=lambda state: state.hello_at, reverse=True)
        assessments: list[FlowAssessment] = []
        for peer in peers[:MAX_REASSESSED_ROOT_PEERS]:
            assessment = self._assess(timestamp, peer)
            if assessment is not None:
                assessments.append(assessment)
        return assessments

    def _reassess_root_profile_cycle_setup_peers(
        self,
        timestamp: float,
        trigger: _FlowState,
    ) -> list[FlowAssessment]:
        trigger_hello = trigger.hello
        if trigger_hello is None:
            return []
        peers = [
            state
            for state in self._flows.values()
            if state.flow != trigger.flow
            and state.flow.client_ip == trigger.flow.client_ip
            and state.flow.server_ip == trigger.flow.server_ip
            and state.flow.server_port == trigger.flow.server_port
            and state.hello is not None
            and state.hello.server_name == trigger_hello.server_name
            and state.hello.record_length <= 640
            and not state.hello.psk_identity_lengths
            and state.hello.fingerprint == trigger_hello.fingerprint
            and (state.hello.lineage_fingerprint == trigger_hello.lineage_fingerprint)
            and state.server.payload_bytes == 0
            and abs(state.hello_at - trigger.hello_at)
            <= ROOT_PROFILE_CYCLE_PAIR_WINDOW_SECONDS
        ]
        peers.sort(key=lambda state: state.hello_at, reverse=True)
        assessments: list[FlowAssessment] = []
        for peer in peers[:MAX_REASSESSED_ROOT_PEERS]:
            assessment = self._assess(timestamp, peer)
            if assessment is not None:
                assessments.append(assessment)
        return assessments

    def _reassess_paired_root_setup_peer(
        self,
        timestamp: float,
        trigger: _FlowState,
    ) -> list[FlowAssessment]:
        trigger_hello = trigger.hello
        if trigger_hello is None:
            return []
        peers = [
            state
            for state in self._flows.values()
            if state.flow != trigger.flow
            and state.flow.client_ip == trigger.flow.client_ip
            and state.flow.server_port == trigger.flow.server_port
            and state.hello is not None
            and state.hello.server_name == trigger_hello.server_name
            and state.hello.record_length <= 640
            and not state.hello.psk_identity_lengths
            and state.hello.fingerprint == trigger_hello.fingerprint
            and (state.hello.lineage_fingerprint == trigger_hello.lineage_fingerprint)
            and abs(state.hello_at - trigger.hello_at)
            <= PAIRED_ROOT_PAIR_WINDOW_SECONDS
        ]
        peers.sort(key=lambda state: state.hello_at, reverse=True)
        assessments: list[FlowAssessment] = []
        for peer in peers[:MAX_REASSESSED_ROOT_PEERS]:
            assessment = self._assess(timestamp, peer)
            if assessment is not None:
                assessments.append(assessment)
        return assessments

    @staticmethod
    def _first_exchange_snapshot(
        state: _FlowState,
    ) -> _PairedRootExchangeSnapshot | None:
        completed = next(
            (
                exchange
                for exchange in state.completed_exchanges
                if exchange.exchange_index == 1
                and exchange.completion_reason == "next_request"
            ),
            None,
        )
        if completed is not None:
            return _PairedRootExchangeSnapshot(
                timestamp=completed.timestamp,
                request_bytes=completed.request_bytes,
                response_bytes=completed.response_bytes,
                completed=True,
            )
        active = state.exchange
        if (
            active is None
            or active.index != 1
            or not active.request_record_count
            or not active.response_record_count
        ):
            return None
        return _PairedRootExchangeSnapshot(
            timestamp=active.last_response_at,
            request_bytes=active.request_bytes,
            response_bytes=active.response_bytes,
            completed=False,
        )

    def _paired_root_first_exchange(
        self,
        state: _FlowState,
    ) -> _PairedRootFirstExchangeMatch:
        hello = state.hello
        current_exchange = self._first_exchange_snapshot(state)
        if (
            hello is None
            or current_exchange is None
            or hello.record_length > 640
            or hello.psk_identity_lengths
            or not _is_root_server_name(hello.server_name)
        ):
            return _PairedRootFirstExchangeMatch()
        companions: list[tuple[_FlowState, _PairedRootExchangeSnapshot]] = []
        for peer in self._flows.values():
            if (
                peer.flow == state.flow
                or peer.flow.client_ip != state.flow.client_ip
                or peer.flow.server_port != state.flow.server_port
                or peer.hello is None
                or peer.hello.server_name != hello.server_name
                or peer.hello.record_length > 640
                or peer.hello.psk_identity_lengths
                or peer.hello.fingerprint != hello.fingerprint
                or peer.hello.lineage_fingerprint != hello.lineage_fingerprint
                or abs(peer.hello_at - state.hello_at) > PAIRED_ROOT_PAIR_WINDOW_SECONDS
            ):
                continue
            peer_exchange = self._first_exchange_snapshot(peer)
            if (
                peer_exchange is not None
                and abs(peer_exchange.timestamp - current_exchange.timestamp)
                <= PAIRED_ROOT_PAIR_WINDOW_SECONDS
            ):
                companions.append((peer, peer_exchange))
        if len(companions) != 1:
            return _PairedRootFirstExchangeMatch()
        peer, peer_exchange = min(
            companions,
            key=lambda item: abs(item[0].hello_at - state.hello_at),
        )
        requests = sorted((current_exchange.request_bytes, peer_exchange.request_bytes))
        responses = sorted(
            (current_exchange.response_bytes, peer_exchange.response_bytes)
        )
        response_ratio = round(responses[1] / max(responses[0], 1), 3)
        if (
            requests[0] < PAIRED_ROOT_REQUEST_MIN_BYTES
            or requests[1] > PAIRED_ROOT_REQUEST_MAX_BYTES
            or responses[0] < PAIRED_ROOT_RESPONSE_MIN_BYTES
            or responses[1] < PAIRED_ROOT_LARGE_RESPONSE_MIN_BYTES
        ):
            return _PairedRootFirstExchangeMatch()
        return _PairedRootFirstExchangeMatch(
            flow_count=2,
            distinct_endpoint_count=len({state.flow.server_ip, peer.flow.server_ip}),
            completed_exchange_count=sum(
                (current_exchange.completed, peer_exchange.completed)
            ),
            hello_delta_ms=max(
                0,
                round(abs(peer.hello_at - state.hello_at) * 1_000),
            ),
            exchange_delta_ms=max(
                0,
                round(
                    abs(peer_exchange.timestamp - current_exchange.timestamp) * 1_000
                ),
            ),
            request_min_bytes=requests[0],
            request_max_bytes=requests[1],
            response_min_bytes=responses[0],
            response_max_bytes=responses[1],
            response_ratio=response_ratio,
        )

    def _could_assess_paired_root_first_exchange(
        self,
        state: _FlowState,
        *,
        allow_completed: bool = False,
    ) -> bool:
        return (
            not state.paired_root_conveyor_emitted
            and (allow_completed or state.next_exchange_index <= 2)
            and self._paired_root_first_exchange(state).flow_count == 2
        )

    def _root_profile_cycle(
        self,
        state: _FlowState,
    ) -> _RootProfileCycleMatch:
        hello = state.hello
        if (
            hello is None
            or hello.record_length > 640
            or hello.psk_identity_lengths
            or not _is_root_server_name(hello.server_name)
            or state.server.payload_bytes != 0
        ):
            return _RootProfileCycleMatch()
        returned_companion = min(
            (
                peer
                for peer in self._flows.values()
                if peer.flow != state.flow
                and peer.flow.client_ip == state.flow.client_ip
                and peer.flow.server_ip == state.flow.server_ip
                and peer.flow.server_port == state.flow.server_port
                and peer.hello is not None
                and peer.hello.server_name == hello.server_name
                and peer.hello.record_length <= 640
                and not peer.hello.psk_identity_lengths
                and peer.hello.fingerprint == hello.fingerprint
                and peer.hello.lineage_fingerprint == hello.lineage_fingerprint
                and peer.server.payload_bytes == 0
                and abs(peer.hello_at - state.hello_at)
                <= ROOT_PROFILE_CYCLE_PAIR_WINDOW_SECONDS
            ),
            key=lambda peer: abs(peer.hello_at - state.hello_at),
            default=None,
        )
        if returned_companion is None:
            return _RootProfileCycleMatch()
        returned_setup_times = (state.hello_at, returned_companion.hello_at)
        returned_setup_started_at = min(returned_setup_times)
        returned_setup_delta_ms = max(
            0,
            round((max(returned_setup_times) - returned_setup_started_at) * 1_000),
        )
        resumed_candidates = [
            peer
            for peer in self._flows.values()
            if peer.flow.client_ip == state.flow.client_ip
            and peer.flow.server_ip == state.flow.server_ip
            and peer.flow.server_port == state.flow.server_port
            and peer.hello is not None
            and peer.hello.server_name == hello.server_name
            and peer.hello.record_length <= 640
            and bool(peer.hello.psk_identity_lengths)
            and peer.hello.fingerprint != hello.fingerprint
            and peer.hello.lineage_fingerprint != hello.lineage_fingerprint
            and returned_setup_started_at - ROOT_PROFILE_CYCLE_PHASE_WINDOW_SECONDS
            <= peer.hello_at
            < returned_setup_started_at
        ]
        resumed_pair: tuple[_FlowState, _FlowState] | None = None
        for resumed in sorted(
            resumed_candidates,
            key=lambda item: item.hello_at,
            reverse=True,
        ):
            companion = min(
                (
                    peer
                    for peer in resumed_candidates
                    if peer.flow != resumed.flow
                    and peer.hello is not None
                    and resumed.hello is not None
                    and peer.hello.fingerprint == resumed.hello.fingerprint
                    and peer.hello.lineage_fingerprint
                    == resumed.hello.lineage_fingerprint
                    and abs(peer.hello_at - resumed.hello_at)
                    <= ROOT_PROFILE_CYCLE_PAIR_WINDOW_SECONDS
                ),
                key=lambda peer: abs(peer.hello_at - resumed.hello_at),
                default=None,
            )
            if companion is not None:
                resumed_pair = (resumed, companion)
                break
        if resumed_pair is None:
            return _RootProfileCycleMatch(
                returned_setup_pair_count=ROOT_PROFILE_CYCLE_MIN_FLOWS,
                returned_setup_pair_delta_ms=returned_setup_delta_ms,
            )
        resumed_times = tuple(peer.hello_at for peer in resumed_pair)
        resumed_started_at = min(resumed_times)
        resumed_ended_at = max(resumed_times)
        prior_setup_flows = [
            peer
            for peer in self._flows.values()
            if peer.flow.client_ip == state.flow.client_ip
            and peer.flow.server_ip == state.flow.server_ip
            and peer.flow.server_port == state.flow.server_port
            and peer.hello is not None
            and peer.hello.server_name == hello.server_name
            and peer.hello.record_length <= 640
            and not peer.hello.psk_identity_lengths
            and peer.hello.fingerprint == hello.fingerprint
            and peer.hello.lineage_fingerprint == hello.lineage_fingerprint
            and resumed_started_at - ROOT_PROFILE_CYCLE_PHASE_WINDOW_SECONDS
            <= peer.hello_at
            < resumed_started_at
        ]
        if not prior_setup_flows:
            return _RootProfileCycleMatch(
                resumed_pair_count=ROOT_PROFILE_CYCLE_MIN_FLOWS,
                returned_setup_pair_count=ROOT_PROFILE_CYCLE_MIN_FLOWS,
                resumed_pair_delta_ms=max(
                    0,
                    round((resumed_ended_at - resumed_started_at) * 1_000),
                ),
                returned_setup_pair_delta_ms=returned_setup_delta_ms,
                resumed_fingerprint=resumed_pair[0].hello.fingerprint,
                resumed_lineage_fingerprint=(resumed_pair[0].hello.lineage_fingerprint),
            )
        latest_prior_setup_at = max(peer.hello_at for peer in prior_setup_flows)
        return _RootProfileCycleMatch(
            prior_setup_count=len(prior_setup_flows),
            resumed_pair_count=ROOT_PROFILE_CYCLE_MIN_FLOWS,
            returned_setup_pair_count=ROOT_PROFILE_CYCLE_MIN_FLOWS,
            setup_to_resumed_ms=max(
                0,
                round((resumed_started_at - latest_prior_setup_at) * 1_000),
            ),
            resumed_to_return_ms=max(
                0,
                round((returned_setup_started_at - resumed_ended_at) * 1_000),
            ),
            resumed_pair_delta_ms=max(
                0,
                round((resumed_ended_at - resumed_started_at) * 1_000),
            ),
            returned_setup_pair_delta_ms=returned_setup_delta_ms,
            resumed_fingerprint=resumed_pair[0].hello.fingerprint,
            resumed_lineage_fingerprint=(resumed_pair[0].hello.lineage_fingerprint),
        )

    def _mirrored_root_transition(
        self,
        timestamp: float,
        state: _FlowState,
    ) -> tuple[int, int, int, int, int, int, int, bool]:
        hello = state.hello
        empty = (0, 0, 0, 0, 0, 0, 0, False)
        if (
            hello is None
            or hello.record_length > 640
            or not _is_root_server_name(hello.server_name)
            or not hello.psk_identity_lengths
        ):
            return empty
        nodes = self._nodes[state.flow.client_ip]
        resumed_peers = [
            node
            for node in nodes
            if node.flow != state.flow
            and node.flow.server_ip != state.flow.server_ip
            and node.flow.server_port == state.flow.server_port
            and node.hello.server_name != hello.server_name
            and node.hello.record_length <= 640
            and _is_root_server_name(node.hello.server_name)
            and bool(node.hello.psk_identity_lengths)
            and node.hello.fingerprint == hello.fingerprint
            and node.hello.lineage_fingerprint == hello.lineage_fingerprint
            and abs(node.timestamp - state.hello_at)
            <= MIRRORED_ROOT_PAIR_WINDOW_SECONDS
        ]
        resumed_peers.sort(key=lambda node: node.timestamp, reverse=True)
        for peer in resumed_peers:
            current_setups = [
                node
                for node in nodes
                if node.timestamp < state.hello_at
                and state.hello_at - MIRRORED_ROOT_TRANSITION_WINDOW_SECONDS
                <= node.timestamp
                and node.flow.server_ip == state.flow.server_ip
                and node.flow.server_port == state.flow.server_port
                and node.hello.server_name == hello.server_name
                and node.hello.record_length <= 640
                and not node.hello.psk_identity_lengths
            ]
            peer_setups = [
                node
                for node in nodes
                if node.timestamp < peer.timestamp
                and peer.timestamp - MIRRORED_ROOT_TRANSITION_WINDOW_SECONDS
                <= node.timestamp
                and node.flow.server_ip == peer.flow.server_ip
                and node.flow.server_port == peer.flow.server_port
                and node.hello.server_name == peer.hello.server_name
                and node.hello.record_length <= 640
                and not node.hello.psk_identity_lengths
            ]
            for current_setup in reversed(current_setups):
                for peer_setup in reversed(peer_setups):
                    setup_delta_ms = abs(
                        round((current_setup.timestamp - peer_setup.timestamp) * 1_000)
                    )
                    if setup_delta_ms > round(
                        MIRRORED_ROOT_PAIR_WINDOW_SECONDS * 1_000
                    ):
                        continue
                    if (
                        current_setup.hello.fingerprint != peer_setup.hello.fingerprint
                        or current_setup.hello.lineage_fingerprint
                        != peer_setup.hello.lineage_fingerprint
                    ):
                        continue
                    profile_changed = (
                        current_setup.hello.fingerprint != hello.fingerprint
                        or current_setup.hello.lineage_fingerprint
                        != hello.lineage_fingerprint
                    )
                    if not profile_changed:
                        continue
                    transition_window_ms = max(
                        0,
                        round(
                            (
                                max(state.hello_at, peer.timestamp)
                                - min(
                                    current_setup.timestamp,
                                    peer_setup.timestamp,
                                )
                            )
                            * 1_000
                        ),
                    )
                    if transition_window_ms > round(
                        MIRRORED_ROOT_TRANSITION_WINDOW_SECONDS * 1_000
                    ):
                        continue
                    resumed_delta_ms = abs(
                        round((state.hello_at - peer.timestamp) * 1_000)
                    )
                    return (
                        2,
                        2,
                        2,
                        2,
                        setup_delta_ms,
                        resumed_delta_ms,
                        transition_window_ms,
                        True,
                    )
        return empty
