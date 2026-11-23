"""TlsAnalysis behavior for FlowGraphEngine."""

from prism_dpi.flowgraph.foundation import (
    Direction,
    FlowKey,
    GRAPH_WINDOW_SECONDS,
    MAX_GRAPH_NODES_PER_CLIENT,
    MAX_ROOT_EXCHANGES_PER_CLIENT,
    MAX_TLS_EXCHANGES_PER_FLOW,
    MAX_TLS_RECORD_SEQUENCE,
    ROOT_EXCHANGE_CONVEYOR_WINDOW_SECONDS,
    ROOT_EXCHANGE_REQUEST_SPREAD_MAX,
    ROOT_EXCHANGE_RESPONSE_SPREAD_MAX,
    SUCCESSOR_EXCHANGE_COUNT,
    TlsClientHello,
    TlsExchangeObservation,
    TlsRecordSequenceObservation,
    UNIFORM_ROOT_SUCCESSOR_WINDOW_SECONDS,
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
    YANDEX_MAIL_INLINE_FIRST_CLIENT_PAYLOAD_MAX_BYTES,
    YANDEX_MAIL_INLINE_FIRST_CLIENT_PAYLOAD_MIN_BYTES,
    YANDEX_MAIL_INLINE_FIRST_HANDSHAKE_DELAY_MAX_MS,
    YANDEX_MAIL_INLINE_FIRST_HANDSHAKE_DELAY_MIN_MS,
    YANDEX_MAIL_INLINE_FIRST_HELLO_MAX_BYTES,
    YANDEX_MAIL_INLINE_FIRST_HELLO_MIN_BYTES,
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
    _CompletedRootExchange,
    _FlowState,
    _GraphNode,
    _TlsExchangeState,
    _edge_score,
    _is_root_server_name,
    _record_delay_ms,
    _relative_distance,
    _relative_spread,
)


class TlsAnalysisMixin:
    """Internal behavior mixed into the stable engine facade."""

    def _observe_tls_record_sequence(
        self,
        timestamp: float,
        state: _FlowState,
        direction: Direction,
        record_length: int,
    ) -> TlsRecordSequenceObservation | None:
        if state.record_sequence_emitted:
            return None
        if not state.record_sequence:
            state.record_sequence_started_at = timestamp
            interarrival_ms = 0
        else:
            interarrival_ms = max(
                0,
                round((timestamp - state.record_sequence_last_at) * 1_000),
            )
        state.record_sequence.append((direction, record_length, interarrival_ms))
        state.record_sequence_last_at = timestamp
        if len(state.record_sequence) < MAX_TLS_RECORD_SEQUENCE:
            return None
        return self._complete_tls_record_sequence(
            state,
            completion_reason="record_limit",
        )

    def _complete_tls_record_sequence(
        self,
        state: _FlowState,
        *,
        completion_reason: str,
    ) -> TlsRecordSequenceObservation:
        points = state.record_sequence
        observation = TlsRecordSequenceObservation(
            timestamp=state.record_sequence_started_at,
            flow=state.flow,
            server_name=state.hello.server_name if state.hello else "",
            tls_fingerprint=state.hello.fingerprint if state.hello else "",
            record_directions=tuple(point[0] for point in points),
            record_lengths=tuple(point[1] for point in points),
            interarrival_ms=tuple(point[2] for point in points),
            duration_ms=max(
                0,
                round(
                    (state.record_sequence_last_at - state.record_sequence_started_at)
                    * 1_000
                ),
            ),
            completion_reason=completion_reason,
        )
        state.record_sequence = []
        state.record_sequence_emitted = True
        self.tls_record_sequences_seen += 1
        return observation

    def _finalize_flow_record_sequence(
        self,
        state: _FlowState,
        *,
        completion_reason: str,
    ) -> TlsRecordSequenceObservation | None:
        if state.record_sequence_emitted or not state.record_sequence:
            return None
        return self._complete_tls_record_sequence(
            state,
            completion_reason=completion_reason,
        )

    def _observe_tls_exchange(
        self,
        timestamp: float,
        state: _FlowState,
        direction: Direction,
        record_length: int,
    ) -> TlsExchangeObservation | None:
        hello = state.hello
        if hello is None:
            return None
        exchange = state.exchange
        if direction is Direction.CLIENT_TO_SERVER:
            if exchange is not None and exchange.response_record_count:
                observation = self._complete_tls_exchange(
                    timestamp,
                    state,
                    exchange,
                    completion_reason="next_request",
                )
                state.exchange = None
                if state.next_exchange_index > MAX_TLS_EXCHANGES_PER_FLOW:
                    return observation
                exchange = _TlsExchangeState(
                    index=state.next_exchange_index,
                    started_at=timestamp,
                )
                state.next_exchange_index += 1
                state.exchange = exchange
                exchange.request_record_count = 1
                exchange.request_bytes = record_length
                return observation
            if exchange is None:
                if state.next_exchange_index > MAX_TLS_EXCHANGES_PER_FLOW:
                    return None
                exchange = _TlsExchangeState(
                    index=state.next_exchange_index,
                    started_at=timestamp,
                )
                state.next_exchange_index += 1
                state.exchange = exchange
            exchange.request_record_count += 1
            exchange.request_bytes += record_length
            return None

        if exchange is None:
            return None
        exchange.response_record_count += 1
        exchange.response_bytes += record_length
        if not exchange.first_response_at:
            exchange.first_response_at = timestamp
        exchange.last_response_at = timestamp
        return None

    def _complete_tls_exchange(
        self,
        timestamp: float,
        state: _FlowState,
        exchange: _TlsExchangeState,
        *,
        completion_reason: str,
    ) -> TlsExchangeObservation:
        previous = state.last_completed_exchange
        response_step_ratio = 0.0
        if previous is not None and previous.response_bytes:
            response_step_ratio = round(
                exchange.response_bytes / previous.response_bytes,
                3,
            )
        observation = TlsExchangeObservation(
            timestamp=timestamp,
            flow=state.flow,
            server_name=state.hello.server_name if state.hello else "",
            tls_fingerprint=state.hello.fingerprint if state.hello else "",
            exchange_index=exchange.index,
            request_record_count=exchange.request_record_count,
            request_bytes=exchange.request_bytes,
            response_record_count=exchange.response_record_count,
            response_bytes=exchange.response_bytes,
            first_response_delay_ms=max(
                0,
                round((exchange.first_response_at - exchange.started_at) * 1000),
            ),
            next_request_delay_ms=max(
                0,
                round((timestamp - exchange.last_response_at) * 1000),
            )
            if completion_reason == "next_request"
            else None,
            flow_age_ms=max(0, round((timestamp - state.hello_at) * 1000)),
            previous_response_bytes=(
                previous.response_bytes if previous is not None else 0
            ),
            previous_next_request_delay_ms=(
                previous.next_request_delay_ms if previous is not None else 0
            ),
            response_step_ratio=response_step_ratio,
            completion_reason=completion_reason,
        )
        state.last_completed_exchange = observation
        state.completed_exchanges.append(observation)
        hello = state.hello
        if (
            exchange.index == 1
            and hello is not None
            and hello.record_length <= 640
            and _is_root_server_name(hello.server_name)
            and exchange.request_bytes > 0
            and exchange.response_bytes > 0
        ):
            history = self._completed_root_exchanges[state.flow.client_ip]
            history.append(
                _CompletedRootExchange(
                    timestamp=timestamp,
                    flow=state.flow,
                    server_name=hello.server_name,
                    tls_fingerprint=hello.fingerprint,
                    request_bytes=exchange.request_bytes,
                    response_bytes=exchange.response_bytes,
                )
            )
            while len(history) > MAX_ROOT_EXCHANGES_PER_CLIENT:
                history.popleft()
        self.tls_exchanges_seen += 1
        return observation

    def _could_assess_yandex_mail_inline_ad_request(
        self,
        state: _FlowState,
        previous: TlsExchangeObservation,
    ) -> bool:
        """Recognize the pre-response edge learned from a Mail web-ad flow.

        This gate is deliberately independent of response size: it runs on the
        first record of exchange two, while the server has not sent the ad body
        yet.  The full context check remains in ``_assess`` and the production
        policy validator.
        """
        hello = state.hello
        pending = state.exchange
        return bool(
            hello is not None
            and hello.server_name == "mail.yandex.ru"
            and previous.exchange_index == 1
            and pending is not None
            and pending.index == 2
            and pending.request_record_count == 1
            and pending.response_record_count == 0
            and YANDEX_MAIL_INLINE_PREVIOUS_REQUEST_MIN_BYTES
            <= previous.request_bytes
            <= YANDEX_MAIL_INLINE_PREVIOUS_REQUEST_MAX_BYTES
            and YANDEX_MAIL_INLINE_PREVIOUS_RESPONSE_MIN_BYTES
            <= previous.response_bytes
            <= YANDEX_MAIL_INLINE_PREVIOUS_RESPONSE_MAX_BYTES
            and YANDEX_MAIL_INLINE_REQUEST_MIN_BYTES
            <= pending.request_bytes
            <= YANDEX_MAIL_INLINE_REQUEST_MAX_BYTES
            and YANDEX_MAIL_INLINE_FLOW_AGE_MIN_MS
            <= previous.flow_age_ms
            <= YANDEX_MAIL_INLINE_FLOW_AGE_MAX_MS
            and YANDEX_MAIL_INLINE_FIRST_RESPONSE_DELAY_MIN_MS
            <= previous.first_response_delay_ms
            <= YANDEX_MAIL_INLINE_FIRST_RESPONSE_DELAY_MAX_MS
            and previous.next_request_delay_ms is not None
            and YANDEX_MAIL_INLINE_NEXT_REQUEST_DELAY_MIN_MS
            <= previous.next_request_delay_ms
            <= YANDEX_MAIL_INLINE_NEXT_REQUEST_DELAY_MAX_MS
        )

    def _could_assess_yandex_mail_inline_first_ad_request(
        self,
        state: _FlowState,
    ) -> bool:
        """Recognize the first-exchange Mail fallback before its response."""
        hello = state.hello
        pending = state.exchange
        return bool(
            hello is not None
            and hello.server_name == "mail.yandex.ru"
            and hello.fingerprint == YANDEX_MAIL_INLINE_FIRST_TLS_FINGERPRINT
            and hello.lineage_fingerprint
            == YANDEX_MAIL_INLINE_FIRST_TLS_LINEAGE_FINGERPRINT
            and bool(hello.psk_identity_lengths)
            and YANDEX_MAIL_INLINE_FIRST_HELLO_MIN_BYTES
            <= hello.record_length
            <= YANDEX_MAIL_INLINE_FIRST_HELLO_MAX_BYTES
            and state.last_completed_exchange is None
            and pending is not None
            and pending.index == 1
            and pending.request_record_count == 1
            and YANDEX_MAIL_INLINE_FIRST_REQUEST_MIN_BYTES
            <= pending.request_bytes
            <= YANDEX_MAIL_INLINE_FIRST_REQUEST_MAX_BYTES
            and pending.response_record_count == 0
            and YANDEX_MAIL_INLINE_FIRST_CLIENT_PAYLOAD_MIN_BYTES
            <= state.client.payload_bytes
            <= YANDEX_MAIL_INLINE_FIRST_CLIENT_PAYLOAD_MAX_BYTES
            and YANDEX_MAIL_INLINE_FIRST_SERVER_PAYLOAD_MIN_BYTES
            <= state.server.payload_bytes
            <= YANDEX_MAIL_INLINE_FIRST_SERVER_PAYLOAD_MAX_BYTES
            and YANDEX_MAIL_INLINE_FIRST_REQUEST_DELAY_MIN_MS
            <= _record_delay_ms(state.client.record_times, state.hello_at)
            <= YANDEX_MAIL_INLINE_FIRST_REQUEST_DELAY_MAX_MS
            and YANDEX_MAIL_INLINE_FIRST_HANDSHAKE_DELAY_MIN_MS
            <= _record_delay_ms(state.server.record_times, state.hello_at)
            <= YANDEX_MAIL_INLINE_FIRST_HANDSHAKE_DELAY_MAX_MS
        )

    def _could_assess_yandex_mail_inline_ad_dna_request(
        self,
        state: _FlowState,
        previous: TlsExchangeObservation,
    ) -> bool:
        """Match a repeated Mail ad cycle before its large request replies.

        Captures showed the same small control exchange immediately before the
        ad payload at exchanges 2->3, 4->5 and 7->8.  Match the cycle, not a
        fixed ordinal, while keeping the learned byte and timing envelope
        narrow.
        """
        hello = state.hello
        pending = state.exchange
        return bool(
            hello is not None
            and hello.server_name == "mail.yandex.ru"
            and previous.exchange_index >= 2
            and pending is not None
            and pending.index == previous.exchange_index + 1
            and pending.request_record_count == 1
            and pending.response_record_count == 0
            and YANDEX_MAIL_INLINE_AD_DNA_PREVIOUS_REQUEST_MIN_BYTES
            <= previous.request_bytes
            <= YANDEX_MAIL_INLINE_AD_DNA_PREVIOUS_REQUEST_MAX_BYTES
            and YANDEX_MAIL_INLINE_AD_DNA_PREVIOUS_RESPONSE_MIN_BYTES
            <= previous.response_bytes
            <= YANDEX_MAIL_INLINE_AD_DNA_PREVIOUS_RESPONSE_MAX_BYTES
            and YANDEX_MAIL_INLINE_AD_DNA_PREVIOUS_RESPONSE_DELAY_MIN_MS
            <= previous.first_response_delay_ms
            <= YANDEX_MAIL_INLINE_AD_DNA_PREVIOUS_RESPONSE_DELAY_MAX_MS
            and previous.next_request_delay_ms is not None
            and 0
            <= previous.next_request_delay_ms
            <= YANDEX_MAIL_INLINE_AD_DNA_NEXT_REQUEST_DELAY_MAX_MS
            and YANDEX_MAIL_INLINE_AD_DNA_REQUEST_MIN_BYTES
            <= pending.request_bytes
            <= YANDEX_MAIL_INLINE_AD_DNA_REQUEST_MAX_BYTES
            and YANDEX_MAIL_INLINE_AD_DNA_FLOW_AGE_MIN_MS
            <= previous.flow_age_ms
            <= YANDEX_MAIL_INLINE_AD_DNA_FLOW_AGE_MAX_MS
        )

    def _yandex_mail_inline_small_peer_count(
        self,
        timestamp: float,
        state: _FlowState,
    ) -> int:
        count = 0
        for peer in self._flows.values():
            if (
                peer.flow == state.flow
                or peer.flow.client_ip != state.flow.client_ip
                or peer.hello is None
                or peer.hello.server_name != "mail.yandex.ru"
                or not 0
                <= timestamp - peer.hello_at
                <= YANDEX_MAIL_INLINE_OUTLIER_PEER_WINDOW_SECONDS
            ):
                continue
            exchange = peer.exchange
            if exchange is not None and (
                exchange.index == 1
                and YANDEX_MAIL_INLINE_OUTLIER_PEER_REQUEST_MIN_BYTES
                <= exchange.request_bytes
                <= YANDEX_MAIL_INLINE_OUTLIER_PEER_REQUEST_MAX_BYTES
                and YANDEX_MAIL_INLINE_OUTLIER_PEER_RESPONSE_MIN_BYTES
                <= exchange.response_bytes
                <= YANDEX_MAIL_INLINE_OUTLIER_PEER_RESPONSE_MAX_BYTES
            ):
                count += 1
                continue
            completed = peer.last_completed_exchange
            if completed is not None and (
                completed.exchange_index == 1
                and YANDEX_MAIL_INLINE_OUTLIER_PEER_REQUEST_MIN_BYTES
                <= completed.request_bytes
                <= YANDEX_MAIL_INLINE_OUTLIER_PEER_REQUEST_MAX_BYTES
                and YANDEX_MAIL_INLINE_OUTLIER_PEER_RESPONSE_MIN_BYTES
                <= completed.response_bytes
                <= YANDEX_MAIL_INLINE_OUTLIER_PEER_RESPONSE_MAX_BYTES
            ):
                count += 1
        return count

    def _could_assess_yandex_mail_inline_response_outlier(
        self,
        timestamp: float,
        state: _FlowState,
    ) -> bool:
        hello = state.hello
        exchange = state.exchange
        return bool(
            not state.yandex_mail_inline_response_outlier_emitted
            and hello is not None
            and hello.server_name == "mail.yandex.ru"
            and exchange is not None
            and exchange.index in (1, 2)
            and YANDEX_MAIL_INLINE_OUTLIER_REQUEST_MIN_BYTES
            <= exchange.request_bytes
            <= YANDEX_MAIL_INLINE_OUTLIER_REQUEST_MAX_BYTES
            and exchange.response_bytes >= YANDEX_MAIL_INLINE_OUTLIER_RESPONSE_MIN_BYTES
            and exchange.first_response_at
            and 0
            <= round((exchange.first_response_at - exchange.started_at) * 1_000)
            <= YANDEX_MAIL_INLINE_OUTLIER_MAX_FIRST_RESPONSE_DELAY_MS
            and 0
            <= round((timestamp - state.hello_at) * 1_000)
            <= YANDEX_MAIL_INLINE_OUTLIER_MAX_FLOW_AGE_MS
            and self._yandex_mail_inline_small_peer_count(timestamp, state)
            >= YANDEX_MAIL_INLINE_OUTLIER_MIN_PEERS
        )

    def _could_assess_yandex_mail_inline_payload_dna(
        self,
        timestamp: float,
        state: _FlowState,
    ) -> bool:
        """Recognize the repeated ~473 KiB Mail ad payload after two records."""
        hello = state.hello
        exchange = state.exchange
        return bool(
            not state.yandex_mail_inline_response_outlier_emitted
            and hello is not None
            and hello.server_name == "mail.yandex.ru"
            and exchange is not None
            and YANDEX_MAIL_INLINE_PAYLOAD_REQUEST_MIN_BYTES
            <= exchange.request_bytes
            <= YANDEX_MAIL_INLINE_PAYLOAD_REQUEST_MAX_BYTES
            and exchange.response_record_count
            >= YANDEX_MAIL_INLINE_PAYLOAD_MIN_RESPONSE_RECORDS
            and exchange.response_bytes >= YANDEX_MAIL_INLINE_PAYLOAD_RESPONSE_MIN_BYTES
            and exchange.first_response_at
            and 0
            <= round((exchange.first_response_at - exchange.started_at) * 1_000)
            <= YANDEX_MAIL_INLINE_PAYLOAD_MAX_FIRST_RESPONSE_DELAY_MS
            and 0
            <= round((timestamp - state.hello_at) * 1_000)
            <= YANDEX_MAIL_INLINE_PAYLOAD_MAX_FLOW_AGE_MS
        )

    def _could_assess_uniform_root_successor(
        self,
        state: _FlowState,
    ) -> bool:
        hello = state.hello
        if (
            hello is None
            or state.successor_exchange_conveyor_emitted
            or len(state.completed_exchanges) < SUCCESSOR_EXCHANGE_COUNT
            or hello.record_length > 640
            or hello.psk_identity_lengths
            or not _is_root_server_name(hello.server_name)
        ):
            return False
        return any(
            item.flow != state.flow
            and state.hello_at - UNIFORM_ROOT_SUCCESSOR_WINDOW_SECONDS
            <= item.timestamp
            <= state.hello_at
            and item.flow.server_ip == state.flow.server_ip
            and item.flow.server_port == state.flow.server_port
            and item.server_name != hello.server_name
            and item.tls_fingerprint != hello.fingerprint
            for item in self._confirmed_uniform_root_conveyors.get(
                state.flow.client_ip, ()
            )
        )

    def _uniform_root_exchange_cluster(
        self,
        timestamp: float,
        state: _FlowState,
    ) -> tuple[int, int, float, float]:
        hello = state.hello
        if (
            hello is None
            or hello.record_length > 640
            or not _is_root_server_name(hello.server_name)
        ):
            return 0, 0, 0.0, 0.0
        recent = [
            item
            for item in self._completed_root_exchanges.get(state.flow.client_ip, ())
            if item.flow != state.flow
            and timestamp - ROOT_EXCHANGE_CONVEYOR_WINDOW_SECONDS
            <= item.timestamp
            <= timestamp
            and item.flow.server_ip == state.flow.server_ip
            and item.flow.server_port == state.flow.server_port
            and item.server_name == hello.server_name
            and item.tls_fingerprint == hello.fingerprint
        ]
        best: list[_CompletedRootExchange] = []
        for anchor in recent:
            cluster = [
                item
                for item in recent
                if _relative_distance(item.request_bytes, anchor.request_bytes)
                <= ROOT_EXCHANGE_REQUEST_SPREAD_MAX / 2
                and _relative_distance(item.response_bytes, anchor.response_bytes)
                <= ROOT_EXCHANGE_RESPONSE_SPREAD_MAX / 2
            ]
            if len(cluster) > len(best):
                best = cluster
        if not best:
            return 0, 0, 0.0, 0.0
        requests = [item.request_bytes for item in best]
        responses = [item.response_bytes for item in best]
        request_spread = _relative_spread(requests)
        response_spread = _relative_spread(responses)
        if (
            request_spread > ROOT_EXCHANGE_REQUEST_SPREAD_MAX
            or response_spread > ROOT_EXCHANGE_RESPONSE_SPREAD_MAX
        ):
            return 0, 0, 0.0, 0.0
        times = [item.timestamp for item in best]
        return (
            len(best),
            max(0, round((max(times) - min(times)) * 1_000)),
            round(request_spread, 3),
            round(response_spread, 3),
        )

    def _finalize_flow_exchange(
        self,
        state: _FlowState,
        *,
        completion_reason: str,
    ) -> TlsExchangeObservation | None:
        exchange = state.exchange
        if exchange is None or not exchange.response_record_count:
            return None
        state.exchange = None
        return self._complete_tls_exchange(
            exchange.last_response_at,
            state,
            exchange,
            completion_reason=completion_reason,
        )

    def _attach_node(
        self, timestamp: float, flow: FlowKey, hello: TlsClientHello
    ) -> tuple[int, float]:
        nodes = self._nodes[flow.client_ip]
        while nodes and nodes[0].timestamp < timestamp - GRAPH_WINDOW_SECONDS:
            nodes.popleft()
        best_score = 0.0
        best_session = 0
        for node in nodes:
            score = _edge_score(timestamp, flow, hello, node)
            if score > best_score:
                best_score = score
                best_session = node.session_id
        if best_score < 0.42:
            best_session = self._next_session_id
            self._next_session_id += 1
            best_score = 0.0
        nodes.append(_GraphNode(timestamp, flow, hello, best_session))
        while len(nodes) > MAX_GRAPH_NODES_PER_CLIENT:
            nodes.popleft()
        return best_session, best_score
