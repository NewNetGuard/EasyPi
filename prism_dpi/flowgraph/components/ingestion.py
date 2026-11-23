"""Ingestion behavior for FlowGraphEngine."""

from prism_dpi.flowgraph.foundation import (
    CONFIRMED_ROOT_CONTINUATION_WINDOW_SECONDS,
    Direction,
    DnsEvent,
    DnsMessage,
    FLOW_IDLE_SECONDS,
    FlowAssessment,
    MAX_ACTIVE_FLOWS,
    MAX_FLOW_RECORDS,
    MAX_OPAQUE_QUIC_OBSERVATIONS_PER_FLOW,
    MAX_OPAQUE_QUIC_STATES,
    MAX_PENDING_DNS_QUERIES,
    MAX_QUIC_CRYPTO_STATES,
    MAX_UDP443_OBSERVATIONS_PER_FLOW,
    MAX_UDP443_STATES,
    OPAQUE_QUIC_IDLE_SECONDS,
    OPAQUE_QUIC_OBSERVATION_INTERVAL_SECONDS,
    OpaqueQuicFlowObservation,
    OpaqueQuicFlowPacket,
    PAIRED_ROOT_CONTEXT_WINDOW_SECONDS,
    QUIC_CRYPTO_IDLE_SECONDS,
    QuicInitialObservation,
    QuicInitialPacket,
    ROOT_EXCHANGE_CONVEYOR_WINDOW_SECONDS,
    ROOT_PROFILE_CYCLE_CONTEXT_WINDOW_SECONDS,
    SUCCESSOR_RESUMPTION_CONTEXT_WINDOW_SECONDS,
    TcpPacket,
    TlsExchangeObservation,
    TlsRecord,
    TlsRecordSequenceObservation,
    UDP443_IDLE_SECONDS,
    UDP443_OBSERVATION_INTERVAL_SECONDS,
    UNIFORM_ROOT_SETUP_CONTEXT_WINDOW_SECONDS,
    UNIFORM_ROOT_SUCCESSOR_WINDOW_SECONDS,
    Udp443FlowObservation,
    UnclassifiedUdp443Packet,
    Verdict,
    _FlowState,
    _OpaqueQuicState,
    _QuicCryptoState,
    _Udp443State,
    deque,
    parse_client_hello,
)


class IngestionMixin:
    """Internal behavior mixed into the stable engine facade."""

    @property
    def active_flows(self) -> int:
        return len(self._flows)

    def ingest(
        self,
        event: (
            TcpPacket
            | DnsMessage
            | QuicInitialPacket
            | OpaqueQuicFlowPacket
            | UnclassifiedUdp443Packet
        ),
    ) -> list[
        FlowAssessment
        | QuicInitialObservation
        | OpaqueQuicFlowObservation
        | Udp443FlowObservation
        | TlsExchangeObservation
        | TlsRecordSequenceObservation
    ]:
        self.packets_seen += 1
        expired = self.expire(event.timestamp)
        if isinstance(event, DnsMessage):
            self._ingest_dns(event)
            return expired
        if isinstance(event, QuicInitialPacket):
            return [*expired, *self._ingest_quic(event)]
        if isinstance(event, OpaqueQuicFlowPacket):
            return [*expired, *self._ingest_opaque_quic(event)]
        if isinstance(event, UnclassifiedUdp443Packet):
            return [*expired, *self._ingest_udp443(event)]
        return [*expired, *self._ingest_tcp(event)]

    def expire(
        self, now: float
    ) -> list[TlsExchangeObservation | TlsRecordSequenceObservation]:
        observations: list[TlsExchangeObservation | TlsRecordSequenceObservation] = []
        cutoff = now - FLOW_IDLE_SECONDS
        for key in [
            key for key, state in self._flows.items() if state.last_seen < cutoff
        ]:
            observation = self._finalize_flow_exchange(
                self._flows[key],
                completion_reason="flow_expired",
            )
            if observation is not None:
                observations.append(observation)
            record_observation = self._finalize_flow_record_sequence(
                self._flows[key],
                completion_reason="flow_expired",
            )
            if record_observation is not None:
                observations.append(record_observation)
            del self._flows[key]
        graph_cutoff = now - FLOW_IDLE_SECONDS
        for client_ip, nodes in list(self._nodes.items()):
            while nodes and nodes[0].timestamp < graph_cutoff:
                nodes.popleft()
            if not nodes:
                del self._nodes[client_ip]
        retry_cutoff = now - CONFIRMED_ROOT_CONTINUATION_WINDOW_SECONDS
        for client_ip, roots in list(self._confirmed_large_roots.items()):
            while roots and roots[0].timestamp < retry_cutoff:
                roots.popleft()
            if not roots:
                del self._confirmed_large_roots[client_ip]
        exchange_cutoff = now - ROOT_EXCHANGE_CONVEYOR_WINDOW_SECONDS
        for client_ip, exchanges in list(self._completed_root_exchanges.items()):
            while exchanges and exchanges[0].timestamp < exchange_cutoff:
                exchanges.popleft()
            if not exchanges:
                del self._completed_root_exchanges[client_ip]
        conveyor_cutoff = now - UNIFORM_ROOT_SUCCESSOR_WINDOW_SECONDS
        for client_ip, conveyors in list(
            self._confirmed_uniform_root_conveyors.items()
        ):
            while conveyors and conveyors[0].timestamp < conveyor_cutoff:
                conveyors.popleft()
            if not conveyors:
                del self._confirmed_uniform_root_conveyors[client_ip]
        setup_context_cutoff = now - UNIFORM_ROOT_SETUP_CONTEXT_WINDOW_SECONDS
        for client_ip, contexts in list(
            self._confirmed_uniform_root_setup_contexts.items()
        ):
            while contexts and contexts[0].timestamp < setup_context_cutoff:
                contexts.popleft()
            if not contexts:
                del self._confirmed_uniform_root_setup_contexts[client_ip]
        successor_context_cutoff = now - SUCCESSOR_RESUMPTION_CONTEXT_WINDOW_SECONDS
        for client_ip, contexts in list(
            self._confirmed_uniform_root_successor_contexts.items()
        ):
            while contexts and contexts[0].timestamp < successor_context_cutoff:
                contexts.popleft()
            if not contexts:
                del self._confirmed_uniform_root_successor_contexts[client_ip]
        profile_cycle_cutoff = now - ROOT_PROFILE_CYCLE_CONTEXT_WINDOW_SECONDS
        for client_ip, contexts in list(self._confirmed_root_profile_cycles.items()):
            while contexts and contexts[0].timestamp < profile_cycle_cutoff:
                contexts.popleft()
            if not contexts:
                del self._confirmed_root_profile_cycles[client_ip]
        paired_root_cutoff = now - PAIRED_ROOT_CONTEXT_WINDOW_SECONDS
        for client_ip, contexts in list(self._confirmed_paired_root_conveyors.items()):
            retained = deque(
                item for item in contexts if item.active_at >= paired_root_cutoff
            )
            if retained:
                self._confirmed_paired_root_conveyors[client_ip] = retained
            else:
                del self._confirmed_paired_root_conveyors[client_ip]
        dns_cutoff = now - FLOW_IDLE_SECONDS
        for client_ip, events in list(self._blocked_dns.items()):
            while events and events[0].timestamp < dns_cutoff:
                events.popleft()
            if not events:
                del self._blocked_dns[client_ip]
        for key, (timestamp, _) in list(self._dns_queries.items()):
            if timestamp < dns_cutoff:
                del self._dns_queries[key]
        for key, state in list(self._quic_crypto.items()):
            if state.last_seen < now - QUIC_CRYPTO_IDLE_SECONDS:
                del self._quic_crypto[key]
        for key, state in list(self._opaque_quic.items()):
            if state.last_seen < now - OPAQUE_QUIC_IDLE_SECONDS:
                del self._opaque_quic[key]
        for key, state in list(self._udp443.items()):
            if state.last_seen < now - UDP443_IDLE_SECONDS:
                del self._udp443[key]
        return observations

    def finalize(
        self, *, completion_reason: str
    ) -> list[TlsExchangeObservation | TlsRecordSequenceObservation]:
        observations: list[TlsExchangeObservation | TlsRecordSequenceObservation] = []
        for state in self._flows.values():
            observation = self._finalize_flow_exchange(
                state,
                completion_reason=completion_reason,
            )
            if observation is not None:
                observations.append(observation)
            record_observation = self._finalize_flow_record_sequence(
                state,
                completion_reason=completion_reason,
            )
            if record_observation is not None:
                observations.append(record_observation)
        return observations

    def snapshot(self) -> dict[str, int]:
        return {
            "packets_seen": self.packets_seen,
            "tls_hellos_seen": self.tls_hellos_seen,
            "quic_hellos_seen": self.quic_hellos_seen,
            "opaque_quic_flows_seen": self.opaque_quic_flows_seen,
            "opaque_quic_observations_emitted": (self.opaque_quic_observations_emitted),
            "udp_443_flows_seen": self.udp_443_flows_seen,
            "udp_443_observations_emitted": self.udp_443_observations_emitted,
            "tls_exchanges_seen": self.tls_exchanges_seen,
            "tls_record_sequences_seen": self.tls_record_sequences_seen,
            "blocked_dns_seen": self.blocked_dns_seen,
            "active_flows": self.active_flows,
            "graph_clients": len(self._nodes),
            "assessments_emitted": self.assessments_emitted,
            "candidate_assessments": self.candidate_assessments,
        }

    def _ingest_quic(self, packet: QuicInitialPacket) -> list[QuicInitialObservation]:
        hello = packet.hello
        state_key = (packet.flow, packet.version, packet.destination_connection_id)
        if hello is None:
            state = self._quic_crypto.get(state_key)
            if state is None:
                if len(self._quic_crypto) >= MAX_QUIC_CRYPTO_STATES:
                    self._quic_crypto.pop(next(iter(self._quic_crypto)))
                state = _QuicCryptoState(last_seen=packet.timestamp)
                self._quic_crypto[state_key] = state
            state.last_seen = packet.timestamp
            for offset, fragment in packet.crypto_fragments:
                if offset not in state.fragments:
                    state.fragments[offset] = fragment
                    state.total_bytes += len(fragment)
            if state.total_bytes > 16_384:
                del self._quic_crypto[state_key]
                return []
            crypto = bytearray()
            while len(crypto) in state.fragments:
                crypto.extend(state.fragments[len(crypto)])
            hello = parse_client_hello(TlsRecord(22, b"\x03\x03", bytes(crypto)))
            if hello is None:
                return []
        self._quic_crypto.pop(state_key, None)
        self.quic_hellos_seen += 1
        return [
            QuicInitialObservation(
                timestamp=packet.timestamp,
                flow=packet.flow,
                version=packet.version,
                destination_connection_id_length=len(packet.destination_connection_id),
                hello=hello,
            )
        ]

    def _ingest_opaque_quic(
        self,
        packet: OpaqueQuicFlowPacket,
    ) -> list[OpaqueQuicFlowObservation]:
        state = self._opaque_quic.get(packet.flow)
        if state is None:
            if len(self._opaque_quic) >= MAX_OPAQUE_QUIC_STATES:
                self._opaque_quic.pop(next(iter(self._opaque_quic)))
            state = _OpaqueQuicState(last_seen=packet.timestamp)
            self._opaque_quic[packet.flow] = state
            self.opaque_quic_flows_seen += 1
        else:
            state.last_seen = max(state.last_seen, packet.timestamp)

        if state.observations_emitted >= MAX_OPAQUE_QUIC_OBSERVATIONS_PER_FLOW:
            return []
        if (
            state.observations_emitted
            and packet.timestamp - state.last_emitted
            < OPAQUE_QUIC_OBSERVATION_INTERVAL_SECONDS
        ):
            return []

        state.last_emitted = packet.timestamp
        state.observations_emitted += 1
        self.opaque_quic_observations_emitted += 1
        return [
            OpaqueQuicFlowObservation(
                timestamp=packet.timestamp,
                flow=packet.flow,
                datagram_bytes=packet.datagram_bytes,
                header_form=packet.header_form,
            )
        ]

    def _ingest_udp443(
        self,
        packet: UnclassifiedUdp443Packet,
    ) -> list[Udp443FlowObservation]:
        state = self._udp443.get(packet.flow)
        if state is None:
            if len(self._udp443) >= MAX_UDP443_STATES:
                self._udp443.pop(next(iter(self._udp443)))
            state = _Udp443State(last_seen=packet.timestamp)
            self._udp443[packet.flow] = state
            self.udp_443_flows_seen += 1
        else:
            state.last_seen = max(state.last_seen, packet.timestamp)

        if state.observations_emitted >= MAX_UDP443_OBSERVATIONS_PER_FLOW:
            return []
        if (
            state.observations_emitted
            and packet.timestamp - state.last_emitted
            < UDP443_OBSERVATION_INTERVAL_SECONDS
        ):
            return []

        state.last_emitted = packet.timestamp
        state.observations_emitted += 1
        self.udp_443_observations_emitted += 1
        return [
            Udp443FlowObservation(
                timestamp=packet.timestamp,
                flow=packet.flow,
                datagram_bytes=packet.datagram_bytes,
            )
        ]

    def _ingest_dns(self, message: DnsMessage) -> None:
        key = (message.client_ip, message.transaction_id)
        if not message.is_response:
            if len(self._dns_queries) >= MAX_PENDING_DNS_QUERIES:
                self._dns_queries.pop(next(iter(self._dns_queries)))
            self._dns_queries[key] = (message.timestamp, message.query_name)
            return
        query = self._dns_queries.pop(key, None)
        query_name = query[1] if query else message.query_name
        if message.blocked and query_name:
            self.blocked_dns_seen += 1
            self._blocked_dns[message.client_ip].append(
                DnsEvent(message.timestamp, message.client_ip, query_name, True)
            )

    def _ingest_tcp(
        self, packet: TcpPacket
    ) -> list[FlowAssessment | TlsExchangeObservation | TlsRecordSequenceObservation]:
        state = self._flows.get(packet.flow)
        if state is None:
            if len(self._flows) >= MAX_ACTIVE_FLOWS:
                self._flows.pop(next(iter(self._flows)))
            state = _FlowState(packet.flow, packet.timestamp, packet.timestamp)
            self._flows[packet.flow] = state
        state.last_seen = packet.timestamp
        direction = (
            state.client
            if packet.direction is Direction.CLIENT_TO_SERVER
            else state.server
        )
        direction.payload_bytes += len(packet.payload)
        stream = direction.assembler.feed(
            packet.sequence, packet.payload, syn=packet.syn
        )
        outputs: list[
            FlowAssessment | TlsExchangeObservation | TlsRecordSequenceObservation
        ] = []
        for record in direction.decoder.feed(stream):
            if len(direction.record_lengths) < MAX_FLOW_RECORDS:
                direction.record_lengths.append(record.length)
                direction.record_times.append(packet.timestamp)
            if packet.direction is Direction.CLIENT_TO_SERVER and state.hello is None:
                hello = parse_client_hello(record)
                if hello is not None:
                    self.tls_hellos_seen += 1
                    state.hello = hello
                    state.hello_at = packet.timestamp
                    state.session_id, state.causal_edge_score = self._attach_node(
                        packet.timestamp, packet.flow, hello
                    )
                    assessment = self._assess(packet.timestamp, state)
                    if assessment is not None:
                        outputs.append(assessment)
                        if {
                            "uniform_root_exchange_conveyor",
                            "uniform_root_endpoint_multiplex",
                        }.intersection(assessment.evidence):
                            outputs.extend(
                                self._reassess_uniform_root_endpoint_peers(
                                    packet.timestamp, state
                                )
                            )
                            outputs.extend(
                                self._reassess_uniform_root_lineage_peers(
                                    packet.timestamp, state
                                )
                            )
                            outputs.extend(
                                self._reassess_uniform_root_setup_peers(
                                    packet.timestamp, state
                                )
                            )
                        if "mirrored_root_resumption_transition" in (
                            assessment.evidence
                        ):
                            outputs.extend(
                                self._reassess_mirrored_root_peers(
                                    packet.timestamp, state
                                )
                            )
                        if "uniform_root_setup_resumption_descendant" in (
                            assessment.evidence
                        ):
                            outputs.extend(
                                self._reassess_uniform_root_setup_resumption_peers(
                                    packet.timestamp, state
                                )
                            )
                        if "uniform_root_successor_resumption_descendant" in (
                            assessment.evidence
                        ):
                            outputs.extend(
                                self._reassess_uniform_root_successor_resumption_peers(
                                    packet.timestamp, state
                                )
                            )
                        if "compact_root_profile_cycle_conveyor" in (
                            assessment.evidence
                        ):
                            outputs.extend(
                                self._reassess_root_profile_cycle_setup_peers(
                                    packet.timestamp, state
                                )
                            )
                        if "paired_root_first_exchange_conveyor" in (
                            assessment.evidence
                        ):
                            outputs.extend(
                                self._reassess_paired_root_setup_peer(
                                    packet.timestamp, state
                                )
                            )
                        if "yandex_mail_browser_root_burst" in (assessment.evidence):
                            outputs.extend(
                                self._reassess_yandex_mail_browser_root_peers(
                                    packet.timestamp, state
                                )
                            )
                    outputs.extend(self._reassess_root_peers(packet.timestamp, state))
            elif state.hello is not None and record.content_type == 23:
                record_observation = self._observe_tls_record_sequence(
                    packet.timestamp,
                    state,
                    packet.direction,
                    record.length,
                )
                if record_observation is not None:
                    outputs.append(record_observation)
                if len(direction.record_lengths) >= 4:
                    observation = self._observe_tls_exchange(
                        packet.timestamp,
                        state,
                        packet.direction,
                        record.length,
                    )
                    if observation is not None:
                        outputs.append(observation)
                    if (
                        (
                            observation is not None
                            and self._could_assess_uniform_root_successor(state)
                        )
                        or self._could_assess_paired_root_first_exchange(
                            state,
                            allow_completed=observation is not None,
                        )
                        or (
                            observation is not None
                            and self._could_assess_yandex_mail_inline_ad_request(
                                state,
                                observation,
                            )
                        )
                        or self._could_assess_yandex_mail_inline_response_outlier(
                            packet.timestamp,
                            state,
                        )
                        or self._could_assess_yandex_mail_inline_payload_dna(
                            packet.timestamp,
                            state,
                        )
                        or (
                            observation is not None
                            and self._could_assess_yandex_mail_inline_ad_dna_request(
                                state,
                                observation,
                            )
                        )
                    ):
                        assessment = self._assess(packet.timestamp, state)
                        if assessment is not None:
                            outputs.append(assessment)
                            if (
                                "paired_root_first_exchange_conveyor"
                                in assessment.evidence
                            ):
                                outputs.extend(
                                    self._reassess_paired_root_setup_peer(
                                        packet.timestamp, state
                                    )
                                )
                # Emit only during handshake/request establishment. Bulk TLS
                # records update byte counters but must not flood JSONL output.
                if len(direction.record_lengths) <= 4:
                    assessment = self._assess(packet.timestamp, state)
                    if assessment is not None:
                        outputs.append(assessment)
        if (packet.fin or packet.rst) and state.hello is not None:
            observation = self._finalize_flow_exchange(
                state,
                completion_reason="flow_closed",
            )
            if observation is not None:
                outputs.append(observation)
            record_observation = self._finalize_flow_record_sequence(
                state,
                completion_reason="flow_closed",
            )
            if record_observation is not None:
                outputs.append(record_observation)
            assessment = self._assess(packet.timestamp, state)
            if assessment is not None:
                outputs.append(assessment)
            self._flows.pop(packet.flow, None)
        assessments = [
            output for output in outputs if isinstance(output, FlowAssessment)
        ]
        self.assessments_emitted += len(assessments)
        self.candidate_assessments += sum(
            assessment.verdict is Verdict.CANDIDATE for assessment in assessments
        )
        return outputs
