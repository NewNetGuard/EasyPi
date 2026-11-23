"""Observation-only coordinator: scoped keys, admission budgets and honest coverage."""

from collections import OrderedDict, deque
from dataclasses import asdict, replace
import json
import re
import threading
import time
from .models import Endpoint, InspectionState, Limits, Provenance, Snapshot
from .transport import InputError, TCPAssembler, parse_ip_packet
from .tls import Secrets, Session
from .decode_errors import CODES


class _Flow:
    def __init__(
        self,
        flow_id,
        transport,
        provenance,
        client,
        server,
        now,
        limits,
        key_session_id=None,
    ):
        self.flow_id, self.transport, self.provenance = flow_id, transport, provenance
        self.client, self.server = client, server
        self.created = self.last = now
        self.key_time = None
        self.abort = None
        self.requests = 0
        self.inputs = 0
        self.input_bytes = 0
        self.saw_initial = False
        self.quic_gap_since = None
        self.secrets = Secrets(
            limits.max_keys, scoped=True, expected_random=key_session_id
        )
        self.assemblers = (
            [
                TCPAssembler(
                    limits.reassembly_bytes, limits.history_bytes, limits.max_segments
                )
                for _ in range(2)
            ]
            if transport == "tcp"
            else []
        )
        self.core = None
        self.snapshot = Snapshot(
            flow_id, transport, InspectionState.UNKNOWN, "awaiting_capture", provenance
        )


class Bridge:
    """No sockets, files, routes or production hooks are opened by this class.

    Call from a dedicated bounded worker. Exported key material must already
    have been authenticated by the embedding collector. The API binds it to
    one explicitly opted-in flow/provenance, not all traffic of an IP address.
    """

    def __init__(self, limits=None, clock=time.monotonic):
        self.limits = limits or Limits()
        self.clock = clock
        self.lock = threading.RLock()
        self.flows = OrderedDict()
        self.closed = OrderedDict()
        self.events = deque()
        self.counts = {
            name: 0
            for name in (
                "opened",
                "closed",
                "headers",
                "key_rejected",
                "resource_rejected",
                "events_dropped",
                "invalid_packets",
                "loss_reports",
                "key_updates",
                "invalid_secret",
                "key_store_full",
                "unrelated_session",
            )
        }
        self.stopped = False
        self.external_reserved = 0
        self.peak_reserved = self.limits.fixed_bytes

    @property
    def reserved_bytes(self):
        return (
            self.limits.fixed_bytes
            + self.external_reserved
            + len(self.flows) * self.limits.per_connection_bytes
        )

    def open_flow(
        self, flow_id, transport, provenance, client, server, key_session_id=None
    ):
        with self.lock:
            self.poll()
            if self.stopped:
                raise RuntimeError("bridge is closed")
            if (
                not isinstance(flow_id, str)
                or not 1 <= len(flow_id) <= 128
                or any(ord(c) < 32 for c in flow_id)
            ):
                raise ValueError("invalid flow identifier")
            if (
                transport not in {"tcp", "quic"}
                or not isinstance(provenance, Provenance)
                or not provenance.opt_in
            ):
                raise ValueError("explicit opt-in transport provenance is required")
            if (
                not isinstance(client, Endpoint)
                or not isinstance(server, Endpoint)
                or client == server
            ):
                raise ValueError("distinct registered endpoints are required")
            if key_session_id is not None and (
                not isinstance(key_session_id, str)
                or not re.fullmatch(r"[0-9a-fA-F]{64}", key_session_id)
            ):
                raise ValueError("invalid key session identifier")
            if flow_id in self.flows or flow_id in self.closed:
                raise ValueError(
                    "flow identifiers must be unique per capture generation"
                )
            if (
                len(self.flows) >= self.limits.max_connections
                or self.reserved_bytes + self.limits.per_connection_bytes
                > self.limits.global_bytes
            ):
                self.counts["resource_rejected"] += 1
                self.closed[flow_id] = Snapshot(
                    flow_id,
                    transport,
                    InspectionState.UNKNOWN,
                    "admission_budget",
                    provenance,
                    transport_closed=True,
                )
                while len(self.closed) > self.limits.max_closed:
                    self.closed.popitem(last=False)
                return False
            flow = _Flow(
                flow_id,
                transport,
                provenance,
                client,
                server,
                self.clock(),
                self.limits,
                key_session_id,
            )

            def callback(event):
                self._decoder_event(flow_id, event)

            if transport == "tcp":
                flow.core = Session(
                    flow.secrets,
                    callback,
                    self.limits.decoder_buffer_bytes,
                    self.limits.header_bytes,
                    self.limits.max_header_fields,
                )
            else:
                from .quic import AdaptiveQUICSession

                flow.core = AdaptiveQUICSession(
                    flow.secrets, callback, self.limits, self.clock
                )
            self.flows[flow_id] = flow
            self.counts["opened"] += 1
            self.peak_reserved = max(self.peak_reserved, self.reserved_bytes)
            return True

    def add_key(self, flow_id, line, provenance):
        with self.lock:
            self.poll()
            flow = self.flows.get(flow_id)
            if flow is None or provenance != flow.provenance or not provenance.opt_in:
                self.counts["key_rejected"] += 1
                return False
            pressure = flow.secrets.store_pressure
            accepted = flow.secrets.add(line)
            self.counts["key_store_full"] += flow.secrets.store_pressure - pressure
            if flow.secrets.last_error in {"invalid_secret", "key_store_full"}:
                flow.snapshot = replace(
                    flow.snapshot, diagnostic=flow.secrets.last_error
                )
            if not accepted:
                self.counts["key_rejected"] += 1
                if flow.secrets.last_error in {"invalid_secret", "unrelated_session"}:
                    self.counts[flow.secrets.last_error] += 1
                return False
            flow.key_time = self.clock()
            flow.core.retry()
            self._check(flow)
            return flow_id in self.flows

    def feed_packet(self, flow_id, packet, capture_point):
        with self.lock:
            flow = self._get(flow_id, capture_point)
            if flow is None:
                return False
            try:
                parsed = parse_ip_packet(packet)
                if parsed.protocol != flow.transport:
                    raise InputError("transport_mismatch")
                if (parsed.source, parsed.destination) == (flow.client, flow.server):
                    client = True
                elif (parsed.source, parsed.destination) == (flow.server, flow.client):
                    client = False
                else:
                    raise InputError("endpoint_mismatch")
                if parsed.protocol == "tcp":
                    if parsed.rst:
                        self._finish(flow, InspectionState.UNKNOWN, "tcp_reset")
                        return False
                    return self.feed_tcp(
                        flow_id,
                        client,
                        parsed.sequence,
                        parsed.payload,
                        capture_point,
                        parsed.syn,
                        parsed.fin,
                    )
                return self.feed_udp(flow_id, client, parsed.payload, capture_point)
            except (InputError, ValueError):
                self.counts["invalid_packets"] += 1
                self._finish(
                    flow, InspectionState.UNKNOWN, "invalid_or_unsupported_packet"
                )
                return False

    def _get(self, flow_id, capture_point):
        self.poll()
        flow = self.flows.get(flow_id)
        if flow is None:
            return None
        if capture_point != flow.provenance.capture_point:
            self._finish(flow, InspectionState.UNKNOWN, "capture_point_mismatch")
            return None
        return flow

    def feed_tcp(
        self, flow_id, client, sequence, data, capture_point, syn=False, fin=False
    ):
        with self.lock:
            flow = self._get(flow_id, capture_point)
            if flow is None:
                return False
            if flow.transport != "tcp":
                raise ValueError("TCP input for non-TCP flow")
            if not self._input(flow, data):
                return False
            assembler = flow.assemblers[0 if client else 1]
            try:
                for part in assembler.feed(sequence, data, self.clock(), syn, fin):
                    flow.core.feed(client, part)
                    if flow.abort:
                        break
            except InputError as error:
                self._finish(flow, InspectionState.UNKNOWN, str(error))
                return False
            self._check(flow)
            if flow_id not in self.flows:
                return False
            if any(a.gap_since is not None for a in flow.assemblers):
                flow.snapshot = replace(
                    flow.snapshot,
                    state=InspectionState.UNKNOWN,
                    reason="tcp_gap_pending",
                    request_headers_complete=False,
                )
            elif flow.snapshot.reason == "tcp_gap_pending":
                flow.snapshot = replace(
                    flow.snapshot,
                    state=InspectionState.DECRYPTED
                    if flow.requests
                    else InspectionState.METADATA,
                    reason="authenticated_request_headers"
                    if flow.requests
                    else "awaiting_matching_keys",
                    request_headers_complete=bool(flow.requests),
                )
            if all(a.closed for a in flow.assemblers):
                self._finish(flow, flow.snapshot.state, "transport_closed")
            return True

    def feed_udp(self, flow_id, client, data, capture_point):
        with self.lock:
            flow = self._get(flow_id, capture_point)
            if flow is None:
                return False
            if flow.transport != "quic":
                raise ValueError("UDP input for non-QUIC flow")
            if not self._input(flow, data):
                return False
            if not client:
                flow.core.observe_server(data)
            else:
                if data and data[0] & 128:
                    from aioquic.buffer import Buffer
                    from aioquic.quic.packet import pull_quic_header, QuicPacketType

                    try:
                        flow.saw_initial |= (
                            pull_quic_header(
                                Buffer(data=data), host_cid_length=8
                            ).packet_type
                            == QuicPacketType.INITIAL
                        )
                    except Exception:
                        self._finish(
                            flow, InspectionState.UNKNOWN, "malformed_quic_header"
                        )
                        return False
                if not flow.saw_initial:
                    self._finish(flow, InspectionState.UNKNOWN, "quic_missing_initial")
                    return False
                flow.core.feed(data)
            self._check(flow)
            return flow_id in self.flows

    def _input(self, flow, data):
        if not isinstance(data, bytes) or len(data) > 65535:
            self._finish(flow, InspectionState.UNKNOWN, "input_size_limit")
            return False
        flow.last = self.clock()
        flow.inputs += 1
        flow.input_bytes += len(data)
        if (
            flow.inputs > self.limits.max_packets * 4
            or flow.input_bytes > 16 * 1024 * 1024
        ):
            self._finish(flow, InspectionState.UNKNOWN, "input_work_budget")
            return False
        if (
            flow.snapshot.state == InspectionState.UNKNOWN
            and flow.snapshot.reason == "awaiting_capture"
        ):
            flow.snapshot = replace(
                flow.snapshot,
                state=InspectionState.METADATA,
                reason="awaiting_matching_keys",
                coverage="transport_metadata",
            )
        return True

    def _decoder_event(self, flow_id, event):
        flow = self.flows.get(flow_id)
        if flow is None or flow.abort:
            return
        kind = event.get("type")
        if kind in {"tls_key_update", "quic_key_update"}:
            name = (
                "server_key_generation"
                if event.get("direction") == "server"
                else "client_key_generation"
            )
            flow.snapshot = replace(flow.snapshot, **{name: event["generation"]})
            self.counts["key_updates"] += 1
            return
        if kind == "invalid_secret":
            self.counts["invalid_secret"] += 1
            flow.snapshot = replace(
                flow.snapshot,
                state=InspectionState.UNKNOWN,
                diagnostic="invalid_secret",
                request_headers_complete=False,
            )
            return
        if kind in {"analysis_unavailable", "quic_analysis_unavailable"}:
            code = event.get("error_code")
            if kind == "quic_analysis_unavailable":
                code = code if isinstance(code, str) and code in CODES else "frame.internal"
                flow.snapshot = replace(flow.snapshot, decoder_code=code)
                if code in {"limits.qpack_table_capacity", "limits.qpack_entry_capacity"}:
                    measured = {}
                    for source, target in (("requested_bytes", "decoder_requested_bytes"),
                                           ("limit_bytes", "decoder_limit_bytes")):
                        value = event.get(source)
                        if type(value) is int and 0 <= value < 1 << 62:
                            measured[target] = value
                    flow.snapshot = replace(flow.snapshot, **measured)
            flow.abort = (
                "invalid_secret"
                if code == "aead.authentication_failed" or (
                    kind == "analysis_unavailable" and "authentication failed" in event.get("reason", ""))
                else "decoder_error"
            )
            return
        if kind != "http_request":
            return
        request = {
            key: event.get(key)
            for key in ("protocol", "stream_id", "method", "authority", "scheme")
        }
        path = event.get("path")
        if not isinstance(path, str) or not path.startswith("/") or len(path) > 8192:
            flow.abort = "unsupported_request_target"
            return
        request["path"] = path.split("?", 1)[0].split("#", 1)[
            0
        ]  # Query strings can contain credentials.
        if any(
            isinstance(value, str)
            and (len(value) > 2048 or any(ord(c) < 32 for c in value))
            for value in request.values()
        ):
            flow.abort = "request_metadata_limit"
            return
        if "@" in (request.get("authority") or ""):
            flow.abort = "sensitive_authority"
            return
        result = {
            "type": "request_headers",
            "flow_id": flow_id,
            "state": InspectionState.DECRYPTED.value,
            "reason": "authenticated_request_headers",
            "coverage": "request_headers_only",
            "direction": "client",
            "request_headers_complete": True,
            "body_inspected": False,
            "request": request,
            "provenance": asdict(flow.provenance),
        }
        if (
            len(json.dumps(result).encode()) > self.limits.event_bytes
            or len(self.events) >= self.limits.max_events
        ):
            self.counts["events_dropped"] += 1
            flow.abort = "output_backpressure"
            return
        self.events.append(result)
        flow.requests += 1
        self.counts["headers"] += 1
        flow.snapshot = replace(
            flow.snapshot,
            state=InspectionState.DECRYPTED,
            reason="authenticated_request_headers",
            diagnostic="none",
            coverage="request_headers_only",
            request_headers_complete=True,
        )

    def _resident(self, flow):
        size = sum(a.resident_bytes for a in flow.assemblers)
        core = flow.core
        if flow.transport == "tcp":
            for direction in (core.client, core.server):
                size += (
                    len(direction.buffer)
                    + len(direction.handshakes)
                    + direction.pending_bytes
                )
                if direction.http:
                    size += len(direction.http.buffer) + len(
                        direction.http.headers or b""
                    )
        else:
            size += (
                core.qpack_reserved_bytes
                + core.pending_bytes
                + len(core.guard.buffer)
                + sum(len(b) for b in core.blocked_headers.values())
            )
            size += sum(
                len(s["data"]) + len(s["seen"]) + len(s["buffer"])
                for s in core.streams.values()
            )
        return size

    def _check(self, flow):
        if flow.flow_id not in self.flows:
            return
        if flow.abort or flow.core.failed:
            self._finish(flow, InspectionState.UNKNOWN, flow.abort or "decoder_error")
        elif self._resident(flow) > self.limits.per_connection_bytes:
            self._finish(flow, InspectionState.UNKNOWN, "retained_payload_budget")
        elif flow.transport == "quic":
            core = flow.core
            gap = core.crypto is not None and (
                bool(core.pending or core.blocked_headers or core.guard.buffer)
                or any(
                    state["end"] < len(state["seen"]) or state["buffer"]
                    for state in core.streams.values()
                )
            )
            if gap:
                if flow.quic_gap_since is None:
                    flow.quic_gap_since = self.clock()
                flow.snapshot = replace(
                    flow.snapshot,
                    state=InspectionState.UNKNOWN,
                    reason="quic_stream_gap_pending",
                    request_headers_complete=False,
                )
            else:
                flow.quic_gap_since = None
                if flow.snapshot.reason == "quic_stream_gap_pending":
                    flow.snapshot = replace(
                        flow.snapshot,
                        state=InspectionState.DECRYPTED
                        if flow.requests
                        else InspectionState.METADATA,
                        reason="authenticated_request_headers"
                        if flow.requests
                        else "awaiting_headers",
                        request_headers_complete=bool(flow.requests),
                    )

    def report_loss(self, flow_id, capture_point):
        with self.lock:
            self.counts["loss_reports"] += 1
            flow = self._get(flow_id, capture_point)
            if flow:
                self._finish(flow, InspectionState.UNKNOWN, "capture_loss_reported")

    def poll(self):
        with self.lock:
            now = self.clock()
            for flow in tuple(self.flows.values()):
                if now - flow.last >= self.limits.idle_seconds:
                    self._finish(flow, flow.snapshot.state, "idle_timeout")
                elif (
                    flow.key_time is not None
                    and now - flow.key_time >= self.limits.key_lease_seconds
                ):
                    self._finish(flow, InspectionState.METADATA, "key_lease_expired")
                elif (
                    not flow.requests
                    and now - flow.created >= self.limits.keys_wait_seconds
                ):
                    self._finish(
                        flow,
                        InspectionState.METADATA
                        if not flow.secrets.values
                        else InspectionState.UNKNOWN,
                        "matching_keys_timeout",
                    )
                elif any(
                    a.gap_since is not None
                    and now - a.gap_since >= self.limits.gap_seconds
                    for a in flow.assemblers
                ):
                    self._finish(flow, InspectionState.UNKNOWN, "tcp_gap_timeout")
                elif (
                    flow.transport == "quic"
                    and flow.quic_gap_since is not None
                    and now - flow.quic_gap_since >= self.limits.gap_seconds
                ):
                    self._finish(
                        flow, InspectionState.UNKNOWN, "quic_or_qpack_gap_timeout"
                    )

    def _finish(self, flow, state, reason):
        if self.flows.pop(flow.flow_id, None) is None:
            return
        if flow.transport == "quic":
            code = flow.snapshot.decoder_code
            if reason in {"matching_keys_timeout", "quic_or_qpack_gap_timeout"}:
                code = flow.core.timeout_code()
            elif reason == "key_lease_expired":
                code = "timeouts.key_lease"
            elif reason == "idle_timeout":
                code = "timeouts.idle"
            elif reason == "retained_payload_budget":
                code = "limits.retained_payload"
            elif reason == "input_work_budget":
                code = "limits.input_work"
            flow.snapshot = replace(flow.snapshot, decoder_code=code,
                quic_authenticated_packets=getattr(flow.core, "authenticated_packets", 0))
        flow.secrets.clear()
        snapshot = replace(
            flow.snapshot,
            state=state,
            reason=reason,
            diagnostic=(
                "capture_loss"
                if reason == "capture_loss_reported"
                else reason
                if reason in {"invalid_secret", "key_store_full"}
                else (
                    flow.snapshot.diagnostic
                    if flow.snapshot.diagnostic in {"invalid_secret", "key_store_full"}
                    else "matching_keys_timeout"
                )
                if reason == "matching_keys_timeout"
                else flow.snapshot.diagnostic
            ),
            transport_closed=True,
            request_headers_complete=state == InspectionState.DECRYPTED
            and flow.requests > 0,
        )
        self.closed[flow.flow_id] = snapshot
        while len(self.closed) > self.limits.max_closed:
            self.closed.popitem(last=False)
        core = flow.core
        if flow.transport == "tcp":
            for direction in (core.client, core.server):
                direction.secret = None
                direction.buffer.clear()
                direction.handshakes.clear()
                direction.pending.clear()
                if direction.http:
                    direction.http.emit = None
                    direction.http.buffer.clear()
                    direction.http.headers = None
                direction.session = None
            core.client = core.server = None
            core.output = None
        else:
            core.pending.clear()
            core.streams.clear()
            core.blocked_headers.clear()
            core.guard.buffer.clear()
            core.guard.entries.clear()
            for crypto in (core.crypto, core.previous_crypto):
                if crypto is not None:
                    crypto.teardown()
            core.crypto = core.previous_crypto = None
            core.emit = None
        flow.core = None
        flow.assemblers.clear()
        self.counts["closed"] += 1

    def close_flow(self, flow_id):
        with self.lock:
            flow = self.flows.get(flow_id)
            if flow:
                self._finish(flow, flow.snapshot.state, "caller_closed")

    def status(self, flow_id):
        with self.lock:
            self.poll()
            flow = self.flows.get(flow_id)
            return flow.snapshot if flow else self.closed.get(flow_id)

    def drain_events(self):
        with self.lock:
            result = list(self.events)
            self.events.clear()
            return result

    def metrics(self):
        with self.lock:
            self.poll()
            return dict(
                self.counts,
                active=len(self.flows),
                closed_cached=len(self.closed),
                queued_events=len(self.events),
                reserved_bytes=self.reserved_bytes,
                peak_reserved_bytes=self.peak_reserved,
                retained_payload_bytes=sum(
                    self._resident(f) for f in self.flows.values()
                ),
                retained_keys=sum(len(f.secrets.values) for f in self.flows.values()),
            )

    def reserve_external(self, amount):
        with self.lock:
            if self.stopped:
                raise RuntimeError("bridge is closed")
            if amount < 0 or self.reserved_bytes + amount > self.limits.global_bytes:
                raise ValueError("external queue exceeds global budget")
            self.external_reserved += amount
            self.peak_reserved = max(self.peak_reserved, self.reserved_bytes)

    def release_external(self, amount):
        with self.lock:
            if not 0 <= amount <= self.external_reserved:
                raise ValueError("invalid reservation release")
            self.external_reserved -= amount

    def close(self):
        with self.lock:
            self.stopped = True
            for flow in tuple(self.flows.values()):
                self._finish(flow, flow.snapshot.state, "bridge_closed")
            self.events.clear()
