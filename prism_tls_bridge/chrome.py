"""Bounded autonomous Chrome observation, using the existing passive Bridge.

No routes, verdicts, packet writes or key files. The administrator supplies one
paired device and explicit destinations. TLS keys arrive through Mobile auth.
"""
from collections import OrderedDict, Counter, deque
import hashlib
import ipaddress
import re
import secrets
import time

from .bridge import Bridge
from .models import Endpoint, Provenance, Limits
from .transport import parse_ip_packet
from .tls import LABELS


class Rejected(ValueError):
    pass


def parse_keys(lines):
    if not isinstance(lines, list) or not 1 <= len(lines) <= 32:
        raise Rejected("invalid_key_batch")
    parsed, staged = [], {}
    for line in lines:
        if not isinstance(line, str) or len(line) > 256:
            raise Rejected("invalid_key_batch")
        fields = line.split()
        if (len(fields) != 3 or fields[0] not in LABELS
            or not re.fullmatch(r"[0-9a-fA-F]{64}", fields[1])
            or not re.fullmatch(r"(?:[0-9a-fA-F]{64}|[0-9a-fA-F]{96})", fields[2])):
            raise Rejected("invalid_key_batch")
        label, random, value = fields[0], fields[1].lower(), fields[2].lower()
        if (label, random) in staged and staged[(label, random)] != value:
            raise Rejected("conflicting_key")
        staged[(label, random)] = value
        parsed.append((label, random, value))
    return parsed


class ChromeObserver:
    KEY_TTL = 60
    MAX_KEYS = 256
    MAX_FLOWS = 16

    def __init__(self, device, phone, destinations, clock=time.monotonic, *, diagnostics=False):
        if not isinstance(device, str) or not 1 <= len(device) <= 64:
            raise Rejected("invalid_device")
        self.phone = str(ipaddress.IPv4Address(phone))
        self.destinations = frozenset(str(ipaddress.IPv4Address(v)) for v in destinations)
        if not 1 <= len(self.destinations) <= 16 or self.phone in self.destinations:
            raise Rejected("invalid_destinations")
        self.device, self.clock = device, clock
        self.diagnostics = diagnostics is True
        self.observations = deque(maxlen=24)
        self.started_at = clock()
        from .chrome_diagnostics import FlowDiagnostics
        self.flow_diagnostics = FlowDiagnostics() if self.diagnostics else None
        self.bridge = Bridge(clock=clock, limits=Limits(key_lease_seconds=300))
        self.provenance = Provenance(device, "gateway-chrome", "paired-mobile", "endpoint-origin", True)
        self.keys, self.flows = OrderedDict(), {}
        self.lease, self.deadline, self.sequence, self.digest = None, 0, -1, None
        self.counts = Counter()

    def authorized(self, device):
        if device != self.device:
            raise Rejected("device_not_enabled")

    def lease_for(self, device):
        self.authorized(device)
        self.tick()
        if self.lease is None:
            self.lease = secrets.token_hex(32)
            self.sequence, self.digest = -1, None
        self.deadline = self.clock() + 60
        return dict(lease=self.lease, expires_in=60, next_sequence=self.sequence+1, max_batch=32)

    def upload(self, device, lease, sequence, lines):
        self.authorized(device)
        self.tick()
        if not self.lease or not isinstance(lease, str) or not secrets.compare_digest(lease, self.lease):
            raise Rejected("lease_expired")
        if type(sequence) is not int or not 0 <= sequence < 2**31:
            raise Rejected("invalid_sequence")
        parsed = parse_keys(lines)  # Entire batch validated before mutation.
        digest = hashlib.sha256("\n".join(lines).encode()).digest()
        if sequence == self.sequence and digest == self.digest:
            return dict(accepted=True, duplicate=True)
        if sequence != self.sequence + 1:
            raise Rejected("replayed_sequence")
        for label, random, value in parsed:
            key = (label, random)
            if key in self.keys and self.keys[key][0] != value:
                raise Rejected("conflicting_key")
        for label, random, value in parsed:
            key = (label, random)
            if key not in self.keys:
                if len(self.keys) >= self.MAX_KEYS:
                    self.keys.popitem(last=False)
                    self.counts["key_evictions"] += 1
                self.keys[key] = (value, self.clock()+self.KEY_TTL)
        self.sequence, self.digest = sequence, digest
        for fid in list(self.flows.values()):
            self._apply(fid)
        self._events()
        return dict(accepted=True, duplicate=False)

    def _apply(self, fid):
        flow = self.bridge.flows.get(fid)
        if not flow:
            return
        random = flow.core.random if flow.transport == "tcp" else getattr(flow, "chrome_random", None)
        if self.flow_diagnostics:
            self.flow_diagnostics.matched(fid, hello=bool(random), other=bool(random) and any(
                session != random and expiry > self.clock()
                for (_, session), (_, expiry) in self.keys.items()))
        if random:
            for (label, session), (value, expiry) in list(self.keys.items()):
                if fid not in self.bridge.flows:
                    # retry() can close the flow while adding an earlier label.
                    break
                if session == random and expiry > self.clock():
                    if self.flow_diagnostics:
                        self.flow_diagnostics.matched(fid, matching=True)
                    if flow.secrets.values.get((label, session)) == bytes.fromhex(value):
                        continue
                    if self.flow_diagnostics:
                        self.flow_diagnostics.matched(fid, submitted=True)
                    self.bridge.add_key(fid, f"{label} {session} {value}", self.provenance)

    def packet(self, raw):
        self.tick()
        if not self.lease:
            self.counts["packets_without_lease"] += 1
            return
        p = parse_ip_packet(raw)
        if p.source.address == self.phone and p.destination.address in self.destinations and p.destination.port == 443:
            client, server, outgoing = p.source, p.destination, True
        elif p.destination.address == self.phone and p.source.address in self.destinations and p.source.port == 443:
            client, server, outgoing = p.destination, p.source, False
        else:
            self.counts["packets_outside_scope"] += 1
            return
        key = (p.protocol, client, server)
        fid = self.flows.get(key)
        if fid is None:
            if not outgoing:
                self.counts["unregistered_server_packets"] += 1
                return
            if len(self.flows) >= self.MAX_FLOWS:
                self.counts["flow_capacity"] += 1
                return
            if p.protocol == "tcp" and not p.syn:
                self.counts["missing_handshake"] += 1
                return
            if p.protocol == "quic" and not (p.payload and p.payload[0] & 128):
                self.counts["missing_handshake"] += 1
                return
            fid = secrets.token_hex(16)
            if not self.bridge.open_flow(fid, p.protocol, self.provenance, client, server):
                self.counts["flow_capacity"] += 1
                return
            self.flows[key] = fid
            if self.flow_diagnostics:
                self.flow_diagnostics.opened(fid, p.protocol)
        flow = self.bridge.flows.get(fid)
        if not flow:
            return
        if p.protocol == "quic" and outgoing and not getattr(flow, "chrome_random", None):
            from prism_dpi.flowgraph.quic import decrypt_quic_initial
            initial = decrypt_quic_initial(p.payload)
            if initial:
                fragments = getattr(flow, "chrome_fragments", {})
                for offset, data in initial.fragments:
                    if offset + len(data) > 16384:
                        self.counts["hello_budget"] += 1
                        return
                    for i, value in enumerate(data, offset):
                        if i in fragments and fragments[i] != value:
                            # A contradictory CRYPTO stream invalidates this flow,
                            # not the authenticated device lease or other flows.
                            self.counts["quic_initial_fragment_conflict"] += 1
                            flow.abort = "quic_initial_fragment_conflict"
                            self.bridge.close_flow(fid)
                            self.flows.pop(key, None)
                            return
                        fragments[i] = value
                flow.chrome_fragments = fragments
                if all(i in fragments for i in range(38)) and fragments[0] == 1:
                    flow.chrome_random = bytes(fragments[i] for i in range(6, 38)).hex()
                    flow.chrome_fragments = {}
            self._apply(fid)
        self.bridge.feed_packet(fid, raw, self.provenance.capture_point)
        self._apply(fid)
        self._events()

    def _events(self):
        if self.flow_diagnostics:
            self.flow_diagnostics.retire(self.bridge)
        for event in self.bridge.drain_events():
            # Deliberately retain counters, never headers, URLs or secrets.
            if event.get("type") == "request_headers":
                self.counts["headers_"+event["request"]["protocol"]] += 1
                if self.diagnostics:
                    from .chrome_diagnostics import request_category
                    value = request_category(event["request"])
                    value.update(flow_id=event["flow_id"],
                                 elapsed_ms=int(max(0, self.clock()-self.started_at)*1000))
                    self.observations.append(value)

    def tick(self):
        now = self.clock()
        if self.lease and now >= self.deadline:
            self.reset("lease_expired")
        for key, (_, expiry) in list(self.keys.items()):
            if now >= expiry:
                del self.keys[key]
        self.bridge.poll()
        self._events()
        self.flows = {key: fid for key, fid in self.flows.items() if fid in self.bridge.flows}

    def reset(self, reason):
        self.bridge.close()
        self.keys.clear()
        self.flows.clear()
        self.observations.clear()
        if self.flow_diagnostics:
            self.flow_diagnostics.clear()
        self.bridge = Bridge(clock=self.clock, limits=Limits(key_lease_seconds=300))
        self.lease = None
        self.counts[reason] += 1

    def loss(self, count):
        if count:
            self.reset("capture_loss")

    def status(self, device):
        self.authorized(device)
        self.tick()
        result = dict(enabled=True, lease_active=bool(self.lease), counts=dict(self.counts),
                    active_flows=len(self.flows), retained_keys=len(self.keys),
                    bridge=self.bridge.metrics())
        if self.diagnostics:
            result["request_categories"] = list(self.observations)
            result["request_categories_limit"] = 24
            result["ad_content_classified"] = False
            result["flow_diagnostics"] = self.flow_diagnostics.status()
            result["capture_scope"] = dict(address_family="IPv4", destination_count=len(self.destinations), complete=False)
        return result
