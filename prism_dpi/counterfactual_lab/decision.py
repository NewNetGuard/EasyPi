"""Pure bounded decision state for controlled per-flow interventions."""

from __future__ import annotations

import ipaddress
from dataclasses import dataclass
from enum import Enum

from prism_dpi.flowgraph.events import FlowKey
from prism_dpi.flowgraph.tls import MAX_TLS_RECORD_LENGTH, TlsRecord, parse_client_hello
from prism_dpi.lineage_gate.packet import QueuedTransportPacket


MAX_TARGET_ORDINAL = 32
MAX_INTERVENTION_SECONDS = 5.0
MAX_DROPS = 64
MAX_SERVER_INTERVENTION_SECONDS = 300.0
MAX_SERVER_DROPS = 4_096
MAX_DISCOVERY_SECONDS = 300.0
MAX_OBSERVED_FLOWS = 256
MAX_CLIENT_HELLO_BYTES = MAX_TLS_RECORD_LENGTH + 5
MAX_CLIENT_HELLO_FLOWS = MAX_OBSERVED_FLOWS
MAX_OBSERVED_SERVER_NAMES = 256
CAUSAL_FANOUT_WINDOW_SECONDS = 15.0
CAUSAL_FANOUT_MIN_SUBDOMAINS = 2
ROOT_SNI_SELECTIONS = frozenset(
    ("root_sni", "first_root_sni", "causal_root_sni")
)
LOCKED_ROOT_SNI_SELECTIONS = frozenset(
    ("first_root_sni", "causal_root_sni")
)


@dataclass
class _ClientHelloAssembly:
    next_sequence: int
    payload: bytearray


class InterventionVerdict(str, Enum):
    ACCEPT = "accept"
    DROP = "drop"


@dataclass(frozen=True)
class ExperimentPlan:
    generation: int
    client_ip: str
    protocol: str
    target_ordinal: int
    intervention_seconds: float
    max_drops: int
    discovery_seconds: float = 15.0
    selection: str = "ordinal"
    target_server_ip: str = ""

    def __post_init__(self) -> None:
        address = ipaddress.ip_address(self.client_ip)
        if address.version != 4 or not address.is_private:
            raise ValueError("experiment client must be private IPv4")
        if self.protocol not in ("tcp", "udp"):
            raise ValueError("experiment protocol must be tcp or udp")
        if self.selection not in (
            "ordinal",
            "server",
            "root_sni",
            "first_root_sni",
            "causal_root_sni",
        ):
            raise ValueError(
                "experiment selection must be ordinal, server, root_sni, "
                "first_root_sni, or causal_root_sni"
            )
        if self.selection == "ordinal":
            if not 1 <= self.target_ordinal <= MAX_TARGET_ORDINAL:
                raise ValueError("target ordinal is out of range")
            if self.target_server_ip:
                raise ValueError("ordinal selection cannot set a target server")
        elif self.selection == "server":
            server = ipaddress.ip_address(self.target_server_ip)
            if server.version != 4 or not server.is_global:
                raise ValueError("target server must be public IPv4")
            if self.target_ordinal != 0:
                raise ValueError("server selection cannot set a target ordinal")
        else:
            if self.protocol != "tcp":
                raise ValueError("root SNI selection requires TCP")
            if self.target_ordinal != 0 or self.target_server_ip:
                raise ValueError("root SNI selection cannot set another target")
        intervention_limit = (
            MAX_SERVER_INTERVENTION_SECONDS
            if self.selection == "server" or self.selection in ROOT_SNI_SELECTIONS
            else MAX_INTERVENTION_SECONDS
        )
        drop_limit = (
            MAX_SERVER_DROPS
            if self.selection == "server" or self.selection in ROOT_SNI_SELECTIONS
            else MAX_DROPS
        )
        if not 0.25 <= self.intervention_seconds <= intervention_limit:
            raise ValueError("intervention duration is out of range")
        if not 1 <= self.max_drops <= drop_limit:
            raise ValueError("maximum drop count is out of range")
        if not 1.0 <= self.discovery_seconds <= MAX_DISCOVERY_SECONDS:
            raise ValueError("discovery duration is out of range")
        if self.generation < 1:
            raise ValueError("generation must be positive")


@dataclass(frozen=True)
class InterventionDecision:
    verdict: InterventionVerdict
    reason: str
    flow: FlowKey | None = None
    ordinal: int = 0
    dropped_count: int = 0


class CounterfactualFlowLab:
    """Drop one newly discovered flow and fail open everywhere else."""

    def __init__(self) -> None:
        self._plan: ExperimentPlan | None = None
        self._armed_at = 0.0
        self._discovery_deadline = 0.0
        self._target_flow: FlowKey | None = None
        self._target_flows: set[FlowKey] = set()
        self._target_server_name = ""
        self._intervention_deadline = 0.0
        self._ordinals: dict[FlowKey, int] = {}
        self._client_hello_assemblies: dict[FlowKey, _ClientHelloAssembly] = {}
        self._recent_server_names: dict[str, float] = {}
        self._dropped_count = 0
        self._completed = False

    def arm(self, plan: ExperimentPlan, *, now: float) -> None:
        self._plan = plan
        self._armed_at = now
        self._discovery_deadline = now + plan.discovery_seconds
        self._target_flow = None
        self._target_flows.clear()
        self._target_server_name = ""
        self._intervention_deadline = 0.0
        self._ordinals.clear()
        self._client_hello_assemblies.clear()
        self._recent_server_names.clear()
        self._dropped_count = 0
        self._completed = False

    def disarm(self) -> None:
        self._plan = None
        self._target_flow = None
        self._target_flows.clear()
        self._target_server_name = ""
        self._ordinals.clear()
        self._client_hello_assemblies.clear()
        self._recent_server_names.clear()
        self._dropped_count = 0
        self._completed = False

    def observe(
        self,
        packet: QueuedTransportPacket,
        *,
        now: float,
    ) -> InterventionDecision:
        plan = self._plan
        if plan is None:
            return InterventionDecision(InterventionVerdict.ACCEPT, "disarmed")
        if self._completed:
            return InterventionDecision(
                InterventionVerdict.ACCEPT,
                "intervention_complete",
                self._target_flow,
                self._target_ordinal,
                self._dropped_count,
            )
        if packet.flow.client_ip != plan.client_ip:
            return InterventionDecision(InterventionVerdict.ACCEPT, "not_canary")
        if packet.flow.protocol != plan.protocol:
            return InterventionDecision(InterventionVerdict.ACCEPT, "protocol_mismatch")

        if self._target_flow is None and now >= self._discovery_deadline:
            self._completed = True
            return InterventionDecision(
                InterventionVerdict.ACCEPT,
                "discovery_timeout",
                ordinal=plan.target_ordinal,
            )

        ordinal = self._ordinals.get(packet.flow)
        if ordinal is None and self._is_new_flow(packet):
            if len(self._ordinals) >= MAX_OBSERVED_FLOWS:
                self._completed = True
                return InterventionDecision(
                    InterventionVerdict.ACCEPT,
                    "observed_flow_limit",
                )
            ordinal = len(self._ordinals) + 1
            self._ordinals[packet.flow] = ordinal
            if (
                self._target_flow is None
                and self._selects_flow(plan, packet.flow, ordinal)
            ):
                self._target_flow = packet.flow
                self._target_flows.add(packet.flow)
                self._intervention_deadline = now + plan.intervention_seconds
            elif (
                self._target_flow is not None
                and plan.selection == "server"
                and packet.flow.server_ip == plan.target_server_ip
            ):
                self._target_flows.add(packet.flow)
        server_name = self._observe_server_name(plan, packet)
        self._remember_server_name(server_name, now=now)
        if self._selects_root_sni(plan, packet, server_name, now=now):
            normalized_name = server_name.rstrip(".").lower()
            if plan.selection in LOCKED_ROOT_SNI_SELECTIONS:
                if not self._target_server_name:
                    self._target_server_name = normalized_name
                if normalized_name != self._target_server_name:
                    return InterventionDecision(
                        InterventionVerdict.ACCEPT,
                        "non_target_root_sni",
                        packet.flow,
                        ordinal or 0,
                        self._dropped_count,
                    )
            if self._target_flow is None:
                self._target_flow = packet.flow
                self._intervention_deadline = now + plan.intervention_seconds
            self._target_flows.add(packet.flow)
        if packet.flow not in self._target_flows:
            return InterventionDecision(
                InterventionVerdict.ACCEPT,
                "non_target_flow" if ordinal else "midstream_flow",
                packet.flow,
                ordinal or 0,
                self._dropped_count,
            )

        if (
            now >= self._intervention_deadline
            or self._dropped_count >= plan.max_drops
        ):
            self._completed = True
            return InterventionDecision(
                InterventionVerdict.ACCEPT,
                "intervention_complete",
                packet.flow,
                self._target_ordinal,
                self._dropped_count,
            )
        self._dropped_count += 1
        return InterventionDecision(
            InterventionVerdict.DROP,
            "target_intervention",
            packet.flow,
            self._target_ordinal,
            self._dropped_count,
        )

    @staticmethod
    def _selects_flow(plan: ExperimentPlan, flow: FlowKey, ordinal: int) -> bool:
        if plan.selection == "ordinal":
            return ordinal == plan.target_ordinal
        return flow.server_ip == plan.target_server_ip

    def _selects_root_sni(
        self,
        plan: ExperimentPlan,
        packet: QueuedTransportPacket,
        server_name: str,
        *,
        now: float,
    ) -> bool:
        if plan.selection not in ROOT_SNI_SELECTIONS:
            return False
        if not packet.client_to_server:
            return False
        normalized_name = server_name.rstrip(".").lower()
        labels = normalized_name.split(".")
        if len(labels) != 2 or not all(labels):
            return False
        if plan.selection != "causal_root_sni" or self._target_server_name:
            return True
        return self._recent_subdomain_count(normalized_name, now=now) >= (
            CAUSAL_FANOUT_MIN_SUBDOMAINS
        )

    def _observe_server_name(
        self,
        plan: ExperimentPlan,
        packet: QueuedTransportPacket,
    ) -> str:
        if plan.selection not in ROOT_SNI_SELECTIONS:
            return packet.server_name
        if packet.server_name:
            self._client_hello_assemblies.pop(packet.flow, None)
            return packet.server_name
        if packet.flow.protocol != "tcp" or not packet.client_to_server:
            return ""
        if packet.fin or packet.rst:
            self._client_hello_assemblies.pop(packet.flow, None)
            return ""
        if not packet.payload:
            return ""

        sequence = (packet.sequence + (1 if packet.syn else 0)) & 0xFFFFFFFF
        assembly = self._client_hello_assemblies.get(packet.flow)
        if assembly is None:
            if not self._looks_like_tls_handshake_prefix(packet.payload):
                return ""
            if len(self._client_hello_assemblies) >= MAX_CLIENT_HELLO_FLOWS:
                return ""
            assembly = _ClientHelloAssembly(
                next_sequence=(sequence + len(packet.payload)) & 0xFFFFFFFF,
                payload=bytearray(packet.payload),
            )
            self._client_hello_assemblies[packet.flow] = assembly
        else:
            delta = (sequence - assembly.next_sequence) & 0xFFFFFFFF
            if delta == 0:
                new_payload = packet.payload
            elif delta < 0x80000000:
                self._client_hello_assemblies.pop(packet.flow, None)
                return ""
            else:
                overlap = (assembly.next_sequence - sequence) & 0xFFFFFFFF
                if overlap >= len(packet.payload):
                    return ""
                new_payload = packet.payload[overlap:]
            if len(assembly.payload) + len(new_payload) > MAX_CLIENT_HELLO_BYTES:
                self._client_hello_assemblies.pop(packet.flow, None)
                return ""
            assembly.payload.extend(new_payload)
            assembly.next_sequence = (
                assembly.next_sequence + len(new_payload)
            ) & 0xFFFFFFFF

        if len(assembly.payload) < 5:
            return ""
        record_length = int.from_bytes(assembly.payload[3:5], "big")
        record_end = 5 + record_length
        if record_length > MAX_TLS_RECORD_LENGTH:
            self._client_hello_assemblies.pop(packet.flow, None)
            return ""
        if len(assembly.payload) < record_end:
            return ""

        record = TlsRecord(
            content_type=assembly.payload[0],
            legacy_version=bytes(assembly.payload[1:3]),
            payload=bytes(assembly.payload[5:record_end]),
        )
        self._client_hello_assemblies.pop(packet.flow, None)
        hello = parse_client_hello(record)
        return hello.server_name if hello is not None else ""

    def _remember_server_name(self, server_name: str, *, now: float) -> None:
        normalized_name = server_name.rstrip(".").lower()
        if not normalized_name:
            return
        self._prune_server_names(now=now)
        if (
            normalized_name not in self._recent_server_names
            and len(self._recent_server_names) >= MAX_OBSERVED_SERVER_NAMES
        ):
            oldest = min(
                self._recent_server_names,
                key=self._recent_server_names.__getitem__,
            )
            self._recent_server_names.pop(oldest, None)
        self._recent_server_names[normalized_name] = now

    def _recent_subdomain_count(self, root_name: str, *, now: float) -> int:
        self._prune_server_names(now=now)
        suffix = f".{root_name}"
        return sum(
            name != root_name and name.endswith(suffix)
            for name in self._recent_server_names
        )

    def _prune_server_names(self, *, now: float) -> None:
        cutoff = now - CAUSAL_FANOUT_WINDOW_SECONDS
        expired = [
            name
            for name, observed_at in self._recent_server_names.items()
            if observed_at < cutoff
        ]
        for name in expired:
            self._recent_server_names.pop(name, None)

    @staticmethod
    def _looks_like_tls_handshake_prefix(payload: bytes) -> bool:
        if not payload or payload[0] != 22:
            return False
        if len(payload) >= 2 and payload[1] != 3:
            return False
        if len(payload) >= 5:
            return int.from_bytes(payload[3:5], "big") <= MAX_TLS_RECORD_LENGTH
        return True

    @staticmethod
    def _is_new_flow(packet: QueuedTransportPacket) -> bool:
        if not packet.client_to_server:
            return False
        if packet.flow.protocol == "udp":
            return True
        return packet.syn and not packet.ack

    @property
    def armed(self) -> bool:
        return self._plan is not None and not self._completed

    @property
    def generation(self) -> int:
        return self._plan.generation if self._plan is not None else 0

    @property
    def observed_flow_count(self) -> int:
        return len(self._ordinals)

    @property
    def dropped_count(self) -> int:
        return self._dropped_count

    @property
    def target_server_name(self) -> str:
        return self._target_server_name

    @property
    def pending_reassembly_count(self) -> int:
        return len(self._client_hello_assemblies)

    @property
    def _target_ordinal(self) -> int:
        if self._target_flow is None:
            return 0
        return self._ordinals.get(self._target_flow, 0)


__all__ = [
    "CounterfactualFlowLab",
    "ExperimentPlan",
    "InterventionDecision",
    "InterventionVerdict",
]
