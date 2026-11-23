"""Strict consumer for fresh FlowGraph candidates.

This module only turns trusted, structured metadata into a bounded flow-block
request. It does not execute commands or modify firewall state.
"""

from __future__ import annotations

import ipaddress
import json
import os
import stat
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from ..modules.mobile_ads.yandex.behavior import (
    matches_learned_ad_control_flow,
    matches_learned_ad_resumption_pair,
    matches_learned_mail_browser_root_burst,
    matches_learned_mail_browser_serial_root,
    matches_learned_mail_browser_dzen_root,
    matches_learned_mail_inline_ad_request,
    matches_learned_mail_inline_first_ad_request,
    matches_learned_mail_inline_bootstrap_large_request,
    matches_learned_mail_inline_response_outlier,
    matches_learned_mail_inline_ad_dna_request,
)


REQUIRED_EVIDENCE = frozenset(
    {
        "compact_root_profile_transition_causal",
        "large_root_after_subdomain_fanout_causal",
        "large_root_after_cross_session_fanout_causal",
        "compact_root_retry_after_large_causal_root",
        "large_root_retry_after_causal_root",
        "large_root_after_active_family_request",
        "uniform_root_exchange_conveyor",
        "uniform_root_endpoint_companion",
        "uniform_root_endpoint_multiplex",
        "uniform_root_cross_endpoint_companion",
        "uniform_root_setup_companion",
        "uniform_root_setup_resumption_descendant",
        "uniform_root_successor_exchange_conveyor",
        "uniform_root_successor_resumption_descendant",
        "compact_root_profile_cycle_conveyor",
        "compact_root_profile_cycle_resumption_descendant",
        "paired_root_first_exchange_conveyor",
        "paired_root_setup_descendant",
        "paired_root_resumption_descendant",
        "mirrored_root_resumption_transition",
        "compact_root_resumption_pair_causal",
        "yandex_mail_browser_root_burst",
        "yandex_mail_browser_serial_root",
        "yandex_mail_browser_dzen_root",
        "yandex_mail_inline_ad_request",
        "yandex_mail_inline_first_ad_request",
        "yandex_mail_inline_bootstrap_large_request",
        "yandex_mail_inline_response_outlier",
        "yandex_mail_inline_ad_dna_request",
    }
)
EXACT_FLOW_ONLY_EVIDENCE = frozenset(
    {
        "large_root_after_subdomain_fanout_causal",
        "large_root_after_cross_session_fanout_causal",
        "compact_root_retry_after_large_causal_root",
        "large_root_retry_after_causal_root",
        "large_root_after_active_family_request",
        "uniform_root_exchange_conveyor",
        "uniform_root_endpoint_companion",
        "uniform_root_endpoint_multiplex",
        "uniform_root_cross_endpoint_companion",
        "uniform_root_setup_companion",
        "uniform_root_setup_resumption_descendant",
        "uniform_root_successor_exchange_conveyor",
        "uniform_root_successor_resumption_descendant",
        "compact_root_profile_cycle_conveyor",
        "compact_root_profile_cycle_resumption_descendant",
        "paired_root_first_exchange_conveyor",
        "paired_root_setup_descendant",
        "paired_root_resumption_descendant",
        "mirrored_root_resumption_transition",
        "compact_root_resumption_pair_causal",
        "yandex_mail_browser_root_burst",
        "yandex_mail_browser_serial_root",
        "yandex_mail_browser_dzen_root",
        "yandex_mail_inline_ad_request",
        "yandex_mail_inline_first_ad_request",
        "yandex_mail_inline_bootstrap_large_request",
        "yandex_mail_inline_response_outlier",
        "yandex_mail_inline_ad_dna_request",
    }
)
MIN_CONFIDENCE = 0.75
MAX_CANDIDATE_AGE_SECONDS = 3.0
MAX_FUTURE_SKEW_SECONDS = 1.0
MAX_LINE_BYTES = 64 * 1024
MAX_READ_BYTES = 1024 * 1024
MAX_ACTIONS_PER_POLL = 16
DEDUP_SECONDS = 90.0


@dataclass(frozen=True)
class CandidateFlow:
    timestamp: float
    flow_id: str
    client_ip: str
    client_port: int
    server_ip: str
    server_port: int
    confidence: float
    retry_guard: bool
    protocol: str = "tcp"
    policy: str = "flowgraph"
    termination: str = "drop"

    def enforcement_request(self) -> bytes:
        """Encode the already validated tuple for the privileged stream helper."""
        retry_guard = "true" if self.retry_guard else "false"
        termination = "" if self.termination == "drop" else f"\t{self.termination}"
        return (
            f"{self.client_ip}\t{self.client_port}\t{self.server_ip}\t"
            f"{self.protocol}\t{retry_guard}{termination}\n"
        ).encode("ascii")


CandidateValidator = Callable[..., CandidateFlow | None]


class CandidateLogFollower:
    """Tail a metadata JSONL file and emit fresh, validated candidates once."""

    def __init__(
        self,
        path: str | Path,
        *,
        validator: CandidateValidator | None = None,
    ) -> None:
        self.path = Path(path)
        self._validator = validator or validate_candidate_event
        self._identity: tuple[int, int] | None = None
        self._offset = 0
        self._backlog = b""
        self._pending = b""
        self._seen: dict[str, float] = {}
        self._prime()

    def poll(self, *, now: float | None = None) -> tuple[CandidateFlow, ...]:
        current_time = time.time() if now is None else now
        source_stat = self._regular_file_stat()
        if source_stat is None:
            return ()

        identity = (source_stat.st_dev, source_stat.st_ino)
        if self._identity is None:
            self._identity = identity
            self._offset = 0
        if identity != self._identity or source_stat.st_size < self._offset:
            self._identity = identity
            self._offset = 0
            self._backlog = b""
            self._pending = b""

        chunk = b""
        if not self._backlog:
            with self.path.open("rb") as source:
                source.seek(self._offset)
                chunk = source.read(MAX_READ_BYTES)
                self._offset = source.tell()
        if not self._backlog and not chunk:
            self._expire_seen(current_time)
            return ()

        data = self._backlog + self._pending + chunk
        self._backlog = b""
        lines = data.split(b"\n")
        self._pending = lines.pop()
        if len(self._pending) > MAX_LINE_BYTES:
            self._pending = b""

        actions: list[CandidateFlow] = []
        for index, raw_line in enumerate(lines):
            if not raw_line or len(raw_line) > MAX_LINE_BYTES:
                continue
            candidate = _parse_candidate(
                raw_line,
                now=current_time,
                validator=self._validator,
            )
            if candidate is None or candidate.flow_id in self._seen:
                continue
            self._seen[candidate.flow_id] = current_time
            actions.append(candidate)
            if len(actions) >= MAX_ACTIONS_PER_POLL:
                remaining_lines = lines[index + 1 :]
                if remaining_lines:
                    self._backlog = b"\n".join(remaining_lines) + b"\n"
                break
        self._expire_seen(current_time)
        return tuple(actions)

    def _prime(self) -> None:
        source_stat = self._regular_file_stat()
        if source_stat is None:
            return
        self._identity = (source_stat.st_dev, source_stat.st_ino)
        self._offset = source_stat.st_size

    def _regular_file_stat(self) -> os.stat_result | None:
        try:
            source_stat = self.path.lstat()
        except FileNotFoundError:
            return None
        if not stat.S_ISREG(source_stat.st_mode):
            return None
        return source_stat

    def _expire_seen(self, now: float) -> None:
        cutoff = now - DEDUP_SECONDS
        for flow_id, seen_at in list(self._seen.items()):
            if seen_at < cutoff:
                del self._seen[flow_id]


def _parse_candidate(
    raw_line: bytes,
    *,
    now: float,
    validator: CandidateValidator,
) -> CandidateFlow | None:
    try:
        value = json.loads(raw_line)
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    return validator(value, now=now)


def validate_candidate_event(
    value: object, *, now: float
) -> CandidateFlow | None:
    """Apply the production policy boundary to one decoded model event."""
    if not isinstance(value, dict):
        return None
    if value.get("event") != "flow_assessment":
        return None
    evidence = value.get("evidence")
    if not isinstance(evidence, list):
        return None
    learned_yandex_control_flow = matches_learned_ad_control_flow(
        server_name=value.get("server_name"),
        features=value.get("features"),
    ) and {"causal_session_fanout", "dense_connection_burst"}.issubset(evidence)
    learned_yandex_mail_browser_flow = (
        "yandex_mail_browser_root_burst" in evidence
        and matches_learned_mail_browser_root_burst(
            server_name=value.get("server_name"),
            features=value.get("features"),
        )
    )
    learned_yandex_mail_desktop_flow = (
        "yandex_mail_browser_serial_root" in evidence
        and matches_learned_mail_browser_serial_root(
            server_name=value.get("server_name"),
            features=value.get("features"),
        )
    )
    learned_yandex_mail_dzen_flow = (
        "yandex_mail_browser_dzen_root" in evidence
        and matches_learned_mail_browser_dzen_root(
            server_name=value.get("server_name"),
            features=value.get("features"),
        )
    )
    learned_yandex_mail_inline_flow = (
        "yandex_mail_inline_ad_request" in evidence
        and matches_learned_mail_inline_ad_request(
            server_name=value.get("server_name"),
            features=value.get("features"),
        )
    )
    learned_yandex_mail_inline_first_flow = (
        "yandex_mail_inline_first_ad_request" in evidence
        and matches_learned_mail_inline_first_ad_request(
            server_name=value.get("server_name"),
            features=value.get("features"),
        )
    )
    learned_yandex_mail_inline_bootstrap_flow = (
        "yandex_mail_inline_bootstrap_large_request" in evidence
        and matches_learned_mail_inline_bootstrap_large_request(
            server_name=value.get("server_name"),
            features=value.get("features"),
        )
    )
    learned_yandex_mail_inline_outlier_flow = (
        "yandex_mail_inline_response_outlier" in evidence
        and matches_learned_mail_inline_response_outlier(
            server_name=value.get("server_name"),
            features=value.get("features"),
        )
    )
    learned_yandex_mail_inline_ad_dna_flow = (
        "yandex_mail_inline_ad_dna_request" in evidence
        and matches_learned_mail_inline_ad_dna_request(
            server_name=value.get("server_name"),
            features=value.get("features"),
        )
    )
    if value.get("verdict") != "candidate" and not (
        value.get("verdict") == "ambiguous" and learned_yandex_control_flow
    ):
        return None
    if (
        not learned_yandex_control_flow
        and not learned_yandex_mail_browser_flow
        and not learned_yandex_mail_desktop_flow
        and not learned_yandex_mail_dzen_flow
        and not learned_yandex_mail_inline_flow
        and not learned_yandex_mail_inline_first_flow
        and not learned_yandex_mail_inline_bootstrap_flow
        and not learned_yandex_mail_inline_outlier_flow
        and not learned_yandex_mail_inline_ad_dna_flow
        and not REQUIRED_EVIDENCE.intersection(evidence)
    ):
        return None
    exact_flow_only = bool(EXACT_FLOW_ONLY_EVIDENCE.intersection(evidence))
    learned_yandex_resumption_pair = (
        "compact_root_resumption_pair_causal" in evidence
        and matches_learned_ad_resumption_pair(
            server_name=value.get("server_name"),
            features=value.get("features"),
        )
    )
    if (
        "compact_root_resumption_pair_causal" in evidence
        and not learned_yandex_resumption_pair
    ):
        return None
    if (
        "yandex_mail_browser_root_burst" in evidence
        and not learned_yandex_mail_browser_flow
    ):
        return None
    if (
        "yandex_mail_browser_serial_root" in evidence
        and not learned_yandex_mail_desktop_flow
    ):
        return None
    if (
        "yandex_mail_browser_dzen_root" in evidence
        and not learned_yandex_mail_dzen_flow
    ):
        return None
    if (
        "yandex_mail_inline_ad_request" in evidence
        and not learned_yandex_mail_inline_flow
    ):
        return None
    if (
        "yandex_mail_inline_first_ad_request" in evidence
        and not learned_yandex_mail_inline_first_flow
    ):
        return None
    if (
        "yandex_mail_inline_bootstrap_large_request" in evidence
        and not learned_yandex_mail_inline_bootstrap_flow
    ):
        return None
    if (
        "yandex_mail_inline_response_outlier" in evidence
        and not learned_yandex_mail_inline_outlier_flow
    ):
        return None
    if (
        "yandex_mail_inline_ad_dna_request" in evidence
        and not learned_yandex_mail_inline_ad_dna_flow
    ):
        return None
    if (
        "large_root_after_subdomain_fanout_causal" in evidence
        and not _valid_large_causal_root(value)
    ):
        return None
    if (
        "large_root_after_cross_session_fanout_causal" in evidence
        and not _valid_cross_session_causal_root(value)
    ):
        return None
    if (
        "compact_root_retry_after_large_causal_root" in evidence
        and not _valid_compact_causal_retry(value)
    ):
        return None
    if (
        "large_root_retry_after_causal_root" in evidence
        and not _valid_delayed_large_causal_retry(value)
    ):
        return None
    if (
        "large_root_after_active_family_request" in evidence
        and not _valid_active_family_continuation(value)
    ):
        return None
    if (
        "uniform_root_exchange_conveyor" in evidence
        and not _valid_uniform_root_exchange_conveyor(value)
    ):
        return None
    if (
        "uniform_root_endpoint_companion" in evidence
        and not _valid_uniform_root_endpoint_companion(value)
    ):
        return None
    if (
        "uniform_root_endpoint_multiplex" in evidence
        and not _valid_uniform_root_endpoint_multiplex(value)
    ):
        return None
    if (
        "uniform_root_cross_endpoint_companion" in evidence
        and not _valid_uniform_root_cross_endpoint_companion(value)
    ):
        return None
    if (
        "uniform_root_setup_companion" in evidence
        and not _valid_uniform_root_setup_companion(value)
    ):
        return None
    if (
        "uniform_root_setup_resumption_descendant" in evidence
        and not _valid_uniform_root_setup_resumption_descendant(value)
    ):
        return None
    if (
        "uniform_root_successor_exchange_conveyor" in evidence
        and not _valid_uniform_root_successor_exchange_conveyor(value)
    ):
        return None
    if (
        "uniform_root_successor_resumption_descendant" in evidence
        and not _valid_uniform_root_successor_resumption_descendant(value)
    ):
        return None
    if (
        "compact_root_profile_cycle_conveyor" in evidence
        and not _valid_compact_root_profile_cycle_conveyor(value)
    ):
        return None
    if (
        "compact_root_profile_cycle_resumption_descendant" in evidence
        and not _valid_compact_root_profile_cycle_resumption_descendant(value)
    ):
        return None
    if (
        "paired_root_first_exchange_conveyor" in evidence
        and not _valid_paired_root_first_exchange_conveyor(value)
    ):
        return None
    if (
        "paired_root_setup_descendant" in evidence
        and not _valid_paired_root_setup_descendant(value)
    ):
        return None
    if (
        "paired_root_resumption_descendant" in evidence
        and not _valid_paired_root_resumption_descendant(value)
    ):
        return None
    if (
        "mirrored_root_resumption_transition" in evidence
        and not _valid_mirrored_root_resumption_transition(value)
    ):
        return None

    try:
        timestamp = float(value["timestamp"])
        confidence = float(value["confidence"])
        client_ip = str(ipaddress.ip_address(value["client_ip"]))
        server_ip = str(ipaddress.ip_address(value["server_ip"]))
        client_port = int(value["client_port"])
        server_port = int(value["server_port"])
        flow_id = str(value["flow"])
    except (KeyError, TypeError, ValueError):
        return None

    client_address = ipaddress.ip_address(client_ip)
    server_address = ipaddress.ip_address(server_ip)
    if client_address.version != 4 or not client_address.is_private:
        return None
    if server_address.version != 4 or not server_address.is_global:
        return None
    if not 1024 <= client_port <= 65535 or server_port != 443:
        return None
    if (
        confidence < MIN_CONFIDENCE
        and not learned_yandex_control_flow
        and not learned_yandex_mail_browser_flow
        and not learned_yandex_mail_desktop_flow
        and not learned_yandex_mail_dzen_flow
        and not learned_yandex_mail_inline_flow
        and not learned_yandex_mail_inline_first_flow
        and not learned_yandex_mail_inline_bootstrap_flow
        and not learned_yandex_mail_inline_outlier_flow
        and not learned_yandex_mail_inline_ad_dna_flow
    ):
        return None
    if timestamp < now - MAX_CANDIDATE_AGE_SECONDS:
        return None
    if timestamp > now + MAX_FUTURE_SKEW_SECONDS:
        return None
    if not flow_id or len(flow_id) > 256:
        return None

    return CandidateFlow(
        timestamp=timestamp,
        flow_id=flow_id,
        client_ip=client_ip,
        client_port=client_port,
        server_ip=server_ip,
        server_port=server_port,
        confidence=confidence,
        retry_guard=not exact_flow_only
        and not (
            learned_yandex_control_flow
            or learned_yandex_mail_browser_flow
            or learned_yandex_mail_desktop_flow
            or learned_yandex_mail_dzen_flow
            or learned_yandex_mail_inline_flow
            or learned_yandex_mail_inline_first_flow
            or learned_yandex_mail_inline_bootstrap_flow
            or learned_yandex_mail_inline_outlier_flow
            or learned_yandex_mail_inline_ad_dna_flow
        ),
        termination=(
            "reset"
            if (
                learned_yandex_resumption_pair
                or learned_yandex_control_flow
                or learned_yandex_mail_browser_flow
                or learned_yandex_mail_desktop_flow
                or learned_yandex_mail_dzen_flow
                or learned_yandex_mail_inline_flow
                or learned_yandex_mail_inline_first_flow
                or learned_yandex_mail_inline_bootstrap_flow
                or learned_yandex_mail_inline_outlier_flow
                or learned_yandex_mail_inline_ad_dna_flow
            )
            else "drop"
        ),
    )


def _valid_large_causal_root(value: dict[str, object]) -> bool:
    features = value.get("features")
    server_name = value.get("server_name")
    if not isinstance(features, dict) or not isinstance(server_name, str):
        return False
    normalized_name = server_name.rstrip(".").lower()
    if normalized_name != server_name or len(normalized_name.split(".")) != 2:
        return False
    try:
        record_length = int(features["tls_record_length"])
        subdomain_count = int(features["same_family_subdomain_count"])
    except (KeyError, TypeError, ValueError):
        return False
    return (
        record_length > 640
        and features.get("compact_client_hello") is False
        and features.get("root_server_name") is True
        and subdomain_count >= 2
        and features.get("large_root_after_subdomain_fanout") is True
    )


def _valid_cross_session_causal_root(value: dict[str, object]) -> bool:
    features = value.get("features")
    server_name = value.get("server_name")
    if not isinstance(features, dict) or not isinstance(server_name, str):
        return False
    normalized_name = server_name.rstrip(".").lower()
    if normalized_name != server_name or len(normalized_name.split(".")) != 2:
        return False
    try:
        record_length = int(features["tls_record_length"])
        subdomain_count = int(
            features["cross_session_same_family_subdomain_count"]
        )
        session_count = int(features["cross_session_distinct_session_count"])
    except (KeyError, TypeError, ValueError):
        return False
    return (
        record_length > 640
        and features.get("compact_client_hello") is False
        and features.get("root_server_name") is True
        and subdomain_count >= 3
        and session_count >= 2
        and features.get("large_root_after_cross_session_fanout") is True
    )


def _valid_delayed_large_causal_retry(value: dict[str, object]) -> bool:
    features = value.get("features")
    server_name = value.get("server_name")
    if not isinstance(features, dict) or not isinstance(server_name, str):
        return False
    normalized_name = server_name.rstrip(".").lower()
    if normalized_name != server_name or len(normalized_name.split(".")) != 2:
        return False
    try:
        record_length = int(features["tls_record_length"])
        prior_root_count = int(features["prior_large_endpoint_root_count"])
    except (KeyError, TypeError, ValueError):
        return False
    return (
        record_length > 640
        and features.get("compact_client_hello") is False
        and features.get("root_server_name") is True
        and prior_root_count >= 1
        and features.get("large_root_causal_retry") is True
    )


def _valid_active_family_continuation(value: dict[str, object]) -> bool:
    features = value.get("features")
    server_name = value.get("server_name")
    if not isinstance(features, dict) or not isinstance(server_name, str):
        return False
    normalized_name = server_name.rstrip(".").lower()
    if normalized_name != server_name or len(normalized_name.split(".")) != 2:
        return False
    try:
        prior_root_count = int(features["prior_confirmed_endpoint_root_count"])
        request_flow_count = int(features["recent_family_request_flow_count"])
        record_length = int(features["tls_record_length"])
    except (KeyError, TypeError, ValueError):
        return False
    return (
        record_length > 640
        and features.get("compact_client_hello") is False
        and features.get("root_server_name") is True
        and prior_root_count >= 1
        and request_flow_count >= 1
        and features.get("large_root_active_family_continuation") is True
    )


def _valid_uniform_root_exchange_conveyor(value: dict[str, object]) -> bool:
    features = value.get("features")
    server_name = value.get("server_name")
    if not isinstance(features, dict) or not isinstance(server_name, str):
        return False
    normalized_name = server_name.rstrip(".").lower()
    if normalized_name != server_name or len(normalized_name.split(".")) != 2:
        return False
    try:
        record_length = int(features["tls_record_length"])
        exchange_count = int(features["uniform_root_exchange_count"])
        distinct_flows = int(features["uniform_root_distinct_flow_count"])
        window_ms = int(features["uniform_root_exchange_window_ms"])
        request_spread = float(features["uniform_root_request_spread"])
        response_spread = float(features["uniform_root_response_spread"])
    except (KeyError, TypeError, ValueError):
        return False
    rapid_conveyor = exchange_count >= 3 and window_ms <= 1_000
    sustained_conveyor = exchange_count >= 8 and window_ms <= 10_000
    return (
        0 < record_length <= 640
        and features.get("compact_client_hello") is True
        and features.get("root_server_name") is True
        and distinct_flows == exchange_count
        and (rapid_conveyor or sustained_conveyor)
        and window_ms >= 0
        and 0 <= request_spread <= 0.20
        and 0 <= response_spread <= 0.10
        and features.get("uniform_root_exact_endpoint") is True
    )


def _valid_uniform_root_endpoint_companion(value: dict[str, object]) -> bool:
    features = value.get("features")
    server_name = value.get("server_name")
    if not isinstance(features, dict) or not isinstance(server_name, str):
        return False
    normalized_name = server_name.rstrip(".").lower()
    if normalized_name != server_name or len(normalized_name.split(".")) != 2:
        return False
    try:
        record_length = int(features["tls_record_length"])
        conveyor_count = int(features["prior_uniform_root_conveyor_count"])
        confirmation_age_ms = int(
            features["uniform_root_companion_confirmation_age_ms"]
        )
        hello_delta_ms = int(features["uniform_root_companion_hello_delta_ms"])
    except (KeyError, TypeError, ValueError):
        return False
    return (
        0 < record_length <= 640
        and features.get("compact_client_hello") is True
        and features.get("root_server_name") is True
        and conveyor_count >= 1
        and 0 <= confirmation_age_ms <= 3_000
        and 0 <= hello_delta_ms <= 2_000
        and features.get("uniform_root_companion_exact_endpoint") is True
    )


def _valid_uniform_root_endpoint_multiplex(value: dict[str, object]) -> bool:
    features = value.get("features")
    server_name = value.get("server_name")
    if not isinstance(features, dict) or not isinstance(server_name, str):
        return False
    normalized_name = server_name.rstrip(".").lower()
    if normalized_name != server_name or len(normalized_name.split(".")) != 2:
        return False
    try:
        record_length = int(features["tls_record_length"])
        seed_exchange_count = int(
            features["uniform_root_endpoint_seed_exchange_count"]
        )
        seed_age_ms = int(features["uniform_root_endpoint_seed_age_ms"])
        endpoint_flows = int(features["uniform_root_endpoint_peer_count"])
        endpoint_names = int(
            features["uniform_root_endpoint_distinct_name_count"]
        )
    except (KeyError, TypeError, ValueError):
        return False
    return (
        0 < record_length <= 640
        and features.get("compact_client_hello") is True
        and features.get("root_server_name") is True
        and seed_exchange_count >= 1
        and 0 <= seed_age_ms <= 1_000
        and endpoint_flows >= 3
        and endpoint_names >= 2
        and features.get("uniform_root_endpoint_multiplex") is True
    )


def _valid_uniform_root_cross_endpoint_companion(
    value: dict[str, object],
) -> bool:
    features = value.get("features")
    server_name = value.get("server_name")
    if not isinstance(features, dict) or not isinstance(server_name, str):
        return False
    normalized_name = server_name.rstrip(".").lower()
    if normalized_name != server_name or len(normalized_name.split(".")) != 2:
        return False
    try:
        record_length = int(features["tls_record_length"])
        server_payload_bytes = int(features["server_payload_bytes"])
        lineage_count = int(features["prior_uniform_root_cross_lineage_count"])
        confirmation_age_ms = int(
            features["uniform_root_cross_confirmation_age_ms"]
        )
        hello_delta_ms = int(features["uniform_root_cross_hello_delta_ms"])
    except (KeyError, TypeError, ValueError):
        return False
    return (
        0 < record_length <= 640
        and features.get("compact_client_hello") is True
        and features.get("root_server_name") is True
        and server_payload_bytes == 0
        and lineage_count >= 1
        and 0 <= confirmation_age_ms <= 3_000
        and 0 <= hello_delta_ms <= 3_000
        and features.get("uniform_root_cross_endpoint") is True
        and features.get("uniform_root_cross_fingerprint_match") is True
        and features.get("uniform_root_cross_lineage_match") is True
    )


def _valid_uniform_root_setup_companion(value: dict[str, object]) -> bool:
    features = value.get("features")
    server_name = value.get("server_name")
    if not isinstance(features, dict) or not isinstance(server_name, str):
        return False
    normalized_name = server_name.rstrip(".").lower()
    if normalized_name != server_name or len(normalized_name.split(".")) != 2:
        return False
    try:
        record_length = int(features["tls_record_length"])
        psk_count = int(features["tls_psk_identity_count"])
        conveyor_count = int(
            features["prior_uniform_root_setup_conveyor_count"]
        )
        setup_peer_count = int(features["uniform_root_setup_peer_count"])
        confirmation_age_ms = int(
            features["uniform_root_setup_confirmation_age_ms"]
        )
        hello_age_ms = int(features["uniform_root_setup_hello_age_ms"])
    except (KeyError, TypeError, ValueError):
        return False
    return (
        0 < record_length <= 640
        and psk_count == 0
        and features.get("compact_client_hello") is True
        and features.get("root_server_name") is True
        and conveyor_count >= 1
        and setup_peer_count >= 2
        and 0 <= confirmation_age_ms <= 2_000
        and 0 <= hello_age_ms <= 2_000
        and features.get("uniform_root_setup_exact_endpoint") is True
        and features.get("uniform_root_setup_distinct_endpoint") is True
        and features.get("uniform_root_setup_distinct_name") is True
        and features.get("uniform_root_setup_profile_changed") is True
    )


def _valid_uniform_root_setup_resumption_descendant(
    value: dict[str, object],
) -> bool:
    features = value.get("features")
    server_name = value.get("server_name")
    if not isinstance(features, dict) or not isinstance(server_name, str):
        return False
    normalized_name = server_name.rstrip(".").lower()
    if normalized_name != server_name or len(normalized_name.split(".")) != 2:
        return False
    try:
        record_length = int(features["tls_record_length"])
        psk_count = int(features["tls_psk_identity_count"])
        server_payload_bytes = int(features["server_payload_bytes"])
        context_count = int(features["prior_uniform_root_setup_context_count"])
        context_age_ms = int(features["uniform_root_setup_context_age_ms"])
        resumed_peer_count = int(features["setup_resumption_peer_count"])
        hello_delta_ms = int(features["setup_resumption_hello_delta_ms"])
    except (KeyError, TypeError, ValueError):
        return False
    return (
        0 < record_length <= 640
        and psk_count >= 1
        and server_payload_bytes == 0
        and features.get("compact_client_hello") is True
        and features.get("root_server_name") is True
        and context_count >= 2
        and 0 <= context_age_ms <= 6_000
        and resumed_peer_count >= 2
        and 0 <= hello_delta_ms <= 250
        and features.get("uniform_root_setup_context_exact_endpoint") is True
        and features.get("uniform_root_setup_context_exact_name") is True
        and features.get("uniform_root_setup_context_profile_match") is True
        and features.get("uniform_root_setup_resumption_profile_changed") is True
        and (
            features.get("uniform_root_setup_resumption_fingerprint_match")
            is True
        )
        and features.get("uniform_root_setup_resumption_lineage_match") is True
    )


def _valid_uniform_root_successor_exchange_conveyor(
    value: dict[str, object],
) -> bool:
    features = value.get("features")
    server_name = value.get("server_name")
    if not isinstance(features, dict) or not isinstance(server_name, str):
        return False
    normalized_name = server_name.rstrip(".").lower()
    if normalized_name != server_name or len(normalized_name.split(".")) != 2:
        return False
    try:
        record_length = int(features["tls_record_length"])
        psk_count = int(features["tls_psk_identity_count"])
        conveyor_count = int(
            features["prior_uniform_root_successor_conveyor_count"]
        )
        confirmation_age_ms = int(
            features["uniform_root_successor_confirmation_age_ms"]
        )
        exchange_count = int(features["successor_exchange_count"])
        exchange_window_ms = int(features["successor_exchange_window_ms"])
        request_min_bytes = int(features["successor_request_min_bytes"])
        request_max_bytes = int(features["successor_request_max_bytes"])
        small_response_count = int(
            features["successor_small_response_count"]
        )
        large_response_count = int(
            features["successor_large_response_count"]
        )
    except (KeyError, TypeError, ValueError):
        return False
    return (
        0 < record_length <= 640
        and psk_count == 0
        and features.get("compact_client_hello") is True
        and features.get("root_server_name") is True
        and conveyor_count >= 1
        and 0 <= confirmation_age_ms <= 30_000
        and exchange_count == 4
        and 0 <= exchange_window_ms <= 4_000
        and request_min_bytes >= 800
        and request_max_bytes <= 4_000
        and small_response_count >= 3
        and large_response_count >= 1
        and features.get("uniform_root_successor_exact_endpoint") is True
        and features.get("uniform_root_successor_distinct_name") is True
        and features.get("uniform_root_successor_profile_changed") is True
    )


def _valid_uniform_root_successor_resumption_descendant(
    value: dict[str, object],
) -> bool:
    features = value.get("features")
    server_name = value.get("server_name")
    if not isinstance(features, dict) or not isinstance(server_name, str):
        return False
    normalized_name = server_name.rstrip(".").lower()
    if normalized_name != server_name or len(normalized_name.split(".")) != 2:
        return False
    try:
        record_length = int(features["tls_record_length"])
        psk_count = int(features["tls_psk_identity_count"])
        server_payload_bytes = int(features["server_payload_bytes"])
        context_count = int(
            features["prior_uniform_root_successor_context_count"]
        )
        context_age_ms = int(features["successor_resumption_context_age_ms"])
        pair_flow_count = int(features["successor_resumption_pair_flow_count"])
        endpoint_count = int(
            features["successor_resumption_distinct_endpoint_count"]
        )
        hello_delta_ms = int(
            features["successor_resumption_pair_hello_delta_ms"]
        )
    except (KeyError, TypeError, ValueError):
        return False
    return (
        0 < record_length <= 640
        and psk_count >= 1
        and server_payload_bytes == 0
        and features.get("compact_client_hello") is True
        and features.get("root_server_name") is True
        and context_count >= 1
        and 0 <= context_age_ms <= 10_000
        and pair_flow_count >= 2
        and endpoint_count >= 2
        and 0 <= hello_delta_ms <= 250
        and features.get("successor_resumption_pair_established") is True
        and features.get("successor_resumption_exact_name") is True
        and features.get("successor_resumption_distinct_origin_endpoint") is True
        and features.get("successor_resumption_origin_profile_changed") is True
        and features.get("successor_resumption_fingerprint_match") is True
        and features.get("successor_resumption_lineage_match") is True
    )


def _valid_compact_root_profile_cycle_conveyor(
    value: dict[str, object],
) -> bool:
    features = value.get("features")
    server_name = value.get("server_name")
    if not isinstance(features, dict) or not isinstance(server_name, str):
        return False
    normalized_name = server_name.rstrip(".").lower()
    if normalized_name != server_name or len(normalized_name.split(".")) != 2:
        return False
    try:
        record_length = int(features["tls_record_length"])
        psk_count = int(features["tls_psk_identity_count"])
        server_payload_bytes = int(features["server_payload_bytes"])
        prior_setup_count = int(features["profile_cycle_prior_setup_count"])
        resumed_pair_count = int(features["profile_cycle_resumed_pair_count"])
        returned_pair_count = int(
            features["profile_cycle_returned_setup_pair_count"]
        )
        setup_to_resumed_ms = int(
            features["profile_cycle_setup_to_resumed_ms"]
        )
        resumed_to_return_ms = int(
            features["profile_cycle_resumed_to_return_ms"]
        )
        resumed_pair_delta_ms = int(
            features["profile_cycle_resumed_pair_delta_ms"]
        )
        returned_pair_delta_ms = int(
            features["profile_cycle_returned_setup_pair_delta_ms"]
        )
    except (KeyError, TypeError, ValueError):
        return False
    return (
        0 < record_length <= 640
        and psk_count == 0
        and server_payload_bytes == 0
        and features.get("compact_client_hello") is True
        and features.get("root_server_name") is True
        and prior_setup_count >= 1
        and resumed_pair_count >= 2
        and returned_pair_count >= 2
        and 0 <= setup_to_resumed_ms <= 6_000
        and 0 <= resumed_to_return_ms <= 6_000
        and 0 <= resumed_pair_delta_ms <= 250
        and 0 <= returned_pair_delta_ms <= 250
        and features.get("profile_cycle_exact_endpoint") is True
        and features.get("profile_cycle_exact_name") is True
        and features.get("profile_cycle_setup_profile_returned") is True
        and features.get("profile_cycle_resumed_profile_changed") is True
    )


def _valid_compact_root_profile_cycle_resumption_descendant(
    value: dict[str, object],
) -> bool:
    features = value.get("features")
    server_name = value.get("server_name")
    if not isinstance(features, dict) or not isinstance(server_name, str):
        return False
    normalized_name = server_name.rstrip(".").lower()
    if normalized_name != server_name or len(normalized_name.split(".")) != 2:
        return False
    try:
        record_length = int(features["tls_record_length"])
        psk_count = int(features["tls_psk_identity_count"])
        server_payload_bytes = int(features["server_payload_bytes"])
        context_count = int(features["prior_profile_cycle_context_count"])
        context_age_ms = int(features["profile_cycle_context_age_ms"])
    except (KeyError, TypeError, ValueError):
        return False
    return (
        0 < record_length <= 640
        and psk_count >= 1
        and server_payload_bytes == 0
        and features.get("compact_client_hello") is True
        and features.get("root_server_name") is True
        and context_count >= 1
        and 0 <= context_age_ms <= 10_000
        and features.get("profile_cycle_context_exact_endpoint") is True
        and features.get("profile_cycle_context_exact_name") is True
        and features.get("profile_cycle_context_profile_changed") is True
        and features.get("profile_cycle_context_fingerprint_match") is True
        and features.get("profile_cycle_context_lineage_match") is True
    )


def _valid_paired_root_first_exchange_conveyor(
    value: dict[str, object],
) -> bool:
    features = value.get("features")
    server_name = value.get("server_name")
    if not isinstance(features, dict) or not isinstance(server_name, str):
        return False
    normalized_name = server_name.rstrip(".").lower()
    if normalized_name != server_name or len(normalized_name.split(".")) != 2:
        return False
    try:
        record_length = int(features["tls_record_length"])
        psk_count = int(features["tls_psk_identity_count"])
        flow_count = int(features["paired_root_flow_count"])
        endpoint_count = int(
            features["paired_root_distinct_endpoint_count"]
        )
        completed_exchange_count = int(
            features["paired_root_completed_exchange_count"]
        )
        hello_delta_ms = int(features["paired_root_hello_delta_ms"])
        exchange_delta_ms = int(features["paired_root_exchange_delta_ms"])
        request_min_bytes = int(features["paired_root_request_min_bytes"])
        request_max_bytes = int(features["paired_root_request_max_bytes"])
        response_min_bytes = int(features["paired_root_response_min_bytes"])
        response_max_bytes = int(features["paired_root_response_max_bytes"])
    except (KeyError, TypeError, ValueError):
        return False
    return (
        0 < record_length <= 640
        and psk_count == 0
        and features.get("compact_client_hello") is True
        and features.get("root_server_name") is True
        and flow_count == 2
        and 1 <= endpoint_count <= 2
        and 0 <= completed_exchange_count <= 2
        and 0 <= hello_delta_ms <= 400
        and 0 <= exchange_delta_ms <= 400
        and request_min_bytes >= 800
        and request_max_bytes <= 4_000
        and request_min_bytes <= request_max_bytes
        and response_min_bytes >= 1_500
        and response_max_bytes >= 10_000
        and response_min_bytes <= response_max_bytes
        and features.get("paired_root_exact_name") is True
        and features.get("paired_root_setup_profile_match") is True
    )


def _valid_paired_root_resumption_descendant(
    value: dict[str, object],
) -> bool:
    features = value.get("features")
    server_name = value.get("server_name")
    if not isinstance(features, dict) or not isinstance(server_name, str):
        return False
    normalized_name = server_name.rstrip(".").lower()
    if normalized_name != server_name or len(normalized_name.split(".")) != 2:
        return False
    try:
        record_length = int(features["tls_record_length"])
        psk_count = int(features["tls_psk_identity_count"])
        server_payload_bytes = int(features["server_payload_bytes"])
        context_count = int(features["prior_paired_root_context_count"])
        context_age_ms = int(features["paired_root_context_age_ms"])
        context_origin_age_ms = int(
            features["paired_root_context_origin_age_ms"]
        )
        descendant_count = int(
            features["paired_root_context_descendant_count"]
        )
        origin_endpoint_count = int(
            features["paired_root_context_origin_endpoint_count"]
        )
    except (KeyError, TypeError, ValueError):
        return False
    initial = features.get("paired_root_resumption_initial") is True
    endpoint_scope_match = (
        features.get("paired_root_initial_endpoint_scope_match") is True
    )
    scope_valid = (
        initial
        and endpoint_scope_match
        and 0 <= context_origin_age_ms <= 10_000
    ) or (
        not initial
        and (
            0 <= context_origin_age_ms <= 45_000
            or (
                descendant_count >= 3
                and 0 <= context_age_ms <= 45_000
            )
        )
    )
    return (
        0 < record_length <= 640
        and psk_count >= 1
        and server_payload_bytes == 0
        and context_age_ms >= 0
        and context_origin_age_ms >= 0
        and descendant_count >= 1
        and features.get("compact_client_hello") is True
        and features.get("root_server_name") is True
        and context_count >= 1
        and 1 <= origin_endpoint_count <= 2
        and scope_valid
        and features.get("paired_root_context_exact_name") is True
        and features.get("paired_root_context_exact_port") is True
        and features.get("paired_root_resumption_profile_established") is True
        and features.get("paired_root_resumption_fingerprint_match") is True
        and features.get("paired_root_resumption_lineage_match") is True
    )


def _valid_paired_root_setup_descendant(
    value: dict[str, object],
) -> bool:
    features = value.get("features")
    server_name = value.get("server_name")
    if not isinstance(features, dict) or not isinstance(server_name, str):
        return False
    normalized_name = server_name.rstrip(".").lower()
    if normalized_name != server_name or len(normalized_name.split(".")) != 2:
        return False
    try:
        record_length = int(features["tls_record_length"])
        psk_count = int(features["tls_psk_identity_count"])
        server_payload_bytes = int(features["server_payload_bytes"])
        context_count = int(
            features["prior_paired_root_setup_context_count"]
        )
        context_age_ms = int(features["paired_root_setup_context_age_ms"])
        context_origin_age_ms = int(
            features["paired_root_setup_context_origin_age_ms"]
        )
        descendant_count = int(
            features["paired_root_setup_context_descendant_count"]
        )
    except (KeyError, TypeError, ValueError):
        return False
    return (
        0 < record_length <= 640
        and psk_count == 0
        and server_payload_bytes == 0
        and features.get("compact_client_hello") is True
        and features.get("root_server_name") is True
        and context_count >= 1
        and context_age_ms >= 0
        and context_origin_age_ms >= 0
        and descendant_count >= 1
        and (
            0 <= context_origin_age_ms <= 45_000
            or (
                descendant_count >= 3
                and 0 <= context_age_ms <= 45_000
            )
        )
        and features.get("paired_root_setup_context_exact_name") is True
        and features.get("paired_root_setup_context_exact_port") is True
        and features.get("paired_root_setup_context_fingerprint_match") is True
        and features.get("paired_root_setup_context_lineage_match") is True
    )


def _valid_mirrored_root_resumption_transition(
    value: dict[str, object],
) -> bool:
    features = value.get("features")
    server_name = value.get("server_name")
    if not isinstance(features, dict) or not isinstance(server_name, str):
        return False
    normalized_name = server_name.rstrip(".").lower()
    if normalized_name != server_name or len(normalized_name.split(".")) != 2:
        return False
    try:
        record_length = int(features["tls_record_length"])
        psk_count = int(features["tls_psk_identity_count"])
        server_payload_bytes = int(features["server_payload_bytes"])
        setup_count = int(features["mirrored_root_setup_pair_count"])
        resumed_count = int(features["mirrored_root_resumed_pair_count"])
        name_count = int(features["mirrored_root_distinct_name_count"])
        endpoint_count = int(features["mirrored_root_distinct_endpoint_count"])
        setup_delta_ms = int(features["mirrored_root_setup_delta_ms"])
        resumed_delta_ms = int(features["mirrored_root_resumed_delta_ms"])
        transition_window_ms = int(
            features["mirrored_root_transition_window_ms"]
        )
    except (KeyError, TypeError, ValueError):
        return False
    return (
        0 < record_length <= 640
        and psk_count >= 1
        and features.get("compact_client_hello") is True
        and features.get("root_server_name") is True
        and server_payload_bytes == 0
        and setup_count == 2
        and resumed_count == 2
        and name_count == 2
        and endpoint_count == 2
        and 0 <= setup_delta_ms <= 250
        and 0 <= resumed_delta_ms <= 250
        and 0 <= transition_window_ms <= 1_000
        and features.get("mirrored_root_profile_changed") is True
        and features.get("mirrored_root_transition") is True
    )


def _valid_compact_causal_retry(value: dict[str, object]) -> bool:
    features = value.get("features")
    server_name = value.get("server_name")
    if not isinstance(features, dict) or not isinstance(server_name, str):
        return False
    normalized_name = server_name.rstrip(".").lower()
    if normalized_name != server_name or len(normalized_name.split(".")) != 2:
        return False
    try:
        record_length = int(features["tls_record_length"])
        subdomain_count = int(features["same_family_subdomain_count"])
        prior_root_count = int(features["prior_large_causal_root_count"])
        causal_edge_score = float(features["causal_edge_score"])
    except (KeyError, TypeError, ValueError):
        return False
    return (
        0 < record_length <= 640
        and features.get("compact_client_hello") is True
        and features.get("root_server_name") is True
        and subdomain_count >= 2
        and prior_root_count >= 1
        and causal_edge_score >= 0.42
        and features.get("compact_root_causal_retry") is True
    )


__all__ = [
    "CandidateFlow",
    "CandidateLogFollower",
    "CandidateValidator",
    "validate_candidate_event",
]
