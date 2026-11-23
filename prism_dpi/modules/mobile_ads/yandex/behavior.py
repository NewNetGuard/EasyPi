"""Temporal operator for the Yandex compact-TLS shadow detector."""

from __future__ import annotations

from collections import Counter, deque
from dataclasses import dataclass
from typing import Iterable


BURST_WINDOW_SECONDS = 3.0
BURST_MIN_HITS_PER_SERVER_NAME = 2
BURST_MIN_TOTAL_HITS = 5
BURST_SERVER_NAMES = frozenset(("yandex.com", "yandex.ru"))

# Learned from the MAO Yandex Ads positive window captured on 2026-08-25.
# The root name and compact ClientHello alone are shared with ordinary Yandex
# traffic.  This profile is therefore usable only when the exact TLS and
# resumption-lineage fingerprints are present together.
LEARNED_AD_SERVER_NAME = "yandex.com"
LEARNED_AD_TLS_FINGERPRINT = "6ed8419477975b64"
LEARNED_AD_TLS_LINEAGE_FINGERPRINT = "fefbd8cf90f71b6b"
LEARNED_AD_TLS_RECORD_LENGTH = 512
LEARNED_AD_CONTROL_TLS_FINGERPRINT = "08611365952576b3"
LEARNED_AD_CONTROL_TLS_LINEAGE_FINGERPRINT = "dc45452e304cb9d9"
LEARNED_MAIL_BROWSER_ROOT_SERVER_NAME = "yandex.ru"
LEARNED_MAIL_BROWSER_MIN_ROOT_FLOWS = 5
LEARNED_MAIL_BROWSER_MIN_CONTEXT_AGE_MS = 5_000
LEARNED_MAIL_BROWSER_MAX_CONTEXT_IDLE_MS = 120_000
LEARNED_MAIL_DESKTOP_MIN_CONTEXT_FLOWS = 4
LEARNED_MAIL_DESKTOP_MIN_CONTEXT_AGE_MS = 1_000
LEARNED_MAIL_DZEN_SERVER_NAME = "dzen.ru"
LEARNED_MAIL_DZEN_MIN_BURST_FLOWS = 5
LEARNED_MAIL_INLINE_SERVER_NAME = "mail.yandex.ru"
LEARNED_MAIL_INLINE_MIN_CONTEXT_FLOWS = 4
LEARNED_MAIL_INLINE_PREVIOUS_REQUEST_MIN_BYTES = 3_400
LEARNED_MAIL_INLINE_PREVIOUS_REQUEST_MAX_BYTES = 4_300
LEARNED_MAIL_INLINE_PREVIOUS_RESPONSE_MIN_BYTES = 1_200
LEARNED_MAIL_INLINE_PREVIOUS_RESPONSE_MAX_BYTES = 1_650
LEARNED_MAIL_INLINE_REQUEST_MIN_BYTES = 1_900
LEARNED_MAIL_INLINE_REQUEST_MAX_BYTES = 2_400
LEARNED_MAIL_INLINE_FLOW_AGE_MIN_MS = 2_500
LEARNED_MAIL_INLINE_FLOW_AGE_MAX_MS = 6_500
LEARNED_MAIL_INLINE_FIRST_RESPONSE_DELAY_MIN_MS = 80
LEARNED_MAIL_INLINE_FIRST_RESPONSE_DELAY_MAX_MS = 250
LEARNED_MAIL_INLINE_NEXT_REQUEST_DELAY_MIN_MS = 100
LEARNED_MAIL_INLINE_NEXT_REQUEST_DELAY_MAX_MS = 500
LEARNED_MAIL_INLINE_FIRST_TLS_FINGERPRINT = "d9c5b4b26de42707"
LEARNED_MAIL_INLINE_FIRST_TLS_LINEAGE_FINGERPRINT = "e49e77cbc38230eb"
LEARNED_MAIL_INLINE_FIRST_HELLO_MIN_BYTES = 1_900
LEARNED_MAIL_INLINE_FIRST_HELLO_MAX_BYTES = 2_150
LEARNED_MAIL_INLINE_FIRST_REQUEST_MIN_BYTES = 2_100
LEARNED_MAIL_INLINE_FIRST_REQUEST_MAX_BYTES = 2_200
LEARNED_MAIL_INLINE_FIRST_CLIENT_PAYLOAD_MIN_BYTES = 4_200
LEARNED_MAIL_INLINE_FIRST_CLIENT_PAYLOAD_MAX_BYTES = 4_400
LEARNED_MAIL_INLINE_FIRST_SERVER_PAYLOAD_MIN_BYTES = 5_000
LEARNED_MAIL_INLINE_FIRST_SERVER_PAYLOAD_MAX_BYTES = 5_500
LEARNED_MAIL_INLINE_FIRST_REQUEST_DELAY_MIN_MS = 70
LEARNED_MAIL_INLINE_FIRST_REQUEST_DELAY_MAX_MS = 130
LEARNED_MAIL_INLINE_FIRST_HANDSHAKE_DELAY_MIN_MS = 40
LEARNED_MAIL_INLINE_FIRST_HANDSHAKE_DELAY_MAX_MS = 90
LEARNED_MAIL_INLINE_FIRST_CONTEXT_MAX_AGE_MS = 1_500
LEARNED_MAIL_INLINE_FIRST_CONTEXT_MAX_IDLE_MS = 250
LEARNED_MAIL_INLINE_FIRST_MIN_BURST_FLOWS = 7
LEARNED_MAIL_INLINE_FIRST_MIN_SESSION_FLOWS = 4
LEARNED_MAIL_INLINE_FIRST_MIN_FAMILY_REQUESTS = 2
LEARNED_MAIL_INLINE_BOOTSTRAP_REQUEST_MIN_BYTES = 6_000
LEARNED_MAIL_INLINE_BOOTSTRAP_REQUEST_MAX_BYTES = 8_000
LEARNED_MAIL_INLINE_BOOTSTRAP_MIN_BURST_FLOWS = 10
LEARNED_MAIL_INLINE_BOOTSTRAP_MIN_SESSION_FLOWS = 5
LEARNED_MAIL_INLINE_OUTLIER_RESPONSE_MIN_BYTES = 16_000
LEARNED_MAIL_INLINE_OUTLIER_REQUEST_MIN_BYTES = 1_900
LEARNED_MAIL_INLINE_OUTLIER_REQUEST_MAX_BYTES = 8_000
LEARNED_MAIL_INLINE_OUTLIER_MIN_PEERS = 2
LEARNED_MAIL_INLINE_OUTLIER_MAX_FLOW_AGE_MS = 2_500
LEARNED_MAIL_INLINE_OUTLIER_MAX_FIRST_RESPONSE_DELAY_MS = 150
LEARNED_MAIL_INLINE_PAYLOAD_REQUEST_MIN_BYTES = 2_050
LEARNED_MAIL_INLINE_PAYLOAD_REQUEST_MAX_BYTES = 2_200
LEARNED_MAIL_INLINE_PAYLOAD_RESPONSE_MIN_BYTES = 32_000
LEARNED_MAIL_INLINE_PAYLOAD_MIN_RESPONSE_RECORDS = 2
LEARNED_MAIL_INLINE_PAYLOAD_MAX_FLOW_AGE_MS = 10_000
LEARNED_MAIL_INLINE_PAYLOAD_MAX_FIRST_RESPONSE_DELAY_MS = 250
LEARNED_MAIL_INLINE_AD_DNA_PREVIOUS_REQUEST_MIN_BYTES = 2_200
LEARNED_MAIL_INLINE_AD_DNA_PREVIOUS_REQUEST_MAX_BYTES = 4_200
LEARNED_MAIL_INLINE_AD_DNA_PREVIOUS_RESPONSE_MIN_BYTES = 500
LEARNED_MAIL_INLINE_AD_DNA_PREVIOUS_RESPONSE_MAX_BYTES = 1_500
LEARNED_MAIL_INLINE_AD_DNA_PREVIOUS_RESPONSE_DELAY_MIN_MS = 30
LEARNED_MAIL_INLINE_AD_DNA_PREVIOUS_RESPONSE_DELAY_MAX_MS = 200
LEARNED_MAIL_INLINE_AD_DNA_NEXT_REQUEST_DELAY_MAX_MS = 100
LEARNED_MAIL_INLINE_AD_DNA_REQUEST_MIN_BYTES = 6_000
LEARNED_MAIL_INLINE_AD_DNA_REQUEST_MAX_BYTES = 12_500
LEARNED_MAIL_INLINE_AD_DNA_FLOW_AGE_MIN_MS = 800
LEARNED_MAIL_INLINE_AD_DNA_FLOW_AGE_MAX_MS = 15_000


@dataclass(frozen=True)
class CompactTlsObservation:
    timestamp: float
    server_name: str


def has_compact_tls_burst(
    observations: Iterable[CompactTlsObservation],
    *,
    window_seconds: float = BURST_WINDOW_SECONDS,
    min_hits_per_server_name: int = BURST_MIN_HITS_PER_SERVER_NAME,
    min_total_hits: int = BURST_MIN_TOTAL_HITS,
) -> bool:
    """Return whether both exact SNI classes reach the threshold in one window."""
    if window_seconds <= 0:
        raise ValueError("window_seconds must be positive")
    if min_hits_per_server_name <= 0:
        raise ValueError("min_hits_per_server_name must be positive")
    if min_total_hits <= 0:
        raise ValueError("min_total_hits must be positive")

    ordered = sorted(observations, key=lambda observation: observation.timestamp)
    window: deque[CompactTlsObservation] = deque()
    counts: Counter[str] = Counter()

    for observation in ordered:
        if observation.server_name not in BURST_SERVER_NAMES:
            continue
        window.append(observation)
        counts[observation.server_name] += 1

        cutoff = observation.timestamp - window_seconds
        while window and window[0].timestamp < cutoff:
            expired = window.popleft()
            counts[expired.server_name] -= 1

        if len(window) >= min_total_hits and all(
            counts[server_name] >= min_hits_per_server_name
            for server_name in BURST_SERVER_NAMES
        ):
            return True

    return False


def matches_learned_ad_resumption_pair(
    *,
    server_name: object,
    features: object,
) -> bool:
    """Match the confirmed MAO Yandex Ads resumption-pair transport profile.

    This is deliberately stricter than the generic compact-TLS observation.
    It is intended to authorize only the already identified flow tuple; it
    must not be used as a domain-wide or device-wide blocking rule.
    """
    if server_name != LEARNED_AD_SERVER_NAME or not isinstance(features, dict):
        return False
    try:
        record_length = int(features["tls_record_length"])
        psk_identity_count = int(features["tls_psk_identity_count"])
        prior_lineage_flow_count = int(features["prior_lineage_flow_count"])
    except (KeyError, TypeError, ValueError):
        return False
    return (
        features.get("tls_fingerprint") == LEARNED_AD_TLS_FINGERPRINT
        and features.get("tls_lineage_fingerprint")
        == LEARNED_AD_TLS_LINEAGE_FINGERPRINT
        and record_length == LEARNED_AD_TLS_RECORD_LENGTH
        and features.get("compact_client_hello") is True
        and features.get("root_server_name") is True
        and features.get("compact_root_resumption_pair") is True
        and psk_identity_count >= 1
        and prior_lineage_flow_count >= 1
    )


def matches_learned_ad_control_flow(
    *,
    server_name: object,
    features: object,
) -> bool:
    """Match an ad-control ClientHello before any server payload arrives.

    The TLS profile alone is shared by Android traffic, so early enforcement
    additionally requires an exact root SNI, the learned lineage, an untouched
    ClientHello-only byte count, and an already dense multi-flow app session.
    """
    if server_name != LEARNED_AD_SERVER_NAME or not isinstance(features, dict):
        return False
    try:
        record_length = int(features["tls_record_length"])
        psk_identity_count = int(features["tls_psk_identity_count"])
        client_payload_bytes = int(features["client_payload_bytes"])
        server_payload_bytes = int(features["server_payload_bytes"])
        session_flow_count = int(features["session_flow_count"])
        burst_flow_count = int(features["burst_flow_count"])
        same_fingerprint_count = int(features["same_fingerprint_count"])
    except (KeyError, TypeError, ValueError):
        return False
    return (
        features.get("tls_fingerprint") == LEARNED_AD_CONTROL_TLS_FINGERPRINT
        and features.get("tls_lineage_fingerprint")
        == LEARNED_AD_CONTROL_TLS_LINEAGE_FINGERPRINT
        and record_length == LEARNED_AD_TLS_RECORD_LENGTH
        and features.get("compact_client_hello") is True
        and features.get("root_server_name") is True
        and psk_identity_count == 0
        and client_payload_bytes == 517
        and server_payload_bytes == 0
        and session_flow_count >= 4
        and burst_flow_count >= 5
        and same_fingerprint_count >= 2
    )


def matches_learned_mail_browser_root_burst(
    *,
    server_name: object,
    features: object,
) -> bool:
    """Match the delayed root-TLS pool observed before a Yandex Mail web ad.

    The browser opens several large ``yandex.ru`` TLS connections while an
    already established ``mail.yandex.ru`` session remains active. One member
    of that pool later carries the ad response. Fingerprints are intentionally
    not used because browser ClientHello padding changed on every connection in
    the positive capture. Enforcement must stay exact-flow-only.
    """
    if (
        server_name != LEARNED_MAIL_BROWSER_ROOT_SERVER_NAME
        or not isinstance(features, dict)
    ):
        return False
    try:
        record_length = int(features["tls_record_length"])
        context_flow_count = int(features["yandex_mail_context_flow_count"])
        context_age_ms = int(features["yandex_mail_context_age_ms"])
        context_idle_ms = int(features["yandex_mail_context_idle_ms"])
        root_burst_count = int(features["yandex_mail_root_burst_count"])
    except (KeyError, TypeError, ValueError):
        return False
    return (
        record_length > 640
        and features.get("compact_client_hello") is False
        and features.get("root_server_name") is True
        and features.get("yandex_mail_browser_root_burst") is True
        and context_flow_count >= 1
        and context_age_ms >= LEARNED_MAIL_BROWSER_MIN_CONTEXT_AGE_MS
        and 0 <= context_idle_ms <= LEARNED_MAIL_BROWSER_MAX_CONTEXT_IDLE_MS
        and root_burst_count >= LEARNED_MAIL_BROWSER_MIN_ROOT_FLOWS
    )


def matches_learned_mail_browser_serial_root(
    *,
    server_name: object,
    features: object,
) -> bool:
    """Match the serial root transport used by Yandex Mail desktop web ads.

    The desktop browser capture used one new large ``yandex.ru`` connection at
    a time. Each was created while at least four established Mail connections
    remained active, then delivered a delayed 30-167 KiB response. The rule is
    intentionally limited to this dense Mail context and exact flow tuples.
    """
    if (
        server_name != LEARNED_MAIL_BROWSER_ROOT_SERVER_NAME
        or not isinstance(features, dict)
    ):
        return False
    try:
        record_length = int(features["tls_record_length"])
        context_flow_count = int(features["yandex_mail_context_flow_count"])
        context_age_ms = int(features["yandex_mail_context_age_ms"])
        context_idle_ms = int(features["yandex_mail_context_idle_ms"])
    except (KeyError, TypeError, ValueError):
        return False
    return (
        record_length > 640
        and features.get("compact_client_hello") is False
        and features.get("root_server_name") is True
        and features.get("yandex_mail_browser_serial_root") is True
        and context_flow_count >= LEARNED_MAIL_DESKTOP_MIN_CONTEXT_FLOWS
        and context_age_ms >= LEARNED_MAIL_DESKTOP_MIN_CONTEXT_AGE_MS
        and 0 <= context_idle_ms <= LEARNED_MAIL_BROWSER_MAX_CONTEXT_IDLE_MS
    )


def matches_learned_mail_browser_dzen_root(
    *,
    server_name: object,
    features: object,
) -> bool:
    """Match the Dzen control flow of the embedded Yandex Mail ad panel.

    The positive desktop capture showed a large exact ``dzen.ru`` ClientHello
    inside a dense connection burst while at least four established
    ``mail.yandex.ru`` flows remained active.  The root flow then fanned out to
    Dzen/VK/OK CDN endpoints.  Enforcement is limited to the root flow before
    any server payload; CDN names and Mail connections stay untouched.
    """
    if server_name != LEARNED_MAIL_DZEN_SERVER_NAME or not isinstance(features, dict):
        return False
    try:
        record_length = int(features["tls_record_length"])
        server_payload_bytes = int(features["server_payload_bytes"])
        context_flow_count = int(features["yandex_mail_context_flow_count"])
        context_age_ms = int(features["yandex_mail_context_age_ms"])
        context_idle_ms = int(features["yandex_mail_context_idle_ms"])
        burst_flow_count = int(features["burst_flow_count"])
    except (KeyError, TypeError, ValueError):
        return False
    return (
        record_length > 640
        and server_payload_bytes == 0
        and features.get("compact_client_hello") is False
        and features.get("root_server_name") is True
        and features.get("yandex_mail_browser_dzen_root") is True
        and context_flow_count >= LEARNED_MAIL_DESKTOP_MIN_CONTEXT_FLOWS
        and context_age_ms >= LEARNED_MAIL_DESKTOP_MIN_CONTEXT_AGE_MS
        and 0 <= context_idle_ms <= LEARNED_MAIL_BROWSER_MAX_CONTEXT_IDLE_MS
        and burst_flow_count >= LEARNED_MAIL_DZEN_MIN_BURST_FLOWS
    )


def matches_learned_mail_inline_ad_request(
    *,
    server_name: object,
    features: object,
) -> bool:
    """Match the pre-response request observed inside Yandex Mail TLS.

    Unlike the root-flow rules, this signature authorizes a reset only after a
    very specific completed first exchange and the first record of exchange
    two, before that exchange receives a response.  It never authorizes an IP
    or SNI-wide block.
    """
    if (
        server_name != LEARNED_MAIL_INLINE_SERVER_NAME
        or not isinstance(features, dict)
    ):
        return False
    try:
        context_flow_count = int(features["yandex_mail_context_flow_count"])
        context_age_ms = int(features["yandex_mail_context_age_ms"])
        context_idle_ms = int(features["yandex_mail_context_idle_ms"])
        pending_index = int(features["yandex_mail_pending_exchange_index"])
        pending_request_count = int(
            features["yandex_mail_pending_request_record_count"]
        )
        pending_request_bytes = int(features["yandex_mail_pending_request_bytes"])
        pending_response_count = int(
            features["yandex_mail_pending_response_record_count"]
        )
        previous_index = int(features["yandex_mail_previous_exchange_index"])
        previous_request_bytes = int(
            features["yandex_mail_previous_request_bytes"]
        )
        previous_response_bytes = int(
            features["yandex_mail_previous_response_bytes"]
        )
        first_response_delay_ms = int(
            features["yandex_mail_previous_first_response_delay_ms"]
        )
        next_request_delay_ms = int(
            features["yandex_mail_previous_next_request_delay_ms"]
        )
        flow_age_ms = int(features["yandex_mail_previous_flow_age_ms"])
    except (KeyError, TypeError, ValueError):
        return False
    return (
        features.get("yandex_mail_inline_ad_request") is True
        and context_flow_count >= LEARNED_MAIL_INLINE_MIN_CONTEXT_FLOWS
        and context_age_ms >= LEARNED_MAIL_DESKTOP_MIN_CONTEXT_AGE_MS
        and 0 <= context_idle_ms <= LEARNED_MAIL_BROWSER_MAX_CONTEXT_IDLE_MS
        and previous_index == 1
        and LEARNED_MAIL_INLINE_PREVIOUS_REQUEST_MIN_BYTES
        <= previous_request_bytes
        <= LEARNED_MAIL_INLINE_PREVIOUS_REQUEST_MAX_BYTES
        and LEARNED_MAIL_INLINE_PREVIOUS_RESPONSE_MIN_BYTES
        <= previous_response_bytes
        <= LEARNED_MAIL_INLINE_PREVIOUS_RESPONSE_MAX_BYTES
        and LEARNED_MAIL_INLINE_FIRST_RESPONSE_DELAY_MIN_MS
        <= first_response_delay_ms
        <= LEARNED_MAIL_INLINE_FIRST_RESPONSE_DELAY_MAX_MS
        and LEARNED_MAIL_INLINE_NEXT_REQUEST_DELAY_MIN_MS
        <= next_request_delay_ms
        <= LEARNED_MAIL_INLINE_NEXT_REQUEST_DELAY_MAX_MS
        and LEARNED_MAIL_INLINE_FLOW_AGE_MIN_MS
        <= flow_age_ms
        <= LEARNED_MAIL_INLINE_FLOW_AGE_MAX_MS
        and pending_index == 2
        and pending_request_count == 1
        and LEARNED_MAIL_INLINE_REQUEST_MIN_BYTES
        <= pending_request_bytes
        <= LEARNED_MAIL_INLINE_REQUEST_MAX_BYTES
        and pending_response_count == 0
    )


def matches_learned_mail_inline_first_ad_request(
    *,
    server_name: object,
    features: object,
) -> bool:
    """Match the first-exchange fallback observed after root-flow resets."""
    if (
        server_name != LEARNED_MAIL_INLINE_SERVER_NAME
        or not isinstance(features, dict)
    ):
        return False
    try:
        record_length = int(features["tls_record_length"])
        psk_identity_count = int(features["tls_psk_identity_count"])
        client_payload_bytes = int(features["client_payload_bytes"])
        server_payload_bytes = int(features["server_payload_bytes"])
        first_request = int(features["first_client_application_record"])
        first_request_delay_ms = int(features["first_request_delay_ms"])
        handshake_delay_ms = int(features["first_response_delay_ms"])
        context_flow_count = int(features["yandex_mail_context_flow_count"])
        context_age_ms = int(features["yandex_mail_context_age_ms"])
        context_idle_ms = int(features["yandex_mail_context_idle_ms"])
        burst_flow_count = int(features["burst_flow_count"])
        session_flow_count = int(features["session_flow_count"])
        family_request_count = int(features["recent_family_request_flow_count"])
        pending_index = int(features["yandex_mail_pending_exchange_index"])
        pending_request_count = int(
            features["yandex_mail_pending_request_record_count"]
        )
        pending_request_bytes = int(features["yandex_mail_pending_request_bytes"])
        pending_response_count = int(
            features["yandex_mail_pending_response_record_count"]
        )
        previous_index = int(features["yandex_mail_previous_exchange_index"])
    except (KeyError, TypeError, ValueError):
        return False
    return (
        features.get("yandex_mail_inline_first_ad_request") is True
        and features.get("tls_fingerprint")
        == LEARNED_MAIL_INLINE_FIRST_TLS_FINGERPRINT
        and features.get("tls_lineage_fingerprint")
        == LEARNED_MAIL_INLINE_FIRST_TLS_LINEAGE_FINGERPRINT
        and psk_identity_count >= 1
        and LEARNED_MAIL_INLINE_FIRST_HELLO_MIN_BYTES
        <= record_length
        <= LEARNED_MAIL_INLINE_FIRST_HELLO_MAX_BYTES
        and LEARNED_MAIL_INLINE_FIRST_CLIENT_PAYLOAD_MIN_BYTES
        <= client_payload_bytes
        <= LEARNED_MAIL_INLINE_FIRST_CLIENT_PAYLOAD_MAX_BYTES
        and LEARNED_MAIL_INLINE_FIRST_SERVER_PAYLOAD_MIN_BYTES
        <= server_payload_bytes
        <= LEARNED_MAIL_INLINE_FIRST_SERVER_PAYLOAD_MAX_BYTES
        and LEARNED_MAIL_INLINE_FIRST_REQUEST_MIN_BYTES
        <= first_request
        <= LEARNED_MAIL_INLINE_FIRST_REQUEST_MAX_BYTES
        and LEARNED_MAIL_INLINE_FIRST_REQUEST_DELAY_MIN_MS
        <= first_request_delay_ms
        <= LEARNED_MAIL_INLINE_FIRST_REQUEST_DELAY_MAX_MS
        and LEARNED_MAIL_INLINE_FIRST_HANDSHAKE_DELAY_MIN_MS
        <= handshake_delay_ms
        <= LEARNED_MAIL_INLINE_FIRST_HANDSHAKE_DELAY_MAX_MS
        and context_flow_count >= LEARNED_MAIL_INLINE_MIN_CONTEXT_FLOWS
        and 0 <= context_age_ms <= LEARNED_MAIL_INLINE_FIRST_CONTEXT_MAX_AGE_MS
        and 0 <= context_idle_ms <= LEARNED_MAIL_INLINE_FIRST_CONTEXT_MAX_IDLE_MS
        and burst_flow_count >= LEARNED_MAIL_INLINE_FIRST_MIN_BURST_FLOWS
        and session_flow_count >= LEARNED_MAIL_INLINE_FIRST_MIN_SESSION_FLOWS
        and family_request_count >= LEARNED_MAIL_INLINE_FIRST_MIN_FAMILY_REQUESTS
        and previous_index == 0
        and pending_index == 1
        and pending_request_count == 1
        and LEARNED_MAIL_INLINE_FIRST_REQUEST_MIN_BYTES
        <= pending_request_bytes
        <= LEARNED_MAIL_INLINE_FIRST_REQUEST_MAX_BYTES
        and pending_response_count == 0
    )


def matches_learned_mail_inline_bootstrap_large_request(
    *,
    server_name: object,
    features: object,
) -> bool:
    """Match the large first request of a dense Mail bootstrap fallback."""
    if (
        server_name != LEARNED_MAIL_INLINE_SERVER_NAME
        or not isinstance(features, dict)
    ):
        return False
    try:
        psk_identity_count = int(features["tls_psk_identity_count"])
        server_payload_bytes = int(features["server_payload_bytes"])
        request_delay_ms = int(features["first_request_delay_ms"])
        handshake_delay_ms = int(features["first_response_delay_ms"])
        burst_flow_count = int(features["burst_flow_count"])
        session_flow_count = int(features["session_flow_count"])
        previous_index = int(features["yandex_mail_previous_exchange_index"])
        pending_index = int(features["yandex_mail_pending_exchange_index"])
        pending_request_count = int(
            features["yandex_mail_pending_request_record_count"]
        )
        pending_request_bytes = int(features["yandex_mail_pending_request_bytes"])
        pending_response_count = int(
            features["yandex_mail_pending_response_record_count"]
        )
    except (KeyError, TypeError, ValueError):
        return False
    return (
        features.get("yandex_mail_inline_bootstrap_large_request") is True
        and psk_identity_count >= 1
        and LEARNED_MAIL_INLINE_FIRST_SERVER_PAYLOAD_MIN_BYTES
        <= server_payload_bytes
        <= LEARNED_MAIL_INLINE_FIRST_SERVER_PAYLOAD_MAX_BYTES
        and 30 <= request_delay_ms <= LEARNED_MAIL_INLINE_FIRST_REQUEST_DELAY_MAX_MS
        and LEARNED_MAIL_INLINE_FIRST_HANDSHAKE_DELAY_MIN_MS
        <= handshake_delay_ms
        <= 130
        and burst_flow_count >= LEARNED_MAIL_INLINE_BOOTSTRAP_MIN_BURST_FLOWS
        and session_flow_count >= LEARNED_MAIL_INLINE_BOOTSTRAP_MIN_SESSION_FLOWS
        and previous_index == 0
        and pending_index == 1
        and pending_request_count == 1
        and LEARNED_MAIL_INLINE_BOOTSTRAP_REQUEST_MIN_BYTES
        <= pending_request_bytes
        <= LEARNED_MAIL_INLINE_BOOTSTRAP_REQUEST_MAX_BYTES
        and pending_response_count == 0
    )


def matches_learned_mail_inline_response_outlier(
    *,
    server_name: object,
    features: object,
) -> bool:
    """Match a Mail response that is large relative to sibling flows."""
    if (
        server_name != LEARNED_MAIL_INLINE_SERVER_NAME
        or not isinstance(features, dict)
    ):
        return False
    try:
        pending_index = int(features["yandex_mail_pending_exchange_index"])
        pending_request_bytes = int(features["yandex_mail_pending_request_bytes"])
        pending_response_count = int(
            features["yandex_mail_pending_response_record_count"]
        )
        pending_response_bytes = int(features["yandex_mail_pending_response_bytes"])
        first_response_delay_ms = int(
            features["yandex_mail_pending_first_response_delay_ms"]
        )
        flow_age_ms = int(features["yandex_mail_current_flow_age_ms"])
        small_peer_count = int(features["yandex_mail_inline_small_peer_count"])
        context_flow_count = int(features.get("yandex_mail_context_flow_count", 0))
        burst_flow_count = int(features.get("burst_flow_count", 0))
    except (KeyError, TypeError, ValueError):
        return False
    classic_outlier = (
        pending_index in (1, 2)
        and LEARNED_MAIL_INLINE_OUTLIER_REQUEST_MIN_BYTES
        <= pending_request_bytes
        <= LEARNED_MAIL_INLINE_OUTLIER_REQUEST_MAX_BYTES
        and pending_response_count >= 1
        and pending_response_bytes >= LEARNED_MAIL_INLINE_OUTLIER_RESPONSE_MIN_BYTES
        and 0
        <= first_response_delay_ms
        <= LEARNED_MAIL_INLINE_OUTLIER_MAX_FIRST_RESPONSE_DELAY_MS
        and 0 <= flow_age_ms <= LEARNED_MAIL_INLINE_OUTLIER_MAX_FLOW_AGE_MS
        and small_peer_count >= LEARNED_MAIL_INLINE_OUTLIER_MIN_PEERS
    )
    payload_dna = (
        context_flow_count >= LEARNED_MAIL_INLINE_MIN_CONTEXT_FLOWS
        and burst_flow_count >= 4
        and LEARNED_MAIL_INLINE_PAYLOAD_REQUEST_MIN_BYTES
        <= pending_request_bytes
        <= LEARNED_MAIL_INLINE_PAYLOAD_REQUEST_MAX_BYTES
        and pending_response_count >= LEARNED_MAIL_INLINE_PAYLOAD_MIN_RESPONSE_RECORDS
        and pending_response_bytes >= LEARNED_MAIL_INLINE_PAYLOAD_RESPONSE_MIN_BYTES
        and 0
        <= first_response_delay_ms
        <= LEARNED_MAIL_INLINE_PAYLOAD_MAX_FIRST_RESPONSE_DELAY_MS
        and 0 <= flow_age_ms <= LEARNED_MAIL_INLINE_PAYLOAD_MAX_FLOW_AGE_MS
    )
    return features.get("yandex_mail_inline_response_outlier") is True and (
        classic_outlier or payload_dna
    )


def matches_learned_mail_inline_ad_dna_request(
    *,
    server_name: object,
    features: object,
) -> bool:
    """Match the repeated small-control to large-request Mail ad cycle."""
    if (
        server_name != LEARNED_MAIL_INLINE_SERVER_NAME
        or not isinstance(features, dict)
    ):
        return False
    try:
        context_flow_count = int(features["yandex_mail_context_flow_count"])
        burst_flow_count = int(features["burst_flow_count"])
        pending_index = int(features["yandex_mail_pending_exchange_index"])
        pending_request_count = int(
            features["yandex_mail_pending_request_record_count"]
        )
        pending_request_bytes = int(features["yandex_mail_pending_request_bytes"])
        pending_response_count = int(
            features["yandex_mail_pending_response_record_count"]
        )
        previous_index = int(features["yandex_mail_previous_exchange_index"])
        previous_request_bytes = int(
            features["yandex_mail_previous_request_bytes"]
        )
        previous_response_bytes = int(
            features["yandex_mail_previous_response_bytes"]
        )
        previous_response_delay_ms = int(
            features["yandex_mail_previous_first_response_delay_ms"]
        )
        previous_next_request_delay_ms = int(
            features["yandex_mail_previous_next_request_delay_ms"]
        )
        previous_flow_age_ms = int(features["yandex_mail_previous_flow_age_ms"])
    except (KeyError, TypeError, ValueError):
        return False
    return (
        features.get("yandex_mail_inline_ad_dna_request") is True
        and context_flow_count >= 1
        and burst_flow_count >= 4
        and previous_index >= 2
        and LEARNED_MAIL_INLINE_AD_DNA_PREVIOUS_REQUEST_MIN_BYTES
        <= previous_request_bytes
        <= LEARNED_MAIL_INLINE_AD_DNA_PREVIOUS_REQUEST_MAX_BYTES
        and LEARNED_MAIL_INLINE_AD_DNA_PREVIOUS_RESPONSE_MIN_BYTES
        <= previous_response_bytes
        <= LEARNED_MAIL_INLINE_AD_DNA_PREVIOUS_RESPONSE_MAX_BYTES
        and LEARNED_MAIL_INLINE_AD_DNA_PREVIOUS_RESPONSE_DELAY_MIN_MS
        <= previous_response_delay_ms
        <= LEARNED_MAIL_INLINE_AD_DNA_PREVIOUS_RESPONSE_DELAY_MAX_MS
        and 0
        <= previous_next_request_delay_ms
        <= LEARNED_MAIL_INLINE_AD_DNA_NEXT_REQUEST_DELAY_MAX_MS
        and LEARNED_MAIL_INLINE_AD_DNA_FLOW_AGE_MIN_MS
        <= previous_flow_age_ms
        <= LEARNED_MAIL_INLINE_AD_DNA_FLOW_AGE_MAX_MS
        and pending_index == previous_index + 1
        and pending_request_count == 1
        and LEARNED_MAIL_INLINE_AD_DNA_REQUEST_MIN_BYTES
        <= pending_request_bytes
        <= LEARNED_MAIL_INLINE_AD_DNA_REQUEST_MAX_BYTES
        and pending_response_count == 0
    )


__all__ = [
    "BURST_MIN_HITS_PER_SERVER_NAME",
    "BURST_MIN_TOTAL_HITS",
    "BURST_SERVER_NAMES",
    "BURST_WINDOW_SECONDS",
    "CompactTlsObservation",
    "LEARNED_AD_SERVER_NAME",
    "LEARNED_AD_CONTROL_TLS_FINGERPRINT",
    "LEARNED_AD_CONTROL_TLS_LINEAGE_FINGERPRINT",
    "LEARNED_AD_TLS_FINGERPRINT",
    "LEARNED_AD_TLS_LINEAGE_FINGERPRINT",
    "LEARNED_AD_TLS_RECORD_LENGTH",
    "LEARNED_MAIL_BROWSER_MAX_CONTEXT_IDLE_MS",
    "LEARNED_MAIL_BROWSER_MIN_CONTEXT_AGE_MS",
    "LEARNED_MAIL_BROWSER_MIN_ROOT_FLOWS",
    "LEARNED_MAIL_BROWSER_ROOT_SERVER_NAME",
    "LEARNED_MAIL_DESKTOP_MIN_CONTEXT_AGE_MS",
    "LEARNED_MAIL_DESKTOP_MIN_CONTEXT_FLOWS",
    "LEARNED_MAIL_DZEN_MIN_BURST_FLOWS",
    "LEARNED_MAIL_DZEN_SERVER_NAME",
    "LEARNED_MAIL_INLINE_SERVER_NAME",
    "has_compact_tls_burst",
    "matches_learned_ad_control_flow",
    "matches_learned_ad_resumption_pair",
    "matches_learned_mail_browser_root_burst",
    "matches_learned_mail_browser_serial_root",
    "matches_learned_mail_browser_dzen_root",
    "matches_learned_mail_inline_ad_request",
    "matches_learned_mail_inline_first_ad_request",
    "matches_learned_mail_inline_bootstrap_large_request",
    "matches_learned_mail_inline_response_outlier",
    "matches_learned_mail_inline_ad_dna_request",
]
