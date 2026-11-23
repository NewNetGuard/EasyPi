"""Policy-gated Spotify TLS and QUIC flow classification.

Only exact Spotify service names and an enabled device toggle can produce an
exact-flow action. Generic cloud, CDN, and Akamai names are not sufficient.
"""

from __future__ import annotations

import ipaddress
import json
import math
import stat
import time
from pathlib import Path
from typing import Callable

from prism_dpi.flowgraph.policy import CandidateFlow


SPOTIFY_SERVER_SUFFIXES = (
    "spotify.com",
    "spotifycdn.com",
    "scdn.co",
    "spotify.net",
    "spoti.fi",
    "spotilocal.com",
    "tospotify.com",
)
SPOTIFY_SERVER_NAMES = frozenset({"audio-ak-spotify-com.akamaized.net"})
SPOTIFY_POLICY_NAMES = frozenset({"spotify", "spotify_ip"})
MAX_CANDIDATE_AGE_SECONDS = 2.0
MAX_FUTURE_SKEW_SECONDS = 1.0
MAX_POLICY_BYTES = 1024 * 1024
ADDRESS_REFRESH_SECONDS = 15.0
MAX_EXCHANGE_BYTES = 64 * 1024 * 1024
MAX_FLOW_AGE_MS = 24 * 60 * 60 * 1000


class SpotifyFlowPolicy:
    """Validate fresh Spotify TLS/QUIC flows against the device toggle."""

    def __init__(
        self,
        devices_path: str | Path,
        address_resolver: Callable[[str], str] | None = None,
    ) -> None:
        self.devices_path = Path(devices_path)
        self.address_resolver = address_resolver
        self._identity: tuple[int, int, int, int] | None = None
        self._next_address_refresh = 0.0
        self._blocked_clients: frozenset[str] = frozenset()

    def is_blocked_client(self, client_ip: str) -> bool:
        self._refresh_policy()
        return client_ip in self._blocked_clients

    def validate_candidate_event(
        self,
        value: object,
        *,
        now: float,
    ) -> CandidateFlow | None:
        if not isinstance(value, dict):
            return None
        event_type = value.get("event")
        if event_type == "flow_assessment":
            protocol = "tcp"
        elif event_type == "quic_initial_observation":
            protocol = "udp"
        elif event_type == "tls_exchange_observation":
            protocol = "tcp"
        else:
            return None

        try:
            timestamp = float(value["timestamp"])
            client_ip = str(ipaddress.ip_address(value["client_ip"]))
            server_ip = str(ipaddress.ip_address(value["server_ip"]))
            client_port = _strict_int(value["client_port"])
            server_port = _strict_int(value["server_port"])
            flow_id = str(value["flow"])
            server_name = str(value["server_name"])
        except (KeyError, TypeError, ValueError):
            return None

        if event_type == "flow_assessment":
            features = value.get("features")
            if not isinstance(features, dict):
                return None
            try:
                record_length = _strict_int(features["tls_record_length"])
                server_payload_bytes = _strict_int(
                    features["server_payload_bytes"]
                )
                fingerprint = str(features["tls_fingerprint"])
            except (KeyError, TypeError, ValueError):
                return None
            if not 1 <= record_length <= 65_535 or server_payload_bytes != 0:
                return None
        elif event_type == "quic_initial_observation":
            fingerprint = str(value.get("tls_fingerprint", ""))
            if value.get("mode") != "shadow" or not _is_quic_version(
                value.get("quic_version")
            ):
                return None
        else:
            fingerprint = str(value.get("tls_fingerprint", ""))
            try:
                exchange_index = _strict_int(value["exchange_index"])
                request_record_count = _strict_int(
                    value["request_record_count"]
                )
                request_bytes = _strict_int(value["request_bytes"])
                response_record_count = _strict_int(
                    value["response_record_count"]
                )
                response_bytes = _strict_int(value["response_bytes"])
                first_response_delay_ms = _strict_int(
                    value["first_response_delay_ms"]
                )
                flow_age_ms = _strict_int(value["flow_age_ms"])
            except (KeyError, TypeError, ValueError):
                return None
            if (
                value.get("mode") != "shadow"
                or not 1 <= exchange_index <= 1_000_000
                or not 1 <= request_record_count <= 65_535
                or not 1 <= response_record_count <= 65_535
                or not 1 <= request_bytes <= MAX_EXCHANGE_BYTES
                or not 1 <= response_bytes <= MAX_EXCHANGE_BYTES
                or not 0 <= first_response_delay_ms <= MAX_FLOW_AGE_MS
                or not first_response_delay_ms <= flow_age_ms <= MAX_FLOW_AGE_MS
            ):
                return None

        if not math.isfinite(timestamp):
            return None
        client_address = ipaddress.ip_address(client_ip)
        server_address = ipaddress.ip_address(server_ip)
        if client_address.version != 4 or not client_address.is_private:
            return None
        if server_address.version != 4 or not server_address.is_global:
            return None
        if not 1024 <= client_port <= 65_535 or server_port != 443:
            return None
        if timestamp < now - MAX_CANDIDATE_AGE_SECONDS:
            return None
        if timestamp > now + MAX_FUTURE_SKEW_SECONDS:
            return None
        if not _is_spotify_server_name(server_name):
            return None
        if not _is_tls_fingerprint(fingerprint):
            return None

        expected_flow = (
            f"{protocol}:{client_ip}:{client_port}>{server_ip}:{server_port}"
        )
        if flow_id != expected_flow or not self.is_blocked_client(client_ip):
            return None

        return CandidateFlow(
            timestamp=timestamp,
            flow_id=flow_id,
            client_ip=client_ip,
            client_port=client_port,
            server_ip=server_ip,
            server_port=server_port,
            confidence=1.0,
            retry_guard=False,
            protocol=protocol,
            policy="spotify",
        )

    def _refresh_policy(self) -> None:
        refresh_now = time.monotonic()
        identity: tuple[int, int, int, int] | None = None
        try:
            source_stat = self.devices_path.lstat()
            if not stat.S_ISREG(source_stat.st_mode):
                self._clear_policy()
                return
            identity = (
                source_stat.st_dev,
                source_stat.st_ino,
                source_stat.st_mtime_ns,
                source_stat.st_size,
            )
            if (
                identity == self._identity
                and refresh_now < self._next_address_refresh
            ):
                return
            if source_stat.st_size > MAX_POLICY_BYTES:
                self._clear_policy(identity)
                return
            payload = json.loads(self.devices_path.read_text(encoding="utf-8"))
            devices = payload if isinstance(payload, list) else payload.get(
                "devices", []
            )
            if not isinstance(devices, list):
                self._clear_policy(identity)
                return

            blocked_clients: set[str] = set()
            for device in devices:
                if not isinstance(device, dict) or not device.get("enabled", True):
                    continue
                selected = _normalized_names(device.get("blocked_services"))
                selected.update(_normalized_names(device.get("blocked_apps")))
                if not SPOTIFY_POLICY_NAMES.intersection(selected):
                    continue
                candidates = list(_device_addresses(device))
                mac = _normalized_mac(device.get("mac"))
                if mac and self.address_resolver is not None:
                    try:
                        resolved = str(self.address_resolver(mac)).strip()
                    except Exception:
                        resolved = ""
                    if resolved:
                        candidates.append(resolved)
                for candidate in candidates:
                    try:
                        address = ipaddress.ip_address(candidate)
                    except ValueError:
                        continue
                    if address.version == 4 and address.is_private:
                        blocked_clients.add(str(address))
            self._blocked_clients = frozenset(blocked_clients)
            self._identity = identity
            self._next_address_refresh = refresh_now + ADDRESS_REFRESH_SECONDS
        except (OSError, UnicodeError, json.JSONDecodeError, AttributeError):
            self._clear_policy(identity)

    def _clear_policy(
        self,
        identity: tuple[int, int, int, int] | None = None,
    ) -> None:
        self._identity = identity
        self._next_address_refresh = time.monotonic() + ADDRESS_REFRESH_SECONDS
        self._blocked_clients = frozenset()


def _strict_int(value: object) -> int:
    if isinstance(value, bool):
        raise ValueError("boolean is not an integer field")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isascii() and value.isdecimal():
        return int(value)
    raise ValueError("field is not a strict integer")


def _normalized_names(value: object) -> set[str]:
    if not isinstance(value, list):
        return set()
    return {str(item).strip().lower() for item in value if str(item).strip()}


def _device_addresses(device: dict[str, object]) -> tuple[str, ...]:
    addresses: list[str] = []
    legacy_ip = str(device.get("ip") or "").strip()
    if legacy_ip:
        addresses.append(legacy_ip)
    ids = device.get("ids")
    if isinstance(ids, list):
        addresses.extend(str(item).strip() for item in ids if str(item).strip())
    return tuple(dict.fromkeys(addresses))


def _normalized_mac(value: object) -> str:
    compact = str(value or "").strip().replace(":", "").replace("-", "")
    compact = compact.replace(".", "")
    if len(compact) != 12 or not compact.isascii():
        return ""
    try:
        int(compact, 16)
    except ValueError:
        return ""
    normalized = compact.upper()
    if normalized in {"000000000000", "FFFFFFFFFFFF"}:
        return ""
    return ":".join(
        normalized[index:index + 2] for index in range(0, 12, 2)
    )


def _is_spotify_server_name(server_name: str) -> bool:
    normalized = server_name.rstrip(".").lower()
    if (
        not normalized
        or normalized != server_name
        or len(normalized) > 253
        or not normalized.isascii()
    ):
        return False
    labels = normalized.split(".")
    if any(
        not label
        or len(label) > 63
        or label.startswith("-")
        or label.endswith("-")
        or any(not (char.isalnum() or char == "-") for char in label)
        for label in labels
    ):
        return False
    if normalized in SPOTIFY_SERVER_NAMES:
        return True
    return any(
        normalized == suffix or normalized.endswith("." + suffix)
        for suffix in SPOTIFY_SERVER_SUFFIXES
    )


def _is_tls_fingerprint(value: str) -> bool:
    if len(value) != 16 or value != value.lower():
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


def _is_quic_version(value: object) -> bool:
    text = str(value)
    if len(text) != 10 or not text.startswith("0x") or text != text.lower():
        return False
    try:
        int(text[2:], 16)
    except ValueError:
        return False
    return True


__all__ = ["SPOTIFY_SERVER_SUFFIXES", "SpotifyFlowPolicy"]
