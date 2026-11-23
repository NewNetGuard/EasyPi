"""Policy-gated Facebook flow classification.

The classifier consumes only FlowGraph metadata derived from a reassembled TLS
ClientHello. Shared Meta addresses and TLS fingerprints are deliberately not
sufficient: an exact Facebook-owned SNI and an enabled per-device policy are
both required before an exact 5-tuple can be blocked.
"""

from __future__ import annotations

import ipaddress
import json
import math
import stat
from pathlib import Path

from prism_dpi.flowgraph.policy import CandidateFlow


FACEBOOK_SERVER_SUFFIXES = (
    "facebook.com",
    "facebook.net",
    "fbcdn.net",
    "fbsbx.com",
    "fb.com",
    "fb.me",
    "messenger.com",
)
FACEBOOK_SERVER_NAMES = frozenset({"graph.fbpigeon.com"})
FACEBOOK_POLICY_NAMES = frozenset({"facebook", "facebook_ip"})
MAX_CANDIDATE_AGE_SECONDS = 2.0
MAX_FUTURE_SKEW_SECONDS = 1.0
MAX_POLICY_BYTES = 1024 * 1024


class FacebookFlowPolicy:
    """Validate fresh Facebook flows against the current device toggle."""

    def __init__(self, devices_path: str | Path) -> None:
        self.devices_path = Path(devices_path)
        self._identity: tuple[int, int, int, int] | None = None
        self._blocked_clients: frozenset[str] = frozenset()

    def is_blocked_client(self, client_ip: str) -> bool:
        """Return whether Facebook is currently prohibited for this client."""
        self._refresh_policy()
        return client_ip in self._blocked_clients

    def validate_candidate_event(
        self,
        value: object,
        *,
        now: float,
    ) -> CandidateFlow | None:
        """Return an exact-flow action only for unserved Facebook TLS."""
        if not isinstance(value, dict) or value.get("event") != "flow_assessment":
            return None
        features = value.get("features")
        if not isinstance(features, dict):
            return None

        try:
            timestamp = float(value["timestamp"])
            client_ip = str(ipaddress.ip_address(value["client_ip"]))
            server_ip = str(ipaddress.ip_address(value["server_ip"]))
            client_port = _strict_int(value["client_port"])
            server_port = _strict_int(value["server_port"])
            flow_id = str(value["flow"])
            server_name = str(value["server_name"])
            record_length = _strict_int(features["tls_record_length"])
            server_payload_bytes = _strict_int(features["server_payload_bytes"])
            fingerprint = str(features["tls_fingerprint"])
        except (KeyError, TypeError, ValueError):
            return None

        if not math.isfinite(timestamp):
            return None
        client_address = ipaddress.ip_address(client_ip)
        server_address = ipaddress.ip_address(server_ip)
        if client_address.version != 4 or not client_address.is_private:
            return None
        if server_address.version != 4 or not server_address.is_global:
            return None
        if not 1024 <= client_port <= 65535 or server_port != 443:
            return None
        if timestamp < now - MAX_CANDIDATE_AGE_SECONDS:
            return None
        if timestamp > now + MAX_FUTURE_SKEW_SECONDS:
            return None
        if not _is_facebook_server_name(server_name):
            return None
        if not 1 <= record_length <= 65535 or server_payload_bytes != 0:
            return None
        if not _is_tls_fingerprint(fingerprint):
            return None

        expected_flow = f"tcp:{client_ip}:{client_port}>{server_ip}:{server_port}"
        if flow_id != expected_flow:
            return None
        if not self.is_blocked_client(client_ip):
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
            policy="facebook",
        )

    def _refresh_policy(self) -> None:
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
            if identity == self._identity:
                return
            if source_stat.st_size > MAX_POLICY_BYTES:
                self._clear_policy(identity)
                return
            payload = json.loads(self.devices_path.read_text(encoding="utf-8"))
            devices = (
                payload
                if isinstance(payload, list)
                else payload.get("devices", [])
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
                if not FACEBOOK_POLICY_NAMES.intersection(selected):
                    continue
                for candidate in _device_addresses(device):
                    try:
                        address = ipaddress.ip_address(candidate)
                    except ValueError:
                        continue
                    if address.version == 4 and address.is_private:
                        blocked_clients.add(str(address))
            self._blocked_clients = frozenset(blocked_clients)
            self._identity = identity
        except (OSError, UnicodeError, json.JSONDecodeError, AttributeError):
            self._clear_policy(identity)

    def _clear_policy(
        self,
        identity: tuple[int, int, int, int] | None = None,
    ) -> None:
        self._identity = identity
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
    return {
        str(item).strip().lower()
        for item in value
        if str(item).strip()
    }


def _device_addresses(device: dict[str, object]) -> tuple[str, ...]:
    addresses: list[str] = []
    legacy_ip = str(device.get("ip") or "").strip()
    if legacy_ip:
        addresses.append(legacy_ip)
    ids = device.get("ids")
    if isinstance(ids, list):
        addresses.extend(str(item).strip() for item in ids if str(item).strip())
    return tuple(dict.fromkeys(addresses))


def _is_facebook_server_name(server_name: str) -> bool:
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
    return normalized in FACEBOOK_SERVER_NAMES or any(
        normalized == suffix or normalized.endswith("." + suffix)
        for suffix in FACEBOOK_SERVER_SUFFIXES
    )


def _is_tls_fingerprint(value: str) -> bool:
    if len(value) != 16 or value != value.lower():
        return False
    try:
        int(value, 16)
    except ValueError:
        return False
    return True


__all__ = [
    "FACEBOOK_SERVER_NAMES",
    "FACEBOOK_SERVER_SUFFIXES",
    "FacebookFlowPolicy",
]
