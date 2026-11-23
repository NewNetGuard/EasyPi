"""Policy-gated TikTok TLS and QUIC flow classification.

Only a fresh, fully parsed TikTok-owned server name and an enabled device
toggle can produce an exact-flow action. Shared CDN addresses are never enough.
"""

from __future__ import annotations

import ipaddress
import json
import math
import os
import stat
import tempfile
import time
from bisect import bisect_left, bisect_right
from collections import deque
from pathlib import Path
from typing import Callable

from prism_dpi.flowgraph.policy import CandidateFlow


TIKTOK_SERVER_SUFFIXES = (
    "tiktok.com",
    "tiktokcdn.com",
    "tiktokcdn-eu.com",
    "tiktokcdn-us.com",
    "tiktokglobalshopv.com",
    "tiktok.org",
    "tiktokv.com",
    "tiktokv.eu",
    "musical.ly",
)
TIKTOK_POLICY_NAMES = frozenset({"tiktok", "tiktok_ip"})
MAX_CANDIDATE_AGE_SECONDS = 2.0
MAX_FUTURE_SKEW_SECONDS = 1.0
MAX_POLICY_BYTES = 1024 * 1024
ENDPOINT_CORRELATION_SECONDS = 30.0 * 60.0
MAX_CONFIRMED_ENDPOINTS = 4_096
MAX_ENDPOINT_STATE_BYTES = 1024 * 1024
MAX_EVIDENCE_FILE_BYTES = 32 * 1024 * 1024
MAX_EVIDENCE_LINE_BYTES = 256 * 1024
ENDPOINT_STATE_VERSION = 1
ENDPOINT_PERSIST_REFRESH_SECONDS = 60.0
ADDRESS_REFRESH_SECONDS = 15.0
ASSOCIATION_WINDOW_SECONDS = 1.0
ASSOCIATION_MIN_DIRECT_ENDPOINTS = 5
ASSOCIATION_MIN_LAUNCH_GAP_SECONDS = 10.0
MAX_ASSOCIATION_OBSERVATIONS = 8_192


class TikTokFlowPolicy:
    """Validate fresh TikTok TLS/QUIC flows against the current toggle."""

    def __init__(
        self,
        devices_path: str | Path,
        endpoint_state_path: str | Path | None = None,
        evidence_paths: tuple[str | Path, ...] | list[str | Path] = (),
        address_resolver: Callable[[str], str] | None = None,
    ) -> None:
        self.devices_path = Path(devices_path)
        self.endpoint_state_path = (
            Path(endpoint_state_path) if endpoint_state_path is not None else None
        )
        self.evidence_paths = tuple(Path(path) for path in evidence_paths)
        self.address_resolver = address_resolver
        self._identity: tuple[int, int, int, int] | None = None
        self._next_address_refresh = 0.0
        self._blocked_clients: frozenset[str] = frozenset()
        self._confirmed_endpoints: dict[tuple[str, str], float] = {}
        self._persisted_endpoints: dict[tuple[str, str], float] = {}
        self._endpoint_state_loaded = endpoint_state_path is None
        self._recent_direct_observations: list[tuple[str, str, float]] = []
        self._udp_flow_starts: dict[tuple[str, str, int], float] = {}

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
        if event_type == "opaque_quic_flow_observation":
            return self._validate_correlated_udp(
                value,
                now=now,
                require_quic_metadata=True,
            )
        if event_type == "udp_443_flow_observation":
            return self._validate_correlated_udp(
                value,
                now=now,
                require_quic_metadata=False,
            )
        if event_type == "flow_assessment":
            protocol = "tcp"
        elif event_type == "quic_initial_observation":
            protocol = "udp"
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
            if not 1 <= record_length <= 65535 or server_payload_bytes != 0:
                return None
        else:
            fingerprint = str(value.get("tls_fingerprint", ""))
            if not _is_quic_version(value.get("quic_version")):
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
        if not _is_tiktok_server_name(server_name):
            return None
        if not _is_tls_fingerprint(fingerprint):
            return None

        expected_flow = (
            f"{protocol}:{client_ip}:{client_port}>{server_ip}:{server_port}"
        )
        if flow_id != expected_flow:
            return None
        if not self.is_blocked_client(client_ip):
            return None

        self._load_endpoint_state(now)
        self._record_direct_observation(
            client_ip,
            server_ip,
            timestamp,
            now=now,
        )
        self._remember_endpoint(client_ip, server_ip, timestamp, now=now)

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
            policy="tiktok",
        )

    def _validate_correlated_udp(
        self,
        value: dict[str, object],
        *,
        now: float,
        require_quic_metadata: bool,
    ) -> CandidateFlow | None:
        try:
            timestamp = float(value["timestamp"])
            client_ip = str(ipaddress.ip_address(value["client_ip"]))
            server_ip = str(ipaddress.ip_address(value["server_ip"]))
            client_port = _strict_int(value["client_port"])
            server_port = _strict_int(value["server_port"])
            datagram_bytes = _strict_int(value["datagram_bytes"])
            flow_id = str(value["flow"])
        except (KeyError, TypeError, ValueError):
            return None

        if value.get("mode") != "shadow":
            return None
        if require_quic_metadata and (
            value.get("quic_fixed_bit") is not True
            or value.get("quic_header_form") != "short"
        ):
            return None
        if not require_quic_metadata and (
            "quic_fixed_bit" in value or "quic_header_form" in value
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
        if not 1024 <= client_port <= 65535 or server_port != 443:
            return None
        if not 1 <= datagram_bytes <= 65_507:
            return None
        if timestamp < now - MAX_CANDIDATE_AGE_SECONDS:
            return None
        if timestamp > now + MAX_FUTURE_SKEW_SECONDS:
            return None
        expected_flow = f"udp:{client_ip}:{client_port}>{server_ip}:{server_port}"
        if flow_id != expected_flow or not self.is_blocked_client(client_ip):
            return None

        self._load_endpoint_state(now)
        if self._expire_confirmed_endpoints(now):
            self._persist_endpoint_state()
        confirmed_at = self._confirmed_endpoints.get((client_ip, server_ip))
        if confirmed_at is None:
            self._record_udp_observation(
                client_ip,
                server_ip,
                client_port,
                timestamp,
                now=now,
            )
            associated = self._associated_endpoints(
                self._recent_direct_observations,
                self._udp_flow_starts,
            )
            if (client_ip, server_ip) in associated:
                self._remember_endpoint(
                    client_ip,
                    server_ip,
                    timestamp,
                    now=now,
                )
                confirmed_at = timestamp
        if confirmed_at is None or not (
            confirmed_at <= timestamp <= confirmed_at + ENDPOINT_CORRELATION_SECONDS
        ):
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
            protocol="udp",
            policy="tiktok",
        )

    def _remember_endpoint(
        self,
        client_ip: str,
        server_ip: str,
        timestamp: float,
        *,
        now: float,
    ) -> None:
        expired = self._expire_confirmed_endpoints(now)
        key = (client_ip, server_ip)
        is_new = key not in self._confirmed_endpoints
        if key not in self._confirmed_endpoints and (
            len(self._confirmed_endpoints) >= MAX_CONFIRMED_ENDPOINTS
        ):
            self._confirmed_endpoints.pop(next(iter(self._confirmed_endpoints)))
        self._confirmed_endpoints[key] = timestamp
        persisted_at = self._persisted_endpoints.get(key)
        if (
            expired
            or is_new
            or persisted_at is None
            or timestamp - persisted_at >= ENDPOINT_PERSIST_REFRESH_SECONDS
        ):
            self._persist_endpoint_state()

    def _expire_confirmed_endpoints(self, now: float) -> bool:
        changed = False
        cutoff = now - ENDPOINT_CORRELATION_SECONDS
        for key, confirmed_at in list(self._confirmed_endpoints.items()):
            if confirmed_at < cutoff:
                del self._confirmed_endpoints[key]
                changed = True
        return changed

    def _load_endpoint_state(self, now: float) -> None:
        if self._endpoint_state_loaded or self.endpoint_state_path is None:
            return
        self._endpoint_state_loaded = True
        loaded = self._read_endpoint_state(now)
        evidence = self._bootstrap_endpoint_state(now)
        if loaded is None:
            loaded = evidence
        else:
            for key, timestamp in evidence.items():
                if timestamp > loaded.get(key, float("-inf")):
                    loaded[key] = timestamp
        self._confirmed_endpoints = loaded
        self._persisted_endpoints = dict(loaded)
        self._persist_endpoint_state()

    def _read_endpoint_state(
        self,
        now: float,
    ) -> dict[tuple[str, str], float] | None:
        if self.endpoint_state_path is None:
            return {}
        path = self.endpoint_state_path
        try:
            source_stat = path.lstat()
            if (
                not stat.S_ISREG(source_stat.st_mode)
                or source_stat.st_size > MAX_ENDPOINT_STATE_BYTES
            ):
                return None
            payload = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(payload, dict):
                return None
            if payload.get("version") != ENDPOINT_STATE_VERSION:
                return None
            entries = payload.get("endpoints")
            if not isinstance(entries, list) or len(entries) > MAX_CONFIRMED_ENDPOINTS:
                return None

            loaded: dict[tuple[str, str], float] = {}
            cutoff = now - ENDPOINT_CORRELATION_SECONDS
            for entry in entries:
                if not isinstance(entry, dict):
                    return None
                client_ip = str(ipaddress.ip_address(entry["client_ip"]))
                server_ip = str(ipaddress.ip_address(entry["server_ip"]))
                confirmed_at = float(entry["confirmed_at"])
                client_address = ipaddress.ip_address(client_ip)
                server_address = ipaddress.ip_address(server_ip)
                if (
                    client_address.version != 4
                    or not client_address.is_private
                    or server_address.version != 4
                    or not server_address.is_global
                    or not math.isfinite(confirmed_at)
                    or confirmed_at < cutoff
                    or confirmed_at > now + MAX_FUTURE_SKEW_SECONDS
                ):
                    continue
                if client_ip in self._blocked_clients:
                    loaded[(client_ip, server_ip)] = confirmed_at
            return loaded
        except (
            OSError,
            UnicodeError,
            json.JSONDecodeError,
            KeyError,
            TypeError,
            ValueError,
        ):
            return None

    def _bootstrap_endpoint_state(
        self,
        now: float,
    ) -> dict[tuple[str, str], float]:
        loaded: dict[tuple[str, str], float] = {}
        direct_observations: deque[tuple[str, str, float]] = deque(
            maxlen=MAX_ASSOCIATION_OBSERVATIONS
        )
        udp_flow_starts: dict[tuple[str, str, int], float] = {}
        for path in self.evidence_paths:
            try:
                source_stat = path.lstat()
                if (
                    not stat.S_ISREG(source_stat.st_mode)
                    or source_stat.st_size > MAX_EVIDENCE_FILE_BYTES
                ):
                    continue
                with path.open("rb") as handle:
                    for raw_line in handle:
                        if len(raw_line) > MAX_EVIDENCE_LINE_BYTES:
                            continue
                        try:
                            value = json.loads(raw_line)
                        except (UnicodeError, json.JSONDecodeError):
                            continue
                        endpoint = self._validated_bootstrap_direct(value, now=now)
                        if endpoint is None:
                            udp_flow = self._validated_bootstrap_udp(value, now=now)
                            if udp_flow is not None:
                                key, timestamp = udp_flow
                                prior = udp_flow_starts.get(key)
                                if prior is None or timestamp < prior:
                                    if (
                                        prior is None
                                        and len(udp_flow_starts)
                                        >= MAX_ASSOCIATION_OBSERVATIONS
                                    ):
                                        udp_flow_starts.pop(next(iter(udp_flow_starts)))
                                    udp_flow_starts[key] = timestamp
                            continue
                        key, timestamp = endpoint
                        direct_observations.append((key[0], key[1], timestamp))
                        if timestamp > loaded.get(key, float("-inf")):
                            loaded[key] = timestamp
            except OSError:
                continue
        for key, timestamp in self._associated_endpoints(
            list(direct_observations),
            udp_flow_starts,
        ).items():
            if timestamp > loaded.get(key, float("-inf")):
                loaded[key] = timestamp
        if len(loaded) <= MAX_CONFIRMED_ENDPOINTS:
            return loaded
        newest = sorted(loaded.items(), key=lambda item: item[1], reverse=True)
        return dict(newest[:MAX_CONFIRMED_ENDPOINTS])

    def _validated_bootstrap_direct(
        self,
        value: object,
        *,
        now: float,
    ) -> tuple[tuple[str, str], float] | None:
        if not isinstance(value, dict):
            return None
        event_type = value.get("event")
        if event_type not in {"quic_initial_observation", "flow_assessment"}:
            return None
        try:
            timestamp = float(value["timestamp"])
            client_ip = str(ipaddress.ip_address(value["client_ip"]))
            server_ip = str(ipaddress.ip_address(value["server_ip"]))
            client_port = _strict_int(value["client_port"])
            server_port = _strict_int(value["server_port"])
            server_name = str(value["server_name"])
            flow_id = str(value["flow"])
        except (KeyError, TypeError, ValueError):
            return None
        if event_type == "flow_assessment":
            features = value.get("features")
            if not isinstance(features, dict):
                return None
            try:
                fingerprint = str(features["tls_fingerprint"])
                record_length = _strict_int(features["tls_record_length"])
                server_payload_bytes = _strict_int(features["server_payload_bytes"])
            except (KeyError, TypeError, ValueError):
                return None
            if not 1 <= record_length <= 65_535 or server_payload_bytes != 0:
                return None
            protocol = "tcp"
        else:
            fingerprint = str(value.get("tls_fingerprint", ""))
            if not _is_quic_version(value.get("quic_version")):
                return None
            protocol = "udp"
        client_address = ipaddress.ip_address(client_ip)
        server_address = ipaddress.ip_address(server_ip)
        if (
            not math.isfinite(timestamp)
            or timestamp < now - ENDPOINT_CORRELATION_SECONDS
            or timestamp > now + MAX_FUTURE_SKEW_SECONDS
            or client_address.version != 4
            or not client_address.is_private
            or server_address.version != 4
            or not server_address.is_global
            or not 1024 <= client_port <= 65535
            or server_port != 443
            or client_ip not in self._blocked_clients
            or not _is_tiktok_server_name(server_name)
            or not _is_tls_fingerprint(fingerprint)
        ):
            return None
        expected_flow = (
            f"{protocol}:{client_ip}:{client_port}>{server_ip}:{server_port}"
        )
        if flow_id != expected_flow:
            return None
        return (client_ip, server_ip), timestamp

    def _validated_bootstrap_udp(
        self,
        value: object,
        *,
        now: float,
    ) -> tuple[tuple[str, str, int], float] | None:
        if not isinstance(value, dict):
            return None
        event_type = value.get("event")
        if event_type not in {
            "opaque_quic_flow_observation",
            "udp_443_flow_observation",
        }:
            return None
        try:
            timestamp = float(value["timestamp"])
            client_ip = str(ipaddress.ip_address(value["client_ip"]))
            server_ip = str(ipaddress.ip_address(value["server_ip"]))
            client_port = _strict_int(value["client_port"])
            server_port = _strict_int(value["server_port"])
            datagram_bytes = _strict_int(value["datagram_bytes"])
            flow_id = str(value["flow"])
        except (KeyError, TypeError, ValueError):
            return None
        if value.get("mode") != "shadow":
            return None
        if event_type == "opaque_quic_flow_observation" and (
            value.get("quic_fixed_bit") is not True
            or value.get("quic_header_form") not in {"long", "short"}
        ):
            return None
        if event_type == "udp_443_flow_observation" and (
            "quic_fixed_bit" in value or "quic_header_form" in value
        ):
            return None
        client_address = ipaddress.ip_address(client_ip)
        server_address = ipaddress.ip_address(server_ip)
        if (
            not math.isfinite(timestamp)
            or timestamp < now - ENDPOINT_CORRELATION_SECONDS
            or timestamp > now + MAX_FUTURE_SKEW_SECONDS
            or client_address.version != 4
            or not client_address.is_private
            or server_address.version != 4
            or not server_address.is_global
            or not 1024 <= client_port <= 65_535
            or server_port != 443
            or not 1 <= datagram_bytes <= 65_507
            or client_ip not in self._blocked_clients
        ):
            return None
        expected_flow = f"udp:{client_ip}:{client_port}>{server_ip}:{server_port}"
        if flow_id != expected_flow:
            return None
        return (client_ip, server_ip, client_port), timestamp

    @staticmethod
    def _associated_endpoints(
        direct_observations: list[tuple[str, str, float]],
        udp_flow_starts: dict[tuple[str, str, int], float],
    ) -> dict[tuple[str, str], float]:
        direct_by_client: dict[str, list[tuple[float, str]]] = {}
        for client_ip, server_ip, timestamp in direct_observations:
            direct_by_client.setdefault(client_ip, []).append(
                (timestamp, server_ip)
            )
        for observations in direct_by_client.values():
            observations.sort()

        qualifying: dict[tuple[str, str], list[tuple[float, int]]] = {}
        for (client_ip, server_ip, client_port), started_at in (
            udp_flow_starts.items()
        ):
            observations = direct_by_client.get(client_ip, [])
            left = bisect_left(
                observations,
                (started_at - ASSOCIATION_WINDOW_SECONDS, ""),
            )
            right = bisect_right(
                observations,
                (started_at + ASSOCIATION_WINDOW_SECONDS, "\U0010ffff"),
            )
            direct_servers: set[str] = set()
            for _, direct_server in observations[left:right]:
                direct_servers.add(direct_server)
                if len(direct_servers) >= ASSOCIATION_MIN_DIRECT_ENDPOINTS:
                    break
            if len(direct_servers) < ASSOCIATION_MIN_DIRECT_ENDPOINTS:
                continue
            qualifying.setdefault((client_ip, server_ip), []).append(
                (started_at, client_port)
            )

        associated: dict[tuple[str, str], float] = {}
        for key, launches in qualifying.items():
            ordered = sorted(set(launches))
            if len({port for _, port in ordered}) < 2:
                continue
            if ordered[-1][0] - ordered[0][0] < ASSOCIATION_MIN_LAUNCH_GAP_SECONDS:
                continue
            associated[key] = ordered[-1][0]
        return associated

    def _record_direct_observation(
        self,
        client_ip: str,
        server_ip: str,
        timestamp: float,
        *,
        now: float,
    ) -> None:
        self._expire_association_observations(now)
        if len(self._recent_direct_observations) >= MAX_ASSOCIATION_OBSERVATIONS:
            self._recent_direct_observations.pop(0)
        self._recent_direct_observations.append((client_ip, server_ip, timestamp))

    def _record_udp_observation(
        self,
        client_ip: str,
        server_ip: str,
        client_port: int,
        timestamp: float,
        *,
        now: float,
    ) -> None:
        self._expire_association_observations(now)
        key = (client_ip, server_ip, client_port)
        prior = self._udp_flow_starts.get(key)
        if prior is not None:
            if timestamp < prior:
                self._udp_flow_starts[key] = timestamp
            return
        if len(self._udp_flow_starts) >= MAX_ASSOCIATION_OBSERVATIONS:
            self._udp_flow_starts.pop(next(iter(self._udp_flow_starts)))
        self._udp_flow_starts[key] = timestamp

    def _expire_association_observations(self, now: float) -> None:
        cutoff = now - ENDPOINT_CORRELATION_SECONDS
        self._recent_direct_observations = [
            observation
            for observation in self._recent_direct_observations
            if observation[2] >= cutoff
        ]
        for key, started_at in list(self._udp_flow_starts.items()):
            if started_at < cutoff:
                del self._udp_flow_starts[key]

    def _persist_endpoint_state(self) -> None:
        if not self._endpoint_state_loaded or self.endpoint_state_path is None:
            return
        path = self.endpoint_state_path
        temporary_path: str | None = None
        payload = {
            "version": ENDPOINT_STATE_VERSION,
            "endpoints": [
                {
                    "client_ip": client_ip,
                    "server_ip": server_ip,
                    "confirmed_at": confirmed_at,
                }
                for (client_ip, server_ip), confirmed_at in sorted(
                    self._confirmed_endpoints.items()
                )
            ],
        }
        try:
            descriptor, temporary_path = tempfile.mkstemp(
                prefix=f".{path.name}.",
                suffix=".tmp",
                dir=path.parent,
            )
            try:
                os.chmod(temporary_path, 0o600)
                with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
                    descriptor = -1
                    json.dump(payload, handle, separators=(",", ":"))
                    handle.flush()
                    os.fsync(handle.fileno())
            except Exception:
                if descriptor >= 0:
                    os.close(descriptor)
                raise
            os.replace(temporary_path, path)
            temporary_path = None
            self._persisted_endpoints = dict(self._confirmed_endpoints)
        except OSError:
            return
        finally:
            if temporary_path is not None:
                try:
                    os.unlink(temporary_path)
                except OSError:
                    pass

    def _refresh_policy(self) -> None:
        previous_identity = self._identity
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
                if not TIKTOK_POLICY_NAMES.intersection(selected):
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
            if previous_identity is not None and not self._endpoint_state_loaded:
                self._endpoint_state_loaded = True
                self._confirmed_endpoints.clear()
                self._persisted_endpoints.clear()
                self._persist_endpoint_state()
            before = len(self._confirmed_endpoints)
            self._confirmed_endpoints = {
                key: confirmed_at
                for key, confirmed_at in self._confirmed_endpoints.items()
                if key[0] in self._blocked_clients
            }
            self._recent_direct_observations = [
                observation
                for observation in self._recent_direct_observations
                if observation[0] in self._blocked_clients
            ]
            self._udp_flow_starts = {
                key: started_at
                for key, started_at in self._udp_flow_starts.items()
                if key[0] in self._blocked_clients
            }
            if len(self._confirmed_endpoints) != before:
                self._persist_endpoint_state()
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
        self._confirmed_endpoints.clear()
        self._persisted_endpoints.clear()
        self._recent_direct_observations.clear()
        self._udp_flow_starts.clear()
        self._persist_endpoint_state()


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
    return ":".join(normalized[index:index + 2] for index in range(0, 12, 2))


def _is_tiktok_server_name(server_name: str) -> bool:
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
    return any(
        normalized == suffix or normalized.endswith("." + suffix)
        for suffix in TIKTOK_SERVER_SUFFIXES
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


__all__ = ["TIKTOK_SERVER_SUFFIXES", "TikTokFlowPolicy"]
