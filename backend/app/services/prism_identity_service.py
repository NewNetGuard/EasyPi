"""Conservative device continuity for randomized MAC addresses.

PRISM Identity never treats a single network attribute as authentication.  It
learns bounded metadata profiles only for administrator-approved devices and
keeps a new MAC quarantined unless independent evidence supports continuity.
No DNS names, SNI values, payload, or browsing history are persisted here.
"""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import math
import os
import stat
import sqlite3
import tempfile
import threading
import time
from collections import Counter
from pathlib import Path
from typing import Any

from app.services.dhcp_identity import DHCPAddressBinding, DHCPIdentity
from app.utils.sanitize import sanitize_mac


STATE_VERSION = 1
MAX_STATE_BYTES = 2 * 1024 * 1024
MAX_PRISM_FILE_BYTES = 256 * 1024 * 1024
MAX_DNS_DB_BYTES = 768 * 1024 * 1024
PRISM_TAIL_BYTES = 4 * 1024 * 1024
MAX_PROFILES = 512
MAX_ALIASES = 16
MAX_FEATURES = 32
MAX_DESTINATION_TOKENS = 64
PROFILE_WRITE_INTERVAL_SECONDS = 30.0
PROFILE_BOOTSTRAP_SECONDS = 90 * 24 * 60 * 60
FEATURE_CACHE_SECONDS = 10.0
TRANSITION_WINDOW_SECONDS = 10 * 60
SIMULTANEOUS_GRACE_SECONDS = 5.0


class PrismIdentityError(RuntimeError):
    """Identity state could not be handled without weakening admission."""


class PrismIdentityService:
    def __init__(
        self,
        data_dir: str | Path,
        *,
        prism_path: str | Path = "/var/lib/easypi/prism/flowgraph.jsonl",
        dns_log_path: str | Path | None = None,
    ) -> None:
        self.data_dir = Path(data_dir)
        self.state_path = self.data_dir / "prism_identity.json"
        self.key_path = self.data_dir / "prism_identity.key"
        self.prism_path = Path(prism_path)
        self.dns_log_path = Path(dns_log_path or self.data_dir / "flow_log.db")
        self._lock = threading.RLock()
        self._feature_cache: dict[
            tuple[tuple[str, float], ...], tuple[float, dict[str, dict[str, Any]]]
        ] = {}
        self._feature_cache_lock = threading.Lock()
        self._prism_tail_cache: tuple[float, list[str]] | None = None

    def refresh_profiles(
        self,
        clients: list[dict[str, Any]],
        identities: list[DHCPIdentity],
        bindings: list[DHCPAddressBinding],
    ) -> None:
        """Learn metadata only from currently managed, traffic-observed pairs."""
        now = time.time()
        identity_by_pair = {(item.mac, item.ip): item for item in identities}
        binding_by_pair = {(item.mac, item.ip): item for item in bindings}
        managed: list[
            tuple[str, str, str, DHCPIdentity, DHCPAddressBinding, list[dict[str, Any]]]
        ] = []
        for client in clients[:MAX_PROFILES]:
            if not isinstance(client, dict):
                continue
            device_id = self._device_id(client.get("id"))
            mac = sanitize_mac(client.get("mac"))
            ip = self._client_ip(client)
            if not device_id or not mac or not ip:
                continue
            identity = identity_by_pair.get((mac, ip))
            binding = binding_by_pair.get((mac, ip))
            binding_age = now - binding.last_seen_timestamp if binding else -1.0
            if (
                not identity
                or not binding
                or not (0 <= binding_age <= PROFILE_BOOTSTRAP_SECONDS)
            ):
                continue
            history = (
                [dict(item) for item in client.get("mac_history", []) if isinstance(item, dict)]
                if isinstance(client.get("mac_history"), list)
                else []
            )
            managed.append((device_id, mac, ip, identity, binding, history))

        if not managed:
            return
        prism_by_ip = self._read_prism_features(
            {
                ip: binding.assigned_at_timestamp
                for _, _, ip, _, binding, _history in managed
            }
        )
        with self._lock:
            state = self._load_state()
            profiles = state["profiles"]
            changed = False
            for device_id, mac, ip, identity, _binding, history in managed:
                current = profiles.get(device_id)
                if not isinstance(current, dict):
                    current = {"device_id": device_id, "aliases": []}
                prior_update = self._finite_float(current.get("updated_at")) or 0.0
                dhcp = self._dhcp_features(identity, mac)
                prism = prism_by_ip.get(ip) or current.get("prism") or {}
                alias_time = (
                    now
                    if current.get("active_mac") != mac
                    or now - prior_update >= PROFILE_WRITE_INTERVAL_SECONDS
                    else prior_update
                )
                aliases = self._merge_client_history(
                    current.get("aliases"), history, mac, alias_time
                )
                updated = {
                    "device_id": device_id,
                    "active_mac": mac,
                    "aliases": aliases,
                    "dhcp": dhcp,
                    "prism": prism,
                    "updated_at": now,
                }
                # Avoid rewriting flash every three-second monitor pass.
                comparable = dict(updated)
                comparable["updated_at"] = current.get("updated_at")
                if comparable != current or now - prior_update >= PROFILE_WRITE_INTERVAL_SECONDS:
                    profiles[device_id] = updated
                    changed = True
            if changed:
                state["profiles"] = dict(list(profiles.items())[-MAX_PROFILES:])
                self._save_state(state)

    def assess(
        self,
        observation: dict[str, Any],
        clients: list[dict[str, Any]],
        identities: list[DHCPIdentity],
        bindings: list[DHCPAddressBinding],
    ) -> dict[str, Any] | None:
        """Return the best continuity candidate, or ``None`` if evidence is weak."""
        candidate_mac = sanitize_mac(observation.get("mac"))
        candidate_ip = self._valid_ipv4(observation.get("ip"))
        if not candidate_mac or not candidate_ip:
            return None
        candidate_identity = next(
            (
                item
                for item in identities
                if item.mac == candidate_mac and item.ip == candidate_ip
            ),
            None,
        )
        candidate_binding = next(
            (
                item
                for item in bindings
                if item.mac == candidate_mac and item.ip == candidate_ip
            ),
            None,
        )
        if candidate_identity is None or candidate_binding is None:
            return None

        with self._lock:
            profiles = self._load_state()["profiles"]
        prism = self._read_prism_features(
            {candidate_ip: candidate_binding.assigned_at_timestamp}
        ).get(candidate_ip, {})
        candidate_dhcp = self._dhcp_features(candidate_identity, candidate_mac)
        client_by_id = {
            self._device_id(item.get("id")): item
            for item in clients
            if isinstance(item, dict) and self._device_id(item.get("id"))
        }
        scored: list[dict[str, Any]] = []
        for device_id, profile in profiles.items():
            client = client_by_id.get(device_id)
            if not client or not isinstance(profile, dict):
                continue
            active_mac = sanitize_mac(client.get("mac"))
            if not active_mac or active_mac == candidate_mac:
                continue
            result = self._score(
                profile=profile,
                candidate_dhcp=candidate_dhcp,
                candidate_prism=prism,
                candidate_binding=candidate_binding,
                active_mac=active_mac,
                bindings=bindings,
            )
            if not result.pop("continuity_supported"):
                continue
            result.update(
                {
                    "device_id": device_id,
                    "name": str(client.get("name") or "Managed device")[:64],
                    "current_mac": active_mac,
                }
            )
            scored.append(result)
        if not scored:
            return None
        scored.sort(key=lambda item: int(item["confidence"]), reverse=True)
        best = scored[0]
        if len(scored) > 1 and int(best["confidence"]) - int(scored[1]["confidence"]) < 15:
            best = dict(best)
            best["action"] = "review"
            best["automatic"] = False
            best["conflicts"] = [*best["conflicts"], "ambiguous_match"]
        return best

    def record_migration(self, device_id: str, old_mac: str, new_mac: str) -> None:
        """Mark an alias transition after policy publication succeeds."""
        old_normalized = sanitize_mac(old_mac)
        new_normalized = sanitize_mac(new_mac)
        normalized_id = self._device_id(device_id)
        if not old_normalized or not new_normalized or not normalized_id:
            raise PrismIdentityError("Invalid identity migration")
        now = time.time()
        with self._lock:
            state = self._load_state()
            profile = state["profiles"].get(normalized_id)
            if not isinstance(profile, dict):
                profile = {"device_id": normalized_id, "dhcp": {}, "prism": {}}
            aliases = self._update_aliases(profile.get("aliases"), new_normalized, now)
            for alias in aliases:
                if alias.get("mac") == old_normalized:
                    alias["status"] = "retired"
                    alias["retired_at"] = now
            profile["aliases"] = aliases
            profile["active_mac"] = new_normalized
            profile["updated_at"] = now
            state["profiles"][normalized_id] = profile
            self._save_state(state)

    def stale_retired_aliases(
        self, bindings: list[DHCPAddressBinding]
    ) -> set[str]:
        """Return retired MACs with no source traffic after their retirement."""
        latest_by_mac: dict[str, DHCPAddressBinding] = {}
        for binding in bindings:
            previous = latest_by_mac.get(binding.mac)
            if previous is None or binding.last_seen_timestamp > previous.last_seen_timestamp:
                latest_by_mac[binding.mac] = binding

        stale: set[str] = set()
        with self._lock:
            profiles = self._load_state()["profiles"]
        for profile in profiles.values():
            if not isinstance(profile, dict):
                continue
            aliases = profile.get("aliases")
            if not isinstance(aliases, list):
                continue
            for alias in aliases:
                if not isinstance(alias, dict) or alias.get("status") != "retired":
                    continue
                mac = sanitize_mac(alias.get("mac"))
                retired_at = self._finite_float(alias.get("retired_at"))
                binding = latest_by_mac.get(mac) if mac else None
                if (
                    mac
                    and retired_at is not None
                    and binding is not None
                    and binding.last_seen_timestamp <= retired_at
                ):
                    stale.add(mac)
        return stale

    def _score(
        self,
        *,
        profile: dict[str, Any],
        candidate_dhcp: dict[str, Any],
        candidate_prism: dict[str, Any],
        candidate_binding: DHCPAddressBinding,
        active_mac: str,
        bindings: list[DHCPAddressBinding],
    ) -> dict[str, Any]:
        prior_dhcp = profile.get("dhcp") if isinstance(profile.get("dhcp"), dict) else {}
        prior_prism = profile.get("prism") if isinstance(profile.get("prism"), dict) else {}
        score = 0
        groups: list[str] = []
        evidence: list[str] = []
        conflicts: list[str] = []

        stable_id = candidate_dhcp.get("stable_client_id")
        if stable_id and stable_id == prior_dhcp.get("stable_client_id"):
            score += 55
            groups.append("stable_identity")
            evidence.append("stable_dhcp_identity")
        elif stable_id and prior_dhcp.get("stable_client_id"):
            conflicts.append("stable_identity_conflict")

        platform = 0
        candidate_hostname = candidate_dhcp.get("hostname")
        prior_hostname = prior_dhcp.get("hostname")
        hostname_match = bool(candidate_hostname and candidate_hostname == prior_hostname)
        hostname_conflict = bool(
            candidate_hostname and prior_hostname and not hostname_match
        )
        if hostname_match:
            platform += 15
            evidence.append("hostname_match")
        if candidate_dhcp.get("vendor_class") and candidate_dhcp.get("vendor_class") == prior_dhcp.get("vendor_class"):
            platform += 5
            evidence.append("dhcp_vendor_match")
        if (
            candidate_dhcp.get("fingerprint")
            and candidate_dhcp.get("fingerprint") == prior_dhcp.get("fingerprint")
            and candidate_dhcp.get("parameter_request_list")
            == prior_dhcp.get("parameter_request_list")
        ):
            platform += 15
            evidence.append("dhcp_stack_match")
        if platform:
            score += min(platform, 35)
            groups.append("platform")

        behavior_score = self._prism_similarity(prior_prism, candidate_prism)
        if behavior_score:
            score += behavior_score
            groups.append("prism_behavior")
            evidence.append("prism_metadata_match")

        old_binding = max(
            (item for item in bindings if item.mac == active_mac),
            key=lambda item: item.last_seen_timestamp,
            default=None,
        )
        if old_binding is not None:
            if old_binding.last_seen_timestamp > (
                candidate_binding.assigned_at_timestamp + SIMULTANEOUS_GRACE_SECONDS
            ):
                conflicts.append("simultaneous_active_mac")
            else:
                gap = candidate_binding.assigned_at_timestamp - old_binding.last_seen_timestamp
                if 0 <= gap <= TRANSITION_WINDOW_SECONDS:
                    score += 20
                    groups.append("transition")
                    evidence.append("recent_mac_transition")

        # DHCP identifiers, names and traffic patterns are passive signals.
        # They can justify a review prompt, but cannot authorize a new MAC.
        continuity_supported = not hostname_conflict and (
            "stable_identity" in groups or (hostname_match and behavior_score >= 25)
        )
        return {
            "confidence": min(score, 100),
            "continuity_supported": continuity_supported,
            "identity_state": "possible_mac_change",
            "action": "review",
            "automatic": False,
            "evidence": evidence,
            "evidence_groups": sorted(set(groups)),
            "conflicts": conflicts,
        }

    def _dhcp_features(self, identity: DHCPIdentity, mac: str) -> dict[str, Any]:
        stable_id = None
        if identity.client_id and not self._client_id_derived_from_mac(identity.client_id, mac):
            stable_id = self._keyed_digest(identity.client_id)
        hostname = str(identity.hostname or "").strip().casefold()[:128] or None
        vendor = str(identity.vendor_class or "").strip().casefold()[:128] or None
        return {
            "hostname": hostname,
            "vendor_class": vendor,
            "fingerprint": identity.dhcp_fingerprint,
            "parameter_request_list": list(identity.parameter_request_list),
            "stable_client_id": stable_id,
        }

    @staticmethod
    def _client_id_derived_from_mac(client_id: str, mac: str) -> bool:
        compact = mac.replace(":", "").lower()
        value = client_id.lower()
        return value in {compact, "01" + compact}

    @staticmethod
    def _prism_similarity(prior: dict[str, Any], candidate: dict[str, Any]) -> int:
        prior_events = int(prior.get("event_count") or 0)
        candidate_events = int(candidate.get("event_count") or 0)
        if prior_events < 12 or candidate_events < 12:
            return 0
        left_tls = set(prior.get("tls_fingerprints") or [])
        right_tls = set(candidate.get("tls_fingerprints") or [])
        left_destinations = set(prior.get("destination_tokens") or [])
        right_destinations = set(candidate.get("destination_tokens") or [])
        if not left_destinations or not right_destinations:
            return 0
        destination_similarity = len(left_destinations & right_destinations) / len(
            left_destinations | right_destinations
        )
        destination_only = (
            prior_events >= 20
            and candidate_events >= 20
            and len(left_destinations) >= 12
            and len(right_destinations) >= 12
            and destination_similarity >= 0.70
        )
        if not left_tls or not right_tls:
            return 30 if destination_only else 0
        tls_similarity = len(left_tls & right_tls) / len(left_tls | right_tls)
        combined = (
            len(left_destinations) >= 5
            and len(right_destinations) >= 5
            and tls_similarity >= 0.60
            and destination_similarity >= 0.45
        )
        if not combined:
            return 30 if destination_only else 0
        similarity = (tls_similarity + destination_similarity) / 2
        return max(30 if destination_only else 0, min(35, max(25, round(35 * similarity))))

    def _read_prism_features(self, ip_starts: dict[str, float]) -> dict[str, dict[str, Any]]:
        if not ip_starts:
            return {}
        cache_key = tuple(sorted((ip, float(start)) for ip, start in ip_starts.items()))
        monotonic_now = time.monotonic()
        with self._feature_cache_lock:
            cached = self._feature_cache.get(cache_key)
            if cached and monotonic_now - cached[0] <= FEATURE_CACHE_SECONDS:
                return cached[1]
        lines = self._cached_prism_tail_lines()
        counters: dict[str, Counter[str]] = {ip: Counter() for ip in ip_starts}
        destinations: dict[str, Counter[str]] = {ip: Counter() for ip in ip_starts}
        event_counts: Counter[str] = Counter()
        digest_key: bytes | None = None
        for line in lines:
            try:
                event = json.loads(line)
                ip = str(ipaddress.IPv4Address(str(event.get("client_ip") or "")))
                timestamp = float(event.get("timestamp"))
            except (ValueError, TypeError, OverflowError, ipaddress.AddressValueError):
                continue
            if ip not in ip_starts or not math.isfinite(timestamp) or timestamp < ip_starts[ip]:
                continue
            features = event.get("features") if isinstance(event.get("features"), dict) else {}
            for value in (
                event.get("tls_fingerprint"),
                event.get("tls_lineage_fingerprint"),
                features.get("tls_fingerprint"),
                features.get("tls_lineage_fingerprint"),
            ):
                fingerprint = str(value or "").strip().lower()
                if 8 <= len(fingerprint) <= 128 and all(c in "0123456789abcdef" for c in fingerprint):
                    counters[ip][fingerprint] += 1
            server_name = str(event.get("server_name") or "").strip().lower().rstrip(".")
            if (
                1 <= len(server_name) <= 253
                and all(
                    char.isascii()
                    and (char.isalnum() or char in {"-", "."})
                    for char in server_name
                )
            ):
                if digest_key is None:
                    digest_key = self._load_or_create_key()
                destination_token = hmac.new(
                    digest_key,
                    server_name.encode("utf-8"),
                    hashlib.sha256,
                ).hexdigest()
                destinations[ip][destination_token] += 1
            event_counts[ip] += 1
        dns_tokens, dns_counts = self._read_dns_destination_tokens(ip_starts)
        for ip, values in dns_tokens.items():
            destinations[ip].update(values)
            event_counts[ip] += dns_counts.get(ip, 0)
        result = {
            ip: {
                "event_count": min(event_counts[ip], 100_000),
                "tls_fingerprints": [
                    value for value, _count in counters[ip].most_common(MAX_FEATURES)
                ],
                "destination_tokens": [
                    value
                    for value, _count in destinations[ip].most_common(
                        MAX_DESTINATION_TOKENS
                    )
                ],
            }
            for ip in ip_starts
            if event_counts[ip]
        }
        with self._feature_cache_lock:
            self._feature_cache[cache_key] = (monotonic_now, result)
            if len(self._feature_cache) > 16:
                oldest = min(
                    self._feature_cache,
                    key=lambda key: self._feature_cache[key][0],
                )
                self._feature_cache.pop(oldest, None)
        return result

    def _read_dns_destination_tokens(
        self, ip_starts: dict[str, float]
    ) -> tuple[dict[str, Counter[str]], Counter[str]]:
        """Read bounded DNS history without retaining plaintext destinations."""
        counters: dict[str, Counter[str]] = {ip: Counter() for ip in ip_starts}
        totals: Counter[str] = Counter()
        path = self.dns_log_path
        try:
            if path.is_symlink():
                return counters, totals
            details = path.stat()
            if not stat.S_ISREG(details.st_mode) or details.st_size > MAX_DNS_DB_BYTES:
                return counters, totals
            uri = path.resolve().as_uri() + "?mode=ro"
            connection = sqlite3.connect(uri, uri=True, timeout=0.2)
        except (OSError, sqlite3.Error, ValueError):
            return counters, totals
        try:
            digest_key: bytes | None = None
            for ip, start in ip_starts.items():
                client_hash = hashlib.sha256(ip.encode("ascii")).hexdigest()[:16]
                since = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(start))
                try:
                    rows = connection.execute(
                        "SELECT domain FROM flow_log "
                        "WHERE client_id = ? AND timestamp >= ? "
                        "ORDER BY timestamp DESC LIMIT 256",
                        (client_hash, since),
                    ).fetchall()
                except sqlite3.Error:
                    continue
                for row in rows:
                    domain = str(row[0] or "").strip().lower().rstrip(".")
                    if not self._valid_domain(domain):
                        continue
                    if digest_key is None:
                        digest_key = self._load_or_create_key()
                    token = hmac.new(
                        digest_key,
                        domain.encode("utf-8"),
                        hashlib.sha256,
                    ).hexdigest()
                    counters[ip][token] += 1
                    totals[ip] += 1
        finally:
            connection.close()
        return counters, totals

    @staticmethod
    def _valid_domain(value: str) -> bool:
        return (
            1 <= len(value) <= 253
            and all(
                char.isascii() and (char.isalnum() or char in {"-", "."})
                for char in value
            )
        )

    def _cached_prism_tail_lines(self) -> list[str]:
        now = time.monotonic()
        with self._feature_cache_lock:
            cached = self._prism_tail_cache
            if cached and now - cached[0] <= FEATURE_CACHE_SECONDS:
                return cached[1]
        lines = self._safe_tail_lines(self.prism_path)
        with self._feature_cache_lock:
            self._prism_tail_cache = (now, lines)
        return lines

    @staticmethod
    def _safe_tail_lines(path: Path) -> list[str]:
        try:
            if path.is_symlink():
                return []
            flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            descriptor = os.open(path, flags)
            try:
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_PRISM_FILE_BYTES:
                    return []
                start = max(0, info.st_size - PRISM_TAIL_BYTES)
                os.lseek(descriptor, start, os.SEEK_SET)
                payload = os.read(descriptor, PRISM_TAIL_BYTES)
            finally:
                os.close(descriptor)
        except OSError:
            return []
        text = payload.decode("utf-8", errors="ignore")
        lines = text.splitlines()
        return lines[1:] if start else lines

    def _keyed_digest(self, value: str) -> str:
        key = self._load_or_create_key()
        return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()

    def _load_or_create_key(self) -> bytes:
        if self.data_dir.exists() and self.data_dir.is_symlink():
            raise PrismIdentityError("Refusing symlinked identity directory")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        try:
            if self.key_path.is_symlink():
                raise PrismIdentityError("Refusing symlinked identity key")
            descriptor = os.open(
                self.key_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or info.st_size != 32:
                    raise PrismIdentityError("Invalid identity key")
                if hasattr(os, "fchmod"):
                    os.fchmod(descriptor, 0o600)
                os.lseek(descriptor, 0, os.SEEK_SET)
                with os.fdopen(descriptor, "rb", closefd=False) as handle:
                    key = handle.read(33)
            finally:
                os.close(descriptor)
            if len(key) != 32:
                raise PrismIdentityError("Invalid identity key")
            return key
        except FileNotFoundError:
            key = os.urandom(32)
            descriptor = os.open(self.key_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(descriptor, "wb") as handle:
                handle.write(key)
                handle.flush()
                os.fsync(handle.fileno())
            return key
        except OSError as exc:
            raise PrismIdentityError("Cannot read identity key") from exc

    def _load_state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return {"version": STATE_VERSION, "profiles": {}}
        try:
            if self.state_path.is_symlink():
                raise PrismIdentityError("Unsafe identity state")
            descriptor = os.open(
                self.state_path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            )
            try:
                info = os.fstat(descriptor)
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_STATE_BYTES:
                    raise PrismIdentityError("Unsafe identity state")
                with os.fdopen(descriptor, "rb", closefd=False) as handle:
                    payload = handle.read(MAX_STATE_BYTES + 1)
            finally:
                os.close(descriptor)
            value = json.loads(payload.decode("utf-8"))
        except PrismIdentityError:
            raise
        except (OSError, ValueError, TypeError) as exc:
            raise PrismIdentityError("Cannot read identity state") from exc
        if (
            not isinstance(value, dict)
            or value.get("version") != STATE_VERSION
            or not isinstance(value.get("profiles"), dict)
        ):
            raise PrismIdentityError("Invalid identity state")
        return value

    def _save_state(self, value: dict[str, Any]) -> None:
        if self.data_dir.exists() and self.data_dir.is_symlink():
            raise PrismIdentityError("Refusing symlinked identity directory")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        encoded = json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode()
        if len(encoded) > MAX_STATE_BYTES:
            raise PrismIdentityError("Identity state is too large")
        temporary = ""
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=self.data_dir, prefix=".prism-identity-", delete=False
            ) as handle:
                temporary = handle.name
                os.chmod(temporary, 0o600)
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.state_path)
            os.chmod(self.state_path, 0o600)
        except OSError as exc:
            if temporary:
                Path(temporary).unlink(missing_ok=True)
            raise PrismIdentityError("Cannot persist identity state") from exc

    @staticmethod
    def _update_aliases(value: Any, active_mac: str, now: float) -> list[dict[str, Any]]:
        aliases: list[dict[str, Any]] = []
        if isinstance(value, list):
            for item in value[-MAX_ALIASES:]:
                if not isinstance(item, dict):
                    continue
                mac = sanitize_mac(item.get("mac"))
                if not mac:
                    continue
                alias = {
                    "mac": mac,
                    "status": "active" if item.get("status") == "active" else "retired",
                }
                for field in ("first_seen", "last_seen", "retired_at"):
                    timestamp = PrismIdentityService._finite_float(item.get(field))
                    if timestamp is not None and timestamp > 0:
                        alias[field] = timestamp
                aliases.append(alias)
        found = False
        for alias in aliases:
            if sanitize_mac(alias.get("mac")) == active_mac:
                alias.update({"mac": active_mac, "status": "active", "last_seen": now})
                alias.pop("retired_at", None)
                found = True
            elif alias.get("status") == "active":
                alias["status"] = "retired"
                alias.setdefault("retired_at", now)
        if not found:
            aliases.append({"mac": active_mac, "status": "active", "first_seen": now, "last_seen": now})
        return aliases[-MAX_ALIASES:]

    @staticmethod
    def _merge_client_history(
        aliases_value: Any,
        client_history: list[dict[str, Any]],
        active_mac: str,
        now: float,
    ) -> list[dict[str, Any]]:
        aliases = PrismIdentityService._update_aliases(
            aliases_value, active_mac, now
        )
        known = {sanitize_mac(item.get("mac")) for item in aliases}
        for item in client_history[-MAX_ALIASES:]:
            mac = sanitize_mac(item.get("mac"))
            if not mac or mac == active_mac or mac in known:
                continue
            aliases.insert(
                0,
                {
                    "mac": mac,
                    "status": "retired",
                    "retired_at": item.get("retired_at") or now,
                },
            )
            known.add(mac)
        return aliases[-MAX_ALIASES:]

    @staticmethod
    def _client_ip(client: dict[str, Any]) -> str | None:
        raw = client.get("ip")
        if not raw and isinstance(client.get("ids"), list) and client["ids"]:
            raw = client["ids"][0]
        return PrismIdentityService._valid_ipv4(raw)

    @staticmethod
    def _valid_ipv4(value: Any) -> str | None:
        try:
            return str(ipaddress.IPv4Address(str(value or "")))
        except ipaddress.AddressValueError:
            return None

    @staticmethod
    def _device_id(value: Any) -> str | None:
        text = str(value or "").strip().lower()
        if not text or len(text) > 64 or any(c not in "abcdefghijklmnopqrstuvwxyz0123456789_-" for c in text):
            return None
        return text

    @staticmethod
    def _finite_float(value: Any) -> float | None:
        try:
            number = float(value)
        except (TypeError, ValueError, OverflowError):
            return None
        return number if math.isfinite(number) else None
