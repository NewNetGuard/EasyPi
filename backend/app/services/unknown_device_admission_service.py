"""Passive unknown-device admission inventory.

The firewall is the enforcement boundary: when ``unknown_devices.mode`` is
``block``, an unapproved MAC+IPv4 pair is rejected before this service sees it.
This service only records passive DHCP/ARP observations and lets an
administrator make an explicit decision.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import socket
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import psutil

from app.core.paths import get_netprotection_data_dir
from app.services.dhcp_identity import (
    DHCPAddressBinding,
    DHCPIdentity,
    load_dhcp_address_bindings,
    load_dhcp_identities,
)
from app.services.prism_identity_service import PrismIdentityError, PrismIdentityService
from app.utils.sanitize import sanitize_mac


STATE_VERSION = 1
MAX_STATE_BYTES = 2 * 1024 * 1024
MAX_DEVICES = 2048
LAST_SEEN_WRITE_INTERVAL_SECONDS = 30.0


class UnknownDeviceAdmissionError(RuntimeError):
    """The quarantine inventory could not be read or written safely."""


class UnknownDeviceNotFound(UnknownDeviceAdmissionError):
    """The requested server-observed device does not exist."""


class UnknownDeviceAdmissionService:
    def __init__(
        self,
        data_dir: str | Path | None = None,
        *,
        arp_path: str | Path = "/proc/net/arp",
        route_path: str | Path = "/proc/net/route",
        dhcp_paths: tuple[Path, ...] | None = None,
        prism_path: str | Path = "/var/lib/easypi/prism/flowgraph.jsonl",
        mobile_tunnel_registry_path: str | Path | None = None,
    ) -> None:
        self.data_dir = Path(data_dir or get_netprotection_data_dir())
        self.state_path = self.data_dir / "unknown_device_admission.json"
        self.settings_path = self.data_dir / "settings.json"
        self.clients_path = self.data_dir / "clients.json"
        self.arp_path = Path(arp_path)
        self.route_path = Path(route_path)
        self.dhcp_paths = dhcp_paths
        self.mobile_tunnel_registry_path = Path(
            mobile_tunnel_registry_path
            or self.data_dir / "mobile-home-tunnel-peers.json"
        )
        self.identity_service = PrismIdentityService(
            self.data_dir, prism_path=prism_path
        )
        self._lock = threading.RLock()

    def is_block_mode(self) -> bool:
        """Fail closed when settings are absent or unreadable."""
        try:
            if not self.settings_path.exists():
                return True
            payload = self._read_json_file(self.settings_path, MAX_STATE_BYTES)
            section = payload.get("unknown_devices", {})
            # Only the explicit administrator-selected permissive mode opens
            # admission. Unknown values must never silently disable quarantine.
            return not isinstance(section, dict) or section.get("mode") != "default"
        except UnknownDeviceAdmissionError:
            return True

    def refresh(self) -> list[dict[str, Any]]:
        """Merge current passive observations and return newly quarantined devices."""
        if not self.is_block_mode():
            return []

        local_ips = self._local_ipv4_addresses()
        identities = load_dhcp_identities(self.dhcp_paths)
        bindings = load_dhcp_address_bindings(self.dhcp_paths)
        observations = self._collect_observations(identities, bindings)
        try:
            stale_retired_aliases = self.identity_service.stale_retired_aliases(bindings)
        except PrismIdentityError:
            # Corrupt identity metadata must fail closed: it may not suppress
            # an otherwise valid quarantine observation.
            stale_retired_aliases = set()
        if stale_retired_aliases:
            observations = [
                observation
                for observation in observations
                if observation["mac"] not in stale_retired_aliases
            ]
        observed_ids = {
            self.device_id(observation["mac"]) for observation in observations
        }

        with self._lock:
            state = self._load_state()
            devices = {
                str(item.get("id")): item
                for item in state["devices"]
                if isinstance(item, dict)
                and item.get("id")
                and str(item.get("ip") or "") not in local_ips
            }
            changed = len(devices) != len(state["devices"])
            # Pending observations are an inventory of devices present now,
            # not a permanent history. Remove entries no longer backed by a
            # recent DHCP or source-traffic observation. Explicit Block
            # decisions remain durable and continue to follow their MAC.
            for device_id, item in list(devices.items()):
                if (
                    item.get("status") in {"pending", "reconnecting"}
                    and device_id not in observed_ids
                ):
                    devices.pop(device_id, None)
                    changed = True
            if not observations:
                if changed:
                    self._save_state(
                        {"version": STATE_VERSION, "devices": list(devices.values())}
                    )
                return []
            clients = self._load_managed_clients()
            approved, managed_by_mac = self._managed_identity_maps(clients)
            identity_profiles_available = True
            try:
                self.identity_service.refresh_profiles(clients, identities, bindings)
            except PrismIdentityError:
                # Identity correlation is optional evidence.  A damaged state
                # can never open access or suppress the quarantine boundary.
                identity_profiles_available = False
            new_devices: list[dict[str, Any]] = []
            now_ts = time.time()
            now_iso = datetime.now(timezone.utc).isoformat()

            for observation in observations:
                pair = (observation["mac"], observation["ip"])
                device_id = self.device_id(observation["mac"])
                existing = devices.get(device_id)
                # An explicit Block follows the MAC even when this MAC returns
                # to an older MAC+IP pair which is still present in the managed
                # inventory. The root-owned firewall deny is removed only by a
                # later successful Allow transaction.
                if pair in approved and not (
                    existing and existing.get("status") == "blocked"
                ):
                    if device_id in devices:
                        devices.pop(device_id, None)
                        changed = True
                    continue

                managed = managed_by_mac.get(observation["mac"])
                identity_candidate = None
                if not managed and identity_profiles_available:
                    try:
                        identity_candidate = self.identity_service.assess(
                            observation, clients, identities, bindings
                        )
                    except PrismIdentityError:
                        identity_profiles_available = False
                can_auto_rebind = bool(
                    managed and "traffic" in observation.get("sources", [])
                )
                # DHCP metadata alone is not ownership proof: a hostile LAN
                # peer can forge a server-looking ACK. Already managed MACs are
                # re-admitted only after the observer sees that MAC+IP pair
                # actually originate IPv4 traffic on the selected LAN scope.
                if managed and not can_auto_rebind:
                    continue

                if existing is None:
                    existing = {
                        "id": device_id,
                        "mac": observation["mac"],
                        "ip": observation["ip"],
                        "hostname": observation.get("hostname"),
                        "vendor": observation.get("vendor"),
                        "sources": observation["sources"],
                        # A MAC which the administrator already approved is not
                        # a new device merely because DHCP assigned a new IP.
                        # Keep it hidden while the backend safely republishes
                        # the existing policy for the new MAC+IP pair.
                        "status": "reconnecting" if can_auto_rebind else "pending",
                        "first_seen": now_iso,
                        "last_seen": now_iso,
                        "last_seen_timestamp": now_ts,
                        "managed_device": bool(managed),
                        "managed_name": managed.get("name") if managed else None,
                        "managed_profile": managed.get("profile") if managed else None,
                        "identity_candidate": identity_candidate,
                    }
                    devices[device_id] = existing
                    new_devices.append(dict(existing))
                    changed = True
                    continue

                # A permanent Block decision follows the MAC. A DHCP address
                # change updates diagnostics but never grants access.
                prior_ts = float(existing.get("last_seen_timestamp") or 0.0)
                updated = {
                    "ip": observation["ip"],
                    "hostname": observation.get("hostname") or existing.get("hostname"),
                    "vendor": observation.get("vendor") or existing.get("vendor"),
                    "sources": sorted(
                        set(existing.get("sources") or []) | set(observation["sources"])
                    ),
                    "managed_device": bool(managed),
                    "managed_name": managed.get("name") if managed else None,
                    "managed_profile": managed.get("profile") if managed else None,
                    "identity_candidate": identity_candidate,
                }
                ip_changed = existing.get("ip") != observation["ip"]
                if (
                    can_auto_rebind
                    and existing.get("status") != "blocked"
                    and (
                        not existing.get("auto_rebind_failed")
                        or ip_changed
                    )
                ):
                    updated["status"] = "reconnecting"
                    existing.pop("auto_rebind_failed", None)
                    existing.pop("activation_error", None)
                if any(existing.get(key) != value for key, value in updated.items()):
                    existing.update(updated)
                    changed = True
                if now_ts - prior_ts >= LAST_SEEN_WRITE_INTERVAL_SECONDS:
                    existing["last_seen"] = now_iso
                    existing["last_seen_timestamp"] = now_ts
                    changed = True

            if changed:
                ordered = sorted(
                    devices.values(),
                    key=lambda item: float(item.get("last_seen_timestamp") or 0.0),
                    reverse=True,
                )[:MAX_DEVICES]
                self._save_state({"version": STATE_VERSION, "devices": ordered})
            return new_devices

    def list_devices(self, *, include_blocked: bool = False) -> list[dict[str, Any]]:
        if not self.is_block_mode():
            return []
        with self._lock:
            devices = self._load_state()["devices"]
            allowed_statuses = {"pending", "blocked"} if include_blocked else {"pending"}
            return [
                dict(item)
                for item in devices
                if isinstance(item, dict) and item.get("status") in allowed_statuses
            ]

    def get_device(self, device_id: str) -> dict[str, Any]:
        with self._lock:
            for item in self._load_state()["devices"]:
                if isinstance(item, dict) and item.get("id") == device_id:
                    return dict(item)
        raise UnknownDeviceNotFound("Unknown device is no longer awaiting review")

    def list_rebindings(self) -> list[dict[str, Any]]:
        """Return already-managed MACs awaiting an automatic DHCP rebind."""
        if not self.is_block_mode():
            return []
        with self._lock:
            return [
                dict(item)
                for item in self._load_state()["devices"]
                if isinstance(item, dict)
                and item.get("status") == "reconnecting"
                and item.get("managed_device") is True
            ]

    def is_pair_allowed(self, mac_value: Any, ip_value: Any) -> bool:
        """Return whether the current MAC+IPv4 identity may use the gateway.

        Status reporting must fail closed too: a stale successful conntrack
        entry must not make a pending or explicitly blocked device look online.
        """
        if not self.is_block_mode():
            return True
        mac = sanitize_mac(mac_value)
        try:
            ip = str(ipaddress.IPv4Address(str(ip_value).strip()))
        except ipaddress.AddressValueError:
            return False
        if not mac:
            return False
        try:
            with self._lock:
                approved, _ = self._load_managed_identities()
                if (mac, ip) not in approved:
                    return False
                for item in self._load_state()["devices"]:
                    if not isinstance(item, dict):
                        continue
                    if sanitize_mac(item.get("mac")) != mac:
                        continue
                    if item.get("status") in {"pending", "blocked", "reconnecting"}:
                        return False
                return True
        except UnknownDeviceAdmissionError:
            return False

    def mark_rebinding_failed(self, device_id: str) -> None:
        """Expose a failed automatic rebind for explicit administrator retry."""
        with self._lock:
            state = self._load_state()
            for item in state["devices"]:
                if not isinstance(item, dict) or item.get("id") != device_id:
                    continue
                if item.get("status") != "reconnecting":
                    return
                item["status"] = "pending"
                item["auto_rebind_failed"] = True
                item["activation_error"] = "policy_activation_failed"
                self._save_state(state)
                return

    def block(self, device_id: str) -> dict[str, Any]:
        """Persist a deny decision after its root-owned firewall rule is active."""
        with self._lock:
            state = self._load_state()
            for item in state["devices"]:
                if not isinstance(item, dict) or item.get("id") != device_id:
                    continue
                item["status"] = "blocked"
                item["decided_at"] = datetime.now(timezone.utc).isoformat()
                self._save_state(state)
                return dict(item)
        raise UnknownDeviceNotFound("Unknown device is no longer awaiting review")

    def mark_allowed(self, device_id: str) -> None:
        """Remove a decision only after the managed MAC+IP policy is published."""
        with self._lock:
            state = self._load_state()
            original = len(state["devices"])
            state["devices"] = [
                item
                for item in state["devices"]
                if not isinstance(item, dict) or item.get("id") != device_id
            ]
            if len(state["devices"]) == original:
                raise UnknownDeviceNotFound("Unknown device is no longer awaiting review")
            self._save_state(state)

    @staticmethod
    def device_id(mac: str) -> str:
        normalized = sanitize_mac(mac)
        if not normalized:
            raise ValueError("Invalid MAC address")
        return "unknown_" + hashlib.sha256(normalized.encode("ascii")).hexdigest()[:20]

    def _collect_observations(
        self,
        identities: list[DHCPIdentity] | None = None,
        bindings: list[DHCPAddressBinding] | None = None,
    ) -> list[dict[str, Any]]:
        by_mac: dict[str, dict[str, Any]] = {}
        infrastructure_ips = self._local_ipv4_addresses()
        gateway_ip = self._default_gateway_ipv4()
        if gateway_ip:
            infrastructure_ips.add(gateway_ip)
        identities = identities if identities is not None else load_dhcp_identities(self.dhcp_paths)
        # Old DHCP metadata may label a MAC that has just resumed real traffic.
        # It is display-only: presence and admission still require a recent,
        # traffic-observed MAC+IP binding below.
        metadata_by_mac = {identity.mac: identity for identity in identities}
        latest_bindings: dict[str, Any] = {}
        bindings = bindings if bindings is not None else load_dhcp_address_bindings(self.dhcp_paths)
        for binding in bindings:
            if not binding.recently_observed:
                continue
            previous = latest_bindings.get(binding.mac)
            if previous is None or (
                binding.last_seen_timestamp,
                binding.assigned_at_timestamp,
            ) > (
                previous.last_seen_timestamp,
                previous.assigned_at_timestamp,
            ):
                latest_bindings[binding.mac] = binding

        for binding in latest_bindings.values():
            metadata = metadata_by_mac.get(binding.mac)
            observation = self._validated_observation(
                binding.ip,
                binding.mac,
                hostname=metadata.hostname if metadata else None,
                vendor=metadata.vendor_class if metadata else None,
                source="traffic",
            )
            if observation:
                by_mac[observation["mac"]] = observation

        for identity in identities:
            if not identity.recently_observed:
                continue
            observation = self._validated_observation(
                identity.ip,
                identity.mac,
                hostname=identity.hostname,
                vendor=identity.vendor_class,
                source="dhcp",
            )
            if observation:
                existing = by_mac.get(observation["mac"])
                if existing and existing["ip"] == observation["ip"]:
                    existing["sources"] = sorted(
                        set(existing["sources"]) | {"dhcp"}
                    )
                    existing["hostname"] = (
                        observation.get("hostname") or existing.get("hostname")
                    )
                    existing["vendor"] = (
                        observation.get("vendor") or existing.get("vendor")
                    )
                elif not existing:
                    by_mac[observation["mac"]] = observation

        # A Mobile home-tunnel peer has no Ethernet MAC because its packets
        # arrive through a layer-3 TUN.  Its UUID and assigned address are,
        # however, cryptographically bound by the Chameleon session.  Derive a
        # stable locally-administered identifier so the existing admission UI
        # and profile transaction can represent it without pretending that an
        # observed LAN MAC exists.
        for peer in self._mobile_tunnel_peers():
            observation = self._validated_observation(
                peer["address"],
                self.mobile_tunnel_mac(peer["id"]),
                hostname="EasyPi Mobile",
                vendor="Authenticated mobile tunnel",
                source="mobile_tunnel",
            )
            if observation:
                by_mac[observation["mac"]] = observation

        try:
            lines = self.arp_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except (FileNotFoundError, OSError):
            lines = []
        for line in lines[1:]:
            parts = line.split()
            if len(parts) < 6 or parts[2].lower() in {"0x0", "0x00"}:
                continue
            observation = self._validated_observation(
                parts[0], parts[3], source="arp"
            )
            if not observation:
                continue
            existing = by_mac.get(observation["mac"])
            if existing:
                if existing["ip"] == observation["ip"]:
                    existing["sources"] = sorted(
                        set(existing["sources"]) | {"arp"}
                    )
                elif {"traffic", "dhcp"} & set(existing["sources"]):
                    # A packet observation or recent DHCP metadata is newer
                    # than an arbitrary stale ARP cache entry for this MAC.
                    continue
                else:
                    by_mac[observation["mac"]] = observation
            # /proc/net/arp has no reliable age or neighbour-state field and
            # may retain disconnected devices for hours. ARP therefore only
            # enriches a recent DHCP or real-source-traffic observation; it is
            # never sufficient by itself to create a quarantine notification.
        return [
            observation
            for observation in by_mac.values()
            if observation["ip"] not in infrastructure_ips
        ]

    def _mobile_tunnel_peers(self) -> list[dict[str, str]]:
        path = self.mobile_tunnel_registry_path
        if not path.exists():
            return []
        try:
            payload = self._read_json_file(path, 64 * 1024)
            devices = payload.get("devices")
            if payload.get("version") != 1 or not isinstance(devices, list):
                raise UnknownDeviceAdmissionError("Invalid mobile tunnel registry")
            peers: list[dict[str, str]] = []
            seen_addresses: set[str] = set()
            for item in devices:
                if not isinstance(item, dict) or set(item) != {"id", "address"}:
                    raise UnknownDeviceAdmissionError("Invalid mobile tunnel registry")
                identity = str(uuid.UUID(str(item["id"])))
                address = str(ipaddress.IPv4Address(str(item["address"])))
                if (
                    identity != item["id"]
                    or ipaddress.IPv4Address(address)
                    not in ipaddress.IPv4Network("10.77.0.0/24")
                    or address in {"10.77.0.0", "10.77.0.1", "10.77.0.255"}
                    or address in seen_addresses
                ):
                    raise UnknownDeviceAdmissionError("Invalid mobile tunnel registry")
                seen_addresses.add(address)
                peers.append({"id": identity, "address": address})
            return peers
        except (ValueError, TypeError) as exc:
            raise UnknownDeviceAdmissionError("Invalid mobile tunnel registry") from exc

    @staticmethod
    def mobile_tunnel_mac(device_id: str) -> str:
        identity = str(uuid.UUID(str(device_id)))
        digest = hashlib.sha256(
            ("easypi/mobile-tunnel-identity/v1/" + identity).encode("ascii")
        ).digest()
        # 02 marks a unicast, locally administered value.  All remaining bytes
        # come from the enrolled UUID, keeping the identifier stable per phone.
        return ":".join(f"{byte:02X}" for byte in bytes([0x02]) + digest[:5])

    @staticmethod
    def _local_ipv4_addresses() -> set[str]:
        """Return addresses owned by this EasyPi, including every LAN interface."""
        addresses: set[str] = set()
        try:
            interface_addresses = psutil.net_if_addrs().values()
        except Exception:
            return addresses
        for interface in interface_addresses:
            for address in interface:
                if address.family != socket.AF_INET:
                    continue
                try:
                    ip = ipaddress.IPv4Address(str(address.address))
                except ipaddress.AddressValueError:
                    continue
                if not ip.is_loopback:
                    addresses.add(str(ip))
        return addresses

    def _default_gateway_ipv4(self) -> str | None:
        """Read Linux's default gateway without invoking a shell command."""
        try:
            lines = self.route_path.read_text(
                encoding="ascii", errors="strict"
            ).splitlines()
        except (FileNotFoundError, OSError, UnicodeError):
            return None
        for line in lines[1:]:
            fields = line.split()
            if len(fields) < 4 or fields[1] != "00000000":
                continue
            try:
                flags = int(fields[3], 16)
                gateway = int(fields[2], 16).to_bytes(4, "little")
                if flags & 0x2:
                    return str(ipaddress.IPv4Address(gateway))
            except (ValueError, OverflowError):
                continue
        return None

    @staticmethod
    def _validated_observation(
        ip_value: Any,
        mac_value: Any,
        *,
        hostname: str | None = None,
        vendor: str | None = None,
        source: str,
    ) -> dict[str, Any] | None:
        try:
            ip_obj = ipaddress.IPv4Address(str(ip_value).strip())
        except ipaddress.AddressValueError:
            return None
        # Admission hooks intentionally cover RFC1918 LAN clients only.
        if not any(
            ip_obj in network
            for network in (
                ipaddress.IPv4Network("10.0.0.0/8"),
                ipaddress.IPv4Network("172.16.0.0/12"),
                ipaddress.IPv4Network("192.168.0.0/16"),
            )
        ):
            return None
        mac = sanitize_mac(mac_value)
        if not mac or mac == "00:00:00:00:00:00" or mac.startswith("ff:"):
            return None

        def clean(value: str | None) -> str | None:
            if not value:
                return None
            text = "".join(char for char in str(value) if char.isprintable()).strip()
            return text[:128] or None

        return {
            "ip": str(ip_obj),
            "mac": mac,
            "hostname": clean(hostname),
            "vendor": clean(vendor),
            "sources": [source],
        }

    def _load_managed_identities(
        self,
    ) -> tuple[set[tuple[str, str]], dict[str, dict[str, str]]]:
        return self._managed_identity_maps(self._load_managed_clients())

    def _load_managed_clients(self) -> list[dict[str, Any]]:
        if not self.clients_path.exists():
            return []
        payload = self._read_json_file(self.clients_path, MAX_STATE_BYTES)
        clients = payload.get("clients", [])
        if not isinstance(clients, list):
            raise UnknownDeviceAdmissionError("Managed device inventory is invalid")
        return [item for item in clients if isinstance(item, dict)]

    @staticmethod
    def _managed_identity_maps(
        clients: list[dict[str, Any]],
    ) -> tuple[set[tuple[str, str]], dict[str, dict[str, str]]]:
        pairs: set[tuple[str, str]] = set()
        managed_by_mac: dict[str, dict[str, str]] = {}
        for client in clients:
            if not isinstance(client, dict):
                continue
            mac = sanitize_mac(client.get("mac"))
            raw_ip = client.get("ip")
            if not raw_ip and isinstance(client.get("ids"), list) and client["ids"]:
                raw_ip = client["ids"][0]
            try:
                ip = str(ipaddress.IPv4Address(str(raw_ip or "")))
            except ipaddress.AddressValueError:
                continue
            if mac:
                pairs.add((mac, ip))
                raw_profile = str(client.get("shield_profile") or "").strip().lower()
                profile = raw_profile if raw_profile in {
                    "strict",
                    "balanced",
                    "kids",
                    "minimal",
                } else ("kids" if client.get("parental_enabled") else "balanced")
                managed_by_mac[mac] = {
                    "name": str(client.get("name") or "Managed device")[:64],
                    "profile": profile,
                }
        return pairs, managed_by_mac

    def _load_state(self) -> dict[str, Any]:
        if not self.state_path.exists():
            return {"version": STATE_VERSION, "devices": []}
        payload = self._read_json_file(self.state_path, MAX_STATE_BYTES)
        if payload.get("version") != STATE_VERSION or not isinstance(payload.get("devices"), list):
            raise UnknownDeviceAdmissionError("Unknown-device quarantine state is invalid")
        return payload

    @staticmethod
    def _read_json_file(path: Path, max_bytes: int) -> dict[str, Any]:
        try:
            if path.is_symlink():
                raise UnknownDeviceAdmissionError(f"Refusing symlinked state file: {path.name}")
            if path.stat().st_size > max_bytes:
                raise UnknownDeviceAdmissionError(f"State file is too large: {path.name}")
            payload = json.loads(path.read_text(encoding="utf-8"))
        except UnknownDeviceAdmissionError:
            raise
        except (OSError, ValueError, TypeError) as exc:
            raise UnknownDeviceAdmissionError(f"Cannot read {path.name}") from exc
        if not isinstance(payload, dict):
            raise UnknownDeviceAdmissionError(f"Invalid object in {path.name}")
        return payload

    def _save_state(self, payload: dict[str, Any]) -> None:
        if self.data_dir.exists() and self.data_dir.is_symlink():
            raise UnknownDeviceAdmissionError("Refusing symlinked data directory")
        self.data_dir.mkdir(parents=True, exist_ok=True)
        encoded = json.dumps(payload, ensure_ascii=False, indent=2).encode("utf-8")
        if len(encoded) > MAX_STATE_BYTES:
            raise UnknownDeviceAdmissionError("Unknown-device quarantine state is too large")
        tmp_name = ""
        try:
            with tempfile.NamedTemporaryFile(
                mode="wb", dir=self.data_dir, prefix=".unknown-device-", delete=False
            ) as handle:
                tmp_name = handle.name
                os.chmod(tmp_name, 0o600)
                handle.write(encoded)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp_name, self.state_path)
            os.chmod(self.state_path, 0o600)
        except OSError as exc:
            if tmp_name:
                try:
                    Path(tmp_name).unlink(missing_ok=True)
                except OSError:
                    pass
            raise UnknownDeviceAdmissionError("Cannot persist unknown-device quarantine") from exc


unknown_device_admission_service = UnknownDeviceAdmissionService()
