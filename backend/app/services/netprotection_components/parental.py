"""Parental operations for NetProtection."""

import ipaddress
import os
import stat
import sys
import tempfile
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass

from app.services.netprotection_components.runtime_context import (
    ADULT_HEURISTIC_MARKER,
    Any,
    Dict,
    EASYPI_ROOT,
    IP_BLOCK_CATALOG_EXCLUSIONS,
    IP_BLOCK_SERVICES,
    List,
    Path,
    _short_err,
    asyncio,
    datetime,
    get_all_domains_for_services,
    get_catalog_categories,
    get_catalog_services,
    json,
    logger,
    sanitize_domain,
    sanitize_mac,
    timezone,
)


# Routed per-phone addresses of the EasyPi Mobile home tunnel.
MOBILE_TUNNEL_NETWORK = ipaddress.IPv4Network("10.77.0.0/24")


def _is_mobile_tunnel_ip(value: str) -> bool:
    try:
        return ipaddress.IPv4Address(value) in MOBILE_TUNNEL_NETWORK
    except ValueError:
        return False


@dataclass(frozen=True)
class _PolicyFileSnapshot:
    content: bytes
    mode: int
    uid: int
    gid: int
    atime_ns: int
    mtime_ns: int


def _capture_policy_files(
    policy_paths: list[Path],
) -> dict[Path, _PolicyFileSnapshot | None]:
    snapshots: dict[Path, _PolicyFileSnapshot | None] = {}
    for path in policy_paths:
        if path.is_symlink():
            raise RuntimeError(f"Refusing unsafe policy file: {path.name}")
        if not path.exists():
            snapshots[path] = None
            continue
        file_stat = path.stat()
        if not stat.S_ISREG(file_stat.st_mode) or file_stat.st_size > 8 * 1024 * 1024:
            raise RuntimeError(f"Refusing unsafe policy file: {path.name}")
        snapshots[path] = _PolicyFileSnapshot(
            content=path.read_bytes(),
            mode=stat.S_IMODE(file_stat.st_mode),
            uid=file_stat.st_uid,
            gid=file_stat.st_gid,
            atime_ns=file_stat.st_atime_ns,
            mtime_ns=file_stat.st_mtime_ns,
        )
    return snapshots


def _policy_file_matches(path: Path, snapshot: _PolicyFileSnapshot | None) -> bool:
    if snapshot is None:
        return not path.exists() and not path.is_symlink()
    if path.is_symlink() or not path.exists():
        return False
    try:
        current_stat = path.stat()
        return (
            stat.S_ISREG(current_stat.st_mode)
            and path.read_bytes() == snapshot.content
            and stat.S_IMODE(current_stat.st_mode) == snapshot.mode
            and current_stat.st_uid == snapshot.uid
            and current_stat.st_gid == snapshot.gid
            and current_stat.st_mtime_ns == snapshot.mtime_ns
        )
    except OSError:
        return False


def _restore_policy_file(path: Path, snapshot: _PolicyFileSnapshot | None) -> None:
    if snapshot is None:
        path.unlink(missing_ok=True)
        return

    rollback_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="wb",
            dir=path.parent,
            prefix=f".{path.name}.parental-rollback.",
            delete=False,
        ) as rollback_file:
            rollback_file.write(snapshot.content)
            rollback_file.flush()
            os.fsync(rollback_file.fileno())
            rollback_path = Path(rollback_file.name)

        rollback_stat = rollback_path.stat()
        if rollback_stat.st_uid != snapshot.uid or rollback_stat.st_gid != snapshot.gid:
            if not hasattr(os, "chown"):
                raise OSError("cannot restore file ownership on this platform")
            os.chown(rollback_path, snapshot.uid, snapshot.gid)
        rollback_path.chmod(snapshot.mode)
        os.utime(rollback_path, ns=(snapshot.atime_ns, snapshot.mtime_ns))
        rollback_path.replace(path)
        rollback_path = None
    finally:
        if rollback_path is not None:
            rollback_path.unlink(missing_ok=True)


def _legacy_runtime():
    """Return the stable facade so existing runtime overrides stay effective."""
    return sys.modules["app.services.netprotection_service"]


class ParentalMixin:
    """Internal behavior mixed into the stable service facade."""

    async def _sync_blocklist(self) -> Dict[str, Any]:
        """
        Sync blocked domains from clients to NetProtection.

        Strategy:
        1. Create/update device bindings in bindings.json
        2. Create device profiles in profiles.json with blacklist
        3. The profiles manager's should_block() will handle blocking
        """
        sync_warnings: list[str] = []
        try:
            # Get clients from clients.json (NOT devices.json!)
            clients_path = self.data_dir / "clients.json"
            clients_data = await self.get_clients()
            clients = clients_data.get("clients", [])
            devices = await self._normalize_parental_devices(
                clients, clients_data, clients_path, sync_warnings
            )
            (
                profiles_path,
                bindings_path,
                profiles_data,
                bindings_data,
                profiles_list,
                bindings_list,
            ) = self._build_parental_policy_documents(devices)
            await self._publish_parental_policy(
                devices=devices,
                profiles_path=profiles_path,
                bindings_path=bindings_path,
                profiles_data=profiles_data,
                bindings_data=bindings_data,
                profiles_list=profiles_list,
                bindings_list=bindings_list,
                sync_warnings=sync_warnings,
            )
            return {"ok": len(sync_warnings) == 0, "warnings": sync_warnings}

        except Exception as e:
            sync_warnings.append(f"Blocklist sync failed: {e}")
            logger.warning(f"Failed to sync blocklist: {e}")
            import traceback

            logger.debug(traceback.format_exc())
            return {"ok": False, "warnings": sync_warnings}

    async def _normalize_parental_devices(
        self,
        clients: list[dict[str, Any]],
        clients_data: dict[str, Any],
        clients_path: Path,
        sync_warnings: list[str],
    ) -> list[dict[str, Any]]:
        clients_changed = False
        # Preserve blocked_apps from existing devices.json (set via app-blocking API)
        existing_blocked_apps_by_ip: dict[str, list] = {}
        existing_blocked_apps_by_id: dict[str, list] = {}
        existing_blocked_apps_by_mac: dict[str, list] = {}
        existing_mac_by_ip: dict[str, str] = {}
        existing_mac_by_id: dict[str, str] = {}
        devices_path = self.data_dir / "devices.json"
        if devices_path.exists():
            try:
                existing_devices = json.loads(devices_path.read_text())
                for device in existing_devices:
                    blocked_apps = device.get("blocked_apps", [])
                    if not isinstance(blocked_apps, list):
                        blocked_apps = []
                    device_ip = device.get("ip")
                    device_id = device.get("id")
                    device_mac = sanitize_mac(device.get("mac"))
                    if device_ip:
                        existing_blocked_apps_by_ip[device_ip] = blocked_apps
                        if device_mac:
                            existing_mac_by_ip[device_ip] = device_mac
                    if device_id:
                        existing_blocked_apps_by_id[device_id] = blocked_apps
                        if device_mac:
                            existing_mac_by_id[device_id] = device_mac
                    if device_mac:
                        existing_blocked_apps_by_mac[device_mac] = blocked_apps
            except Exception as e:
                logger.warning(f"Failed to read existing blocked_apps: {e}")

        # Convert clients to devices format for processing
        devices = []
        for client in clients:
            if not isinstance(client, dict):
                continue

            client_name = str(client.get("name", "")).strip()
            if not client_name:
                continue

            client_id = self._normalize_client_id(client.get("id"))
            if client.get("id") != client_id:
                client["id"] = client_id
                clients_changed = True

            client_ip = self._first_client_ip(client)
            if client_ip:
                if client.get("ip") != client_ip:
                    client["ip"] = client_ip
                    clients_changed = True
                ids = client.get("ids")
                if (
                    not isinstance(ids, list)
                    or not ids
                    or str(ids[0]).strip() != client_ip
                ):
                    client["ids"] = [client_ip]
                    clients_changed = True

            raw_mac = client.get("mac")
            client_mac = sanitize_mac(raw_mac)
            if raw_mac and not client_mac:
                sync_warnings.append(
                    f"Client '{client_name}' has invalid MAC and it was ignored"
                )
            if not client_mac:
                client_mac = (
                    existing_mac_by_ip.get(client_ip)
                    or existing_mac_by_id.get(client_id)
                    or ""
                )
            if not client_mac and client_ip:
                client_mac = self._resolve_mac_from_arp(client_ip)
            if client_mac:
                if client.get("mac") != client_mac:
                    client["mac"] = client_mac
                    clients_changed = True
            elif "mac" in client:
                client.pop("mac", None)
                clients_changed = True

            # A transactional admission/rebind carries a server-observed IP.
            # Do not immediately replace it with an older neighbor-cache row.
            try:
                observed_age = time.time() - float(
                    client.get("ip_observed_timestamp") or 0
                )
                recently_observed_ip = 0 <= observed_age <= 15 * 60
            except (TypeError, ValueError, OverflowError):
                recently_observed_ip = False

            # Keep legacy clients aligned from active ARP/neigh data. STALE
            # neighbors are deliberately ignored by _resolve_ipv4_from_mac.
            if client_mac and not recently_observed_ip:
                resolved_ip = self._resolve_ipv4_from_mac(client_mac)
                if resolved_ip and resolved_ip != client_ip:
                    logger.info(
                        "Updating client IP from ARP/neigh via MAC %s: %s -> %s",
                        client_mac,
                        client_ip or "<none>",
                        resolved_ip,
                    )
                    client_ip = resolved_ip
                    client["ip"] = resolved_ip
                    client["ids"] = [resolved_ip]
                    clients_changed = True

            bypass_mode = str(client.get("bypass_mode") or "warn").strip().lower()
            if bypass_mode not in {"warn", "quarantine", "log_only"}:
                bypass_mode = "warn"
            if client.get("bypass_mode") != bypass_mode:
                client["bypass_mode"] = bypass_mode
                clients_changed = True

            blocked_apps = (
                existing_blocked_apps_by_ip.get(client_ip)
                or existing_blocked_apps_by_id.get(client_id)
                or existing_blocked_apps_by_mac.get(client_mac)
                or []
            )
            if not isinstance(blocked_apps, list):
                blocked_apps = []
            devices.append(
                {
                    "id": client_id,
                    "name": client_name,
                    "ip": client_ip,
                    "mac": client_mac or None,
                    "enabled": True,
                    "parental": client.get("parental_enabled", False),
                    "safesearch": client.get("safesearch_enabled", False),
                    "safebrowsing": client.get("safebrowsing_enabled", False),
                    "shield_profile": client.get("shield_profile"),
                    "blocked_services": client.get("blocked_services", []),
                    "blocked_apps": blocked_apps,
                    "bypass_mode": bypass_mode,
                    "custom_blocked_domains": client.get("custom_blocked_domains", [])
                    or [],
                    "custom_allowed_domains": client.get("custom_allowed_domains", [])
                    or [],
                }
            )

        # Persist any auto-normalized IDs/MACs back to clients.json
        if clients_changed:
            clients_data["clients"] = clients
            clients_data["updated_at"] = datetime.now(timezone.utc).isoformat()
            tmp_clients = clients_path.with_suffix(".tmp")
            tmp_clients.write_text(json.dumps(clients_data, indent=2))
            tmp_clients.replace(clients_path)

        logger.info(f"Syncing {len(devices)} clients to NetProtection profiles")

        return devices

    def _build_parental_policy_documents(
        self, devices: list[dict[str, Any]]
    ) -> tuple[Path, Path, dict[str, Any], dict[str, Any], list, list]:
        # Load existing profiles and bindings
        profiles_path = self.data_dir / "profiles.json"
        bindings_path = self.data_dir / "bindings.json"

        if profiles_path.exists():
            profiles_data = json.loads(profiles_path.read_text())
        else:
            profiles_data = {
                "version": 1,
                "updated_at": datetime.now().isoformat(),
                "profiles": [],
            }

        if bindings_path.exists():
            bindings_data = json.loads(bindings_path.read_text())
        else:
            bindings_data = {
                "version": 1,
                "updated_at": datetime.now().isoformat(),
                "bindings": [],
            }

        profiles_list = profiles_data.get("profiles", [])
        bindings_list = bindings_data.get("bindings", [])

        managed_prefix = "parental_device_"
        managed_binding_ip_prefix = f"{managed_prefix}binding_ip_"
        managed_binding_mac_prefix = f"{managed_prefix}binding_mac_"
        legacy_binding_prefix = f"{managed_prefix}binding_"
        now = datetime.now().isoformat()

        existing_profiles_by_id: dict[str, dict[str, Any]] = {}
        for profile in profiles_list:
            if isinstance(profile, dict):
                profile_id = str(profile.get("id") or "")
                if profile_id:
                    existing_profiles_by_id[profile_id] = profile

        existing_bindings: list[dict[str, Any]] = [
            binding for binding in bindings_list if isinstance(binding, dict)
        ]
        existing_bindings_by_id: dict[str, dict[str, Any]] = {}
        for binding in existing_bindings:
            binding_id = str(binding.get("id") or "")
            if binding_id:
                existing_bindings_by_id[binding_id] = binding

        def _find_existing_binding(
            binding_id: str,
            *,
            profile_id: str,
            binding_type: str,
            value: str,
            legacy_id: str | None = None,
        ) -> dict[str, Any] | None:
            if binding_id in existing_bindings_by_id:
                return existing_bindings_by_id[binding_id]
            if legacy_id and legacy_id in existing_bindings_by_id:
                return existing_bindings_by_id[legacy_id]
            for candidate in existing_bindings:
                if candidate.get("profile_id") != profile_id:
                    continue
                if str(candidate.get("binding_type") or "").lower() != binding_type:
                    continue
                if str(candidate.get("value") or "").strip() != value:
                    continue
                return candidate
            return None

        desired_profiles: dict[str, dict[str, Any]] = {}
        desired_bindings: dict[str, dict[str, Any]] = {}

        for device in devices:
            if not device.get("enabled", True):
                continue

            device_id = device.get("id", "")
            device_ip = device.get("ip", "")
            device_mac = sanitize_mac(device.get("mac"))
            device_name = device.get("name", f"Device {device_id}")
            blocked_services = [
                s.strip().lower()
                for s in (device.get("blocked_services", []) or [])
                if isinstance(s, str) and s.strip()
            ]
            bypass_mode = str(device.get("bypass_mode") or "warn").strip().lower()
            if bypass_mode not in {"warn", "quarantine", "log_only"}:
                bypass_mode = "warn"
            custom_blocked = device.get("custom_blocked_domains", []) or []
            custom_allowed = device.get("custom_allowed_domains", []) or []
            safesearch = device.get("safesearch", False)
            parental_enabled = device.get("parental", False)
            safebrowsing_enabled = device.get("safebrowsing", False)
            shield_profile = str(device.get("shield_profile") or "").strip().lower()

            if not device_id or not (device_mac or device_ip):
                continue

            # "pornography" quick-add is treated as a parental shortcut.
            # Keep behavior consistent even for legacy clients/config files.
            if "pornography" in blocked_services:
                parental_enabled = True
                blocked_services = [s for s in blocked_services if s != "pornography"]

            blacklist: list[str] = []

            # Build the exact service set selected for this device. The
            # parental toggle is the UI shortcut for pornography only.
            effective_services = list(blocked_services or [])
            adult_requested = parental_enabled or any(
                service in {"pornography", "adult", "strict_parental"}
                for service in effective_services
            )
            # Keep explicit pornography rules to guarantee the feed and
            # heuristic marker for both current and legacy adult policies.
            if adult_requested and "pornography" not in effective_services:
                effective_services.append("pornography")

            if effective_services:
                # Use service_domains module to get all domains for services/categories.
                blacklist = get_all_domains_for_services(effective_services)
            # Safety net: keep adult heuristic marker for every adult-enabled profile.
            if adult_requested and ADULT_HEURISTIC_MARKER not in blacklist:
                blacklist.append(ADULT_HEURISTIC_MARKER)

            # Merge per-device custom domains (from client config)
            if custom_blocked:
                for domain in custom_blocked:
                    d = sanitize_domain(domain)
                    if d and d != "unknown":
                        blacklist.append(d)

            whitelist: list[str] = []
            if custom_allowed:
                for domain in custom_allowed:
                    d = sanitize_domain(domain)
                    if d and d != "unknown":
                        whitelist.append(d)

            # De-duplicate and resolve allow > block
            if blacklist:
                blacklist = sorted(set(blacklist))
            if whitelist:
                whitelist = sorted(set(whitelist))
            if whitelist and blacklist:
                blacklist = [d for d in blacklist if d not in whitelist]

            profile_id = f"{managed_prefix}{device_id}"

            # Pornography is enforced by the explicit profile blacklist.
            # Do not use STRICT here: it also enables unrelated gambling
            # and social categories. Safe Browsing remains independently
            # responsible for malware/phishing categories.
            enabled_blocklists: list[str] = []
            if shield_profile == "balanced":
                filter_level = "standard"
            elif shield_profile == "minimal":
                filter_level = "minimal"
            elif shield_profile == "strict":
                filter_level = "custom"
                enabled_blocklists = [
                    "ads",
                    "trackers",
                    "telemetry",
                    "malware",
                    "phishing",
                    "adult",
                ]
            elif shield_profile == "kids":
                filter_level = "strict"
                safesearch = True
            elif parental_enabled:
                filter_level = "custom"
                if safebrowsing_enabled:
                    enabled_blocklists = ["malware", "phishing"]
            elif safebrowsing_enabled:
                filter_level = "minimal"
            else:
                filter_level = "none"

            profile_entry = {
                "id": profile_id,
                "name": (
                    f"Parental: {device_name}"
                    if parental_enabled
                    else f"Device policy: {device_name}"
                ),
                "description": (
                    f"Auto-managed parental profile for {device_name}"
                    if parental_enabled
                    else f"Auto-managed protection profile for {device_name}"
                ),
                "filter_level": filter_level,
                "enabled_blocklists": enabled_blocklists,
                "whitelist": whitelist,
                "blacklist": blacklist,
                "safe_search": safesearch,
                "parental_enabled": bool(parental_enabled),
                "bypass_mode": bypass_mode,
                "schedule_enabled": False,
                "schedule": {},
                "log_queries": True,
                "is_default": False,
                "device_count": 1,
                "enabled": True,
                "created_at": now,
                "updated_at": now,
            }

            existing_profile = existing_profiles_by_id.get(profile_id, {})
            profile_entry["created_at"] = existing_profile.get("created_at", now)
            profile_entry["device_count"] = existing_profile.get("device_count", 1)
            desired_profiles[profile_id] = profile_entry

            # Admission requires the durable MAC and current network address to
            # match the same managed identity. Persist both whenever available.
            if device_mac:
                mac_binding_id = f"{managed_binding_mac_prefix}{device_id}"
                mac_binding_entry = {
                    "id": mac_binding_id,
                    "profile_id": profile_id,
                    "binding_type": "mac",
                    "value": device_mac,
                    "name": device_name,
                    "enabled": True,
                    "trusted": False,
                    "last_seen": None,
                    "query_count": 0,
                    "blocked_count": 0,
                    "created_at": now,
                    "updated_at": now,
                }
                existing_mac_binding = _find_existing_binding(
                    mac_binding_id,
                    profile_id=profile_id,
                    binding_type="mac",
                    value=device_mac,
                )
                if existing_mac_binding:
                    mac_binding_entry["created_at"] = existing_mac_binding.get(
                        "created_at", now
                    )
                    mac_binding_entry["query_count"] = existing_mac_binding.get(
                        "query_count", 0
                    )
                    mac_binding_entry["blocked_count"] = existing_mac_binding.get(
                        "blocked_count", 0
                    )
                    mac_binding_entry["last_seen"] = existing_mac_binding.get(
                        "last_seen"
                    )
                    mac_binding_entry["trusted"] = bool(
                        existing_mac_binding.get("trusted", False)
                    )
                desired_bindings[mac_binding_id] = mac_binding_entry
            if device_ip:
                ip_binding_id = f"{managed_binding_ip_prefix}{device_id}"
                legacy_binding_id = f"{legacy_binding_prefix}{device_id}"
                ip_binding_entry = {
                    "id": ip_binding_id,
                    "profile_id": profile_id,
                    "binding_type": "ip",
                    "value": device_ip,
                    "name": device_name,
                    "enabled": True,
                    "trusted": False,
                    "last_seen": None,
                    "query_count": 0,
                    "blocked_count": 0,
                    "created_at": now,
                    "updated_at": now,
                }
                existing_ip_binding = _find_existing_binding(
                    ip_binding_id,
                    profile_id=profile_id,
                    binding_type="ip",
                    value=device_ip,
                    legacy_id=legacy_binding_id,
                )
                if existing_ip_binding:
                    ip_binding_entry["created_at"] = existing_ip_binding.get(
                        "created_at", now
                    )
                    ip_binding_entry["query_count"] = existing_ip_binding.get(
                        "query_count", 0
                    )
                    ip_binding_entry["blocked_count"] = existing_ip_binding.get(
                        "blocked_count", 0
                    )
                    ip_binding_entry["last_seen"] = existing_ip_binding.get("last_seen")
                    ip_binding_entry["trusted"] = bool(
                        existing_ip_binding.get("trusted", False)
                    )
                desired_bindings[ip_binding_id] = ip_binding_entry

        # Rebuild profiles list: keep user-managed profiles untouched, replace managed set.
        unmanaged_profiles = []
        for profile in profiles_list:
            profile_id = str((profile or {}).get("id") or "")
            if profile_id.startswith(managed_prefix):
                continue
            unmanaged_profiles.append(profile)
        managed_profiles_sorted = [
            desired_profiles[profile_id]
            for profile_id in sorted(desired_profiles.keys())
        ]
        profiles_list = unmanaged_profiles + managed_profiles_sorted

        # Rebuild bindings: keep non-managed bindings untouched, replace managed set.
        unmanaged_bindings = []
        for binding in bindings_list:
            binding_id = str((binding or {}).get("id") or "")
            profile_id = str((binding or {}).get("profile_id") or "")
            is_managed = (
                binding_id.startswith(managed_binding_ip_prefix)
                or binding_id.startswith(managed_binding_mac_prefix)
                or binding_id.startswith(legacy_binding_prefix)
                or profile_id.startswith(managed_prefix)
            )
            if is_managed:
                continue
            unmanaged_bindings.append(binding)

        managed_bindings_sorted = [
            desired_bindings[binding_id]
            for binding_id in sorted(desired_bindings.keys())
        ]
        bindings_list = unmanaged_bindings + managed_bindings_sorted

        return (
            profiles_path,
            bindings_path,
            profiles_data,
            bindings_data,
            profiles_list,
            bindings_list,
        )

    async def _publish_parental_policy(
        self,
        *,
        devices: list[dict[str, Any]],
        profiles_path: Path,
        bindings_path: Path,
        profiles_data: dict[str, Any],
        bindings_data: dict[str, Any],
        profiles_list: list,
        bindings_list: list,
        sync_warnings: list[str],
    ) -> None:
        # Save updated profiles and bindings
        profiles_data["profiles"] = profiles_list
        profiles_data["updated_at"] = datetime.now().isoformat()
        profiles_path.write_text(json.dumps(profiles_data, indent=2))

        bindings_data["bindings"] = bindings_list
        bindings_data["updated_at"] = datetime.now().isoformat()
        bindings_path.write_text(json.dumps(bindings_data, indent=2))

        # Save devices.json for VPN/Tor blocker and app blocker
        devices_path = self.data_dir / "devices.json"
        devices_path.write_text(json.dumps(devices, indent=2))
        logger.info(f"Saved {len(devices)} devices to devices.json")

        total_blocked = sum(
            len(d.get("blocked_services", []))
            for d in devices
            if d.get("parental") and d.get("enabled", True)
        )
        logger.info(
            f"Synced {len(devices)} device profiles with {total_blocked} blocked services"
        )

        # Trigger VPN/Tor port blocking sync via runner script
        try:
            import subprocess

            runner_path = EASYPI_ROOT / "scripts" / "runner"
            result = await asyncio.to_thread(
                subprocess.run,
                [
                    "sudo",
                    "-n",
                    str(runner_path),
                    "settings/setup_vpn_blocking.sh",
                    "sync",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                logger.info(f"VPN/Tor blocking synced: {result.stdout.strip()}")
            else:
                err_msg = _short_err(result.stderr or result.stdout)
                if not err_msg:
                    err_msg = "unknown error"
                sync_warnings.append(f"VPN blocking sync failed: {err_msg}")
                logger.warning(f"VPN blocking sync failed: {err_msg}")
        except Exception as vpn_err:
            sync_warnings.append(f"VPN blocking sync error: {vpn_err}")
            logger.warning(f"Failed to sync VPN blocking: {vpn_err}")

        # Trigger app blocking sync via runner script
        try:
            import subprocess

            runner_path = EASYPI_ROOT / "scripts" / "runner"
            result = await asyncio.to_thread(
                subprocess.run,
                [
                    "sudo",
                    "-n",
                    str(runner_path),
                    "settings/setup_app_blocking.sh",
                    "sync",
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                logger.info(f"App blocking synced: {result.stdout.strip()}")
            else:
                err_msg = _short_err(result.stderr or result.stdout)
                if not err_msg:
                    err_msg = "unknown error"
                sync_warnings.append(f"App blocking sync failed: {err_msg}")
                logger.warning(f"App blocking sync failed: {err_msg}")
        except Exception as app_err:
            sync_warnings.append(f"App blocking sync error: {app_err}")
            logger.warning(f"Failed to sync app blocking: {app_err}")

        # ProfileManager consumes this signal during DNS lookups (within two
        # seconds). Restarting the resolver on every save made the API wait
        # for systemd and briefly interrupted DNS, so restart only when the
        # live-reload signal itself cannot be created.
        if _legacy_runtime().trigger_profiles_reload(str(self.data_dir)):
            logger.info("Profile reload signal sent to NetProtection")
        else:
            sync_warnings.append(
                "Profile reload signal failed; NetProtection was restarted"
            )
            logger.warning("Profile reload signal failed; restarting NetProtection")
            await self._reload_netprotection()

    async def _reload_netprotection(self) -> None:
        """Restart NetProtection when a live reload is unavailable."""
        try:
            # restart is more reliable than reload (SIGHUP not fully implemented)
            proc = await asyncio.create_subprocess_exec(
                "sudo",
                "systemctl",
                "restart",
                "easypi-netprotection",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode == 0:
                logger.info("NetProtection restarted to apply profile changes")
            else:
                logger.warning(f"Failed to restart NetProtection: {stderr.decode()}")
        except Exception as e:
            logger.debug(f"Could not restart NetProtection: {e}")

    async def get_blocked_services_list(self) -> List[str]:
        """
        Get list of available services and categories that can be blocked.
        Returns combined list of individual services and category names.
        """
        try:
            services = get_catalog_services()
            # Include IP-only app blockers so UI/clients can save them
            services.extend(
                service
                for service in IP_BLOCK_SERVICES
                if service not in IP_BLOCK_CATALOG_EXCLUSIONS
            )
            categories = get_catalog_categories()
            return sorted(set(services + categories))
        except Exception as e:
            logger.error(f"Error getting blocked services list: {e}")
            return []

    async def get_clients(self) -> Dict[str, Any]:
        """Get list of configured clients/devices with parental controls."""
        clients_path = self.data_dir / "clients.json"

        if clients_path.exists():
            try:
                data = json.loads(clients_path.read_text())
                return data
            except Exception as e:
                logger.error(f"Error reading clients: {e}")

        return {"clients": []}

    async def _run_parental_policy_transaction(
        self, mutation: Callable[[], Awaitable[Dict[str, Any]]]
    ) -> Dict[str, Any]:
        """Rollback disk and runtime policy if a parental update cannot publish."""
        active_policy_paths = [
            self.data_dir / name
            for name in ("clients.json", "devices.json", "profiles.json", "bindings.json")
        ]
        backup_policy_paths = [
            self.data_dir / name for name in ("profiles.bak", "bindings.bak")
        ]
        policy_paths = active_policy_paths + backup_policy_paths
        snapshots = _capture_policy_files(policy_paths)

        try:
            result = await mutation()
            failures: list[str] = []
            for key, label in (("sync", "DNS/firewall"), ("ip_blocking", "IP blocking")):
                status = result.get(key) or {}
                if not status.get("ok", False):
                    details = "; ".join(
                        str(item) for item in status.get("warnings", []) if item
                    )
                    failures.append(f"{label}: {details or 'publication failed'}")
            if failures:
                raise RuntimeError("; ".join(failures))
            return result
        except Exception as original_error:
            changed = False
            for path, snapshot in snapshots.items():
                if not _policy_file_matches(path, snapshot):
                    changed = True
                    break
            if not changed:
                raise

            rollback_errors: list[str] = []
            for path, snapshot in snapshots.items():
                try:
                    _restore_policy_file(path, snapshot)
                except OSError as exc:
                    rollback_errors.append(f"{path.name}: {exc}")

            restored_clients: list[dict[str, Any]] = []
            clients_snapshot = snapshots.get(self.data_dir / "clients.json")
            if clients_snapshot:
                try:
                    restored = json.loads(clients_snapshot.content.decode("utf-8"))
                    restored_clients = [
                        item
                        for item in restored.get("clients", [])
                        if isinstance(item, dict)
                    ]
                except (UnicodeDecodeError, ValueError, TypeError):
                    rollback_errors.append("clients.json snapshot is invalid")

            rollback_sync = await self._sync_blocklist()
            if not rollback_sync.get("ok", False):
                rollback_errors.append("DNS/firewall policy")
            rollback_ip = await self._sync_ip_blocking(restored_clients)
            if not rollback_ip.get("ok", False):
                rollback_errors.append("IP blocking policy")

            # Publication updates timestamps and may rotate .bak files. Restore
            # the exact pre-transaction files after requesting the runtime
            # re-sync, so a failed mutation leaves no stale state on disk.
            for path, snapshot in snapshots.items():
                try:
                    _restore_policy_file(path, snapshot)
                except OSError as exc:
                    rollback_errors.append(f"final {path.name}: {exc}")
            if rollback_errors:
                raise RuntimeError(
                    "Parental policy update failed and rollback was incomplete: "
                    + "; ".join(rollback_errors)
                ) from original_error
            raise

    async def add_parental_client_transactional(
        self, client_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        async with self._client_policy_lock:
            return await self._run_parental_policy_transaction(
                lambda: self._add_client_unlocked(client_data)
            )

    async def update_parental_client_transactional(
        self, client_name: str, client_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        async with self._client_policy_lock:
            return await self._run_parental_policy_transaction(
                lambda: self._update_client_unlocked(client_name, client_data)
            )

    async def add_client(self, client_data: Dict[str, Any]) -> Dict[str, Any]:
        async with self._client_policy_lock:
            return await self._add_client_unlocked(client_data)

    async def _add_client_unlocked(
        self, client_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Add a new client with parental control settings."""
        clients_path = self.data_dir / "clients.json"
        client_data = dict(client_data or {})
        client_data.pop("whatsapp_ip_learn", None)
        client_data.setdefault("parental_managed", False)

        # Load existing clients
        if clients_path.exists():
            try:
                data = json.loads(clients_path.read_text())
            except Exception:
                data = {"clients": []}
        else:
            data = {"clients": []}

        clients = data.get("clients", [])

        # Check if client already exists
        name = client_data.get("name", "")
        if any(c.get("name") == name for c in clients):
            raise ValueError(f"Client '{name}' already exists")

        # Ensure stable ID and normalized MAC are stored with the client.
        client_data["id"] = self._normalize_client_id(client_data.get("id"))
        raw_mac = client_data.get("mac")
        normalized_mac = sanitize_mac(raw_mac)
        if not normalized_mac:
            normalized_mac = self._resolve_mac_from_arp(
                self._first_client_ip(client_data)
            )
        if raw_mac and not normalized_mac:
            logger.warning(f"Ignoring invalid client MAC: {raw_mac}")
        if not normalized_mac:
            raise ValueError("Select a discovered device with a valid MAC address")
        if any(sanitize_mac(c.get("mac")) == normalized_mac for c in clients):
            raise ValueError("This device is already managed")
        client_data["mac"] = normalized_mac

        # Keep legacy "ip" and modern "ids" in sync for compatibility.
        client_ip = self._first_client_ip(client_data)
        if client_ip:
            client_data["ip"] = client_ip
            ids = client_data.get("ids")
            if not isinstance(ids, list) or not ids:
                client_data["ids"] = [client_ip]

        # Add timestamp
        client_data["created_at"] = datetime.now(timezone.utc).isoformat()
        client_data["updated_at"] = datetime.now(timezone.utc).isoformat()

        clients.append(client_data)
        data["clients"] = clients
        data["updated_at"] = datetime.now(timezone.utc).isoformat()

        # Save atomically
        tmp_path = clients_path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(data, indent=2))
        tmp_path.replace(clients_path)

        # Sync with profiles
        sync_result = await self._sync_blocklist()

        # Sync IP-based app blocking
        ip_blocking_result = await self._sync_ip_blocking(clients)

        logger.info(f"Added client: {name}")
        return {
            "success": True,
            "client": client_data,
            "sync": sync_result,
            "ip_blocking": ip_blocking_result,
        }

    @staticmethod
    def managed_client_record(
        name: str, ip: str, mac: str, access_profile: str
    ) -> Dict[str, Any]:
        """Return the initial policy for an administrator-approved device."""
        kids = access_profile == "kids"
        return {
            "name": name,
            "ip": ip,
            "ids": [ip],
            "mac": mac,
            "shield_profile": access_profile,
            "parental_managed": kids,
            "parental_enabled": kids,
            "safesearch_enabled": kids,
            "safebrowsing_enabled": True,
            "filtering_enabled": True,
            "use_global_settings": False,
            "blocked_services": [],
            "custom_blocked_domains": [],
            "custom_allowed_domains": [],
            "bypass_mode": "warn",
        }

    async def approve_client_transactional(
        self,
        client_data: Dict[str, Any],
        *,
        require_existing: bool = False,
        release_persistent_block: bool = False,
        existing_client_id: str | None = None,
    ) -> Dict[str, Any]:
        """Publish or update a managed identity under a durable deny hold.

        Unknown-device approval is a security boundary: the API must not report
        success merely because ``clients.json`` was written. The complete
        MAC+IP profile and the firewall admission chain must be active first.
        A root-owned transaction hold remains active across failures/restarts
        and is released only as the final successful operation.
        """
        active_policy_paths = [
            self.data_dir / name
            for name in ("clients.json", "devices.json", "profiles.json", "bindings.json")
        ]
        backup_policy_paths = [
            self.data_dir / name for name in ("profiles.bak", "bindings.bak")
        ]
        policy_paths = active_policy_paths + backup_policy_paths
        client_data = dict(client_data or {})
        # This marker is generated only after the backend has loaded the IP and
        # MAC from its own admission record. It prevents stale ARP data from
        # undoing the identity update during policy publication.
        client_data["ip_observed_timestamp"] = time.time()
        async with self._client_policy_lock:
            client_ip = self._first_client_ip(client_data)
            client_mac = sanitize_mac(client_data.get("mac"))
            if not client_ip or not client_mac:
                raise ValueError("A server-observed MAC and IPv4 address are required")
            snapshots = _capture_policy_files(policy_paths)
            parsed_snapshots: dict[str, Any] = {}
            previous_hold: tuple[str, str] | None = None
            previous_block_added = False
            for path in active_policy_paths:
                snapshot = snapshots[path]
                if snapshot is not None:
                    try:
                        parsed = json.loads(snapshot.content.decode("utf-8"))
                    except (UnicodeDecodeError, ValueError, TypeError) as exc:
                        raise RuntimeError(
                            f"Refusing to overwrite invalid policy file: {path.name}"
                        ) from exc
                    expected_type = list if path.name == "devices.json" else dict
                    if not isinstance(parsed, expected_type):
                        raise RuntimeError(
                            f"Refusing to overwrite invalid policy file: {path.name}"
                        )
                    parsed_snapshots[path.name] = parsed

            if _is_mobile_tunnel_ip(client_ip):
                known = parsed_snapshots.get("clients.json", {}).get("clients", [])
                owner_id = str(existing_client_id or "").strip().lower()
                if isinstance(known, list) and any(
                    isinstance(item, dict)
                    and self._first_client_ip(item) == client_ip
                    and sanitize_mac(item.get("mac")) != client_mac
                    and str(item.get("id") or "").strip().lower() != owner_id
                    for item in known
                ):
                    # A home-tunnel address is the routed identity of exactly
                    # one enrolled phone. A second record for it would make
                    # admission and per-device profile lookup ambiguous.
                    raise ValueError(
                        "This mobile tunnel address already belongs to another managed device"
                    )

            hold_result = await self._run_vpn_blocking_action(
                "hold-admission", client_ip, client_mac, timeout=30
            )
            if not hold_result.get("success"):
                raise RuntimeError(
                    "Could not establish the fail-closed admission hold"
                )

            try:
                clients_payload = parsed_snapshots.get("clients.json", {"clients": []})
                clients = clients_payload.get("clients", [])
                if not isinstance(clients, list):
                    raise RuntimeError("Refusing to overwrite invalid policy file: clients.json")
                if existing_client_id is not None:
                    target_id = str(existing_client_id).strip().lower()
                    if (
                        not target_id
                        or len(target_id) > 64
                        or any(
                            char not in "abcdefghijklmnopqrstuvwxyz0123456789_-"
                            for char in target_id
                        )
                    ):
                        raise ValueError("Managed device identity is invalid")
                    matching_clients = [
                        item
                        for item in clients
                        if isinstance(item, dict)
                        and str(item.get("id") or "").strip().lower() == target_id
                    ]
                else:
                    matching_clients = [
                        item
                        for item in clients
                        if isinstance(item, dict)
                        and sanitize_mac(item.get("mac")) == client_mac
                    ]
                if len(matching_clients) > 1:
                    raise RuntimeError("Managed device identity is ambiguous")
                existing = matching_clients[0] if matching_clients else None
                if (require_existing or existing_client_id is not None) and existing is None:
                    raise ValueError("Managed device no longer exists")
                if existing_client_id is not None and any(
                    isinstance(item, dict)
                    and item is not existing
                    and sanitize_mac(item.get("mac")) == client_mac
                    for item in clients
                ):
                    raise ValueError("The new MAC address is already managed")
                requested_name = str(client_data.get("name") or "").strip()
                if any(
                    isinstance(item, dict)
                    and item is not existing
                    and str(item.get("name") or "") == requested_name
                    for item in clients
                ):
                    raise ValueError(f"Client '{requested_name}' already exists")

                if existing is not None:
                    # Re-admission after a DHCP change is an identity/profile
                    # update, not a reset. Creation defaults in the API payload
                    # must never erase the device's individual restrictions.
                    merged = dict(existing)
                    for field in (
                        "name",
                        "ip",
                        "ids",
                        "mac",
                        "shield_profile",
                        "ip_observed_timestamp",
                    ):
                        if field in client_data:
                            merged[field] = client_data[field]
                    merged["id"] = existing.get("id")
                    previous_mac = sanitize_mac(existing.get("mac"))
                    previous_ip = self._first_client_ip(existing)
                    if existing_client_id is not None and previous_mac != client_mac:
                        if not previous_mac or not self._is_valid_ipv4(previous_ip):
                            raise ValueError(
                                "Managed device has no valid current network identity"
                            )
                        old_hold = await self._run_vpn_blocking_action(
                            "hold-admission", previous_ip, previous_mac, timeout=30
                        )
                        if not old_hold.get("success"):
                            raise RuntimeError(
                                "Could not secure the previous MAC during identity migration"
                            )
                        previous_hold = (previous_ip, previous_mac)
                        history = [
                            dict(item)
                            for item in existing.get("mac_history", [])
                            if isinstance(item, dict) and sanitize_mac(item.get("mac"))
                        ] if isinstance(existing.get("mac_history"), list) else []
                        now_iso = datetime.now(timezone.utc).isoformat()
                        history = [
                            item
                            for item in history
                            if sanitize_mac(item.get("mac")) != previous_mac
                        ]
                        history.append(
                            {
                                "mac": previous_mac,
                                "status": "retired",
                                "retired_at": now_iso,
                            }
                        )
                        merged["mac_history"] = history[-16:]
                    result = await self._update_client_unlocked(
                        str(existing.get("name") or ""),
                        merged,
                        observed_ip=client_ip,
                    )
                    result["updated_existing"] = True
                else:
                    result = await self._add_client_unlocked(client_data)
                    result["updated_existing"] = False
                sync = result.get("sync") or {}
                if not sync.get("ok", False):
                    warnings = sync.get("warnings") or ["firewall policy was not activated"]
                    raise RuntimeError("; ".join(str(item) for item in warnings))
                if release_persistent_block:
                    unblock_result = await self._run_vpn_blocking_action(
                        "unblock-admission", client_ip, client_mac, timeout=30
                    )
                    if not unblock_result.get("success"):
                        raise RuntimeError(
                            "Policy was prepared but the persistent device block remains active"
                        )
                if previous_hold is not None:
                    previous_ip, previous_mac = previous_hold
                    blocked_old = await self._run_vpn_blocking_action(
                        "block-admission", previous_ip, previous_mac, timeout=30
                    )
                    if not blocked_old.get("success"):
                        raise RuntimeError(
                            "Could not retire the previous MAC safely"
                        )
                    previous_block_added = True
                if previous_hold is not None:
                    previous_ip, previous_mac = previous_hold
                    released_old = await self._run_vpn_blocking_action(
                        "release-admission", previous_ip, previous_mac, timeout=30
                    )
                    if not released_old.get("success"):
                        raise RuntimeError(
                            "The previous MAC hold could not be finalized"
                        )
                release_result = await self._run_vpn_blocking_action(
                    "release-admission", client_ip, client_mac, timeout=30
                )
                if not release_result.get("success"):
                    raise RuntimeError(
                        "Policy was prepared but the fail-closed admission hold remains active"
                    )
                return result
            except Exception as original_error:
                rollback_errors: list[str] = []
                policy_changed = any(
                    not _policy_file_matches(path, snapshot)
                    for path, snapshot in snapshots.items()
                )
                if policy_changed:
                    for path, snapshot in snapshots.items():
                        try:
                            _restore_policy_file(path, snapshot)
                        except OSError as rollback_error:
                            rollback_errors.append(f"{path.name}: {rollback_error}")

                    restored_clients = parsed_snapshots.get("clients.json", {}).get(
                        "clients", []
                    )
                    if not isinstance(restored_clients, list):
                        restored_clients = []
                    rollback_sync = await self._sync_blocklist()
                    if not rollback_sync.get("ok", False):
                        rollback_errors.append("DNS/firewall policy")
                        logger.critical(
                            "Managed-device approval rolled back on disk; firewall re-sync failed"
                        )
                    rollback_ip = await self._sync_ip_blocking(restored_clients)
                    if not rollback_ip.get("ok", False):
                        rollback_errors.append("IP blocking policy")

                    # The rollback publication can refresh timestamps and rotate
                    # a backup. Restore exact pre-transaction files after asking
                    # the runtime to load the restored policy.
                    for path, snapshot in snapshots.items():
                        try:
                            _restore_policy_file(path, snapshot)
                        except OSError as rollback_error:
                            rollback_errors.append(f"final {path.name}: {rollback_error}")
                if previous_hold is not None:
                    previous_ip, previous_mac = previous_hold
                    if previous_block_added:
                        unblocked_old = await self._run_vpn_blocking_action(
                            "unblock-admission", previous_ip, previous_mac, timeout=30
                        )
                        if not unblocked_old.get("success"):
                            rollback_errors.append("previous MAC block")
                    released_old = await self._run_vpn_blocking_action(
                        "release-admission", previous_ip, previous_mac, timeout=30
                    )
                    if not released_old.get("success"):
                        rollback_errors.append("previous MAC hold")
                if rollback_errors:
                    raise RuntimeError(
                        "Managed-device approval failed and policy rollback was incomplete: "
                        + "; ".join(rollback_errors)
                    ) from original_error
                raise

    async def update_client(
        self, client_name: str, client_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        async with self._client_policy_lock:
            return await self._update_client_unlocked(client_name, client_data)

    async def _update_client_unlocked(
        self,
        client_name: str,
        client_data: Dict[str, Any],
        *,
        observed_ip: str | None = None,
    ) -> Dict[str, Any]:
        """Update an existing client."""
        clients_path = self.data_dir / "clients.json"
        client_data = dict(client_data or {})
        client_data.pop("whatsapp_ip_learn", None)

        if not clients_path.exists():
            raise ValueError(f"Client '{client_name}' not found")

        try:
            data = json.loads(clients_path.read_text())
        except Exception:
            raise ValueError(f"Client '{client_name}' not found")

        clients = data.get("clients", [])
        found = False

        for i, c in enumerate(clients):
            if c.get("name") == client_name:
                # Preserve created_at
                created_at = c.get("created_at", datetime.now(timezone.utc).isoformat())
                client_data["created_at"] = created_at
                client_data["updated_at"] = datetime.now(timezone.utc).isoformat()
                if "parental_managed" not in client_data and "parental_managed" in c:
                    client_data["parental_managed"] = c["parental_managed"]

                # Preserve/generate stable ID
                client_data["id"] = self._normalize_client_id(
                    client_data.get("id") or c.get("id")
                )

                # Preserve/normalize MAC
                incoming_mac = client_data.get("mac", c.get("mac"))
                normalized_mac = sanitize_mac(incoming_mac)
                if incoming_mac and not normalized_mac:
                    logger.warning(
                        f"Ignoring invalid client MAC during update: {incoming_mac}"
                    )
                    normalized_mac = sanitize_mac(c.get("mac"))
                if not normalized_mac:
                    normalized_mac = self._resolve_mac_from_arp(
                        self._first_client_ip(client_data) or self._first_client_ip(c)
                    )
                if not normalized_mac:
                    raise ValueError(
                        "Select a discovered device with a valid MAC address"
                    )
                if any(
                    index != i and sanitize_mac(other.get("mac")) == normalized_mac
                    for index, other in enumerate(clients)
                ):
                    raise ValueError("This device is already managed")
                client_data["mac"] = normalized_mac

                # IP is a current display snapshot, never the durable identity.
                existing_ip = self._first_client_ip(c)
                client_ip = (
                    observed_ip
                    or self._resolve_ipv4_from_mac(normalized_mac)
                    or self._first_client_ip(client_data)
                    or existing_ip
                )
                if client_ip:
                    client_data["ip"] = client_ip
                    client_data["ids"] = [client_ip]

                clients[i] = client_data
                found = True
                break

        if not found:
            raise ValueError(f"Client '{client_name}' not found")

        data["clients"] = clients
        data["updated_at"] = datetime.now(timezone.utc).isoformat()

        # Save atomically
        tmp_path = clients_path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(data, indent=2))
        tmp_path.replace(clients_path)

        # Sync with profiles
        sync_result = await self._sync_blocklist()

        # Sync IP-based app blocking
        ip_blocking_result = await self._sync_ip_blocking(clients)

        logger.info(f"Updated client: {client_name}")
        return {
            "success": True,
            "client": client_data,
            "sync": sync_result,
            "ip_blocking": ip_blocking_result,
        }

    async def set_bypass_mode_by_ip(self, client_ip: str, mode: str) -> Dict[str, Any]:
        """Update anti-bypass response mode for a client (lookup by IP)."""
        ip = str(client_ip or "").strip()
        if not self._is_valid_ipv4(ip):
            raise ValueError("Invalid IPv4 address")

        mode_s = str(mode or "").strip().lower()
        if mode_s not in {"warn", "quarantine", "log_only"}:
            raise ValueError("Invalid bypass_mode")

        clients_path = self.data_dir / "clients.json"
        if not clients_path.exists():
            raise ValueError("clients.json not found")

        try:
            data = json.loads(clients_path.read_text(encoding="utf-8", errors="ignore"))
        except Exception as e:
            raise ValueError(f"Failed to read clients.json: {e}") from e

        clients = data.get("clients", [])
        if not isinstance(clients, list):
            clients = []

        found = False
        observed_mac = self._resolve_mac_from_arp(ip)
        if observed_mac:
            for client in clients:
                if (
                    not isinstance(client, dict)
                    or sanitize_mac(client.get("mac")) != observed_mac
                ):
                    continue
                client["ip"] = ip
                client["ids"] = [ip]
                client["bypass_mode"] = mode_s
                client["updated_at"] = datetime.now(timezone.utc).isoformat()
                found = True
                break

        # Compatibility only for old records that do not yet have a MAC binding.
        if not found and not observed_mac:
            for client in clients:
                if not isinstance(client, dict) or sanitize_mac(client.get("mac")):
                    continue
                ids = client.get("ids") or []
                if not isinstance(ids, list):
                    ids = []
                legacy_ip = str(client.get("ip") or "").strip()
                if ip in [str(x or "").strip() for x in ids] or legacy_ip == ip:
                    client["bypass_mode"] = mode_s
                    client["updated_at"] = datetime.now(timezone.utc).isoformat()
                    found = True
                    break

        if not found:
            raise ValueError("Client not found for IP")

        data["clients"] = clients
        data["updated_at"] = datetime.now(timezone.utc).isoformat()

        tmp_path = clients_path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        tmp_path.replace(clients_path)

        sync_result = await self._sync_blocklist()
        ip_blocking_result = await self._sync_ip_blocking(clients)
        return {
            "success": True,
            "ip": ip,
            "bypass_mode": mode_s,
            "sync": sync_result,
            "ip_blocking": ip_blocking_result,
        }

    async def delete_client(self, client_name: str) -> Dict[str, Any]:
        async with self._client_policy_lock:
            return await self._delete_client_unlocked(client_name)

    async def _delete_client_unlocked(self, client_name: str) -> Dict[str, Any]:
        """Delete a client."""
        clients_path = self.data_dir / "clients.json"

        if not clients_path.exists():
            raise ValueError(f"Client '{client_name}' not found")

        try:
            data = json.loads(clients_path.read_text())
        except Exception:
            raise ValueError(f"Client '{client_name}' not found")

        clients = data.get("clients", [])
        original_count = len(clients)
        clients = [c for c in clients if c.get("name") != client_name]

        if len(clients) == original_count:
            raise ValueError(f"Client '{client_name}' not found")

        data["clients"] = clients
        data["updated_at"] = datetime.now(timezone.utc).isoformat()

        # Save atomically
        tmp_path = clients_path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(data, indent=2))
        tmp_path.replace(clients_path)

        # Sync with profiles
        sync_result = await self._sync_blocklist()

        # Sync IP-based app blocking
        ip_blocking_result = await self._sync_ip_blocking(clients)

        logger.info(f"Deleted client: {client_name}")
        return {
            "success": True,
            "sync": sync_result,
            "ip_blocking": ip_blocking_result,
        }

    async def _sync_ip_blocking(self, clients: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Sync IP-based app blocking rules based on client blocked_services/blocked_apps.

        This handles apps like Telegram, WhatsApp that use hardcoded IPs
        and bypass DNS filtering. Uses iptables/ipset for true IP blocking.
        """
        warnings: list[str] = []

        # Callers reach this method after _sync_blocklist(), which can wait on a
        # service restart. Another request may save newer client settings while
        # they are waiting, so never enforce the pre-restart in-memory snapshot.
        persisted = await self.get_clients()
        persisted_clients = persisted.get("clients", [])
        if isinstance(persisted_clients, list):
            clients = persisted_clients

        # Build map: stable MAC -> current runtime IP + apps.
        client_blocks: Dict[str, Dict[str, Any]] = {}

        for client in clients:
            # Support both 'ip' field and 'ids' array (legacy format)
            client_ip = client.get("ip", "")
            if not client_ip:
                # Try 'ids' array format
                ids = client.get("ids", [])
                if ids and isinstance(ids, list):
                    client_ip = ids[0]  # Use first IP

            blocked_services = client.get("blocked_services", []) or []
            blocked_apps = client.get("blocked_apps", []) or []
            client_mac = sanitize_mac(client.get("mac"))

            if not client_ip or not client_mac:
                continue

            # Collect IP-blockable apps for this client.
            # blocked_apps are explicit app-level rules, blocked_services are UI toggles.
            apps_to_block: list[str] = [
                str(app).strip().lower() for app in blocked_apps if str(app).strip()
            ]
            for service in blocked_services:
                service_key = str(service).strip().lower()
                if service_key in IP_BLOCK_SERVICES:
                    app_name = IP_BLOCK_SERVICES[service_key]
                    if app_name not in apps_to_block:  # Avoid duplicates
                        apps_to_block.append(app_name)

            if apps_to_block:
                client_blocks[client_mac] = {"ip": client_ip, "apps": apps_to_block}

        if not _legacy_runtime().APP_BLOCKER_AVAILABLE:
            msg = "IP app blocking module unavailable (missing in build)"
            logger.warning(msg)
            return {"ok": False, "warnings": [msg]}

        try:
            blocker = _legacy_runtime().AppBlocker()

            # Apply blocking rules per client
            for client_mac, block in client_blocks.items():
                client_ip = str(block["ip"])
                apps = list(block["apps"])
                try:
                    ok = blocker.enable_blocking(client_ip, apps, client_mac)
                    if ok:
                        logger.info(f"Enabled IP blocking for {client_ip}: {apps}")
                    else:
                        warnings.append(
                            f"Failed to apply IP blocking for {client_ip} ({', '.join(apps)})"
                        )
                except Exception as e:
                    warnings.append(
                        f"Failed to apply IP blocking for {client_ip} ({', '.join(apps)}): {e}"
                    )

            # Disable blocking for clients that no longer have IP-blocked services/apps.
            try:
                await self._cleanup_stale_ip_blocks(client_blocks)
            except Exception as e:
                warnings.append(f"Failed to cleanup stale IP blocking rules: {e}")

            logger.info(
                f"IP blocking sync completed: {len(client_blocks)} clients configured"
            )

        except Exception as e:
            warnings.append(f"Error syncing IP blocking: {e}")
            logger.error(f"Error syncing IP blocking: {e}")

        return {"ok": len(warnings) == 0, "warnings": warnings}

    async def _cleanup_stale_ip_blocks(
        self, active_blocks: Dict[str, Dict[str, Any]]
    ) -> None:
        """Remove IP blocking rules for clients that no longer need them."""
        if not _legacy_runtime().APP_BLOCKER_AVAILABLE:
            return

        try:
            blocker = _legacy_runtime().AppBlocker()

            # Load all clients to find IPs that should have blocking disabled
            clients_path = self.data_dir / "clients.json"
            if not clients_path.exists():
                return

            data = json.loads(clients_path.read_text())
            all_clients = data.get("clients", [])

            for client in all_clients:
                # Support both modern "ids" and legacy "ip"
                client_ip = client.get("ip", "")
                if not client_ip:
                    ids = client.get("ids", [])
                    if ids and isinstance(ids, list):
                        client_ip = ids[0]
                if not client_ip:
                    continue
                client_mac = sanitize_mac(client.get("mac"))
                desired = active_blocks.get(client_mac, {}) if client_mac else {}
                desired_apps = set(desired.get("apps", []))
                if not desired_apps:
                    try:
                        blocker.disable_blocking(
                            client_ip, client_mac=client_mac or None
                        )
                        logger.debug(f"Disabled all IP blocking for {client_ip}")
                    except Exception as e:
                        logger.debug(f"Could not disable blocking for {client_ip}: {e}")
                    continue

                # enable_blocking replaces only the requested app chains. Remove
                # chains for toggles that were switched off while other app
                # restrictions remain enabled for this client.
                try:
                    status = blocker.get_blocking_status(client_ip, client_mac)
                    current_apps = status.get("apps", [])
                    if not isinstance(current_apps, list):
                        continue
                    stale_apps = sorted(
                        {
                            str(app).strip().lower()
                            for app in current_apps
                            if str(app).strip()
                        }
                        - desired_apps
                    )
                    if stale_apps:
                        blocker.disable_blocking(client_ip, stale_apps, client_mac)
                        logger.debug(
                            f"Disabled stale IP blocking for {client_ip}: {stale_apps}"
                        )
                except Exception as e:
                    logger.debug(
                        f"Could not remove stale blocking for {client_ip}: {e}"
                    )

        except Exception as e:
            logger.error(f"Error cleaning up stale IP blocks: {e}")

    async def get_user_rules(self) -> List[str]:
        """Get user-defined filtering rules (adblock format)."""
        rules_path = self.data_dir / "user_rules.txt"

        if rules_path.exists():
            try:
                content = rules_path.read_text()
                # Split by newlines, filter empty lines and comments
                rules = [
                    line.strip()
                    for line in content.split("\n")
                    if line.strip() and not line.strip().startswith("#")
                ]
                return rules
            except Exception as e:
                logger.error(f"Error reading user rules: {e}")

        return []

    async def set_user_rules(self, rules: List[str]) -> Dict[str, Any]:
        """Set user-defined filtering rules."""
        rules_path = self.data_dir / "user_rules.txt"

        try:
            # Filter and clean rules
            clean_rules = [r.strip() for r in rules if r.strip()]

            # Write with header
            content = "# EasyPi NetProtection User Rules\n"
            content += f"# Updated: {datetime.now(timezone.utc).isoformat()}\n"
            content += "# Format: Adblock Plus filter syntax\n\n"
            content += "\n".join(clean_rules)

            rules_path.write_text(content)

            logger.info(f"Saved {len(clean_rules)} user rules")
            return {"success": True, "count": len(clean_rules)}
        except Exception as e:
            logger.error(f"Error saving user rules: {e}")
            return {"success": False, "error": str(e)}
