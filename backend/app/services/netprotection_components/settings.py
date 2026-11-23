"""Settings operations for NetProtection."""

import asyncio
import json
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict

from app.services.netprotection_components.runtime_context import logger
from easypi_netprotection.healthcheck import RESOLVER_HEALTHCHECK_DOMAIN


class SettingsMixin:
    """Internal behavior mixed into the stable service facade."""

    def _get_settings_file(self) -> Path:
        """Get path to settings file."""
        return self.data_dir / "settings.json"

    def _load_settings(self) -> Dict[str, Any]:
        """Load settings from file."""
        settings_file = self._get_settings_file()
        default_settings = {
            "unknown_devices": {
                # Unknown identities are quarantined until an administrator creates
                # a complete MAC + IP binding for them.
                "mode": "block",
            },
            "ipv6": {
                "enabled": True,
                "block_ipv6_dns": False,
                "audit_mode": True,
            },
            "fail_safe": {
                "enabled": True,
                "fallback_dns": "1.1.1.1",
                "fallback_dns_secondary": "8.8.8.8",
                "timeout_seconds": 5,
                "auto_recover": True,
                "is_active": False,
                "failure_count": 0,
            },
            "shadow_mode": {
                "enabled": False,
                "duration_hours": None,
                "started_at": None,
                "capture_all": True,
            },
        }

        if not settings_file.exists():
            return default_settings

        try:
            data = json.loads(settings_file.read_text())
            # Security migrations must not preserve the historical permissive
            # behavior. An absent key is indistinguishable from an unreviewed
            # legacy configuration, so migrate it fail closed.
            if "unknown_devices" not in data:
                data["unknown_devices"] = {"mode": "block"}

            # Merge with defaults
            for key in default_settings:
                if key not in data:
                    data[key] = default_settings[key]
                else:
                    for subkey in default_settings[key]:
                        if subkey not in data[key]:
                            data[key][subkey] = default_settings[key][subkey]
            return data
        except Exception as e:
            logger.error(f"Error loading settings: {e}")
            return default_settings

    def _save_settings(self, settings: Dict[str, Any]) -> None:
        """Save settings to file atomically."""
        self.data_dir.mkdir(parents=True, exist_ok=True)
        settings_file = self._get_settings_file()

        # Atomic write: write to temp file then rename
        temp_file = settings_file.with_suffix(".json.tmp")
        try:
            temp_file.write_text(json.dumps(settings, indent=2))
            temp_file.replace(settings_file)  # Atomic on POSIX
        except Exception as e:
            # Clean up temp file on failure
            if temp_file.exists():
                temp_file.unlink()
            raise e

    async def get_all_settings(self) -> Dict[str, Any]:
        """Get all settings."""
        return {"success": True, "data": self._load_settings()}

    async def get_unknown_device_settings(self) -> Dict[str, Any]:
        settings = self._load_settings()
        data = dict(settings.get("unknown_devices", {}))
        # This admission layer prevents accidental/unapproved access. It is not
        # a cryptographic identity boundary: a hostile peer on the same L2 can
        # clone both an approved MAC and IPv4 address. Expose the assurance
        # level so API consumers cannot mistake it for 802.1X or client certs.
        data.update(
            {
                "identity_assurance": "observed_mac_ip_pair",
                "spoof_resistant": False,
                "requires_trusted_lan": True,
            }
        )
        return {"success": True, "data": data}

    async def update_unknown_device_settings(self, mode: str) -> Dict[str, Any]:
        if mode not in {"block", "default"}:
            raise ValueError("Unknown-device mode must be 'block' or 'default'")
        settings = self._load_settings()
        settings["unknown_devices"] = {"mode": mode}
        self._save_settings(settings)
        logger.info("Updated unknown-device policy: %s", mode)
        return {"success": True, "data": settings["unknown_devices"]}

    async def sync_unknown_device_admission_policy(self) -> bool:
        """Apply the matching L3 admission policy through the privileged runner."""
        run_action = getattr(self, "_run_vpn_blocking_action", None)
        if not callable(run_action):
            logger.error("VPN blocking controller is unavailable")
            return False
        result = await run_action("sync", timeout=60)
        if not result.get("success"):
            logger.error(
                "Unknown-device firewall sync failed: %s",
                result.get("stderr") or result.get("error") or "unknown error",
            )
            return False
        return True

    async def block_unknown_device_admission(self, ip: str, mac: str) -> bool:
        """Persist and activate an administrator deny decision by MAC."""
        run_action = getattr(self, "_run_vpn_blocking_action", None)
        if not callable(run_action):
            logger.error("VPN blocking controller is unavailable")
            return False
        result = await run_action("block-admission", ip, mac, timeout=30)
        if not result.get("success"):
            logger.error(
                "Persistent device admission block failed: %s",
                result.get("stderr") or result.get("error") or "unknown error",
            )
            return False
        return True

    async def get_ipv6_settings(self) -> Dict[str, Any]:
        """Get IPv6 settings."""
        settings = self._load_settings()
        return {"success": True, "data": settings.get("ipv6", {})}

    async def update_ipv6_settings(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update IPv6 settings."""
        settings = self._load_settings()
        settings["ipv6"].update(updates)
        self._save_settings(settings)
        logger.info(f"Updated IPv6 settings: {updates}")
        return {"success": True, "data": settings["ipv6"]}

    async def get_ipv6_status(self) -> Dict[str, Any]:
        """
        Report the real IPv6 state of this device (read-only, non-blocking).

        The safest configuration remains disabling IPv6 at the router. When a
        global route does appear, also report whether the short-lived status of
        the root-managed forwarding guard proves that transit is being blocked.
        """
        has_global_ipv6 = False
        try:
            p = Path("/proc/net/if_inet6")
            if p.exists():
                for line in p.read_text(encoding="utf-8", errors="ignore").splitlines():
                    parts = line.split()
                    # columns: address ifindex prefixlen scope flags devname; scope 00 == global
                    if len(parts) >= 4 and parts[3] == "00":
                        if (
                            parts[0] != "00000000000000000000000000000001"
                        ):  # exclude ::1
                            has_global_ipv6 = True
                            break
        except Exception:
            pass
        forwarding = False
        try:
            forwarding = (
                Path("/proc/sys/net/ipv6/conf/all/forwarding").read_text().strip()
                == "1"
            )
        except Exception:
            pass
        guard_status = "unavailable"
        guard_interfaces: list[str] = []
        guard_fresh = False
        try:
            guard_state = json.loads(
                Path(
                    "/var/lib/easypi/security/ipv6_policy_guard.json"
                ).read_text(encoding="utf-8")
            )
            guard_status = str(guard_state.get("status") or "unknown")
            guard_interfaces = str(
                guard_state.get("interfaces") or ""
            ).split()
            checked_at = float(guard_state.get("checked_at") or 0)
            # The timer runs every 15 seconds. A stale status must never be
            # presented as active protection after the service has stopped.
            guard_fresh = 0 <= time.time() - checked_at <= 60
        except (OSError, ValueError, TypeError, json.JSONDecodeError):
            pass
        guard_active = guard_status in {
            "blocked",
            "emergency-blocked",
            "emergency-forwarding-disabled",
        } and guard_fresh
        return {
            "success": True,
            "data": {
                "has_global_ipv6": has_global_ipv6,
                "ipv6_forwarding": forwarding,
                "guard_status": guard_status,
                "guard_active": guard_active,
                "guard_interfaces": guard_interfaces,
                # Protected means either no global path exists or the current,
                # root-managed forwarding guard is actively rejecting bypass.
                "protected": not has_global_ipv6 or guard_active,
            },
        }

    async def get_failsafe_settings(self) -> Dict[str, Any]:
        """Get Fail-Safe settings."""
        settings = self._load_settings()
        return {"success": True, "data": settings.get("fail_safe", {})}

    async def update_failsafe_settings(self, updates: Dict[str, Any]) -> Dict[str, Any]:
        """Update Fail-Safe settings."""
        settings = self._load_settings()
        # Don't allow direct setting of runtime state
        safe_updates = {
            k: v for k, v in updates.items() if k not in ("is_active", "failure_count")
        }
        settings["fail_safe"].update(safe_updates)
        self._save_settings(settings)
        logger.info(f"Updated Fail-Safe settings: {safe_updates}")
        return {"success": True, "data": settings["fail_safe"]}

    async def trigger_failsafe(self, action: str) -> Dict[str, Any]:
        """Manually trigger Fail-Safe activation/deactivation."""
        settings = self._load_settings()

        if action == "activate":
            settings["fail_safe"]["is_active"] = True
            settings["fail_safe"]["activated_at"] = datetime.now(
                timezone.utc
            ).isoformat()
            logger.warning("Fail-Safe mode manually ACTIVATED")
        elif action == "deactivate":
            settings["fail_safe"]["is_active"] = False
            settings["fail_safe"]["activated_at"] = None
            settings["fail_safe"]["failure_count"] = 0
            logger.info("Fail-Safe mode manually deactivated")
        else:
            return {"success": False, "error": f"Invalid action: {action}"}

        self._save_settings(settings)
        return {"success": True, "data": settings["fail_safe"]}

    # ---------------------------------------------------------------- fail-safe
    def _dns_probe(self, server: str, port: int, timeout: float) -> bool:
        """Send one minimal DNS query and return True if any reply is received.

        Runs in a worker thread (blocking socket); never on the event loop.
        Proves the resolver is alive even if it answers SERVFAIL/NXDOMAIN.
        """
        import socket
        import struct
        import random

        try:
            tid = random.randint(0, 0xFFFF)
            header = struct.pack(
                ">HHHHHH", tid, 0x0100, 1, 0, 0, 0
            )  # standard query, RD
            labels = RESOLVER_HEALTHCHECK_DOMAIN.split(".")
            qname = b"".join(bytes([len(p)]) + p.encode() for p in labels) + b"\x00"
            query = header + qname + struct.pack(">HH", 1, 1)  # A / IN
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(timeout)
            try:
                s.sendto(query, (server, port))
                data, _ = s.recvfrom(512)
                return len(data) >= 2 and data[:2] == struct.pack(">H", tid)
            finally:
                s.close()
        except Exception:
            return False

    async def _restart_resolver(self) -> bool:
        """Restart the NetProtection DNS service (allowed via sudoers)."""
        try:
            proc = await asyncio.create_subprocess_exec(
                "sudo",
                "-n",
                "systemctl",
                "restart",
                "easypi-netprotection",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await asyncio.wait_for(proc.communicate(), timeout=30)
            return proc.returncode == 0
        except Exception as e:
            logger.error(f"Fail-safe: failed to restart resolver: {e}")
            return False

    async def _notify_failsafe(self, restarted: bool) -> None:
        """Best-effort alert when the resolver went unresponsive."""
        try:
            from app.services.email_service import (
                broadcast_security_alert,
                AlertType,
                EmailPriority,
            )

            if restarted:
                await broadcast_security_alert(
                    AlertType.SERVICE_RESTORED,
                    title="DNS service auto-recovered",
                    description="NetProtection DNS stopped responding and was automatically restarted by Fail-Safe.",
                    priority=EmailPriority.CRITICAL,
                )
            else:
                await broadcast_security_alert(
                    AlertType.SERVICE_DOWN,
                    title="DNS service failure",
                    description="NetProtection DNS stopped responding and the automatic restart FAILED — manual check needed.",
                    priority=EmailPriority.CRITICAL,
                )
        except Exception as e:
            logger.debug(f"fail-safe notification skipped: {e}")

    async def _failsafe_monitor_loop(self) -> None:
        """Watchdog: detect a HUNG resolver (alive but not answering) and restart it.

        systemd already auto-restarts the resolver on crash (Restart=on-failure);
        this catches the case where it is running but no longer responding to DNS.
        Conservative: requires several consecutive failures and a cooldown between
        restarts so a transient blip never triggers a restart loop.
        """
        import time as _time

        CHECK_INTERVAL = 30
        FAIL_THRESHOLD = 3
        RESTART_COOLDOWN = 120
        consecutive_failures = 0
        last_restart = 0.0
        while True:
            try:
                settings = self._load_settings()
                fs = settings.get("fail_safe", {})
                if not fs.get("enabled", True):
                    consecutive_failures = 0
                    await asyncio.sleep(CHECK_INTERVAL)
                    continue
                timeout = max(1.0, min(float(fs.get("timeout_seconds", 5) or 5), 30.0))
                healthy = await asyncio.to_thread(
                    self._dns_probe, "127.0.0.1", 53, timeout
                )
                if healthy:
                    if (
                        consecutive_failures
                        or fs.get("is_active")
                        or fs.get("failure_count")
                    ):
                        consecutive_failures = 0
                        fs["is_active"] = False
                        fs["failure_count"] = 0
                        self._save_settings(settings)
                else:
                    consecutive_failures += 1
                    fs["failure_count"] = consecutive_failures
                    self._save_settings(settings)
                    logger.warning(
                        f"Fail-safe: resolver health check failed ({consecutive_failures}/{FAIL_THRESHOLD})"
                    )
                    now = _time.monotonic()
                    if (
                        consecutive_failures >= FAIL_THRESHOLD
                        and fs.get("auto_recover", True)
                        and (now - last_restart) > RESTART_COOLDOWN
                    ):
                        last_restart = now
                        fs["is_active"] = True
                        fs["activated_at"] = datetime.now(timezone.utc).isoformat()
                        fs["last_restart_at"] = datetime.now(timezone.utc).isoformat()
                        fs["restart_count"] = int(fs.get("restart_count", 0)) + 1
                        self._save_settings(settings)
                        logger.error(
                            "Fail-safe: resolver unresponsive — restarting easypi-netprotection"
                        )
                        ok = await self._restart_resolver()
                        asyncio.create_task(self._notify_failsafe(ok))
                        consecutive_failures = 0
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"Fail-safe monitor error: {e}")
            await asyncio.sleep(CHECK_INTERVAL)

    async def get_shadow_mode_settings(self) -> Dict[str, Any]:
        """Get Shadow Mode settings."""
        settings = self._load_settings()
        shadow = settings.get("shadow_mode", {})

        # Check for auto-expire
        if (
            shadow.get("enabled")
            and shadow.get("duration_hours")
            and shadow.get("started_at")
        ):
            try:
                started = datetime.fromisoformat(
                    shadow["started_at"].replace("Z", "+00:00")
                )
                expires = started + timedelta(hours=shadow["duration_hours"])
                if datetime.now(timezone.utc) >= expires:
                    shadow["enabled"] = False
                    shadow["started_at"] = None
                    settings["shadow_mode"] = shadow
                    self._save_settings(settings)
                    logger.info("Shadow mode auto-expired")
            except Exception as exc:
                logger.warning("Could not evaluate Shadow Mode expiry: %s", exc)

        return {"success": True, "data": shadow}

    async def update_shadow_mode_settings(
        self, updates: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Update Shadow Mode settings."""
        settings = self._load_settings()
        was_enabled = settings["shadow_mode"].get("enabled", False)

        settings["shadow_mode"].update(updates)

        # Track when enabled
        if not was_enabled and settings["shadow_mode"].get("enabled"):
            settings["shadow_mode"]["started_at"] = datetime.now(
                timezone.utc
            ).isoformat()
            logger.info("Shadow mode ENABLED")
        elif was_enabled and not settings["shadow_mode"].get("enabled"):
            settings["shadow_mode"]["started_at"] = None
            logger.info("Shadow mode disabled")

        self._save_settings(settings)
        return {"success": True, "data": settings["shadow_mode"]}
