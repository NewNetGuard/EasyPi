"""
Proactive Watchdog Monitor.

Turns the dashboard into a "smart watchdog": a background loop periodically checks
system state and, on a state CHANGE (not every tick), records a watchdog event that
surfaces in the notification inbox. Signals:

- disk filling up (root filesystem crosses a warn/critical threshold)
- a critical service went down / recovered
- an unapproved device was passively observed by DHCP/ARP and quarantined
- a protected device is actively bypassing the filter (from the bypass detector)
- IPv6 appeared on the LAN while Stealth is on (traffic could bypass the tunnel)

Events are appended to ``watchdog_events.jsonl`` in the NetProtection data dir and
read back (deduplicated by event_id, latest state wins) by the InboxService.
"""

from __future__ import annotations

import asyncio
import html
import json
import logging
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

WATCHDOG_EVENTS_FILE = "watchdog_events.jsonl"

# Services whose outage the admin must know about immediately. Kept intentionally
# small (only truly critical units) to avoid false alarms on optional services.
CRITICAL_SERVICES: list[tuple[str, str]] = [
    ("easypi-netprotection", "NetProtection DNS filtering"),
    ("nginx", "Web panel (nginx)"),
]

DISK_WARN_PCT = 85.0
DISK_CRIT_PCT = 93.0
MAX_EVENTS = 300
DEVICE_ALERT_LIMIT = 5
DEVICE_ALERT_WINDOW_SECONDS = 60.0


class ProactiveMonitor:
    def __init__(self, data_dir: str | Path | None = None, interval_sec: float = 45.0) -> None:
        if data_dir is None:
            try:
                from app.core.paths import get_netprotection_data_dir
                data_dir = get_netprotection_data_dir()
            except Exception:
                data_dir = "/opt/EasyPi/data/netprotection"
        self._data_dir = Path(data_dir)
        self._events_path = self._data_dir / WATCHDOG_EVENTS_FILE
        self._interval = max(15.0, float(interval_sec))
        self._task: asyncio.Task | None = None
        self._device_task: asyncio.Task | None = None
        self._device_summary_task: asyncio.Task | None = None

        # Alerting state (in-memory). The events file persists across restarts, so
        # the inbox keeps history; re-emitting the same event_id after a restart
        # just refreshes the existing row (dedup keeps the latest).
        self._service_down: set[str] = set()
        self._disk_level: str = "ok"  # ok | warn | crit
        self._bypass_alerted: set[str] = set()
        self._stealth_ipv6_exposed = False
        self._device_alert_times: list[float] = []
        self._suppressed_device_alerts = 0

    # ── lifecycle ────────────────────────────────────────────────────────────
    def start(self) -> None:
        if self._task is None or self._task.done():
            self._task = asyncio.create_task(self._loop())
            self._device_task = asyncio.create_task(self._device_loop())
            logger.info("Proactive watchdog monitor started")

    async def stop(self) -> None:
        """Cancel the watchdog loop without leaving work behind at shutdown."""
        task = self._task
        device_task = self._device_task
        summary_task = self._device_summary_task
        self._task = None
        self._device_task = None
        self._device_summary_task = None
        if task is None and device_task is None and summary_task is None:
            return
        for running in (task, device_task, summary_task):
            if running is not None:
                running.cancel()
        for running in (task, device_task, summary_task):
            if running is None:
                continue
            try:
                await running
            except asyncio.CancelledError:
                pass
        logger.info("Proactive watchdog monitor stopped")

    async def _loop(self) -> None:
        while True:
            try:
                await self.check_once()
            except asyncio.CancelledError:
                break
            except Exception as e:
                logger.warning(f"Proactive monitor error: {e}")
            await asyncio.sleep(self._interval)

    async def _device_loop(self) -> None:
        """Keep admission discovery responsive without polling every subsystem."""
        while True:
            try:
                await self._check_new_devices()
            except asyncio.CancelledError:
                break
            except Exception as exc:
                logger.warning("Unknown-device observer error: %s", exc)
            await asyncio.sleep(3)

    async def check_once(self) -> None:
        await asyncio.gather(
            self._check_disk(),
            self._check_services(),
            self._check_bypass(),
            self._vpn_reconcile(),
            self._stealth_reconcile(),
            self._check_stealth_ipv6(),
            return_exceptions=True,
        )

    async def _check_stealth_ipv6(self) -> None:
        """Warn when the router offers IPv6 while devices rely on Stealth.

        Stealth routes IPv4 through the tunnel and blocks IPv6 that passes
        through EasyPi. A router advertising its own default IPv6 route with
        global addresses lets devices reach the internet over IPv6 directly,
        never touching EasyPi, so that traffic would bypass the tunnel.
        """
        try:
            from app.services.dhcp_identity import load_ipv6_bypass_routers
            from app.services.stealth_service import get_stealth_service

            covers_all, covered = get_stealth_service().covered_ips()
            routers = await asyncio.to_thread(load_ipv6_bypass_routers)
        except Exception as exc:
            logger.debug("stealth IPv6 check failed: %s", exc)
            return
        exposed = bool(routers) and (covers_all or bool(covered))
        if exposed == self._stealth_ipv6_exposed:
            return
        self._stealth_ipv6_exposed = exposed
        if exposed:
            prefixes = sorted({p for r in routers for p in r["global_prefixes"]})
            detail = f" (prefix {', '.join(prefixes[:3])})" if prefixes else ""
            self._emit(
                kind="stealth", event_id="watchdog:stealth-ipv6", severity="warning",
                title="IPv6 can bypass Stealth",
                message=(
                    f"Your router now offers IPv6{detail}. Devices protected by "
                    "Stealth can reach the internet over IPv6 without the tunnel. "
                    "Disable IPv6 on the router to keep their traffic hidden."
                ),
                route="/stealth",
            )
        else:
            self._emit(
                kind="stealth", event_id="watchdog:stealth-ipv6", severity="success",
                title="Stealth IPv6 bypass closed",
                message="The router no longer offers IPv6, or no device uses Stealth.",
                route="/stealth",
            )

    async def _vpn_reconcile(self) -> None:
        """If per-device outbound VPN routing is live, follow DHCP: re-apply the
        rules when a targeted device's IP changed. Cheap no-op otherwise."""
        try:
            from app.services.vpn_client_service import get_vpn_client_service
            await get_vpn_client_service().reconcile_if_needed()
        except Exception as e:
            logger.debug(f"vpn reconcile failed: {e}")

    async def _stealth_reconcile(self) -> None:
        """Same DHCP-follow for the per-device Stealth (Chameleon) tunnel."""
        try:
            from app.services.stealth_service import get_stealth_service
            await get_stealth_service().reconcile_if_needed()
        except Exception as e:
            logger.debug(f"stealth reconcile failed: {e}")

    # ── emit / read ──────────────────────────────────────────────────────────
    def _emit(self, *, kind: str, event_id: str, severity: str, title: str, message: str, route: str) -> None:
        rec = {
            "ts": time.time(),
            "kind": kind,
            "event_id": event_id,
            "severity": severity,
            "title": title,
            "message": message,
            "route": route,
            "triggered_at": datetime.now(timezone.utc).isoformat(),
        }
        try:
            self._data_dir.mkdir(parents=True, exist_ok=True)
            with self._events_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(rec, ensure_ascii=False) + "\n")
            self._trim()
            logger.info(f"[watchdog] {severity.upper()} {title}: {message}")
        except Exception as e:
            logger.warning(f"watchdog emit failed: {e}")
        # Fan the fresh alert out to phones (web push + Telegram), best-effort.
        try:
            asyncio.get_running_loop().create_task(self._dispatch_alert(rec))
        except RuntimeError:
            pass  # no running loop (e.g. unit tests) — inbox still records it

    async def _dispatch_alert(self, rec: dict[str, Any]) -> None:
        """Send a fresh watchdog alert to the phone via web push + Telegram."""
        title = rec.get("title", "EasyPi")
        msg = rec.get("message", "")
        sev = rec.get("severity", "info")
        route = rec.get("route", "/")
        try:
            from app.services.push_notification_service import get_push_service, NotificationPayload
            ps = get_push_service()
            if ps.is_configured and ps.get_subscription_count() > 0:
                await ps.send_notification(NotificationPayload(
                    title=title, body=msg, tag=rec.get("event_id"),
                    data={"url": route, "kind": rec.get("kind"), "severity": sev},
                    require_interaction=sev in ("warning", "critical"),
                ))
        except Exception as e:
            logger.debug(f"push dispatch failed: {e}")
        try:
            from app.services.telegram_alert_service import get_telegram_alerts
            ta = get_telegram_alerts()
            if ta.is_configured:
                emoji = {"critical": "🔴", "warning": "⚠️", "success": "🟢", "info": "ℹ️"}.get(sev, "🔔")
                safe_title = html.escape(str(title), quote=True)
                safe_message = html.escape(str(msg), quote=True)
                await ta.send(f"{emoji} <b>{safe_title}</b>\n{safe_message}")
        except Exception as e:
            logger.debug(f"telegram dispatch failed: {e}")

    def _trim(self) -> None:
        try:
            lines = self._events_path.read_text(encoding="utf-8", errors="ignore").splitlines()
            if len(lines) > MAX_EVENTS:
                self._events_path.write_text("\n".join(lines[-MAX_EVENTS:]) + "\n", encoding="utf-8")
        except Exception:
            pass

    def read_events(self, limit: int = 60) -> list[dict[str, Any]]:
        """Latest watchdog events, deduplicated by event_id (current state wins)."""
        try:
            lines = self._events_path.read_text(encoding="utf-8", errors="ignore").splitlines()
        except Exception:
            return []
        latest: dict[str, dict[str, Any]] = {}
        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                rec = json.loads(line)
            except Exception:
                continue
            key = str(rec.get("event_id") or rec.get("ts"))
            latest[key] = rec
        recs = sorted(latest.values(), key=lambda r: r.get("ts", 0), reverse=True)
        return recs[: max(1, min(limit, MAX_EVENTS))]

    # ── checks ───────────────────────────────────────────────────────────────
    async def _check_disk(self) -> None:
        try:
            usage = await asyncio.to_thread(shutil.disk_usage, "/")
        except Exception:
            return
        pct = (usage.used / usage.total * 100.0) if usage.total else 0.0
        level = "crit" if pct >= DISK_CRIT_PCT else ("warn" if pct >= DISK_WARN_PCT else "ok")
        if level == self._disk_level:
            return
        prev, self._disk_level = self._disk_level, level
        if level == "ok":
            if prev != "ok":
                self._emit(
                    kind="disk", event_id="watchdog:disk", severity="info",
                    title="Disk space recovered",
                    message=f"Root filesystem is back to {pct:.0f}% used.",
                    route="/monitoring",
                )
        else:
            gb_free = usage.free / (1024 ** 3)
            self._emit(
                kind="disk", event_id="watchdog:disk",
                severity="critical" if level == "crit" else "warning",
                title="Disk filling up",
                message=f"Root filesystem is {pct:.0f}% full ({gb_free:.1f} GB free). Free up space or expand storage.",
                route="/monitoring",
            )

    async def _check_services(self) -> None:
        for unit, label in CRITICAL_SERVICES:
            try:
                state = await asyncio.to_thread(self._systemctl_state, unit)
            except Exception:
                continue
            active = state == "active"
            if not active and unit not in self._service_down:
                self._service_down.add(unit)
                self._emit(
                    kind="service", event_id=f"watchdog:service:{unit}", severity="critical",
                    title="Service is down",
                    message=f"{label} is not running (state: {state or 'unknown'}). Restart it to restore protection.",
                    route="/monitoring",
                )
            elif active and unit in self._service_down:
                self._service_down.discard(unit)
                self._emit(
                    kind="service", event_id=f"watchdog:service:{unit}", severity="success",
                    title="Service recovered",
                    message=f"{label} is running again.",
                    route="/monitoring",
                )

    @staticmethod
    def _systemctl_state(unit: str) -> str:
        # `systemctl is-active` needs no privileges; returns the state on stdout
        # even when the exit code is non-zero (inactive/failed).
        try:
            proc = subprocess.run(
                ["systemctl", "is-active", unit],
                capture_output=True, text=True, timeout=8,
            )
            return (proc.stdout or "").strip()
        except Exception:
            return ""

    async def _check_new_devices(self) -> None:
        from app.services.unknown_device_admission_service import (
            unknown_device_admission_service,
        )

        new_devices = await asyncio.to_thread(unknown_device_admission_service.refresh)
        for device in await asyncio.to_thread(
            unknown_device_admission_service.list_rebindings
        ):
            await self._rebind_known_device(device)
        for device in new_devices:
            if device.get("managed_device") is not True:
                self._queue_new_device_alert(device)

    async def _rebind_known_device(self, device: dict[str, Any]) -> None:
        """Follow DHCP for an approved MAC without weakening its saved policy."""
        from app.services.netprotection_service import netprotection_service
        from app.services.unknown_device_admission_service import (
            UnknownDeviceAdmissionError,
            UnknownDeviceNotFound,
            unknown_device_admission_service,
        )

        device_id = str(device.get("id") or "")
        try:
            await netprotection_service.approve_client_transactional(
                {
                    "ip": device.get("ip"),
                    "ids": [device.get("ip")],
                    "mac": device.get("mac"),
                },
                require_existing=True,
            )
            await asyncio.to_thread(
                unknown_device_admission_service.mark_allowed, device_id
            )
            logger.info(
                "Automatically rebound approved device %s to its current DHCP address",
                device_id,
            )
        except UnknownDeviceNotFound:
            # A concurrent administrator action already resolved the record.
            return
        except (UnknownDeviceAdmissionError, RuntimeError, ValueError) as exc:
            try:
                await asyncio.to_thread(
                    unknown_device_admission_service.mark_rebinding_failed, device_id
                )
            except UnknownDeviceAdmissionError:
                logger.exception("Could not persist failed device rebind state")
            logger.error("Automatic rebind failed for %s: %s", device_id, exc)

    def _queue_new_device_alert(self, device: dict[str, Any]) -> None:
        """Rate-limit external alerts while every device remains in the UI queue."""
        now = time.monotonic()
        self._device_alert_times = [
            timestamp
            for timestamp in self._device_alert_times
            if now - timestamp < DEVICE_ALERT_WINDOW_SECONDS
        ]
        if len(self._device_alert_times) < DEVICE_ALERT_LIMIT:
            self._device_alert_times.append(now)
            ip = str(device.get("ip") or "")
            mac = str(device.get("mac") or "")
            name = str(device.get("hostname") or device.get("vendor") or "New device")
            identity_candidate = device.get("identity_candidate")
            identity_conflict = bool(
                isinstance(identity_candidate, dict)
                and identity_candidate.get("conflicts")
            )
            self._emit(
                kind="device-admission",
                event_id=f"watchdog:unknown-device:{device.get('id')}",
                severity="warning",
                title=(
                    "Possible device identity conflict"
                    if identity_conflict
                    else "New device detected"
                ),
                message=(
                    f"{name}: {ip} ({mac}). "
                    + (
                        "Its signals overlap with a managed device, but conflict; "
                        "EasyPi kept it quarantined."
                        if identity_conflict
                        else "Internet access is blocked until an administrator allows this device."
                    )
                ),
                route="/guard?tab=devices",
            )
            return

        self._suppressed_device_alerts += 1
        if self._device_summary_task is None or self._device_summary_task.done():
            oldest = min(self._device_alert_times, default=now)
            delay = max(0.1, DEVICE_ALERT_WINDOW_SECONDS - (now - oldest))
            self._device_summary_task = asyncio.create_task(
                self._emit_suppressed_device_summary(delay)
            )

    async def _emit_suppressed_device_summary(self, delay: float) -> None:
        try:
            await asyncio.sleep(delay)
            count = self._suppressed_device_alerts
            self._suppressed_device_alerts = 0
            self._device_alert_times = [
                timestamp
                for timestamp in self._device_alert_times
                if time.monotonic() - timestamp < DEVICE_ALERT_WINDOW_SECONDS
            ]
            if count:
                self._emit(
                    kind="device-admission",
                    event_id="watchdog:unknown-device:rate-limit-summary",
                    severity="warning",
                    title="More new devices detected",
                    message=(
                        f"EasyPi quarantined {count} additional device identities. "
                        "Open Guard Security / Devices to review them."
                    ),
                    route="/guard?tab=devices",
                )
        finally:
            self._device_summary_task = None

    async def _check_bypass(self) -> None:
        path = self._data_dir / "bypass_events_meta.json"
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
            by_ip = data.get("by_ip", {}) if isinstance(data, dict) else {}
        except Exception:
            by_ip = {}

        active: set[str] = set()
        for ip, entry in by_ip.items():
            if not isinstance(entry, dict) or not entry.get("leak"):
                continue
            try:
                ts = float(entry.get("ts")) if entry.get("ts") is not None else None
                ack = float(entry.get("ack_ts")) if entry.get("ack_ts") is not None else None
            except Exception:
                continue
            if ts is None or (ack is not None and ack >= ts):
                continue  # acknowledged / resolved
            active.add(ip)

        for ip in active - self._bypass_alerted:
            entry = by_ip.get(ip, {})
            groups = entry.get("groups") or []
            gl = ", ".join(str(g).upper() for g in groups) if groups else "a bypass channel"
            self._emit(
                kind="bypass", event_id=f"watchdog:bypass:{ip}", severity="warning",
                title="Device is bypassing protection",
                message=f"{ip} tried to bypass the filter ({gl}). It was blocked — open Parental Controls to quarantine if needed.",
                route="/guard",
            )
        self._bypass_alerted = active


_monitor: ProactiveMonitor | None = None


def get_proactive_monitor() -> ProactiveMonitor:
    global _monitor
    if _monitor is None:
        _monitor = ProactiveMonitor()
    return _monitor
