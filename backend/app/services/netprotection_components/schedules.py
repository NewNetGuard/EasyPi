"""Schedules operations for NetProtection."""

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from app.services.netprotection_components.runtime_context import (
    DeviceAnomalyStoreError,
    ScheduleStoreError,
    logger,
    sanitize_mac,
)


class SchedulesMixin:
    """Internal behavior mixed into the stable service facade."""

    def _load_schedule_store(self) -> Dict[str, Any]:
        """Load and validate the schedule store without inventing replacement data."""
        schedules_file = self.data_dir / "schedules.json"
        if not schedules_file.exists():
            return {"schedules": []}
        try:
            data = json.loads(schedules_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            logger.error("Could not read schedules from %s: %s", schedules_file, exc)
            raise ScheduleStoreError(
                "Schedule configuration is unavailable or corrupted"
            ) from exc
        if not isinstance(data, dict) or not isinstance(data.get("schedules"), list):
            logger.error("Invalid schedule configuration format in %s", schedules_file)
            raise ScheduleStoreError("Schedule configuration has an invalid format")
        return data

    def _save_schedule_store(self, data: Dict[str, Any]) -> None:
        """Persist schedules atomically so an interrupted write keeps the old rules."""
        schedules_file = self.data_dir / "schedules.json"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        temporary_file = schedules_file.with_name(
            f".{schedules_file.name}.{uuid.uuid4().hex}.tmp"
        )
        try:
            temporary_file.write_text(json.dumps(data, indent=2), encoding="utf-8")
            temporary_file.replace(schedules_file)
        except OSError as exc:
            logger.error("Could not persist schedules to %s: %s", schedules_file, exc)
            try:
                temporary_file.unlink(missing_ok=True)
            except OSError:
                logger.warning(
                    "Could not remove temporary schedule file %s", temporary_file
                )
            raise ScheduleStoreError(
                "Could not persist schedule configuration"
            ) from exc

    async def get_schedules(self) -> Dict[str, Any]:
        """Get all schedules."""
        data = self._load_schedule_store()
        return {"success": True, "data": data["schedules"]}

    async def get_schedule(self, schedule_id: str) -> Optional[Dict[str, Any]]:
        """Get schedule by ID."""
        schedules = await self.get_schedules()
        for schedule in schedules.get("data", []):
            if schedule.get("id") == schedule_id:
                return {"success": True, "data": schedule}
        return None

    async def get_schedule_enforcement_status(self) -> Dict[str, Any]:
        """Whether schedule enforcement can act at the GATEWAY (unbypassable — the
        box routes the device's traffic and can DROP it / block bypass ports) or is
        DNS-only (bypassable by changing the device's DNS). Read-only heuristic."""
        import shutil

        # NOTE: the backend's PATH excludes /usr/sbin, so shutil.which("iptables")
        # alone falsely returns None (iptables lives in /usr/sbin) → the box would be
        # misreported as DNS-only. Check the absolute locations too.
        has_iptables = (
            shutil.which("iptables") is not None
            or os.path.exists("/usr/sbin/iptables")
            or os.path.exists("/sbin/iptables")
        )
        ip_forward = False
        try:
            ip_forward = (
                Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() == "1"
            )
        except Exception:
            pass
        gateway = bool(has_iptables and ip_forward)
        return {
            "success": True,
            "gateway_enforcement": gateway,
            "ip_forward": ip_forward,
            "iptables": has_iptables,
            "mode": "gateway" if gateway else "dns-only",
        }

    async def create_schedule(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new schedule."""
        # Create new schedule. NOTE: device_ips/device_macs/profile_id MUST be
        # persisted here — without them the schedule silently applies to ALL devices
        # (and per-device targeting picked in the UI is lost).
        device_macs = [
            mac for raw in (data.get("device_macs") or []) if (mac := sanitize_mac(raw))
        ]
        device_macs = list(dict.fromkeys(device_macs))
        device_ips = (
            [] if device_macs else list(dict.fromkeys(data.get("device_ips") or []))
        )
        new_schedule = {
            "id": str(uuid.uuid4()),
            "name": data.get("name", "New Schedule"),
            "profile_id": data.get("profile_id"),
            "device_ips": device_ips,
            "device_macs": device_macs,
            "rules": data.get("rules", []),
            "enabled": data.get("enabled", True),
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }

        async with self._schedules_lock:
            existing = self._load_schedule_store()
            existing["schedules"].append(new_schedule)
            self._save_schedule_store(existing)

        # Trigger immediate reload in DNS server
        self._trigger_schedule_reload()

        logger.info(f"Created schedule: {new_schedule['id']}")
        return {"success": True, "data": new_schedule}

    async def update_schedule(
        self, schedule_id: str, updates: Dict[str, Any]
    ) -> Optional[Dict[str, Any]]:
        """Update a schedule."""
        schedules_file = self.data_dir / "schedules.json"
        if not schedules_file.exists():
            return None

        async with self._schedules_lock:
            data = self._load_schedule_store()
            for i, schedule in enumerate(data.get("schedules", [])):
                if schedule.get("id") == schedule_id:
                    incoming_macs = updates.get("device_macs")
                    if incoming_macs is not None:
                        normalized = [
                            mac for raw in incoming_macs if (mac := sanitize_mac(raw))
                        ]
                        updates["device_macs"] = list(dict.fromkeys(normalized))
                        if updates["device_macs"]:
                            updates["device_ips"] = []
                    for key, value in updates.items():
                        schedule[key] = value
                    schedule["updated_at"] = datetime.now(timezone.utc).isoformat()
                    data["schedules"][i] = schedule
                    self._save_schedule_store(data)

                    # Trigger immediate reload in DNS server
                    self._trigger_schedule_reload()

                    return {"success": True, "data": schedule}
            return None

    async def delete_schedule(self, schedule_id: str) -> bool:
        """Delete a schedule."""
        schedules_file = self.data_dir / "schedules.json"
        if not schedules_file.exists():
            return False

        async with self._schedules_lock:
            data = self._load_schedule_store()
            original_len = len(data.get("schedules", []))
            data["schedules"] = [
                s for s in data.get("schedules", []) if s.get("id") != schedule_id
            ]

            if len(data["schedules"]) < original_len:
                self._save_schedule_store(data)

                # Trigger immediate reload in DNS server
                self._trigger_schedule_reload()

                logger.info(f"Deleted schedule: {schedule_id}")
                return True
            return False

    async def toggle_schedule(
        self, schedule_id: str, enabled: bool
    ) -> Optional[Dict[str, Any]]:
        """Toggle schedule enabled/disabled."""
        result = await self.update_schedule(schedule_id, {"enabled": enabled})

        # Note: update_schedule already triggers reload, no need to call again

        return result

    def _trigger_schedule_reload(self) -> None:
        """Create signal file to trigger immediate schedule reload in DNS server."""
        signal_file = self.data_dir / ".schedules_reload"
        try:
            signal_file.touch()
            logger.info(f"Schedule reload signal created: {signal_file}")
        except Exception as e:
            logger.error(f"Failed to create schedule reload signal: {e}")

    # ============ Devices with Baseline ============

    async def get_devices_with_baseline(
        self, page: int = 1, page_size: int = 50
    ) -> Dict[str, Any]:
        """Get all devices with baseline information."""
        devices_file = self.data_dir / "devices.json"

        if not devices_file.exists():
            # Return empty list - no mock data
            return {
                "success": True,
                "data": {
                    "items": [],
                    "total": 0,
                    "page": page,
                    "page_size": page_size,
                    "pages": 0,
                },
            }

        try:
            data = json.loads(devices_file.read_text())
            devices = data.get("devices", [])
            total = len(devices)
            start = (page - 1) * page_size
            end = start + page_size

            return {
                "success": True,
                "data": {
                    "items": devices[start:end],
                    "total": total,
                    "page": page,
                    "page_size": page_size,
                    "pages": (total + page_size - 1) // page_size,
                },
            }
        except Exception as e:
            logger.error(f"Error loading devices: {e}")
            return {"success": False, "error": str(e)}

    async def get_device_baseline(self, device_id: str) -> Optional[Dict[str, Any]]:
        """Get baseline for specific device."""
        devices = await self.get_devices_with_baseline()
        for device in devices.get("data", {}).get("items", []):
            if device.get("id") == device_id:
                return {
                    "success": True,
                    "data": {
                        "device_id": device_id,
                        "name": device.get("name"),
                        "baseline": device.get("baseline", {}),
                        "anomaly_score": device.get("anomaly_score", 0),
                    },
                }
        return None

    async def get_device_anomalies(self, device_id: str) -> Dict[str, Any]:
        """Get anomalies for specific device from database."""
        try:
            anomaly_db = self.data_dir / "device_anomaly.db"
            if not anomaly_db.exists():
                return {"success": True, "data": []}

            import sqlite3

            with sqlite3.connect(str(anomaly_db)) as conn:
                cursor = conn.execute(
                    """
                    SELECT id, device_id, type, severity, description, domain, detected_at
                    FROM anomaly_log
                    WHERE device_id = ?
                    ORDER BY detected_at DESC
                    LIMIT 50
                    """,
                    (device_id,),
                )
                anomalies = [
                    {
                        "id": row[0],
                        "device_id": row[1],
                        "type": row[2],
                        "severity": row[3],
                        "description": row[4],
                        "domain": row[5],
                        "detected_at": row[6],
                    }
                    for row in cursor.fetchall()
                ]
            return {"success": True, "data": anomalies}
        except Exception as exc:
            logger.exception("Could not read anomaly data for device %s", device_id)
            raise DeviceAnomalyStoreError(
                "Device anomaly data is temporarily unavailable"
            ) from exc
