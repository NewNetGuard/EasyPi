"""Read-only evidence sources for explicit extended diagnostic probes."""

from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import tarfile
from dataclasses import asdict
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from typing import Any

from app.services.operation_event_service import OperationEventService


class ExtendedDiagnosticsAdapter:
    """Bridge existing backend health/state stores into the Agent probe API.

    These methods are only reached through an explicit ``/diagnostics/probe``
    request.  They never mutate the inspected subsystem.
    """

    _EVENT_PREFIXES: dict[str, tuple[str, ...]] = {
        "camera.discovery": ("camera.discovery", "cameras.discovery", "camera.detect"),
        "dns.profiles": ("profiles.",),
        "dns.rewrites": ("rewrites.",),
        "prism.pipeline": ("prism.",),
        "threat_monitor.journal": ("threat-monitor.", "threat_monitor."),
        "tailscale.routes": ("tailscale-admin.routes.", "tailscale-admin.exit-node."),
        "tailscale.funnel": ("tailscale.funnel.",),
        "notifications.delivery": ("notifications.smtp.test", "notifications.telegram.test", "notifications.push.test"),
        "cloud.metadata": ("picloud.", "cloud."),
        "files.outcome": ("files.",),
        "terminal.live": ("terminal.",),
        "auth.workflow": ("auth.",),
        "wireguard.artifacts": ("wireguard.",),
        "marketplace.runtime": ("marketplace.",),
        "ai.inference": ("ai.chat", "ai.inference"),
        "personal_dns.tenancy": ("dns.", "personal_dns."),
        "netprotection.components": ("netprotection.",),
    }

    def __init__(self, operation_events: OperationEventService | None = None) -> None:
        self.operation_events = operation_events or OperationEventService()

    async def run(self, probe_id: str, parameters: dict[str, Any]) -> dict[str, Any]:
        special = {
            "health.dependencies": self._health_dependencies,
            "camera.ptz": self._camera_ptz,
            "camera.discovery": self._camera_discovery,
            "camera.live": self._camera_live,
            "dns.profiles": self._dns_profiles,
            "dns.rewrites": self._dns_rewrites,
            "prism.pipeline": self._prism_pipeline,
            "threat_monitor.journal": self._threat_journal,
            "tailscale.routes": self._tailscale_routes,
            "tailscale.funnel": self._tailscale_funnel,
            "cloud.metadata": self._cloud_metadata,
            "tasks.runtime": self._tasks_runtime,
            "services.runtime": self._services_runtime,
            "backup.integrity": self._backup_integrity,
            "personal_dns.tenancy": self._personal_dns_tenancy,
            "devices.admission": self._device_admission,
            "heuristics.alerts": self._heuristic_alerts,
            "netprotection.components": self._netprotection_components,
            "wireguard.artifacts": self._wireguard_artifacts,
            "ai.inference": self._ai_inference,
        }.get(probe_id)
        if special is not None:
            return await special(parameters)
        return self._operation_evidence(probe_id, parameters)

    async def _health_dependencies(self, _parameters: dict[str, Any]) -> dict[str, Any]:
        from app.api.v1.endpoints.health import check_database, check_redis
        from app.db.session import SessionLocal

        db = SessionLocal()
        try:
            database = await check_database(db)
            redis = await check_redis()
        finally:
            db.close()
        checks = [database.model_dump(mode="json"), redis.model_dump(mode="json")]
        failed = [item for item in checks if str(item.get("status") or "").lower() != "healthy"]
        return {
            "success": not failed,
            "source_status": "ok" if not failed else "partial",
            "message": "Dependency health checks completed." if not failed else "One or more dependency checks are unhealthy or unavailable.",
            "checks": checks,
        }

    async def _camera_ptz(self, parameters: dict[str, Any]) -> dict[str, Any]:
        from app.db.session import SessionLocal
        from app.models.camera import Camera
        from app.services.ptz.service import build_capabilities_response

        camera_id = str(parameters["camera_id"])
        db = SessionLocal()
        try:
            camera = db.query(Camera).filter(Camera.id == camera_id).first()
            if camera is None:
                return self._missing("Camera was not found.")
            state = build_capabilities_response(camera)
        finally:
            db.close()
        observed_at = self._parse_datetime(state.get("last_probe_at"))
        now = datetime.now(timezone.utc)
        future = observed_at is not None and observed_at > now + timedelta(minutes=5)
        stale = observed_at is None or observed_at < now - timedelta(hours=24)
        healthy = not bool(state.get("probe_error")) and not stale
        if future:
            return {
                "success": False,
                "source_status": "conflict",
                "message": "PTZ capability timestamp is unexpectedly in the future.",
                "state": state,
            }
        return {
            "success": healthy,
            "source_status": "stale" if stale else ("ok" if healthy else "partial"),
            "message": "PTZ capability evidence is missing or stale." if stale else str(state.get("probe_error") or "PTZ capability state loaded."),
            "state": state,
        }

    async def _camera_live(self, parameters: dict[str, Any]) -> dict[str, Any]:
        from app.db.session import SessionLocal
        from app.models.camera import Camera
        from app.api.v1.endpoints.camera_helpers import check_camera_online
        from app.services.mediamtx_client import mediamtx_client

        camera_id = str(parameters["camera_id"])
        db = SessionLocal()
        try:
            camera = db.query(Camera).filter(Camera.id == camera_id).first()
            if camera is None:
                return self._missing("Camera was not found.")
            network_online = check_camera_online(camera.ip, camera.port)
            stream = await mediamtx_client.get_stream_info(camera_id)
            try:
                frame_ok, frame, frame_error = await mediamtx_client.capture_snapshot(camera_id)
            except (AttributeError, OSError, RuntimeError) as exc:
                frame_ok, frame, frame_error = False, None, f"Frame probe unavailable: {exc}"
        finally:
            db.close()
        source_ready = bool(stream and stream.get("sourceReady"))
        frame_valid = bool(frame_ok and frame and self._valid_image_payload(frame))
        ready = bool(network_online and source_ready and frame_valid)
        failure_reasons: list[str] = []
        if not network_online:
            failure_reasons.append("the camera network endpoint did not respond")
        if not source_ready:
            failure_reasons.append("the MediaMTX source is not ready")
        if not frame_valid:
            failure_reasons.append(frame_error or "no valid frame was returned")
        return {
            "success": ready,
            "source_status": "ok" if ready else "partial",
            "message": (
                "Camera live path returned a valid frame."
                if ready
                else "Camera live path check failed: " + "; ".join(failure_reasons)
            ),
            "network_online": network_online,
            "stream": stream or {},
            "frame_valid": frame_valid,
        }

    async def _camera_discovery(self, parameters: dict[str, Any]) -> dict[str, Any]:
        import socket

        from app.services.ptz import discovery

        requested_interface = str(parameters.get("interface") or "").strip()
        try:
            interface_names = [name for _index, name in socket.if_nameindex()]
        except OSError as exc:
            return self._missing(f"Camera discovery could not enumerate network interfaces: {exc}")
        if requested_interface and requested_interface not in interface_names:
            return self._missing(f"Camera discovery interface '{requested_interface}' does not exist.")
        target = str(parameters.get("target") or "").strip()
        devices = await asyncio.to_thread(
            discovery.discover,
            targets=[target] if target else None,
            interface=requested_interface or None,
        )
        transport_ok = bool(getattr(devices, "transport_ok", False))
        transport_errors = list(getattr(devices, "transport_errors", None) or [])
        if not transport_ok:
            transport_errors = transport_errors or [
                "Discovery transport returned no execution diagnostics."
            ]
            return {
                "success": False,
                "source_status": "unavailable",
                "message": "ONVIF discovery transport failed: " + "; ".join(map(str, transport_errors)),
                "devices": list(devices),
                "interfaces": interface_names,
                "requested_interface": requested_interface or None,
            }
        normalized_devices = [dict(item) for item in devices if isinstance(item, dict)]
        matching_devices = [
            item
            for item in normalized_devices
            if not target
            or self._matches_exact_target(
                target,
                (
                    item.get("ip"),
                    item.get("name"),
                    item.get("hardware"),
                    item.get("xaddr"),
                ),
            )
        ]
        if target and not matching_devices:
            return {
                "success": False,
                "source_status": "partial",
                "message": f"ONVIF discovery completed, but the requested target '{target}' did not reply.",
                "devices": normalized_devices,
                "interfaces": interface_names,
                "requested_interface": requested_interface or None,
                "transport_errors": transport_errors,
            }
        if transport_errors:
            return {
                "success": False,
                "source_status": "partial",
                "message": "ONVIF discovery completed with partial transport failures: "
                + "; ".join(map(str, transport_errors)),
                "devices": matching_devices,
                "interfaces": interface_names,
                "requested_interface": requested_interface or None,
                "transport_errors": transport_errors,
            }
        return {
            "success": True,
            "source_status": "ok",
            "message": f"Camera discovery completed with {len(matching_devices)} ONVIF device(s).",
            "devices": matching_devices,
            "interfaces": interface_names,
            "requested_interface": requested_interface or None,
            "transport_errors": [],
        }

    @staticmethod
    def _valid_image_payload(payload: bytes) -> bool:
        try:
            from PIL import Image

            with Image.open(BytesIO(payload)) as image:
                image_format = image.format
                image.load()
                if image_format == "JPEG" and not payload.endswith(b"\xff\xd9"):
                    return False
                return image_format in {"JPEG", "PNG", "WEBP"}
        except (ImportError, OSError, SyntaxError, ValueError):
            return False

    async def _dns_profiles(self, parameters: dict[str, Any]) -> dict[str, Any]:
        from config import get_settings

        data_dir = Path(get_settings().NETPROTECTION_DATA_DIR)
        profiles_result = self._read_json_file(data_dir / "profiles.json")
        bindings_result = self._read_json_file(data_dir / "bindings.json")
        errors = [
            str(result["error"])
            for result in (profiles_result, bindings_result)
            if result.get("error")
        ]
        if errors:
            return {
                "success": False,
                "source_status": "partial" if any(result.get("data") for result in (profiles_result, bindings_result)) else "unavailable",
                "message": "; ".join(errors),
                "profiles": [],
                "bindings": [],
            }

        profiles_data = profiles_result.get("data") or {}
        bindings_data = bindings_result.get("data") or {}
        profiles = profiles_data.get("profiles", []) if isinstance(profiles_data, dict) else []
        bindings = bindings_data.get("bindings", []) if isinstance(bindings_data, dict) else []
        if not isinstance(profiles, list) or not isinstance(bindings, list):
            return self._missing("Profile or binding store has an invalid schema.")

        malformed = sum(
            not isinstance(item, dict) or not str(item.get("id") or "").strip()
            for item in profiles
        ) + sum(
            not isinstance(item, dict)
            or not str(item.get("id") or "").strip()
            or not str(item.get("profile_id") or "").strip()
            for item in bindings
        )
        normalized_profiles = [dict(item) for item in profiles if isinstance(item, dict)]
        normalized_bindings = [dict(item) for item in bindings if isinstance(item, dict)]
        profiles_by_id = {str(item.get("id")): item for item in normalized_profiles if item.get("id")}
        conflicts: list[dict[str, Any]] = []
        for binding in normalized_bindings:
            profile = profiles_by_id.get(str(binding.get("profile_id") or ""))
            if profile is None:
                conflicts.append({"binding_id": binding.get("id"), "reason": "profile_missing"})
            elif binding.get("enabled", True) and not profile.get("enabled", True):
                conflicts.append({"binding_id": binding.get("id"), "profile_id": profile.get("id"), "reason": "profile_disabled"})

        target = str(parameters.get("target") or parameters.get("entity_id") or "").strip().lower()
        matching_profile_ids = {
            str(item.get("id") or "")
            for item in normalized_profiles
            if target
            and self._matches_exact_target(
                target,
                (item.get("id"), item.get("name")),
            )
        }
        matches = [
            item
            for item in normalized_bindings
            if not target
            or self._matches_exact_target(
                target,
                (item.get("id"), item.get("name"), item.get("value"), item.get("profile_id")),
            )
            or str(item.get("profile_id") or "") in matching_profile_ids
        ]
        if target and not matches and not matching_profile_ids:
            return {
                "success": False,
                "source_status": "unavailable",
                "message": f"No DNS profile binding matched '{target}'.",
                "profiles": normalized_profiles,
                "bindings": [],
                "conflicts": conflicts,
                "malformed_records": malformed,
            }
        return {
            "success": not conflicts and not malformed,
            "source_status": "conflict" if conflicts else ("partial" if malformed else "ok"),
            "message": "Profile bindings contain conflicts." if conflicts else ("Profile stores contain malformed records." if malformed else "Profile and binding stores loaded successfully."),
            "profiles": normalized_profiles,
            "bindings": matches,
            "conflicts": conflicts,
            "malformed_records": malformed,
        }

    async def _dns_rewrites(self, parameters: dict[str, Any]) -> dict[str, Any]:
        from config import get_settings

        result = self._read_json_file(Path(get_settings().NETPROTECTION_DATA_DIR) / "rewrites.json")
        if result.get("error"):
            return self._missing(str(result["error"]))
        data = result.get("data")
        if data is None:
            return {"success": True, "message": "No DNS rewrite store exists yet.", "rules": [], "total": 0}
        if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
            return self._missing("DNS rewrite store has an invalid schema.")
        allowed_types = {"A", "AAAA", "CNAME", "MX", "TXT"}
        malformed = sum(
            not isinstance(item, dict)
            or not str(item.get("id") or "").strip()
            or not str(item.get("domain") or "").strip()
            or not str(item.get("answer") or "").strip()
            or str(item.get("rewrite_type") or item.get("type") or "A").upper() not in allowed_types
            for item in data["rules"]
        )
        rules = [dict(item) for item in data["rules"] if isinstance(item, dict)]
        updated_at = self._parse_datetime(data.get("updated_at"))
        stale = updated_at is not None and updated_at < datetime.now(timezone.utc) - timedelta(days=7)
        target = str(parameters.get("target") or parameters.get("entity_id") or "").strip().lower()
        matches = [
            item
            for item in rules
            if not target
            or self._matches_exact_target(
                target,
                (item.get("id"), item.get("domain"), item.get("answer")),
            )
        ]
        if target and not matches:
            return {
                "success": False,
                "source_status": "unavailable",
                "message": f"No DNS rewrite matched '{target}'.",
                "rules": [],
                "total": len(rules),
                "updated_at": data.get("updated_at"),
                "malformed_records": malformed,
            }
        return {
            "success": not malformed and not stale,
            "source_status": "stale" if stale else ("partial" if malformed else "ok"),
            "message": "DNS rewrite store is stale." if stale else ("DNS rewrite store contains malformed records." if malformed else "DNS rewrite store loaded successfully."),
            "rules": matches,
            "total": len(rules),
            "updated_at": data.get("updated_at"),
            "malformed_records": malformed,
        }

    async def _prism_pipeline(self, _parameters: dict[str, Any]) -> dict[str, Any]:
        path = Path("/var/lib/easypi/prism/flowgraph.jsonl")
        if not path.is_file() or path.is_symlink():
            return self._missing("PRISM flowgraph file is missing or unsafe.")
        try:
            stat = path.stat()
            age_seconds = max(0.0, datetime.now(timezone.utc).timestamp() - stat.st_mtime)
            last_line = self._read_last_line(path, max_bytes=512 * 1024)
            latest = json.loads(last_line) if last_line else None
        except (OSError, ValueError, json.JSONDecodeError) as exc:
            return self._missing(f"PRISM flowgraph cannot be read: {type(exc).__name__}: {exc}")
        now = datetime.now(timezone.utc)
        failure_statuses = {"error", "failed", "failure", "stopped", "crashed"}
        latest_status = str(latest.get("status") or "").strip().lower() if isinstance(latest, dict) else ""
        latest_error = latest.get("error") if isinstance(latest, dict) else None
        timestamp_value = latest.get("timestamp") if isinstance(latest, dict) else None
        if isinstance(timestamp_value, (int, float)):
            try:
                observed_at = datetime.fromtimestamp(float(timestamp_value), tz=timezone.utc)
            except (OSError, OverflowError, ValueError):
                observed_at = None
        else:
            observed_at = self._parse_datetime(timestamp_value)
        structurally_valid = (
            isinstance(latest, dict)
            and bool(str(latest.get("event") or "").strip())
            and observed_at is not None
            and not latest_error
            and latest_status not in failure_statuses
        )
        future = observed_at is not None and observed_at > now + timedelta(minutes=5)
        stale = age_seconds > 900 or observed_at is None or observed_at < now - timedelta(minutes=15)
        if future:
            return {
                "success": False,
                "source_status": "conflict",
                "message": "PRISM flowgraph contains a future-dated event.",
                "path": str(path),
                "size": stat.st_size,
                "age_seconds": round(age_seconds, 1),
                "latest_event": latest,
            }
        if latest_error or latest_status in failure_statuses:
            return {
                "success": False,
                "source_status": "partial",
                "message": f"PRISM flowgraph reports a failed pipeline: {latest_error or latest_status}.",
                "path": str(path),
                "size": stat.st_size,
                "age_seconds": round(age_seconds, 1),
                "latest_event": latest,
            }
        return {
            "success": not stale and structurally_valid,
            "source_status": "stale" if stale else ("ok" if structurally_valid else "partial"),
            "message": "PRISM flowgraph is stale." if stale else ("PRISM flowgraph is receiving valid events." if structurally_valid else "PRISM flowgraph contains no valid event payload."),
            "path": str(path),
            "size": stat.st_size,
            "age_seconds": round(age_seconds, 1),
            "latest_event": latest,
        }

    async def _threat_journal(self, _parameters: dict[str, Any]) -> dict[str, Any]:
        candidates = [Path("/var/log/auth.log"), Path("/var/log/secure")]
        existing = [path for path in candidates if path.exists()]
        readable = [path for path in existing if path.is_file() and not path.is_symlink() and os.access(path, os.R_OK)]
        fresh_readable: list[Path] = []
        stale_or_empty: list[Path] = []
        unverifiable: list[Path] = []
        future_dated: list[Path] = []
        now = datetime.now(timezone.utc)
        for path in readable:
            try:
                stat = path.stat()
                observed_at = self._latest_auth_log_timestamp(path, now=now) if stat.st_size > 0 else None
                if observed_at is not None and observed_at > now + timedelta(minutes=5):
                    future_dated.append(path)
                elif observed_at is not None and observed_at >= now - timedelta(days=7):
                    fresh_readable.append(path)
                elif observed_at is None and stat.st_size > 0:
                    unverifiable.append(path)
                else:
                    stale_or_empty.append(path)
            except (OSError, UnicodeError):
                stale_or_empty.append(path)
        if future_dated:
            return {
                "success": False,
                "source_status": "conflict",
                "message": "SSH authentication journal contains future-dated evidence.",
                "sources": [str(path) for path in future_dated],
            }
        if fresh_readable:
            return {
                "success": True,
                "source_status": "ok",
                "message": "At least one SSH authentication journal source has recent entries.",
                "sources": [str(path) for path in fresh_readable],
            }
        if stale_or_empty:
            return {"success": False, "source_status": "stale", "message": "SSH authentication journal sources are empty or stale.", "sources": [str(path) for path in stale_or_empty]}
        if unverifiable:
            return {
                "success": False,
                "source_status": "unavailable",
                "message": "SSH authentication journal entry timestamps could not be verified.",
                "sources": [str(path) for path in unverifiable],
            }
        if existing:
            return self._missing("SSH authentication journal exists but is not readable by EasyPi.")
        try:
            result = subprocess.run(
                [
                    "journalctl",
                    "--no-pager",
                    "-n",
                    "20",
                    "--since",
                    "7 days ago",
                    "-u",
                    "ssh",
                    "-u",
                    "sshd",
                    "--output=json",
                ],
                capture_output=True,
                text=True,
                timeout=4,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            return self._missing(f"SSH journal probe is unavailable: {type(exc).__name__}: {exc}")
        if result.returncode != 0:
            return self._missing(f"SSH journal cannot be read: {(result.stderr or 'journalctl failed').strip()[:300]}")
        journal_timestamps: list[datetime] = []
        for line in result.stdout.splitlines():
            try:
                record = json.loads(line)
                raw_timestamp = record.get("__REALTIME_TIMESTAMP") or record.get("_SOURCE_REALTIME_TIMESTAMP")
                if raw_timestamp is not None:
                    journal_timestamps.append(
                        datetime.fromtimestamp(int(raw_timestamp) / 1_000_000, tz=timezone.utc)
                    )
            except (AttributeError, json.JSONDecodeError, OSError, OverflowError, TypeError, ValueError):
                continue
        if any(timestamp > now + timedelta(minutes=5) for timestamp in journal_timestamps):
            return {
                "success": False,
                "source_status": "conflict",
                "message": "systemd SSH journal returned future-dated evidence.",
            }
        has_entries = any(timestamp >= now - timedelta(days=7) for timestamp in journal_timestamps)
        return {
            "success": has_entries,
            "source_status": "ok" if has_entries else "stale",
            "message": "systemd SSH journal returned recent evidence." if has_entries else "systemd SSH journal is readable but returned no current timestamped evidence.",
            "has_entries": has_entries,
        }

    async def _tailscale_routes(self, parameters: dict[str, Any]) -> dict[str, Any]:
        from app.services.remote_access.tailscale_admin_api import TailscaleAdminAPI

        api = TailscaleAdminAPI()
        try:
            config = api.load_config(migrate_plaintext=False)
            if not config.api_key or not config.tailnet:
                return self._operation_evidence("tailscale.routes", parameters)
            devices = await api.list_devices()
        finally:
            await api.close()
        target = str(parameters.get("target") or parameters.get("entity_id") or "").strip().lower()
        payload = []
        pending: list[dict[str, Any]] = []
        for device in devices:
            item = asdict(device)
            if target and not self._matches_exact_target(target, tuple(item.values())):
                continue
            item_pending = sorted(set(device.advertised_routes) - set(device.enabled_routes))
            item["pending_routes"] = item_pending
            payload.append(item)
            if item_pending:
                pending.append({"device_id": device.id, "routes": item_pending})
        if target and not payload:
            return self._missing("No Tailscale device matched the requested route or target.")
        return {
            "success": not pending,
            "source_status": "partial" if pending else "ok",
            "message": "One or more advertised routes require control-plane approval." if pending else "Tailscale route approvals are consistent.",
            "devices": payload,
            "pending": pending,
        }

    async def _tailscale_funnel(self, parameters: dict[str, Any]) -> dict[str, Any]:
        try:
            result = subprocess.run(
                ["tailscale", "funnel", "status", "--json"],
                capture_output=True,
                text=True,
                timeout=5,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return self._operation_evidence("tailscale.funnel", parameters)
        if result.returncode != 0:
            message = (result.stderr or result.stdout or "Tailscale Funnel status failed").strip()[:300]
            return {"success": False, "source_status": "unavailable", "message": message}
        try:
            state = json.loads(result.stdout or "{}")
        except json.JSONDecodeError as exc:
            return self._missing(f"Tailscale Funnel returned invalid JSON: {exc}")
        enabled = bool(state)
        return {
            "success": True,
            "message": "Tailscale Funnel is enabled." if enabled else "Tailscale Funnel is disabled.",
            "enabled": enabled,
            "state": state,
        }

    async def _cloud_metadata(self, parameters: dict[str, Any]) -> dict[str, Any]:
        from app.services.picloud_service import pi_cloud_service

        file_id = str(parameters.get("entity_id") or parameters.get("target") or "").strip()
        if not file_id:
            return self._operation_evidence("cloud.metadata", parameters)
        try:
            metadata = pi_cloud_service.metadata(file_id)
            payload = metadata.model_dump(mode="json") if hasattr(metadata, "model_dump") else dict(metadata)
            target = pi_cloud_service.resolve_file(file_id)
            thumbnail = pi_cloud_service._find_thumbnail_path(file_id, target.name)
        except (FileNotFoundError, ValueError, OSError) as exc:
            return self._missing(f"Cloud metadata could not be loaded: {type(exc).__name__}: {exc}")
        expects_preview = bool(pi_cloud_service._should_thumbnail(payload.get("mime"), target.name))
        thumbnail_ready = False
        thumbnail_error: str | None = None
        if thumbnail is not None and thumbnail.is_file() and not thumbnail.is_symlink():
            try:
                if thumbnail.stat().st_size > 16 * 1024 * 1024:
                    raise ValueError("Preview image is too large")
                thumbnail_ready = self._valid_image_payload(thumbnail.read_bytes())
                if not thumbnail_ready:
                    raise ValueError("Preview image cannot be fully decoded")
            except (OSError, ValueError) as exc:
                thumbnail_error = f"Preview validation failed: {exc}"
        return {
            "success": not expects_preview or thumbnail_ready,
            "source_status": "ok" if not expects_preview or thumbnail_ready else "partial",
            "message": "Cloud metadata and preview are available." if not expects_preview or thumbnail_ready else (thumbnail_error or "Cloud metadata loaded, but the expected preview is missing."),
            "metadata": payload,
            "thumbnail_expected": expects_preview,
            "thumbnail_ready": thumbnail_ready,
        }

    async def _tasks_runtime(self, parameters: dict[str, Any]) -> dict[str, Any]:
        from app.api.v1.endpoints.tasks import active_tasks

        task_id = str(parameters.get("task_id") or "").strip()
        if task_id:
            task = active_tasks.get(task_id)
            if task is None:
                return self._missing("Task was not found in the live runtime registry.")
            payload = self._safe_task(task)
            task_status = str(payload.get("status") or "unknown").strip().lower()
            process = task.get("process")
            return_code = getattr(process, "returncode", None)
            invalid_return_code = False
            parsed_return_code: int | None = None
            if return_code is not None:
                try:
                    parsed_return_code = int(return_code)
                except (TypeError, ValueError):
                    invalid_return_code = True
            failed = (
                task_status in {"failed", "error", "cancelled", "canceled", "timeout"}
                or invalid_return_code
                or (parsed_return_code is not None and parsed_return_code != 0)
            )
            terminal_ok = task_status in {"success", "succeeded", "completed", "complete"} and (
                parsed_return_code is None or parsed_return_code == 0
            )
            running = task_status in {"pending", "queued", "running", "active", "in_progress"}
            runtime_conflict = running and return_code is not None
            healthy = (terminal_ok or running) and not runtime_conflict
            return {
                "success": healthy and not failed,
                "source_status": "conflict" if runtime_conflict else ("ok" if healthy and not failed else "partial"),
                "message": (
                    "The task is marked running although its process has already exited."
                    if runtime_conflict
                    else (
                        "Live task state loaded."
                        if healthy and not failed
                        else "The live task is failed or has an invalid runtime state."
                    )
                ),
                "task": payload,
                "return_code": return_code,
            }
        tasks: dict[str, dict[str, Any]] = {}
        failed_tasks: list[str] = []
        conflicting_tasks: list[str] = []
        valid_states = {
            "pending",
            "queued",
            "running",
            "active",
            "in_progress",
            "success",
            "succeeded",
            "completed",
            "complete",
        }
        for key, task in active_tasks.items():
            if not isinstance(task, dict):
                failed_tasks.append(str(key))
                continue
            safe_task = self._safe_task(task)
            tasks[str(key)] = safe_task
            task_status = str(safe_task.get("status") or "unknown").strip().lower()
            process = task.get("process")
            return_code = getattr(process, "returncode", None)
            bad_return_code = False
            if return_code is not None:
                try:
                    bad_return_code = int(return_code) != 0
                except (TypeError, ValueError):
                    bad_return_code = True
            running_state = task_status in {"pending", "queued", "running", "active", "in_progress"}
            if running_state and return_code is not None:
                conflicting_tasks.append(str(key))
            elif task_status not in valid_states or bad_return_code:
                failed_tasks.append(str(key))
        healthy = not failed_tasks and not conflicting_tasks
        return {
            "success": healthy,
            "source_status": "conflict" if conflicting_tasks else ("ok" if healthy else "partial"),
            "message": (
                "Live task registry loaded."
                if healthy
                else (
                    "Live task registry contains running tasks whose processes have exited: "
                    + f"{', '.join(conflicting_tasks)}."
                    if conflicting_tasks
                    else f"Live task registry contains failed or invalid tasks: {', '.join(failed_tasks)}."
                )
            ),
            "tasks": tasks,
            "failed_tasks": failed_tasks,
            "conflicting_tasks": conflicting_tasks,
        }

    async def _services_runtime(self, parameters: dict[str, Any]) -> dict[str, Any]:
        from app.core.service_manager import ServiceManager

        name = str(parameters["service_name"])
        try:
            status = ServiceManager().get_service_status(name)
        except FileNotFoundError:
            return self._missing("Service was not found in the allowlisted Services catalog.")
        payload = status.model_dump(mode="json") if hasattr(status, "model_dump") else dict(status)
        state = str(payload.get("state") or payload.get("status") or "").lower()
        running = payload.get("running")
        installed = payload.get("installed")
        running_states = {"running", "active"}
        failed_states = {"stopped", "inactive", "failed", "error", "dead", "unavailable"}
        conflict = (
            (running is False and state in running_states)
            or (running is True and state in failed_states)
            or (installed is False and (running is True or state in running_states))
        )
        if conflict:
            return {
                "success": False,
                "source_status": "conflict",
                "message": f"Service '{name}' returned conflicting runtime fields.",
                "service": payload,
            }
        healthy = running is True and installed is not False and (not state or state in running_states)
        return {
            "success": healthy,
            "source_status": "ok" if healthy else "partial",
            "message": f"Service '{name}' runtime state loaded.",
            "service": payload,
        }

    async def _backup_integrity(self, parameters: dict[str, Any]) -> dict[str, Any]:
        from app.services.rollback_service import RollbackService

        service = RollbackService()
        try:
            snapshot = service.get_snapshot(str(parameters["snapshot_id"]))
        except Exception as exc:
            return self._missing(f"Snapshot metadata unavailable: {exc}")
        metadata_errors: list[str] = []
        snapshot_status = str(getattr(snapshot, "status", "") or "").strip().lower()
        snapshot_error = str(getattr(snapshot, "error_message", "") or "").strip()
        if snapshot_status != "ready":
            metadata_errors.append(f"snapshot metadata status is {snapshot_status or 'unknown'}")
        if snapshot_error:
            metadata_errors.append(f"snapshot metadata reports: {snapshot_error}")
        archive_path = str(snapshot.archive_path or "")
        archive_candidate = Path(archive_path)
        if archive_path and archive_candidate.is_symlink():
            return self._missing("Snapshot archive is a symbolic link and cannot be restored safely.")
        real_path = os.path.realpath(archive_path)
        backup_root = os.path.realpath(str(service.backup_dir))
        if not archive_path or not real_path.startswith(backup_root + os.sep):
            return self._missing("Snapshot archive path is missing or outside the rollback backup directory.")
        path = Path(real_path)
        if not path.is_file() or path.is_symlink():
            return self._missing("Snapshot archive file is missing or unsafe.")
        actual_size = path.stat().st_size
        expected_size = getattr(snapshot, "size_bytes", None)
        if expected_size is not None:
            try:
                if int(expected_size) != actual_size:
                    metadata_errors.append(
                        f"snapshot size metadata is {int(expected_size)} bytes but archive is {actual_size} bytes"
                    )
            except (TypeError, ValueError):
                metadata_errors.append("snapshot size metadata is invalid")
        integrity_error: str | None = None
        if path.name.endswith(".epibak"):
            try:
                verification = subprocess.run(
                    [
                        "sudo",
                        "-n",
                        str(service.runner),
                        "backup/backup_file.sh",
                        "verify",
                        path.name,
                    ],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )
                if verification.returncode != 0:
                    integrity_error = (
                        "encrypted backup authentication or archive validation failed"
                    )
            except (OSError, subprocess.TimeoutExpired) as exc:
                integrity_error = f"privileged verification unavailable: {type(exc).__name__}"
        else:
            try:
                with tarfile.open(path, "r:*") as archive:
                    members = archive.getmembers()
                    if not members:
                        raise ValueError("archive contains no members")
                    if len(members) > 100_000:
                        raise ValueError("archive contains too many members")
                    for member in members:
                        member_path = Path(member.name.replace("\\", "/"))
                        if member_path.is_absolute() or ".." in member_path.parts:
                            raise ValueError(f"unsafe archive member path: {member.name}")
                        if member.isdev() or member.isfifo():
                            raise ValueError(f"unsafe special archive member: {member.name}")
                        if member.issym() or member.islnk():
                            link_path = Path(member.linkname.replace("\\", "/"))
                            if link_path.is_absolute() or ".." in link_path.parts:
                                raise ValueError(f"unsafe archive link target: {member.linkname}")
                        if member.isfile():
                            extracted = archive.extractfile(member)
                            if extracted is None:
                                raise ValueError(f"archive member payload is unreadable: {member.name}")
                            while extracted.read(1024 * 1024):
                                pass
            except (tarfile.TarError, OSError, ValueError) as exc:
                integrity_error = f"{type(exc).__name__}: {exc}"
        if integrity_error is not None:
            return {
                "success": False,
                "source_status": "partial",
                "message": f"Snapshot archive integrity check failed: {integrity_error}",
            }
        if metadata_errors:
            return {
                "success": False,
                "source_status": "conflict",
                "message": "Snapshot archive conflicts with its metadata: " + "; ".join(metadata_errors),
                "archive_size": actual_size,
                "metadata_status": snapshot_status or "unknown",
                "metadata_size": expected_size,
            }
        return {
            "success": True,
            "source_status": "ok",
            "message": "Snapshot archive structure and metadata are consistent.",
            "archive_size": actual_size,
            "metadata_status": snapshot_status,
            "metadata_size": expected_size,
        }

    async def _device_admission(self, parameters: dict[str, Any]) -> dict[str, Any]:
        from app.services.unknown_device_admission_service import UnknownDeviceAdmissionService

        service = UnknownDeviceAdmissionService()
        device_id = str(parameters.get("device_id") or "").strip()
        devices = service.list_devices(include_blocked=True)
        if device_id:
            match = next(
                (
                    item
                    for item in devices
                    if isinstance(item, dict) and str(item.get("id")) == device_id
                ),
                None,
            )
            if match is None:
                return self._missing("Unknown-device admission record was not found.")
            admission_status = str(match.get("status") or "unknown").strip().lower()
            healthy = admission_status in {"admitted", "approved", "allowed", "known", "trusted"}
            return {
                "success": healthy,
                "source_status": "ok" if healthy else "partial",
                "message": "Device admission state loaded." if healthy else f"Device is not admitted ({admission_status}).",
                "device": match,
                "block_mode": service.is_block_mode(),
            }
        healthy_states = {"admitted", "approved", "allowed", "known", "trusted"}
        unresolved: list[str] = []
        for item in devices:
            if not isinstance(item, dict):
                unresolved.append("invalid-record")
                continue
            if str(item.get("status") or "unknown").strip().lower() not in healthy_states:
                unresolved.append(str(item.get("id") or item.get("name") or "unknown"))
        healthy = not unresolved
        return {
            "success": healthy,
            "source_status": "ok" if healthy else "partial",
            "message": (
                "Unknown-device admission inventory loaded."
                if healthy
                else f"Device admission inventory contains unresolved or blocked devices: {', '.join(unresolved)}."
            ),
            "devices": devices,
            "block_mode": service.is_block_mode(),
            "unresolved_devices": unresolved,
        }

    async def _personal_dns_tenancy(self, parameters: dict[str, Any]) -> dict[str, Any]:
        from app.agent.adapters.personal_dns import PersonalDNSAdapter

        try:
            actor_user_id = int(parameters["actor_user_id"])
        except (KeyError, TypeError, ValueError):
            return self._missing("A valid authenticated user is required for this probe.")
        if actor_user_id <= 0:
            return self._missing("A valid authenticated user is required for this probe.")

        deploy = PersonalDNSAdapter().get_latest_deploy(user_id=actor_user_id)
        if deploy is None:
            return self._missing("No Personal DNS deployment belongs to the authenticated user.")
        # The deployment log can contain command output and infrastructure details;
        # the tenancy probe only exposes the scoped state required for diagnosis.
        safe_deploy = {
            key: value
            for key, value in deploy.items()
            if key not in {"deployment_log"}
        }
        deploy_status = str(safe_deploy.get("status") or "unknown").strip().lower()
        online = safe_deploy.get("is_online")
        last_check_raw = safe_deploy.get("last_check")
        last_check = self._parse_datetime(last_check_raw)
        now = datetime.now(timezone.utc)
        # Personal DNS stores a naive UTC value via utc_now(); parsing naive values
        # as UTC is therefore part of the source contract. Only tolerate ordinary
        # clock drift, not same-day future observations.
        if last_check is None:
            return {
                "success": False,
                "source_status": "unavailable",
                "message": (
                    "Personal DNS health timestamp is malformed."
                    if last_check_raw is not None and last_check_raw != ""
                    else "Personal DNS health observation has no timestamp."
                ),
                "deployment": safe_deploy,
            }
        stale = last_check < now - timedelta(hours=24)
        future = last_check > now + timedelta(minutes=5)
        healthy_status = deploy_status in {
            "active",
            "running",
            "online",
            "success",
            "completed",
            "deployed",
        }
        healthy = healthy_status and not stale and not future
        if stale or future:
            return {
                "success": False,
                "source_status": "stale" if stale else "conflict",
                "message": (
                    "Personal DNS online evidence is stale."
                    if stale
                    else "Personal DNS health timestamp is unexpectedly in the future."
                ),
                "deployment": safe_deploy,
            }
        if online is not True:
            return {
                "success": False,
                "source_status": "partial",
                "message": "Personal DNS online state is missing, false, or unverified.",
                "deployment": safe_deploy,
            }
        return {
            "success": healthy,
            "source_status": "ok" if healthy else "partial",
            "message": "Authenticated user's Personal DNS deployment is healthy." if healthy else "Authenticated user's Personal DNS deployment is failed, offline, or unverified.",
            "deployment": safe_deploy,
        }

    async def _wireguard_artifacts(self, parameters: dict[str, Any]) -> dict[str, Any]:
        import base64
        import configparser
        import ipaddress
        import re

        from app.api.v1.endpoints.wireguard import CLIENTS_DIR

        name = str(parameters.get("entity_id") or parameters.get("target") or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,32}", name):
            return self._missing("A valid WireGuard peer name is required.")
        root = Path(CLIENTS_DIR).resolve()
        config_path = (root / f"{name}.conf").resolve()
        qr_path = (root / f"{name}.png").resolve()
        if config_path.parent != root or qr_path.parent != root:
            return self._missing("WireGuard artifact path escaped the client directory.")
        errors: list[str] = []
        config_text = ""
        if not config_path.is_file() or config_path.is_symlink():
            errors.append("configuration file is missing or unsafe")
        else:
            try:
                if config_path.stat().st_size > 64 * 1024:
                    raise ValueError("configuration file is too large")
                parser = configparser.ConfigParser(interpolation=None, strict=True)
                config_text = config_path.read_text(encoding="utf-8")
                parser.read_string(config_text)
                if not parser.has_section("Interface") or not parser.has_section("Peer"):
                    raise ValueError("required Interface/Peer sections are missing")
                for section, field in (("Interface", "PrivateKey"), ("Peer", "PublicKey")):
                    key = parser.get(section, field, fallback="").strip()
                    if len(base64.b64decode(key, validate=True)) != 32:
                        raise ValueError(f"{section}.{field} is not a valid WireGuard key")
                address_value = parser.get("Interface", "Address", fallback="").strip()
                allowed_ips_value = parser.get("Peer", "AllowedIPs", fallback="").strip()
                endpoint_value = parser.get("Peer", "Endpoint", fallback="").strip()
                if not address_value or not allowed_ips_value or not endpoint_value:
                    raise ValueError("Address, AllowedIPs, and Endpoint are required")
                if not self._valid_wireguard_endpoint(endpoint_value):
                    raise ValueError("Peer.Endpoint must use a valid host:port value")
                for address in address_value.split(","):
                    if address.strip():
                        ipaddress.ip_interface(address.strip())
                for network in allowed_ips_value.split(","):
                    if network.strip():
                        ipaddress.ip_network(network.strip(), strict=False)
            except (OSError, UnicodeError, ValueError, configparser.Error) as exc:
                errors.append(f"configuration integrity failed: {exc}")
        if not qr_path.is_file() or qr_path.is_symlink():
            errors.append("QR image is missing or unsafe")
        else:
            try:
                from PIL import Image

                if qr_path.stat().st_size > 16 * 1024 * 1024:
                    raise ValueError("QR image is too large")
                with Image.open(qr_path) as image:
                    image.verify()
                decoded = subprocess.run(
                    ["zbarimg", "--quiet", "--raw", str(qr_path)],
                    capture_output=True,
                    text=True,
                    timeout=5,
                    check=False,
                )
                if decoded.returncode != 0 or not decoded.stdout.strip():
                    raise ValueError("QR payload could not be decoded")
                if decoded.stdout.strip().replace("\r\n", "\n") != config_text.strip().replace("\r\n", "\n"):
                    raise ValueError("QR payload does not match the peer configuration")
            except (OSError, subprocess.TimeoutExpired, ValueError) as exc:
                errors.append(f"QR integrity failed: {exc}")
        return {
            "success": not errors,
            "source_status": "ok" if not errors else "partial",
            "message": "WireGuard configuration and QR artifacts are structurally valid." if not errors else "; ".join(errors),
            "peer": name,
            "config_valid": not any("configuration" in error for error in errors),
            "qr_valid": not any("QR" in error for error in errors),
        }

    async def _ai_inference(self, _parameters: dict[str, Any]) -> dict[str, Any]:
        import httpx

        from app.api.v1.endpoints.ai import ai_service

        base_url = str(ai_service.ollama_url).rstrip("/")
        timeout = httpx.Timeout(20.0, connect=3.0)
        try:
            async with httpx.AsyncClient(timeout=timeout) as client:
                tags_response = await client.get(f"{base_url}/api/tags")
                tags_response.raise_for_status()
                models = tags_response.json().get("models") or []
                model_name = str((models[0] if models else {}).get("name") or "")
                if not model_name:
                    return self._missing("Ollama is reachable but no installed model is available for inference.")
                response = await client.post(
                    f"{base_url}/api/generate",
                    json={"model": model_name, "prompt": "Reply with OK.", "stream": False, "options": {"num_predict": 2}},
                )
                response.raise_for_status()
                payload = response.json()
        except (httpx.HTTPError, ValueError, TypeError) as exc:
            return self._missing(f"AI inference probe failed: {type(exc).__name__}: {exc}")
        generated = (
            isinstance(payload, dict)
            and isinstance(payload.get("response"), str)
            and bool(payload.get("response", "").strip())
            and payload.get("done") is True
        )
        return {
            "success": generated,
            "source_status": "ok" if generated else "partial",
            "message": "AI model completed a bounded inference probe." if generated else "AI runtime returned an invalid inference payload.",
            "model": model_name,
            "done": bool(payload.get("done")) if isinstance(payload, dict) else False,
        }

    async def _heuristic_alerts(self, parameters: dict[str, Any]) -> dict[str, Any]:
        from app.api.v1.endpoints.heuristics import get_alerts

        payload = await get_alerts(
            severity=parameters.get("severity"),
            alert_type=None,
            acknowledged=False,
            limit=int(parameters.get("limit") or 50),
            current_user=None,
        )
        if payload.get("error"):
            return {"success": False, "source_status": "unavailable", "message": str(payload["error"]), "alerts": []}
        raw_alerts = payload.get("alerts", [])
        if not isinstance(raw_alerts, list):
            return self._missing("Heuristic alert source returned an invalid alerts schema.")
        malformed = sum(not isinstance(item, dict) for item in raw_alerts)
        alerts = [
            item
            for item in raw_alerts
            if isinstance(item, dict)
            and not bool(item.get("acknowledged"))
            and str(item.get("state") or "active").lower() not in {"allowed", "allowlisted", "acknowledged", "dismissed", "resolved"}
        ]
        reported_total = payload.get("total")
        reported_unacknowledged = payload.get("unacknowledged")
        missing_counts = [
            name
            for name, value in (
                ("total", reported_total),
                ("unacknowledged", reported_unacknowledged),
            )
            if value is None
        ]
        invalid_counts = [
            name
            for name, value in (
                ("total", reported_total),
                ("unacknowledged", reported_unacknowledged),
            )
            if value is not None
            and (not isinstance(value, int) or isinstance(value, bool) or value < 0)
        ]
        contradictory_counts = []
        if not malformed and not missing_counts and not invalid_counts:
            if reported_total != len(raw_alerts):
                contradictory_counts.append("total")
            if reported_unacknowledged != len(alerts):
                contradictory_counts.append("unacknowledged")
        counts_valid = not missing_counts and not invalid_counts and not contradictory_counts
        healthy = not alerts and not malformed and counts_valid
        critical = sum(str(item.get("severity") or "").lower() == "critical" for item in alerts)
        if contradictory_counts:
            source_status = "conflict"
            message = (
                "Heuristic alert counters contradict the returned alert records: "
                f"{', '.join(contradictory_counts)}."
            )
        elif missing_counts or invalid_counts:
            source_status = "partial"
            affected = missing_counts + invalid_counts
            message = f"Heuristic alert source has missing or invalid counters: {', '.join(affected)}."
        elif healthy:
            source_status = "ok"
            message = "Heuristic alert records loaded; no active unacknowledged alerts were found."
        elif alerts:
            source_status = "partial"
            message = f"Heuristic engine has {len(alerts)} active unacknowledged alert(s), including {critical} critical."
        else:
            source_status = "partial"
            message = f"Heuristic alert source contains {malformed} malformed record(s)."
        return {
            **payload,
            "success": healthy,
            "source_status": source_status,
            "message": message,
            "alerts": alerts,
            "total": len(alerts),
            "unacknowledged": len(alerts),
            "malformed_records": malformed,
            "reported_total": reported_total,
            "reported_unacknowledged": reported_unacknowledged,
        }

    async def _netprotection_components(self, _parameters: dict[str, Any]) -> dict[str, Any]:
        from app.services.netprotection_service import netprotection_service

        status = await netprotection_service.get_status()
        standalone = os.environ.get("NETPROTECTION_STANDALONE", "").strip().lower() in {"1", "true", "yes"}
        tasks = {
            "prism_policy": self._task_state(netprotection_service._prism_flow_policy_task),
            "fail_closed_worker": self._task_state(netprotection_service._fail_closed_worker_task),
            "failsafe_monitor": self._task_state(netprotection_service._failsafe_monitor_task),
        }
        failed_states = {"failed", "completed", "cancelled"}
        failed = [name for name, state in tasks.items() if state in failed_states]
        if not standalone:
            failed.extend(name for name, state in tasks.items() if state == "stopped")
        flow_logger_state = "running" if netprotection_service._flow_logger is not None else "not_initialized"
        if not standalone and flow_logger_state != "running":
            failed.append("flow_logger")
        running = bool(status.get("running"))
        return {
            "success": running and not failed,
            "source_status": "ok" if running and not failed else "partial",
            "message": "NetProtection components are healthy." if running and not failed else "One or more NetProtection components are unavailable.",
            "runtime": status,
            "standalone": standalone,
            "tasks": tasks,
            "failed_components": sorted(set(failed)),
            "flow_logger": flow_logger_state,
        }

    def _operation_evidence(self, probe_id: str, parameters: dict[str, Any]) -> dict[str, Any]:
        prefixes = self._EVENT_PREFIXES.get(probe_id, ())
        target = str(parameters.get("target") or parameters.get("entity_id") or "").strip().lower()
        for event in self.operation_events.list_events(limit=200):
            if prefixes and not any(event.action_id.startswith(prefix) for prefix in prefixes):
                continue
            haystack = " ".join(filter(None, (event.title, event.subtitle, event.message))).lower()
            if target and not self._matches_event_target(target, haystack):
                continue
            status = str(event.status or "unknown").lower()
            observed_at = self._parse_datetime(event.updated_at or event.started_at)
            if observed_at is None:
                return {
                    "success": False,
                    "source_status": "unavailable",
                    "message": "Matching operational evidence has no valid timestamp.",
                    "event": asdict(event),
                }
            if observed_at > datetime.now(timezone.utc) + timedelta(minutes=5):
                return {
                    "success": False,
                    "source_status": "conflict",
                    "message": "Matching operational evidence has a future timestamp.",
                    "event": asdict(event),
                }
            if observed_at < datetime.now(timezone.utc) - timedelta(days=7):
                return {
                    "success": False,
                    "source_status": "stale",
                    "message": "Matching operational evidence is stale and cannot prove current state.",
                    "event": asdict(event),
                }
            return {
                "success": status in {"success", "completed", "ok"},
                "source_status": "ok" if status in {"success", "completed", "ok"} else "partial",
                "message": event.message or event.title,
                "event": asdict(event),
            }
        return self._missing("No matching operational evidence is available for this probe.")

    @staticmethod
    def _matches_event_target(target: str, haystack: str) -> bool:
        normalized = str(target or "").strip().lower()
        if not normalized:
            return True
        boundary_chars = r"A-Za-z0-9._:@/+-"
        return re.search(
            rf"(?<![{boundary_chars}]){re.escape(normalized)}(?![{boundary_chars}])",
            str(haystack or "").lower(),
        ) is not None

    def _safe_task(self, task: dict[str, Any]) -> dict[str, Any]:
        return {key: value for key, value in task.items() if key not in {"process"}}

    def _read_json_file(self, path: Path, *, max_bytes: int = 8 * 1024 * 1024) -> dict[str, Any]:
        if not path.exists():
            return {"data": None}
        if not path.is_file() or path.is_symlink():
            return {"error": f"Unsafe data source: {path.name}."}
        try:
            if path.stat().st_size > max_bytes:
                return {"error": f"Data source is too large: {path.name}."}
            return {"data": json.loads(path.read_text(encoding="utf-8"))}
        except (OSError, json.JSONDecodeError) as exc:
            return {"error": f"Could not load {path.name}: {type(exc).__name__}: {exc}"}

    def _latest_auth_log_timestamp(self, path: Path, *, now: datetime) -> datetime | None:
        """Read the newest parseable entry timestamp instead of trusting file mtime."""

        sample = self._read_last_line_block(path, max_bytes=512 * 1024)
        for line in reversed(sample):
            iso_match = re.match(r"^(\d{4}-\d{2}-\d{2}T\S+)", line)
            if iso_match:
                parsed = self._parse_datetime(iso_match.group(1))
                if parsed is not None:
                    return parsed
            syslog_match = re.match(r"^([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})", line)
            if syslog_match:
                try:
                    local_timezone = datetime.now().astimezone().tzinfo or timezone.utc
                    local_now = now.astimezone(local_timezone)
                    parsed = datetime.strptime(
                        f"{local_now.year} {syslog_match.group(1)}", "%Y %b %d %H:%M:%S"
                    ).replace(tzinfo=local_timezone)
                    if parsed > local_now + timedelta(days=1):
                        parsed = parsed.replace(year=parsed.year - 1)
                    return parsed.astimezone(timezone.utc)
                except ValueError:
                    continue
        return None

    def _read_last_line_block(self, path: Path, *, max_bytes: int) -> list[str]:
        with path.open("rb") as handle:
            size = handle.seek(0, os.SEEK_END)
            handle.seek(max(0, size - max_bytes))
            data = handle.read(max_bytes)
        return [line.decode("utf-8", errors="replace") for line in data.splitlines() if line.strip()]

    def _read_last_line(self, path: Path, *, max_bytes: int) -> str:
        lines = self._read_last_line_block(path, max_bytes=max_bytes)
        return lines[-1] if lines else ""

    def _task_state(self, task: Any) -> str:
        if task is None:
            return "stopped"
        if task.cancelled():
            return "cancelled"
        if task.done():
            try:
                return "failed" if task.exception() is not None else "completed"
            except (asyncio.CancelledError, RuntimeError):
                return "cancelled"
        return "running"

    @staticmethod
    def _matches_exact_target(target: str, values: tuple[Any, ...]) -> bool:
        normalized = str(target or "").strip().casefold()
        candidates: list[Any] = []
        for value in values:
            if isinstance(value, (list, tuple, set, frozenset)):
                candidates.extend(value)
            else:
                candidates.append(value)
        return bool(normalized) and any(
            str(value or "").strip().casefold() == normalized for value in candidates
        )

    @staticmethod
    def _valid_wireguard_endpoint(value: str) -> bool:
        import ipaddress

        endpoint = str(value or "").strip()
        host = ""
        port_text = ""
        if endpoint.startswith("["):
            match = re.fullmatch(r"\[([^\]]+)\]:(\d{1,5})", endpoint)
            if not match:
                return False
            host, port_text = match.groups()
            try:
                ipaddress.IPv6Address(host)
            except ValueError:
                return False
        else:
            host, separator, port_text = endpoint.rpartition(":")
            if not separator or not host or ":" in host:
                return False
            try:
                ipaddress.ip_address(host)
            except ValueError:
                if len(host) > 253 or not all(
                    re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
                    for label in host.rstrip(".").split(".")
                ):
                    return False
        try:
            port = int(port_text)
        except ValueError:
            return False
        return 1 <= port <= 65535

    def _parse_datetime(self, value: Any) -> datetime | None:
        normalized = str(value or "").strip()
        if not normalized:
            return None
        if normalized.endswith("Z"):
            normalized = normalized[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(normalized)
        except ValueError:
            return None
        return parsed.replace(tzinfo=parsed.tzinfo or timezone.utc).astimezone(timezone.utc)

    def _missing(self, message: str) -> dict[str, Any]:
        return {"success": False, "source_status": "unavailable", "message": message}
