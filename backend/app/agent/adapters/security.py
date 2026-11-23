"""Security scan and fix fact adapter."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from app.db.session import SessionLocal
from app.models.security import SecurityScan
from app.services.security_service import SecurityService
from app.services.threat_service import threat_service


class SecurityAdapter:
    """Expose read-only security scan and monitoring state."""

    def __init__(
        self,
        service: Any | None = None,
        *,
        threat_monitor: Any | None = None,
        session_factory: Callable[[], Any] | None = None,
    ) -> None:
        self.service = service or SecurityService()
        self.threat_monitor = threat_monitor or threat_service
        self.session_factory = session_factory or SessionLocal

    async def run_scan(self) -> dict[str, Any]:
        db = self.session_factory()
        try:
            result = await self.service.run_security_scan(db)
            if hasattr(result, "model_dump"):
                return result.model_dump(mode="json")
            return dict(result)
        finally:
            db.close()

    def get_latest_scan(self) -> dict[str, Any] | None:
        db = self.session_factory()
        try:
            latest = (
                db.query(SecurityScan)
                .order_by(SecurityScan.scan_date.desc(), SecurityScan.id.desc())
                .first()
            )
            if latest is None:
                return None

            raw_payload = latest.scan_data or "{}"
            try:
                payload = json.loads(raw_payload)
            except json.JSONDecodeError:
                payload = {}

            if not isinstance(payload, dict):
                payload = {}

            payload.setdefault("critical", [])
            payload.setdefault("warnings", [])
            payload.setdefault("passed", [])
            payload["last_scan"] = latest.scan_date.isoformat() if latest.scan_date else None
            return payload
        finally:
            db.close()

    def get_outdated_packages_status(self, job_id: str | None = None) -> dict[str, Any]:
        status = self.service.get_outdated_packages_status(job_id)
        if hasattr(status, "model_dump"):
            return status.model_dump(mode="json")
        return dict(status)

    async def get_threat_monitor_status(self) -> dict[str, Any]:
        status = await self.threat_monitor.get_status()
        return status if isinstance(status, dict) else {}

    async def fix_firewall(self) -> dict[str, Any]:
        db = self.session_factory()
        try:
            result = await self.service.fix_firewall()
            if hasattr(result, "model_dump"):
                return result.model_dump(mode="json")
            return dict(result) if isinstance(result, dict) else {"success": False, "message": "Firewall remediation returned no completion evidence."}
        finally:
            db.close()

    async def fix_password_auth(self) -> dict[str, Any]:
        db = self.session_factory()
        try:
            result = await self.service.fix_password_auth()
            if hasattr(result, "model_dump"):
                return result.model_dump(mode="json")
            return dict(result) if isinstance(result, dict) else {"success": False, "message": "Password-auth remediation returned no completion evidence."}
        finally:
            db.close()

    async def fix_filesystem_readonly(self) -> dict[str, Any]:
        db = self.session_factory()
        try:
            result = await self.service.fix_filesystem_readonly()
            if hasattr(result, "model_dump"):
                return result.model_dump(mode="json")
            return dict(result) if isinstance(result, dict) else {"success": False, "message": "Filesystem remediation returned no completion evidence."}
        finally:
            db.close()

    async def start_outdated_packages_fix(self) -> dict[str, Any]:
        result = await self.service.start_outdated_packages_fix()
        if hasattr(result, "model_dump"):
            return result.model_dump(mode="json")
        return dict(result) if isinstance(result, dict) else {"success": False, "message": "Package remediation returned no completion evidence."}

    def get_audit_logs(self, limit: int = 20) -> list[dict[str, Any]]:
        logs: list[dict[str, Any]] = []
        candidates = [Path("/var/log/auth.log"), Path("/var/log/secure"), Path("/var/log/messages")]
        for path in candidates:
            if not path.exists():
                continue
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except Exception:
                continue
            for line in lines[-limit:]:
                text = str(line).strip()
                if not text:
                    continue
                logs.append({"source": str(path), "message": text})
            if logs:
                break
        return logs
