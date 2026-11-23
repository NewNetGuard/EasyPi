"""Personal DNS fact adapter."""

from __future__ import annotations

from typing import Any, Callable

from app.api.v1.endpoints.dns import get_dns_status
from app.db.session import SessionLocal
from app.models.dns_deploy import DNSDeploy


class PersonalDNSAdapter:
    """Expose read-only Personal DNS deployment state."""

    def __init__(self, *, session_factory: Callable[[], Any] | None = None) -> None:
        self.session_factory = session_factory or SessionLocal

    def get_latest_deploy(self, *, user_id: int | None = None) -> dict[str, Any] | None:
        db = self.session_factory()
        try:
            query = db.query(DNSDeploy)
            if user_id is not None:
                query = query.filter(DNSDeploy.user_id == user_id)
            deploy = query.order_by(
                DNSDeploy.deployment_date.desc(),
                DNSDeploy.id.desc(),
            ).first()
            if deploy is None:
                return None

            return {
                "id": deploy.id,
                "vps_ip": deploy.vps_ip,
                "domain": deploy.domain,
                "dns_ipv4": deploy.dns_ipv4,
                "admin_url": deploy.admin_url,
                "doh_url": deploy.doh_url,
                "dot_address": deploy.dot_address,
                "status": deploy.status,
                "deployment_date": deploy.deployment_date.isoformat() if deploy.deployment_date else None,
                "last_check": deploy.last_check.isoformat() if deploy.last_check else None,
                "is_online": deploy.is_online,
                "wireguard_installed": bool(deploy.wireguard_installed),
                "warnings": list(deploy.warnings or []),
                "recommendations": list(deploy.recommendations or []),
                "deployment_log": deploy.deployment_log,
            }
        finally:
            db.close()

    async def get_remote_status(self, vps_ip: str) -> dict[str, Any]:
        status = await get_dns_status(vps_ip)
        return status if isinstance(status, dict) else {}

    def inspect_deployment_log(self, deploy: dict[str, Any] | None) -> dict[str, bool]:
        text = str((deploy or {}).get("deployment_log") or "").lower()
        return {
            "mentions_certificate": any(token in text for token in ("certificate", "certbot", "tls")),
            "mentions_upstream": any(token in text for token in ("upstream", "resolver", "dns server", "dns query")),
            "mentions_cleanup": any(token in text for token in ("cleanup", "remove", "deleted", "destroy")),
            "mentions_firewall": any(token in text for token in ("ufw", "iptables", "firewall", "port 53", "port 443", "port 853")),
        }
