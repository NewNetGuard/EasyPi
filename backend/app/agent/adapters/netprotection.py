"""NetProtection fact adapter for the EasyPi agent."""

from __future__ import annotations

from typing import Any


class NetProtectionAdapter:
    """Wrap NetProtection service calls for agent modules."""

    def __init__(
        self,
        service: Any | None = None,
        *,
        firewall: Any | None = None,
        threat_monitor: Any | None = None,
        heuristics_api: Any | None = None,
    ) -> None:
        if service is None:
            from app.services.netprotection_service import netprotection_service

            service = netprotection_service
        self.service = service
        self._firewall = firewall
        self._threat_monitor = threat_monitor
        self._heuristics_api = heuristics_api

    @staticmethod
    def _as_dict(value: Any) -> dict[str, Any]:
        if hasattr(value, "model_dump"):
            value = value.model_dump(mode="json")
        return dict(value) if isinstance(value, dict) else {}

    @classmethod
    def _unwrap_data(cls, value: Any) -> dict[str, Any]:
        payload = cls._as_dict(value)
        data = payload.get("data")
        return dict(data) if isinstance(data, dict) else payload

    @staticmethod
    def _as_list(value: Any) -> list[dict[str, Any]]:
        return [item for item in value if isinstance(item, dict)] if isinstance(value, list) else []

    def _get_firewall(self) -> Any:
        if self._firewall is None:
            from app.services.firewall_service import firewall_service

            self._firewall = firewall_service
        return self._firewall

    def _get_threat_monitor(self) -> Any:
        if self._threat_monitor is None:
            from app.services.threat_service import threat_service

            self._threat_monitor = threat_service
        return self._threat_monitor

    def _get_heuristics_api(self) -> Any:
        if self._heuristics_api is None:
            from app.api.v1.endpoints import heuristics

            self._heuristics_api = heuristics
        return self._heuristics_api

    async def get_clients(self) -> list[dict[str, Any]]:
        data = await self.service.get_clients()
        clients = data.get("clients", []) if isinstance(data, dict) else []
        return [client for client in clients if isinstance(client, dict)]

    async def get_client_activity(self, client_ips: list[str]) -> dict[str, dict[str, Any]]:
        activity = await self.service.get_client_activity(client_ips)
        return activity if isinstance(activity, dict) else {}

    def get_bypass_events(self) -> dict[str, dict[str, Any]]:
        events = self.service.get_bypass_events()
        return events if isinstance(events, dict) else {}

    def get_fail_closed_triggers(self) -> dict[str, dict[str, Any]]:
        triggers = self.service.get_fail_closed_triggers()
        return triggers if isinstance(triggers, dict) else {}

    async def list_fail_closed_clients(self) -> set[str]:
        raw = await self.service.list_fail_closed_clients()
        return {str(value).strip() for value in raw if str(value).strip()}

    async def get_verdicts(self, *, search: str, limit: int = 25) -> list[dict[str, Any]]:
        result = await self.service.get_verdicts(search=search, limit=limit)
        data = result.get("data", []) if isinstance(result, dict) else []
        return [entry for entry in data if isinstance(entry, dict)]

    async def get_status(self) -> dict[str, Any]:
        status = await self.service.get_status()
        return status if isinstance(status, dict) else {}

    async def get_stats(self) -> dict[str, Any]:
        stats = await self.service.get_stats()
        return stats if isinstance(stats, dict) else {}

    async def get_dashboard_stats(self) -> dict[str, Any]:
        stats = await self.service.get_dashboard_stats()
        return stats if isinstance(stats, dict) else {}

    async def get_query_log_stats(self) -> dict[str, Any]:
        stats = await self.service.get_query_log_stats()
        return stats if isinstance(stats, dict) else {}

    async def get_recent_verdicts(self, *, limit: int = 25) -> list[dict[str, Any]]:
        result = await self.service.get_verdicts(limit=limit)
        data = result.get("data", []) if isinstance(result, dict) else []
        return self._as_list(data)

    async def get_config(self) -> dict[str, Any]:
        return self._as_dict(await self.service.get_config())

    async def get_dns_config(self) -> dict[str, Any]:
        return self._as_dict(await self.service.get_dns_config())

    async def get_query_log_config(self) -> dict[str, Any]:
        return self._as_dict(await self.service.get_query_log_config())

    async def get_upstream_servers(self) -> dict[str, Any]:
        return self._as_dict(await self.service.get_upstream_servers())

    async def get_period_stats(self, period: str = "24h") -> dict[str, Any]:
        return self._as_dict(await self.service.get_period_stats(period))

    async def get_encrypted_dns_settings(self) -> dict[str, Any]:
        result = await self.service.get_encrypted_dns_settings()
        if not isinstance(result, dict):
            return {}
        # The service wraps the real values in {"success", "data": {...}};
        # unwrap so the agent sees doh_enabled/dot_enabled/tls_ready directly,
        # and map them onto the flat keys the diagnostic module reads.
        data = result.get("data")
        data = data if isinstance(data, dict) else result
        doh = bool(data.get("doh_enabled"))
        dot = bool(data.get("dot_enabled"))
        enriched = dict(data)
        enriched["doh_enabled"] = doh
        enriched["dot_enabled"] = dot
        enriched["enabled"] = doh or dot
        enriched.setdefault("tls_cert_path", bool(data.get("tls_ready")))
        return enriched

    async def test_upstream_dns(self, servers: list[str]) -> dict[str, Any]:
        result = await self.service.test_upstream_dns(servers)
        return result if isinstance(result, dict) else {}

    async def get_matchers(self) -> list[dict[str, Any]]:
        matchers = await self.service.get_matchers()
        return [matcher for matcher in matchers if isinstance(matcher, dict)]

    async def get_whitelist(self) -> list[dict[str, Any]]:
        entries = await self.service.get_whitelist()
        return [entry for entry in entries if isinstance(entry, dict)]

    async def get_blacklist(self) -> list[dict[str, Any]]:
        entries = await self.service.get_blacklist()
        return [entry for entry in entries if isinstance(entry, dict)]

    async def get_rewrites(self) -> list[dict[str, Any]]:
        rewrites = await self.service.get_rewrites()
        return [rewrite for rewrite in rewrites if isinstance(rewrite, dict)]

    async def get_shield_profiles(self) -> list[dict[str, Any]]:
        profiles = await self.service.get_shield_profiles()
        return [profile for profile in profiles if isinstance(profile, dict)]

    async def get_user_rules(self) -> list[str]:
        rules = await self.service.get_user_rules()
        return [str(rule) for rule in rules if rule]

    async def get_shadow_domains(self, *, limit: int = 25) -> list[dict[str, Any]]:
        domains = await self.service.get_shadow_domains(limit=limit)
        if isinstance(domains, dict):
            data = domains.get("domains")
            if not isinstance(data, list):
                data = domains.get("data", [])
            return self._as_list(data)
        return self._as_list(domains)

    async def get_shadow_stats(self) -> dict[str, Any]:
        stats = await self.service.get_shadow_stats()
        return self._unwrap_data(stats)

    async def get_shadow_mode_settings(self) -> dict[str, Any]:
        return self._unwrap_data(await self.service.get_shadow_mode_settings())

    async def get_schedules(self) -> list[dict[str, Any]]:
        result = self._as_dict(await self.service.get_schedules())
        return self._as_list(result.get("data", []))

    async def get_schedule_enforcement_status(self) -> dict[str, Any]:
        return self._as_dict(await self.service.get_schedule_enforcement_status())

    async def get_devices_with_baseline(self) -> dict[str, Any]:
        raw_devices = await self.service.get_devices()
        if isinstance(raw_devices, list):
            devices = self._as_list(raw_devices)
            return {
                "items": devices,
                "total": len(devices),
                "page": 1,
                "page_size": len(devices),
                "pages": 1 if devices else 0,
                "baseline_available": False,
            }

        try:
            result = self._unwrap_data(await self.service.get_devices_with_baseline())
            if isinstance(result.get("items"), list):
                return result
        except Exception:
            # Older installations store devices.json as a top-level list, while
            # get_devices_with_baseline() in those releases expects a wrapped
            # {"devices": [...]} object. Fall through to the compatible reader.
            pass

        if isinstance(raw_devices, dict):
            raw_devices = raw_devices.get("devices", [])
        devices = self._as_list(raw_devices)
        return {
            "items": devices,
            "total": len(devices),
            "page": 1,
            "page_size": len(devices),
            "pages": 1 if devices else 0,
            "baseline_available": False,
        }

    async def get_blocked_services(self) -> list[str]:
        result = await self.service.get_blocked_services_list()
        return [str(item) for item in result if item] if isinstance(result, list) else []

    def get_bypass_history(self) -> dict[str, dict[str, Any]]:
        result = self.service.get_bypass_history()
        return result if isinstance(result, dict) else {}

    async def get_blocklist_status(self) -> dict[str, Any]:
        return self._as_dict(await self.service.get_blocklist_status())

    async def get_verified_sources(self) -> list[dict[str, Any]]:
        return self._as_list(await self.service.get_verified_sources())

    async def get_custom_sources(self) -> list[dict[str, Any]]:
        return self._as_list(await self.service.get_custom_sources())

    def get_use_custom_blocklist(self) -> dict[str, Any]:
        return self._as_dict(self.service.get_use_custom_blocklist())

    async def get_blocklist_progress(self) -> dict[str, Any]:
        return self._as_dict(await self.service.get_blocklist_progress())

    async def get_all_settings(self) -> dict[str, Any]:
        return self._unwrap_data(await self.service.get_all_settings())

    async def get_ipv6_status(self) -> dict[str, Any]:
        return self._unwrap_data(await self.service.get_ipv6_status())

    async def get_failsafe_settings(self) -> dict[str, Any]:
        return self._unwrap_data(await self.service.get_failsafe_settings())

    async def get_firewall_rules(self) -> list[dict[str, Any]]:
        return self._as_list(await self._get_firewall().get_rules())

    async def get_threat_monitor_status(self) -> dict[str, Any]:
        return self._as_dict(await self._get_threat_monitor().get_status())

    async def get_threats(self, *, limit: int = 100) -> list[dict[str, Any]]:
        return self._as_list(await self._get_threat_monitor().get_threats(limit=limit))

    async def get_banned_threats(self) -> list[dict[str, Any]]:
        return self._as_list(await self._get_threat_monitor().get_banned_threats())

    async def get_ad_tracker_stats(self) -> dict[str, Any]:
        api = self._get_heuristics_api()
        return self._unwrap_data(await api.get_ad_tracker_stats(range="today", current_user=None))

    async def get_recent_ad_tracker_detections(self, *, limit: int = 10) -> list[dict[str, Any]]:
        api = self._get_heuristics_api()
        result = self._as_dict(await api.get_recent_ad_tracker_detections(limit=limit, current_user=None))
        return self._as_list(result.get("data", []))

    async def get_nrd_status(self) -> dict[str, Any]:
        api = self._get_heuristics_api()
        return self._as_dict(await api.get_nrd_status(_admin=None))

    async def get_nrd_blocked(self, *, limit: int = 10) -> list[dict[str, Any]]:
        api = self._get_heuristics_api()
        result = self._as_dict(await api.get_nrd_blocked(limit=limit, _admin=None))
        return self._as_list(result.get("domains", []))

    async def get_heuristics_stats(self) -> dict[str, Any]:
        api = self._get_heuristics_api()
        return self._as_dict(await api.get_heuristics_stats(current_user=None))

    async def get_heuristics_config(self) -> dict[str, Any]:
        api = self._get_heuristics_api()
        return self._as_dict(await api.get_heuristics_config(current_user=None))

    async def get_ml_status(self) -> dict[str, Any]:
        api = self._get_heuristics_api()
        return self._as_dict(await api.get_ml_status(_admin=None))

    async def restore_internet(self, client_ip: str) -> dict[str, Any]:
        result = await self.service.unquarantine_client(client_ip)
        return result if isinstance(result, dict) else {"success": False, "message": "Unexpected restore result"}

    async def add_to_whitelist(self, domain: str) -> dict[str, Any]:
        from app.services.netprotection_components.policy_data import (
            ALLOWLIST_SOURCE_ASSISTANT,
        )

        try:
            result = await self.service.add_to_whitelist(
                domain, source=ALLOWLIST_SOURCE_ASSISTANT
            )
        except ValueError as exc:  # not one host name, or a shared zone
            return {"success": False, "message": str(exc)}
        return result if isinstance(result, dict) else {"success": False, "message": "Unexpected whitelist result"}

    async def add_to_blacklist(self, domain: str) -> dict[str, Any]:
        try:
            result = await self.service.add_to_blacklist(domain)
        except ValueError as exc:  # not one host name
            return {"success": False, "message": str(exc)}
        return result if isinstance(result, dict) else {"success": False, "message": "Unexpected blacklist result"}

    async def restart_service(self) -> dict[str, Any]:
        result = await self.service.restart_service()
        return result if isinstance(result, dict) else {"success": False, "message": "Unexpected restart result"}

    async def start_service(self) -> dict[str, Any]:
        result = await self.service.start_service()
        return result if isinstance(result, dict) else {"success": False, "message": "Unexpected start result"}

    async def stop_service(self) -> dict[str, Any]:
        result = await self.service.stop_service()
        return result if isinstance(result, dict) else {"success": False, "message": "Unexpected stop result"}

    async def enable_protection(self) -> dict[str, Any]:
        result = await self.service.enable_protection()
        return result if isinstance(result, dict) else {"success": False, "message": "Unexpected enable result"}

    async def disable_protection(self) -> dict[str, Any]:
        result = await self.service.disable_protection()
        return result if isinstance(result, dict) else {"success": False, "message": "Unexpected disable result"}
