"""
EasyPi NetProtection — Gateway Routes Module.

HTTP REST API для интеграции с EasyPi Dashboard.
Все эндпоинты под base path /api/v1/netprotection.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from datetime import datetime
from typing import Any, TYPE_CHECKING

if TYPE_CHECKING:
    from ..system.bootstrap import BootstrapContext

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

API_VERSION = "v1"
BASE_PATH = f"/api/{API_VERSION}/netprotection"


# ════════════════════════════════════════════════════════════════════════════════
# REQUEST/RESPONSE MODELS
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class APIResponse:
    """Стандартный ответ API."""
    
    success: bool
    data: Any = None
    error: str | None = None
    
    def to_dict(self) -> dict[str, Any]:
        result = {"success": self.success}
        if self.data is not None:
            result["data"] = self.data
        if self.error is not None:
            result["error"] = self.error
        return result


@dataclass
class PaginatedResponse:
    """Ответ с пагинацией."""
    
    items: list[Any]
    total: int
    page: int
    page_size: int
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "success": True,
            "data": {
                "items": self.items,
                "total": self.total,
                "page": self.page,
                "page_size": self.page_size,
                "pages": (self.total + self.page_size - 1) // self.page_size,
            },
        }


# ════════════════════════════════════════════════════════════════════════════════
# ROUTE HANDLERS
# ════════════════════════════════════════════════════════════════════════════════

class NetProtectionAPI:
    """
    HTTP API для NetProtection.
    
    Предоставляет REST endpoints для:
    - Статус и метрики
    - Управление правилами (matchers)
    - Управление устройствами
    - Shield профили
    - Chronicle (история запросов)
    """
    
    def __init__(self, context: "BootstrapContext"):
        self._context = context
    
    # ─────────────────────────────────────────────────────────────────────────
    # Status & Health
    # ─────────────────────────────────────────────────────────────────────────
    
    async def get_status(self) -> dict[str, Any]:
        """
        GET /status
        
        Состояние модуля и базовая статистика.
        """
        guardian_status = {}
        if self._context.guardian:
            guardian_status = self._context.guardian.get_status()
        
        metrics_summary = {}
        if self._context.metrics:
            metrics_summary = self._context.metrics.get_summary()
        
        return APIResponse(
            success=True,
            data={
                "enabled": True,
                "ready": self._context.ready,
                "guardian": guardian_status,
                "metrics": metrics_summary,
                "uptime_seconds": self._context.metrics.registry.uptime_seconds() if self._context.metrics else 0,
            },
        ).to_dict()
    
    async def get_health(self) -> dict[str, Any]:
        """
        GET /health
        
        Health check для load balancer.
        """
        if self._context.guardian:
            health = self._context.guardian.get_health_summary()
            is_healthy = all(
                status.value in ("healthy", "degraded")
                for status in health.values()
            )
        else:
            is_healthy = self._context.ready
            health = {}
        
        return APIResponse(
            success=is_healthy,
            data={
                "status": "healthy" if is_healthy else "unhealthy",
                "components": {k: v.value if hasattr(v, 'value') else v for k, v in health.items()},
            },
        ).to_dict()
    
    async def get_cache_health(self) -> dict[str, Any]:
        """
        GET /cache/health
        
        Состояние кэшей (CNAME analyzer, DNS cache).
        Полезно для мониторинга hit rate.
        """
        cache_health = {
            "status": "healthy",
            "warnings": [],
            "caches": {},
        }
        
        # CNAME analyzer cache
        if self._context.verdict_engine:
            try:
                engine_health = self._context.verdict_engine.get_cache_health()
                if "cname_cache" in engine_health:
                    cache_health["caches"]["cname_analyzer"] = engine_health["cname_cache"]
                if engine_health.get("warnings"):
                    cache_health["warnings"].extend(engine_health["warnings"])
                if engine_health.get("status") == "degraded":
                    cache_health["status"] = "degraded"
            except Exception as e:
                cache_health["caches"]["cname_analyzer"] = {"error": str(e)}
        
        # DNS cache
        if self._context.dns_cache:
            try:
                dns_stats = self._context.dns_cache.stats()
                total = dns_stats.get("hits", 0) + dns_stats.get("misses", 0)
                hit_rate = dns_stats.get("hits", 0) / total * 100 if total > 0 else 0
                cache_health["caches"]["dns"] = {
                    "hit_rate": round(hit_rate, 1),
                    "size": dns_stats.get("size", 0),
                    "hits": dns_stats.get("hits", 0),
                    "misses": dns_stats.get("misses", 0),
                }
                # Warn if DNS cache hit rate is low
                if total > 1000 and hit_rate < 20:
                    cache_health["warnings"].append(
                        f"DNS cache hit rate low: {hit_rate:.1f}%"
                    )
                    cache_health["status"] = "degraded"
            except Exception as e:
                cache_health["caches"]["dns"] = {"error": str(e)}
        
        return APIResponse(
            success=True,
            data=cache_health,
        ).to_dict()
    
    # ─────────────────────────────────────────────────────────────────────────
    # Verdicts
    # ─────────────────────────────────────────────────────────────────────────
    
    async def get_recent_verdicts(
        self,
        limit: int = 50,
        offset: int = 0,
    ) -> dict[str, Any]:
        """
        GET /verdicts/recent
        
        Последние вердикты.
        """
        if not self._context.flow_logger:
            return APIResponse(success=False, error="Flow logger not available").to_dict()
        
        entries = await self._context.flow_logger.get_recent(limit)
        
        return PaginatedResponse(
            items=[e.to_dict() for e in entries],
            total=len(entries),
            page=1,
            page_size=limit,
        ).to_dict()
    
    async def get_verdict(self, flow_id: str) -> dict[str, Any]:
        """
        GET /verdicts/{flow_id}
        
        Детали вердикта с evidence.
        """
        if not self._context.flow_logger:
            return APIResponse(success=False, error="Flow logger not available").to_dict()
        
        entry = await self._context.flow_logger.get_flow(flow_id)
        
        if entry is None:
            return APIResponse(success=False, error="Verdict not found").to_dict()
        
        return APIResponse(success=True, data=entry.to_dict()).to_dict()
    
    # ─────────────────────────────────────────────────────────────────────────
    # Matchers (Rules)
    # ─────────────────────────────────────────────────────────────────────────
    
    async def get_matchers(
        self,
        page: int = 1,
        page_size: int = 50,
        kind: str | None = None,
        action: str | None = None,
        enabled: bool | None = None,
    ) -> dict[str, Any]:
        """
        GET /matchers
        
        Список правил с фильтрацией.
        """
        if not self._context.matchers:
            return APIResponse(success=False, error="Matchers not available").to_dict()
        
        all_matchers = self._context.matchers.get_all()
        
        # Фильтрация
        filtered = all_matchers
        if kind:
            filtered = [m for m in filtered if m.kind.value == kind]
        if action:
            filtered = [m for m in filtered if m.action.value == action]
        if enabled is not None:
            filtered = [m for m in filtered if m.enabled == enabled]
        
        # Пагинация
        total = len(filtered)
        start = (page - 1) * page_size
        end = start + page_size
        items = filtered[start:end]
        
        return PaginatedResponse(
            items=[m.to_dict() for m in items],
            total=total,
            page=page,
            page_size=page_size,
        ).to_dict()
    
    async def create_matcher(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        POST /matchers
        
        Создание нового правила.
        """
        if not self._context.matchers:
            return APIResponse(success=False, error="Matchers not available").to_dict()
        
        try:
            matcher = self._context.matchers.create_from_dict(data)
            self._context.matchers.add(matcher)
            
            return APIResponse(success=True, data=matcher.to_dict()).to_dict()
        except ValueError as e:
            return APIResponse(success=False, error=str(e)).to_dict()
    
    async def get_matcher(self, matcher_id: str) -> dict[str, Any]:
        """
        GET /matchers/{id}
        
        Получение правила по ID.
        """
        if not self._context.matchers:
            return APIResponse(success=False, error="Matchers not available").to_dict()
        
        matcher = self._context.matchers.get(matcher_id)
        
        if matcher is None:
            return APIResponse(success=False, error="Matcher not found").to_dict()
        
        return APIResponse(success=True, data=matcher.to_dict()).to_dict()
    
    async def update_matcher(self, matcher_id: str, data: dict[str, Any]) -> dict[str, Any]:
        """
        PUT /matchers/{id}
        
        Обновление правила.
        """
        if not self._context.matchers:
            return APIResponse(success=False, error="Matchers not available").to_dict()
        
        try:
            matcher = self._context.matchers.get(matcher_id)
            if matcher is None:
                return APIResponse(success=False, error="Matcher not found").to_dict()
            
            # Обновляем поля
            updated = self._context.matchers.update(matcher_id, data)
            
            return APIResponse(success=True, data=updated.to_dict()).to_dict()
        except ValueError as e:
            return APIResponse(success=False, error=str(e)).to_dict()
    
    async def delete_matcher(self, matcher_id: str) -> dict[str, Any]:
        """
        DELETE /matchers/{id}
        
        Удаление правила.
        """
        if not self._context.matchers:
            return APIResponse(success=False, error="Matchers not available").to_dict()
        
        try:
            self._context.matchers.remove(matcher_id)
            return APIResponse(success=True, data={"deleted": matcher_id}).to_dict()
        except ValueError as e:
            return APIResponse(success=False, error=str(e)).to_dict()
    
    # ─────────────────────────────────────────────────────────────────────────
    # Devices
    # ─────────────────────────────────────────────────────────────────────────
    
    async def get_devices(
        self,
        page: int = 1,
        page_size: int = 50,
        device_type: str | None = None,
        status: str | None = None,
    ) -> dict[str, Any]:
        """
        GET /devices
        
        Список обнаруженных устройств.
        """
        if not self._context.device_manager:
            return APIResponse(success=False, error="Device manager not available").to_dict()
        
        devices = self._context.device_manager.get_all_devices()
        
        # Фильтрация
        filtered = devices
        if device_type:
            filtered = [d for d in filtered if d.device_type.value == device_type]
        if status:
            filtered = [d for d in filtered if d.status.value == status]
        
        # Пагинация
        total = len(filtered)
        start = (page - 1) * page_size
        end = start + page_size
        items = filtered[start:end]
        
        return PaginatedResponse(
            items=[d.to_dict() for d in items],
            total=total,
            page=page,
            page_size=page_size,
        ).to_dict()
    
    async def get_device(self, device_id: str) -> dict[str, Any]:
        """
        GET /devices/{id}
        
        Информация об устройстве.
        """
        if not self._context.device_manager:
            return APIResponse(success=False, error="Device manager not available").to_dict()
        
        device = self._context.device_manager.get_device(device_id)
        
        if device is None:
            return APIResponse(success=False, error="Device not found").to_dict()
        
        return APIResponse(success=True, data=device.to_dict()).to_dict()
    
    async def update_device(self, device_id: str, data: dict[str, Any]) -> dict[str, Any]:
        """
        PUT /devices/{id}
        
        Обновление устройства (имя, тип).
        """
        if not self._context.device_manager:
            return APIResponse(success=False, error="Device manager not available").to_dict()
        
        try:
            device = self._context.device_manager.get_device(device_id)
            if device is None:
                return APIResponse(success=False, error="Device not found").to_dict()
            
            # Обновляем разрешённые поля
            if "name" in data:
                device.name = data["name"]
            if "custom_name" in data:
                device.custom_name = data["custom_name"]
            
            self._context.device_manager.update_device(device)
            
            return APIResponse(success=True, data=device.to_dict()).to_dict()
        except ValueError as e:
            return APIResponse(success=False, error=str(e)).to_dict()
    
    async def set_device_shield(self, device_id: str, profile_id: str) -> dict[str, Any]:
        """
        PUT /devices/{id}/shield
        
        Назначение Shield-профиля устройству.
        """
        if not self._context.device_manager or not self._context.profile_manager:
            return APIResponse(success=False, error="Managers not available").to_dict()
        
        try:
            device = self._context.device_manager.get_device(device_id)
            if device is None:
                return APIResponse(success=False, error="Device not found").to_dict()
            
            profile = self._context.profile_manager.get_profile(profile_id)
            if profile is None:
                return APIResponse(success=False, error="Profile not found").to_dict()
            
            # Назначаем профиль
            self._context.profile_manager.assign_to_device(profile_id, device_id)
            device.profile_id = profile_id
            self._context.device_manager.update_device(device)
            
            return APIResponse(
                success=True,
                data={"device_id": device_id, "profile_id": profile_id},
            ).to_dict()
        except ValueError as e:
            return APIResponse(success=False, error=str(e)).to_dict()
    
    # ─────────────────────────────────────────────────────────────────────────
    # Shield Profiles
    # ─────────────────────────────────────────────────────────────────────────
    
    async def get_shields(self) -> dict[str, Any]:
        """
        GET /shields
        
        Доступные Shield-профили.
        """
        if not self._context.profile_manager:
            return APIResponse(success=False, error="Profile manager not available").to_dict()
        
        profiles = self._context.profile_manager.get_all_profiles()
        
        return APIResponse(
            success=True,
            data=[p.to_dict() for p in profiles],
        ).to_dict()
    
    async def get_shield(self, profile_id: str) -> dict[str, Any]:
        """
        GET /shields/{id}
        
        Детали Shield-профиля.
        """
        if not self._context.profile_manager:
            return APIResponse(success=False, error="Profile manager not available").to_dict()
        
        profile = self._context.profile_manager.get_profile(profile_id)
        
        if profile is None:
            return APIResponse(success=False, error="Profile not found").to_dict()
        
        return APIResponse(success=True, data=profile.to_dict()).to_dict()
    
    async def create_shield(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        POST /shields
        
        Создание кастомного профиля.
        """
        if not self._context.profile_manager:
            return APIResponse(success=False, error="Profile manager not available").to_dict()
        
        try:
            profile = self._context.profile_manager.create_custom_profile(data)
            
            return APIResponse(success=True, data=profile.to_dict()).to_dict()
        except ValueError as e:
            return APIResponse(success=False, error=str(e)).to_dict()
    
    async def update_shield(self, profile_id: str, data: dict[str, Any]) -> dict[str, Any]:
        """
        PUT /shields/{id}
        
        Обновление профиля.
        """
        if not self._context.profile_manager:
            return APIResponse(success=False, error="Profile manager not available").to_dict()
        
        try:
            profile = self._context.profile_manager.update_profile(profile_id, data)
            
            return APIResponse(success=True, data=profile.to_dict()).to_dict()
        except ValueError as e:
            return APIResponse(success=False, error=str(e)).to_dict()
    
    async def delete_shield(self, profile_id: str) -> dict[str, Any]:
        """
        DELETE /shields/{id}
        
        Удаление кастомного профиля.
        """
        if not self._context.profile_manager:
            return APIResponse(success=False, error="Profile manager not available").to_dict()
        
        try:
            self._context.profile_manager.delete_profile(profile_id)
            return APIResponse(success=True, data={"deleted": profile_id}).to_dict()
        except ValueError as e:
            return APIResponse(success=False, error=str(e)).to_dict()
    
    # ─────────────────────────────────────────────────────────────────────────
    # Schedules
    # ─────────────────────────────────────────────────────────────────────────
    
    # NOTE: schedule CRUD lived here as an in-memory API that was never wired into
    # get_routes() and called ScheduleManager methods that don't exist (create_schedule/
    # toggle_schedule) — i.e. dead + broken. Schedules are managed by the backend
    # (schedules.json) and enforced by verdict.schedule_checker. Removed to avoid a
    # confusing second, non-functional path.
    
    # ─────────────────────────────────────────────────────────────────────────
    # Device Baseline & Anomaly Detection
    # ─────────────────────────────────────────────────────────────────────────
    
    async def get_device_baseline(self, device_id: str) -> dict[str, Any]:
        """
        GET /devices/{id}/baseline
        
        Baseline поведения устройства.
        """
        if not self._context.device_manager:
            return APIResponse(success=False, error="Device manager not available").to_dict()
        
        try:
            baseline = self._context.device_manager.get_device_baseline(device_id)
            if not baseline:
                return APIResponse(success=False, error="Device not found").to_dict()
            return APIResponse(success=True, data=baseline).to_dict()
        except Exception as e:
            return APIResponse(success=False, error=str(e)).to_dict()
    
    async def get_device_anomalies(self, device_id: str) -> dict[str, Any]:
        """
        GET /devices/{id}/anomalies
        
        Обнаруженные аномалии для устройства.
        """
        if not self._context.device_manager:
            return APIResponse(success=False, error="Device manager not available").to_dict()
        
        try:
            anomalies = self._context.device_manager.get_device_anomalies(device_id)
            return APIResponse(success=True, data=anomalies).to_dict()
        except Exception as e:
            return APIResponse(success=False, error=str(e)).to_dict()
    
    async def get_devices_with_baseline(
        self,
        page: int = 1,
        page_size: int = 50,
    ) -> dict[str, Any]:
        """
        GET /devices/baseline
        
        Все устройства с baseline-информацией.
        """
        if not self._context.device_manager:
            return APIResponse(success=False, error="Device manager not available").to_dict()
        
        try:
            devices = self._context.device_manager.get_all_devices_with_baseline()
            
            # Пагинация
            total = len(devices)
            start = (page - 1) * page_size
            end = start + page_size
            items = devices[start:end]
            
            return PaginatedResponse(
                items=items,
                total=total,
                page=page,
                page_size=page_size,
            ).to_dict()
        except Exception as e:
            return APIResponse(success=False, error=str(e)).to_dict()
    
    # ─────────────────────────────────────────────────────────────────────────
    # Settings: IPv6, Fail-Safe, Shadow Mode
    # ─────────────────────────────────────────────────────────────────────────
    
    async def get_settings(self) -> dict[str, Any]:
        """
        GET /settings
        
        Все настройки NetProtection.
        """
        try:
            from ..system.settings import get_settings_manager
            manager = get_settings_manager()
            return APIResponse(success=True, data=manager.export_settings()).to_dict()
        except Exception as e:
            return APIResponse(success=False, error=str(e)).to_dict()
    
    async def get_ipv6_settings(self) -> dict[str, Any]:
        """
        GET /settings/ipv6
        
        Настройки IPv6.
        """
        try:
            from ..system.settings import get_settings_manager
            manager = get_settings_manager()
            return APIResponse(success=True, data=manager.get_ipv6_settings().to_dict()).to_dict()
        except Exception as e:
            return APIResponse(success=False, error=str(e)).to_dict()
    
    async def update_ipv6_settings(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        PUT /settings/ipv6
        
        Обновление настроек IPv6.
        """
        try:
            from ..system.settings import get_settings_manager
            manager = get_settings_manager()
            settings = manager.update_ipv6_settings(**data)
            return APIResponse(success=True, data=settings.to_dict()).to_dict()
        except Exception as e:
            return APIResponse(success=False, error=str(e)).to_dict()
    
    async def get_failsafe_settings(self) -> dict[str, Any]:
        """
        GET /settings/failsafe
        
        Настройки Fail-Safe.
        """
        try:
            from ..system.settings import get_settings_manager
            manager = get_settings_manager()
            return APIResponse(success=True, data=manager.get_fail_safe_settings().to_dict()).to_dict()
        except Exception as e:
            return APIResponse(success=False, error=str(e)).to_dict()
    
    async def update_failsafe_settings(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        PUT /settings/failsafe
        
        Обновление настроек Fail-Safe.
        """
        try:
            from ..system.settings import get_settings_manager
            manager = get_settings_manager()
            settings = manager.update_fail_safe_settings(**data)
            return APIResponse(success=True, data=settings.to_dict()).to_dict()
        except Exception as e:
            return APIResponse(success=False, error=str(e)).to_dict()
    
    async def trigger_failsafe(self, action: str) -> dict[str, Any]:
        """
        POST /settings/failsafe/trigger
        
        Ручное управление Fail-Safe (activate/deactivate).
        """
        try:
            from ..system.settings import get_settings_manager
            manager = get_settings_manager()
            
            if action == "activate":
                manager.activate_fail_safe()
            elif action == "deactivate":
                manager.deactivate_fail_safe()
            else:
                return APIResponse(success=False, error="Invalid action. Use 'activate' or 'deactivate'").to_dict()
            
            return APIResponse(success=True, data=manager.get_fail_safe_settings().to_dict()).to_dict()
        except Exception as e:
            return APIResponse(success=False, error=str(e)).to_dict()
    
    async def get_shadow_mode_settings(self) -> dict[str, Any]:
        """
        GET /settings/shadow-mode
        
        Настройки Shadow Mode.
        """
        try:
            from ..system.settings import get_settings_manager
            manager = get_settings_manager()
            return APIResponse(success=True, data=manager.get_shadow_mode_settings().to_dict()).to_dict()
        except Exception as e:
            return APIResponse(success=False, error=str(e)).to_dict()
    
    async def update_shadow_mode_settings(self, data: dict[str, Any]) -> dict[str, Any]:
        """
        PUT /settings/shadow-mode
        
        Обновление настроек Shadow Mode.
        """
        try:
            from ..system.settings import get_settings_manager
            manager = get_settings_manager()
            settings = manager.update_shadow_mode_settings(**data)
            return APIResponse(success=True, data=settings.to_dict()).to_dict()
        except Exception as e:
            return APIResponse(success=False, error=str(e)).to_dict()
    
    # ─────────────────────────────────────────────────────────────────────────
    # Shadow Domains (observed suspicious domains)
    # ─────────────────────────────────────────────────────────────────────────
    
    async def get_shadow_domains(
        self,
        limit: int = 100,
        offset: int = 0,
        sort_by: str = "max_score",
        sort_desc: bool = True,
        status: str | None = None,
    ) -> dict[str, Any]:
        """
        GET /shadow/domains
        
        List domains in Shadow Mode (observed but not blocked).
        """
        try:
            from ..heuristics.shadow_mode import get_shadow_mode
            shadow = get_shadow_mode()
            
            if not shadow:
                return APIResponse(success=False, error="Shadow mode not available").to_dict()
            
            # Get domains (always use list_active for now)
            records = shadow.list_active(limit=limit, offset=offset, sort_by=sort_by, sort_desc=sort_desc)
            
            # Convert to dict
            domains = []
            for r in records:
                # Get signals for this domain
                signals = shadow.get_domain_signals(r.domain)
                
                domains.append({
                    "domain": r.domain,
                    "score": r.max_score,
                    "avg_score": r.avg_score,
                    "hit_count": r.hit_count,
                    "first_seen": r.first_observed.isoformat() if r.first_observed else None,
                    "last_seen": r.last_observed.isoformat() if r.last_observed else None,
                    "status": r.action.value,
                    "action_at": r.action_at.isoformat() if r.action_at else None,
                    "action_by": r.action_by,
                    "notes": r.notes,
                    "age_days": round(r.age_days, 1),
                    "signals": signals,
                })
            
            # Get stats
            stats = shadow.get_stats()
            
            return APIResponse(
                success=True,
                data={
                    "domains": domains,
                    "stats": stats,
                    "total": len(domains),
                },
            ).to_dict()
            
        except ImportError:
            return APIResponse(success=False, error="Shadow mode module not available").to_dict()
        except Exception as e:
            logger.exception("Failed to get shadow domains")
            return APIResponse(success=False, error=str(e)).to_dict()
    
    async def shadow_domain_action(
        self,
        domain: str,
        action: str,
        notes: str = "",
    ) -> dict[str, Any]:
        """
        POST /shadow/domains/{domain}/action
        
        Take action on shadow domain: promote (block) or dismiss (allow).
        """
        try:
            from ..heuristics.shadow_mode import get_shadow_mode
            shadow = get_shadow_mode()
            
            if not shadow:
                return APIResponse(success=False, error="Shadow mode not available").to_dict()
            
            if action == "promote":
                success = shadow.promote(domain, actor="admin", notes=notes)
                if success:
                    # Also add to blocklist
                    if self._blocklist:
                        self._blocklist.add_to_blacklist(domain)
                    return APIResponse(success=True, data={"action": "promoted", "domain": domain}).to_dict()
            elif action == "dismiss":
                success = shadow.dismiss(domain, actor="admin", notes=notes)
                if success:
                    # Also add to whitelist
                    if self._blocklist:
                        self._blocklist.add_to_whitelist(domain)
                    return APIResponse(success=True, data={"action": "dismissed", "domain": domain}).to_dict()
            else:
                return APIResponse(success=False, error=f"Invalid action: {action}. Use 'promote' or 'dismiss'").to_dict()
            
            return APIResponse(success=False, error="Domain not found").to_dict()
            
        except ImportError:
            return APIResponse(success=False, error="Shadow mode module not available").to_dict()
        except Exception as e:
            return APIResponse(success=False, error=str(e)).to_dict()
    
    async def get_shadow_stats(self) -> dict[str, Any]:
        """
        GET /shadow/stats
        
        Get Shadow Mode statistics.
        """
        try:
            from ..heuristics.shadow_mode import get_shadow_mode
            shadow = get_shadow_mode()
            
            if not shadow:
                return APIResponse(success=False, error="Shadow mode not available").to_dict()
            
            stats = shadow.get_stats()
            return APIResponse(success=True, data=stats).to_dict()
            
        except ImportError:
            return APIResponse(success=False, error="Shadow mode module not available").to_dict()
        except Exception as e:
            return APIResponse(success=False, error=str(e)).to_dict()

    # ─────────────────────────────────────────────────────────────────────────
    # Chronicle (Flow Log)
    # ─────────────────────────────────────────────────────────────────────────
    
    async def get_chronicle(
        self,
        page: int = 1,
        page_size: int = 100,
        domain: str | None = None,
        device_id: str | None = None,
        verdict: str | None = None,
        since: str | None = None,
        until: str | None = None,
    ) -> dict[str, Any]:
        """
        GET /chronicle
        
        Журнал DNS-потоков с фильтрацией и пагинацией.
        """
        if not self._context.flow_logger:
            return APIResponse(success=False, error="Flow logger not available").to_dict()
        
        # Парсинг дат
        since_dt = datetime.fromisoformat(since) if since else None
        until_dt = datetime.fromisoformat(until) if until else None
        
        offset = (page - 1) * page_size
        
        entries = await self._context.flow_logger.query(
            limit=page_size,
            offset=offset,
            domain=domain,
            device_id=device_id,
            verdict=verdict,
            since=since_dt,
            until=until_dt,
        )
        
        # Общее количество (приблизительно)
        stats = await self._context.flow_logger.get_stats()
        total = stats.get("storage_total", len(entries))
        
        return PaginatedResponse(
            items=[e.to_dict() for e in entries],
            total=total,
            page=page,
            page_size=page_size,
        ).to_dict()
    
    # ─────────────────────────────────────────────────────────────────────────
    # Metrics
    # ─────────────────────────────────────────────────────────────────────────
    
    async def get_metrics(self) -> dict[str, Any]:
        """
        GET /metrics
        
        Агрегированная статистика.
        """
        if not self._context.metrics:
            return APIResponse(success=False, error="Metrics not available").to_dict()
        
        summary = self._context.metrics.get_summary()
        
        return APIResponse(success=True, data=summary).to_dict()
    
    async def get_metrics_timeseries(
        self,
        granularity: str = "hour",
    ) -> dict[str, Any]:
        """
        GET /metrics/timeseries
        
        Временные ряды метрик.
        """
        if not self._context.metrics:
            return APIResponse(success=False, error="Metrics not available").to_dict()
        
        from ..chronicle.metrics import TimeGranularity
        
        try:
            gran = TimeGranularity(granularity)
        except ValueError:
            gran = TimeGranularity.HOUR
        
        data = self._context.metrics.get_time_series(gran)
        
        return APIResponse(success=True, data=data).to_dict()
    
    # ─────────────────────────────────────────────────────────────────────────
    # Guardian Controls
    # ─────────────────────────────────────────────────────────────────────────
    
    async def get_guardian_status(self) -> dict[str, Any]:
        """
        GET /guardian
        
        Статус Guardian watchdog.
        """
        if not self._context.guardian:
            return APIResponse(success=False, error="Guardian not available").to_dict()
        
        status = self._context.guardian.get_status()
        
        return APIResponse(success=True, data=status).to_dict()
    
    async def trigger_health_check(self) -> dict[str, Any]:
        """
        POST /guardian/health-check
        
        Принудительная проверка здоровья.
        """
        if not self._context.guardian:
            return APIResponse(success=False, error="Guardian not available").to_dict()
        
        results = await self._context.guardian.trigger_health_check()
        
        return APIResponse(
            success=True,
            data=[r.to_dict() for r in results],
        ).to_dict()
    
    async def set_safe_mode(self, enabled: bool) -> dict[str, Any]:
        """
        POST /guardian/safe-mode
        
        Включение/выключение safe mode.
        """
        if not self._context.guardian:
            return APIResponse(success=False, error="Guardian not available").to_dict()
        
        if enabled:
            await self._context.guardian.force_safe_mode()
        else:
            await self._context.guardian.force_normal_mode()
        
        return APIResponse(
            success=True,
            data={"safe_mode": self._context.guardian.is_safe_mode},
        ).to_dict()
    
    # ─────────────────────────────────────────────────────────────────────────
    # Parental Control (ADMIN ONLY)
    # All endpoints require admin authorization
    # ─────────────────────────────────────────────────────────────────────────
    
    async def get_parental_profiles(self, user_role: str = "guest") -> dict[str, Any]:
        """
        GET /parental/profiles
        
        List all parental control profiles.
        AUTHORIZATION: admin only
        """
        if user_role != "admin":
            return APIResponse(
                success=False,
                error="Parental control access requires admin role",
            ).to_dict()
        
        try:
            from ..parental import get_parental_controller
            controller = get_parental_controller()
            profiles = controller.list_profiles()
            return APIResponse(
                success=True,
                data=[p.to_dict() for p in profiles],
            ).to_dict()
        except ImportError:
            return APIResponse(success=False, error="Parental module not available").to_dict()
    
    async def create_parental_profile(
        self,
        name: str,
        preset: str | None = None,
        age_category: str | None = None,
        user_role: str = "guest",
        **kwargs,
    ) -> dict[str, Any]:
        """
        POST /parental/profiles
        
        Create a new parental control profile.
        AUTHORIZATION: admin only
        """
        if user_role != "admin":
            return APIResponse(
                success=False,
                error="Creating parental profiles requires admin role",
            ).to_dict()
        
        try:
            from ..parental import get_parental_controller, AgeCategory
            controller = get_parental_controller()
            
            age_cat = None
            if age_category:
                age_cat = AgeCategory(age_category)
            
            profile = controller.create_profile(
                name=name,
                preset=preset,
                age_category=age_cat,
                **kwargs,
            )
            return APIResponse(success=True, data=profile.to_dict()).to_dict()
        except ImportError:
            return APIResponse(success=False, error="Parental module not available").to_dict()
        except Exception as e:
            return APIResponse(success=False, error=str(e)).to_dict()
    
    async def update_parental_profile(
        self,
        profile_id: str,
        user_role: str = "guest",
        **updates,
    ) -> dict[str, Any]:
        """
        PUT /parental/profiles/{profile_id}
        
        Update a parental control profile.
        AUTHORIZATION: admin only
        """
        if user_role != "admin":
            return APIResponse(
                success=False,
                error="Updating parental profiles requires admin role",
            ).to_dict()
        
        try:
            from ..parental import get_parental_controller
            controller = get_parental_controller()
            
            profile = controller.update_profile(profile_id, **updates)
            if not profile:
                return APIResponse(success=False, error="Profile not found").to_dict()
            return APIResponse(success=True, data=profile.to_dict()).to_dict()
        except ImportError:
            return APIResponse(success=False, error="Parental module not available").to_dict()
        except Exception as e:
            return APIResponse(success=False, error=str(e)).to_dict()
    
    async def delete_parental_profile(
        self,
        profile_id: str,
        user_role: str = "guest",
    ) -> dict[str, Any]:
        """
        DELETE /parental/profiles/{profile_id}
        
        Delete a parental control profile.
        AUTHORIZATION: admin only
        """
        if user_role != "admin":
            return APIResponse(
                success=False,
                error="Deleting parental profiles requires admin role",
            ).to_dict()
        
        try:
            from ..parental import get_parental_controller
            controller = get_parental_controller()
            
            if controller.delete_profile(profile_id):
                return APIResponse(success=True).to_dict()
            return APIResponse(success=False, error="Profile not found").to_dict()
        except ImportError:
            return APIResponse(success=False, error="Parental module not available").to_dict()
    
    async def bind_parental_profile(
        self,
        device_profile_id: str,
        parental_profile_id: str,
        user_role: str = "guest",
    ) -> dict[str, Any]:
        """
        POST /parental/profiles/{parental_profile_id}/bind
        
        Bind a parental profile to a device profile.
        AUTHORIZATION: admin only
        """
        if user_role != "admin":
            return APIResponse(
                success=False,
                error="Binding profiles requires admin role",
            ).to_dict()
        
        try:
            from ..parental import get_parental_controller
            controller = get_parental_controller()
            
            if controller.bind_to_device(device_profile_id, parental_profile_id):
                return APIResponse(success=True).to_dict()
            return APIResponse(success=False, error="Failed to bind profile").to_dict()
        except ImportError:
            return APIResponse(success=False, error="Parental module not available").to_dict()
    
    async def pause_device(
        self,
        device_profile_id: str,
        duration_minutes: int = 30,
        user_role: str = "guest",
    ) -> dict[str, Any]:
        """
        POST /parental/devices/{device_profile_id}/pause
        
        Pause internet access for a device.
        AUTHORIZATION: admin only
        """
        if user_role != "admin":
            return APIResponse(
                success=False,
                error="Pausing devices requires admin role",
            ).to_dict()
        
        try:
            from ..parental import get_parental_controller
            controller = get_parental_controller()
            
            if controller.pause_device(device_profile_id, duration_minutes):
                return APIResponse(success=True, data={"paused_minutes": duration_minutes}).to_dict()
            return APIResponse(success=False, error="Failed to pause device").to_dict()
        except ImportError:
            return APIResponse(success=False, error="Parental module not available").to_dict()
    
    async def resume_device(
        self,
        device_profile_id: str,
        user_role: str = "guest",
    ) -> dict[str, Any]:
        """
        POST /parental/devices/{device_profile_id}/resume
        
        Resume internet access for a device.
        AUTHORIZATION: admin only
        """
        if user_role != "admin":
            return APIResponse(
                success=False,
                error="Resuming devices requires admin role",
            ).to_dict()
        
        try:
            from ..parental import get_parental_controller
            controller = get_parental_controller()
            
            if controller.resume_device(device_profile_id):
                return APIResponse(success=True).to_dict()
            return APIResponse(success=False, error="Failed to resume device").to_dict()
        except ImportError:
            return APIResponse(success=False, error="Parental module not available").to_dict()
    
    async def get_parental_presets(self, user_role: str = "guest") -> dict[str, Any]:
        """
        GET /parental/presets
        
        Get available parental control presets.
        AUTHORIZATION: admin only (to prevent kids from seeing what's filtered)
        """
        if user_role != "admin":
            return APIResponse(
                success=False,
                error="Viewing presets requires admin role",
            ).to_dict()
        
        try:
            from ..parental import get_parental_controller
            controller = get_parental_controller()
            return APIResponse(success=True, data=controller.get_presets()).to_dict()
        except ImportError:
            return APIResponse(success=False, error="Parental module not available").to_dict()
    
    async def get_parental_stats(self, user_role: str = "guest") -> dict[str, Any]:
        """
        GET /parental/stats
        
        Get parental control statistics.
        AUTHORIZATION: admin only
        """
        if user_role != "admin":
            return APIResponse(
                success=False,
                error="Viewing parental stats requires admin role",
            ).to_dict()
        
        try:
            from ..parental import get_parental_controller
            controller = get_parental_controller()
            return APIResponse(success=True, data=controller.get_stats()).to_dict()
        except ImportError:
            return APIResponse(success=False, error="Parental module not available").to_dict()
    
    # ─────────────────────────────────────────────────────────────────────────
    # Streaming Apps Blocking
    # ─────────────────────────────────────────────────────────────────────────
    
    async def get_streaming_status(self) -> dict[str, Any]:
        """
        GET /streaming/status
        
        Get current streaming blocking status.
        """
        try:
            from .streaming_blocker import get_streaming_blocker
            blocker = get_streaming_blocker()
            return APIResponse(success=True, data=blocker.get_status()).to_dict()
        except ImportError:
            return APIResponse(success=False, error="Streaming blocker not available").to_dict()
        except Exception as e:
            return APIResponse(success=False, error=str(e)).to_dict()
    
    async def block_streaming_service(
        self,
        service: str,
        block_dns: bool = True,
        block_asn: bool = True,
        block_doh: bool = True,
    ) -> dict[str, Any]:
        """
        POST /streaming/block
        
        Block a streaming service (Netflix, YouTube, TikTok, etc.)
        Uses multi-layer blocking: DNS + ASN IP blocking + DoH/DoT blocking.
        """
        try:
            from .streaming_blocker import get_streaming_blocker, StreamingService
            
            blocker = get_streaming_blocker()
            
            # Validate service
            try:
                svc = StreamingService(service.lower())
            except ValueError:
                available = [s.value for s in StreamingService]
                return APIResponse(
                    success=False,
                    error=f"Unknown service: {service}. Available: {available}",
                ).to_dict()
            
            result = await blocker.block_service(
                svc,
                block_dns=block_dns,
                block_asn=block_asn,
                block_doh=block_doh,
            )
            
            return APIResponse(success=True, data=result).to_dict()
            
        except ImportError:
            return APIResponse(success=False, error="Streaming blocker not available").to_dict()
        except Exception as e:
            logger.exception(f"Failed to block streaming service {service}")
            return APIResponse(success=False, error=str(e)).to_dict()
    
    async def unblock_streaming_service(self, service: str) -> dict[str, Any]:
        """
        POST /streaming/unblock
        
        Unblock a streaming service.
        """
        try:
            from .streaming_blocker import get_streaming_blocker, StreamingService
            
            blocker = get_streaming_blocker()
            
            try:
                svc = StreamingService(service.lower())
            except ValueError:
                return APIResponse(success=False, error=f"Unknown service: {service}").to_dict()
            
            result = await blocker.unblock_service(svc)
            return APIResponse(success=True, data=result).to_dict()
            
        except ImportError:
            return APIResponse(success=False, error="Streaming blocker not available").to_dict()
        except Exception as e:
            return APIResponse(success=False, error=str(e)).to_dict()
    
    async def block_doh_dot(self) -> dict[str, Any]:
        """
        POST /streaming/block-doh
        
        Block all DoH/DoT servers globally to prevent DNS bypass.
        """
        try:
            from .streaming_blocker import get_streaming_blocker
            
            blocker = get_streaming_blocker()
            result = await blocker.block_doh_dot()
            return APIResponse(success=True, data=result).to_dict()
            
        except ImportError:
            return APIResponse(success=False, error="Streaming blocker not available").to_dict()
        except Exception as e:
            return APIResponse(success=False, error=str(e)).to_dict()
    
    async def unblock_doh_dot(self) -> dict[str, Any]:
        """
        POST /streaming/unblock-doh
        
        Unblock DoH/DoT servers.
        """
        try:
            from .streaming_blocker import get_streaming_blocker
            
            blocker = get_streaming_blocker()
            result = await blocker.unblock_doh_dot()
            return APIResponse(success=True, data=result).to_dict()
            
        except ImportError:
            return APIResponse(success=False, error="Streaming blocker not available").to_dict()
        except Exception as e:
            return APIResponse(success=False, error=str(e)).to_dict()
    
    async def enable_force_dns(self, dns_server: str = "127.0.0.1") -> dict[str, Any]:
        """
        POST /streaming/force-dns/enable
        
        Enable Force DNS mode - all DNS traffic forced through EasyPi.
        """
        try:
            from .streaming_blocker import get_streaming_blocker
            
            blocker = get_streaming_blocker()
            if blocker.enable_force_dns(dns_server):
                return APIResponse(success=True, data={"force_dns": True, "dns_server": dns_server}).to_dict()
            return APIResponse(success=False, error="Failed to enable force DNS mode").to_dict()
            
        except ImportError:
            return APIResponse(success=False, error="Streaming blocker not available").to_dict()
        except Exception as e:
            return APIResponse(success=False, error=str(e)).to_dict()
    
    async def disable_force_dns(self) -> dict[str, Any]:
        """
        POST /streaming/force-dns/disable
        
        Disable Force DNS mode.
        """
        try:
            from .streaming_blocker import get_streaming_blocker
            
            blocker = get_streaming_blocker()
            blocker.disable_force_dns()
            return APIResponse(success=True, data={"force_dns": False}).to_dict()
            
        except ImportError:
            return APIResponse(success=False, error="Streaming blocker not available").to_dict()
        except Exception as e:
            return APIResponse(success=False, error=str(e)).to_dict()
    
    async def get_streaming_services(self) -> dict[str, Any]:
        """
        GET /streaming/services
        
        Get list of available streaming services to block.
        """
        try:
            from .streaming_blocker import STREAMING_SERVICES, StreamingService
            
            services = []
            for service in StreamingService:
                definition = STREAMING_SERVICES.get(service)
                if definition:
                    services.append({
                        "id": service.value,
                        "name": definition.display_name,
                        "domains_count": len(definition.domains),
                        "asn_count": len(definition.asn_list),
                        "has_doh": len(definition.doh_domains) > 0,
                    })
            
            return APIResponse(success=True, data=services).to_dict()
            
        except ImportError:
            return APIResponse(success=False, error="Streaming blocker not available").to_dict()
        except Exception as e:
            return APIResponse(success=False, error=str(e)).to_dict()


# ════════════════════════════════════════════════════════════════════════════════
# ROUTE REGISTRATION
# ════════════════════════════════════════════════════════════════════════════════

def get_routes() -> list[dict[str, Any]]:
    """
    Список всех маршрутов API.
    
    Формат для регистрации в FastAPI/Starlette/aiohttp.
    """
    return [
        # Status & Health
        {"method": "GET", "path": f"{BASE_PATH}/status", "handler": "get_status"},
        {"method": "GET", "path": f"{BASE_PATH}/health", "handler": "get_health"},
        {"method": "GET", "path": f"{BASE_PATH}/cache/health", "handler": "get_cache_health"},
        
        # Verdicts
        {"method": "GET", "path": f"{BASE_PATH}/verdicts/recent", "handler": "get_recent_verdicts"},
        {"method": "GET", "path": f"{BASE_PATH}/verdicts/{{flow_id}}", "handler": "get_verdict"},
        
        # Matchers
        {"method": "GET", "path": f"{BASE_PATH}/matchers", "handler": "get_matchers"},
        {"method": "POST", "path": f"{BASE_PATH}/matchers", "handler": "create_matcher"},
        {"method": "GET", "path": f"{BASE_PATH}/matchers/{{matcher_id}}", "handler": "get_matcher"},
        {"method": "PUT", "path": f"{BASE_PATH}/matchers/{{matcher_id}}", "handler": "update_matcher"},
        {"method": "DELETE", "path": f"{BASE_PATH}/matchers/{{matcher_id}}", "handler": "delete_matcher"},
        
        # Devices
        {"method": "GET", "path": f"{BASE_PATH}/devices", "handler": "get_devices"},
        {"method": "GET", "path": f"{BASE_PATH}/devices/{{device_id}}", "handler": "get_device"},
        {"method": "PUT", "path": f"{BASE_PATH}/devices/{{device_id}}", "handler": "update_device"},
        {"method": "PUT", "path": f"{BASE_PATH}/devices/{{device_id}}/shield", "handler": "set_device_shield"},
        
        # Shields
        {"method": "GET", "path": f"{BASE_PATH}/shields", "handler": "get_shields"},
        {"method": "POST", "path": f"{BASE_PATH}/shields", "handler": "create_shield"},
        {"method": "GET", "path": f"{BASE_PATH}/shields/{{profile_id}}", "handler": "get_shield"},
        {"method": "PUT", "path": f"{BASE_PATH}/shields/{{profile_id}}", "handler": "update_shield"},
        {"method": "DELETE", "path": f"{BASE_PATH}/shields/{{profile_id}}", "handler": "delete_shield"},
        
        # Schedules (CRUD)
        {"method": "GET", "path": f"{BASE_PATH}/schedules", "handler": "get_schedules"},
        {"method": "POST", "path": f"{BASE_PATH}/schedules", "handler": "create_schedule"},
        {"method": "GET", "path": f"{BASE_PATH}/schedules/{{schedule_id}}", "handler": "get_schedule"},
        {"method": "PUT", "path": f"{BASE_PATH}/schedules/{{schedule_id}}", "handler": "update_schedule"},
        {"method": "DELETE", "path": f"{BASE_PATH}/schedules/{{schedule_id}}", "handler": "delete_schedule"},
        {"method": "POST", "path": f"{BASE_PATH}/schedules/{{schedule_id}}/toggle", "handler": "toggle_schedule"},
        
        # Devices with Baseline
        {"method": "GET", "path": f"{BASE_PATH}/devices/baseline", "handler": "get_devices_with_baseline"},
        {"method": "GET", "path": f"{BASE_PATH}/devices/{{device_id}}/baseline", "handler": "get_device_baseline"},
        {"method": "GET", "path": f"{BASE_PATH}/devices/{{device_id}}/anomalies", "handler": "get_device_anomalies"},
        
        # Settings
        {"method": "GET", "path": f"{BASE_PATH}/settings", "handler": "get_settings"},
        {"method": "GET", "path": f"{BASE_PATH}/settings/ipv6", "handler": "get_ipv6_settings"},
        {"method": "PUT", "path": f"{BASE_PATH}/settings/ipv6", "handler": "update_ipv6_settings"},
        {"method": "GET", "path": f"{BASE_PATH}/settings/failsafe", "handler": "get_failsafe_settings"},
        {"method": "PUT", "path": f"{BASE_PATH}/settings/failsafe", "handler": "update_failsafe_settings"},
        {"method": "POST", "path": f"{BASE_PATH}/settings/failsafe/trigger", "handler": "trigger_failsafe"},
        {"method": "GET", "path": f"{BASE_PATH}/settings/shadow-mode", "handler": "get_shadow_mode_settings"},
        {"method": "PUT", "path": f"{BASE_PATH}/settings/shadow-mode", "handler": "update_shadow_mode_settings"},
        
        # Shadow Domains (observed suspicious domains)
        {"method": "GET", "path": f"{BASE_PATH}/shadow/domains", "handler": "get_shadow_domains"},
        {"method": "GET", "path": f"{BASE_PATH}/shadow/stats", "handler": "get_shadow_stats"},
        {"method": "POST", "path": f"{BASE_PATH}/shadow/domains/{{domain}}/action", "handler": "shadow_domain_action"},
        
        # Chronicle
        {"method": "GET", "path": f"{BASE_PATH}/chronicle", "handler": "get_chronicle"},
        
        # Metrics
        {"method": "GET", "path": f"{BASE_PATH}/metrics", "handler": "get_metrics"},
        {"method": "GET", "path": f"{BASE_PATH}/metrics/timeseries", "handler": "get_metrics_timeseries"},
        
        # Guardian
        {"method": "GET", "path": f"{BASE_PATH}/guardian", "handler": "get_guardian_status"},
        {"method": "POST", "path": f"{BASE_PATH}/guardian/health-check", "handler": "trigger_health_check"},
        {"method": "POST", "path": f"{BASE_PATH}/guardian/safe-mode", "handler": "set_safe_mode"},
        
        # Parental Control (ADMIN ONLY)
        {"method": "GET", "path": f"{BASE_PATH}/parental/profiles", "handler": "get_parental_profiles", "auth": "admin"},
        {"method": "POST", "path": f"{BASE_PATH}/parental/profiles", "handler": "create_parental_profile", "auth": "admin"},
        {"method": "PUT", "path": f"{BASE_PATH}/parental/profiles/{{profile_id}}", "handler": "update_parental_profile", "auth": "admin"},
        {"method": "DELETE", "path": f"{BASE_PATH}/parental/profiles/{{profile_id}}", "handler": "delete_parental_profile", "auth": "admin"},
        {"method": "POST", "path": f"{BASE_PATH}/parental/profiles/{{profile_id}}/bind", "handler": "bind_parental_profile", "auth": "admin"},
        {"method": "POST", "path": f"{BASE_PATH}/parental/devices/{{device_id}}/pause", "handler": "pause_device", "auth": "admin"},
        {"method": "POST", "path": f"{BASE_PATH}/parental/devices/{{device_id}}/resume", "handler": "resume_device", "auth": "admin"},
        {"method": "GET", "path": f"{BASE_PATH}/parental/presets", "handler": "get_parental_presets", "auth": "admin"},
        {"method": "GET", "path": f"{BASE_PATH}/parental/stats", "handler": "get_parental_stats", "auth": "admin"},
        
        # Streaming Apps Blocking
        {"method": "GET", "path": f"{BASE_PATH}/streaming/status", "handler": "get_streaming_status"},
        {"method": "GET", "path": f"{BASE_PATH}/streaming/services", "handler": "get_streaming_services"},
        {"method": "POST", "path": f"{BASE_PATH}/streaming/block", "handler": "block_streaming_service"},
        {"method": "POST", "path": f"{BASE_PATH}/streaming/unblock", "handler": "unblock_streaming_service"},
        {"method": "POST", "path": f"{BASE_PATH}/streaming/block-doh", "handler": "block_doh_dot"},
        {"method": "POST", "path": f"{BASE_PATH}/streaming/unblock-doh", "handler": "unblock_doh_dot"},
        {"method": "POST", "path": f"{BASE_PATH}/streaming/force-dns/enable", "handler": "enable_force_dns"},
        {"method": "POST", "path": f"{BASE_PATH}/streaming/force-dns/disable", "handler": "disable_force_dns"},
    ]


def create_api(context: "BootstrapContext") -> NetProtectionAPI:
    """Создание экземпляра API."""
    return NetProtectionAPI(context)
