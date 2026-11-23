"""
EasyPi NetProtection — Guardian Module.

Watchdog, health-checks, safe-mode recovery.
Автоматическое восстановление при сбоях.
"""

from __future__ import annotations

import asyncio
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Callable, TYPE_CHECKING

if TYPE_CHECKING:
    from .bootstrap import BootstrapContext

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

DEFAULT_HEALTH_CHECK_INTERVAL = 30  # seconds
DEFAULT_RECOVERY_ATTEMPTS = 3
DEFAULT_RECOVERY_COOLDOWN = 60  # seconds
SAFE_MODE_UPSTREAM_TIMEOUT = 5000  # ms


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════

class HealthStatus(str, Enum):
    """Статус здоровья компонента."""
    
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class GuardianMode(str, Enum):
    """Режим работы Guardian."""
    
    NORMAL = "normal"       # Нормальная работа
    SAFE = "safe"           # Safe mode — только upstream
    RECOVERY = "recovery"   # Попытка восстановления
    DISABLED = "disabled"   # Отключён


class ComponentType(str, Enum):
    """Тип компонента для мониторинга."""
    
    DNS_RESOLVER = "dns_resolver"
    UPSTREAM = "upstream"
    CACHE = "cache"
    VAULT = "vault"
    VERDICT_ENGINE = "verdict_engine"
    FLOW_LOGGER = "flow_logger"
    METRICS = "metrics"


# ════════════════════════════════════════════════════════════════════════════════
# HEALTH CHECK RESULT
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class HealthCheckResult:
    """Результат проверки здоровья."""
    
    component: ComponentType
    status: HealthStatus
    message: str = ""
    latency_ms: float = 0.0
    details: dict[str, Any] = field(default_factory=dict)
    timestamp: datetime = field(default_factory=datetime.now)
    
    @property
    def ok(self) -> bool:
        return self.status in (HealthStatus.HEALTHY, HealthStatus.DEGRADED)
    
    def to_dict(self) -> dict[str, Any]:
        return {
            "component": self.component.value,
            "status": self.status.value,
            "message": self.message,
            "latency_ms": self.latency_ms,
            "details": self.details,
            "timestamp": self.timestamp.isoformat(),
        }


# ════════════════════════════════════════════════════════════════════════════════
# HEALTH CHECKER
# ════════════════════════════════════════════════════════════════════════════════

class HealthChecker:
    """
    Проверка здоровья компонентов.
    
    Каждый компонент имеет свой метод проверки.
    """
    
    def __init__(self, context: "BootstrapContext"):
        self._context = context
    
    async def check_all(self) -> list[HealthCheckResult]:
        """Проверка всех компонентов."""
        results = []
        
        # Проверяем каждый компонент
        checks = [
            self.check_upstream(),
            self.check_cache(),
            self.check_vault(),
            self.check_verdict_engine(),
            self.check_flow_logger(),
        ]
        
        # Выполняем параллельно
        completed = await asyncio.gather(*checks, return_exceptions=True)
        
        for result in completed:
            if isinstance(result, HealthCheckResult):
                results.append(result)
            elif isinstance(result, Exception):
                results.append(HealthCheckResult(
                    component=ComponentType.DNS_RESOLVER,
                    status=HealthStatus.UNKNOWN,
                    message=f"Check failed: {result}",
                ))
        
        return results
    
    async def check_upstream(self) -> HealthCheckResult:
        """Проверка upstream DNS серверов."""
        start = time.perf_counter()
        
        try:
            upstream = self._context.upstream_manager
            if upstream is None:
                return HealthCheckResult(
                    component=ComponentType.UPSTREAM,
                    status=HealthStatus.UNHEALTHY,
                    message="Upstream manager not initialized",
                )
            
            # Проверяем доступность хотя бы одного upstream
            healthy_count = 0
            total_count = len(upstream.servers) if hasattr(upstream, 'servers') else 0
            
            for server in getattr(upstream, 'servers', []):
                try:
                    # Попытка резолва тестового домена
                    await asyncio.wait_for(
                        upstream.query("health.check.local", "A"),
                        timeout=5.0,
                    )
                    healthy_count += 1
                except Exception:
                    pass
            
            latency = (time.perf_counter() - start) * 1000
            
            if healthy_count == 0:
                return HealthCheckResult(
                    component=ComponentType.UPSTREAM,
                    status=HealthStatus.UNHEALTHY,
                    message="No healthy upstream servers",
                    latency_ms=latency,
                    details={"healthy": 0, "total": total_count},
                )
            elif healthy_count < total_count:
                return HealthCheckResult(
                    component=ComponentType.UPSTREAM,
                    status=HealthStatus.DEGRADED,
                    message=f"{healthy_count}/{total_count} upstream servers healthy",
                    latency_ms=latency,
                    details={"healthy": healthy_count, "total": total_count},
                )
            else:
                return HealthCheckResult(
                    component=ComponentType.UPSTREAM,
                    status=HealthStatus.HEALTHY,
                    message="All upstream servers healthy",
                    latency_ms=latency,
                    details={"healthy": healthy_count, "total": total_count},
                )
        except Exception as e:
            return HealthCheckResult(
                component=ComponentType.UPSTREAM,
                status=HealthStatus.UNKNOWN,
                message=f"Check failed: {e}",
                latency_ms=(time.perf_counter() - start) * 1000,
            )
    
    async def check_cache(self) -> HealthCheckResult:
        """Проверка DNS кеша."""
        start = time.perf_counter()
        
        try:
            cache = self._context.dns_cache
            if cache is None:
                return HealthCheckResult(
                    component=ComponentType.CACHE,
                    status=HealthStatus.UNHEALTHY,
                    message="Cache not initialized",
                )
            
            # Проверяем базовые операции
            test_domain = "__health_check__.local"
            test_value = {"answers": [], "ttl": 60}
            
            await cache.set_response(test_domain, "A", test_value, ttl=60)
            retrieved = await cache.get_response(test_domain, "A")
            await cache.invalidate(test_domain, "A")
            
            latency = (time.perf_counter() - start) * 1000
            
            if retrieved is None:
                return HealthCheckResult(
                    component=ComponentType.CACHE,
                    status=HealthStatus.DEGRADED,
                    message="Cache read/write issue",
                    latency_ms=latency,
                )
            
            # Статистика кеша — строго best-effort. `stats` это @property (не метод),
            # поэтому прежний вызов cache.stats() кидал TypeError на КАЖДОЙ проверке,
            # из-за чего кеш помечался UNHEALTHY и Guardian чистил его в цикле — кеш
            # никогда не прогревался, и часть запросов отваливалась в SERVFAIL.
            # Сбор статистики не должен влиять на вердикт о здоровье кеша.
            stats: dict = {}
            try:
                s = getattr(cache, "stats", None)
                if callable(s):
                    s = s()
                if isinstance(s, dict):
                    stats = s
                elif s is not None and hasattr(s, "__dict__"):
                    stats = {k: v for k, v in vars(s).items() if not k.startswith("_")}
            except Exception:
                stats = {}

            return HealthCheckResult(
                component=ComponentType.CACHE,
                status=HealthStatus.HEALTHY,
                message="Cache operational",
                latency_ms=latency,
                details=stats,
            )
        except Exception as e:
            return HealthCheckResult(
                component=ComponentType.CACHE,
                status=HealthStatus.UNHEALTHY,
                message=f"Cache error: {e}",
                latency_ms=(time.perf_counter() - start) * 1000,
            )
    
    async def check_vault(self) -> HealthCheckResult:
        """Проверка Vault хранилища."""
        start = time.perf_counter()
        
        try:
            vault = self._context.vault_repository
            if vault is None:
                return HealthCheckResult(
                    component=ComponentType.VAULT,
                    status=HealthStatus.UNHEALTHY,
                    message="Vault not initialized",
                )
            
            # Проверяем доступность БД
            if hasattr(vault, 'health_check'):
                ok = await vault.health_check()
            else:
                ok = True  # Предполагаем OK если нет метода проверки
            
            latency = (time.perf_counter() - start) * 1000
            
            if ok:
                return HealthCheckResult(
                    component=ComponentType.VAULT,
                    status=HealthStatus.HEALTHY,
                    message="Vault operational",
                    latency_ms=latency,
                )
            else:
                return HealthCheckResult(
                    component=ComponentType.VAULT,
                    status=HealthStatus.UNHEALTHY,
                    message="Vault health check failed",
                    latency_ms=latency,
                )
        except Exception as e:
            return HealthCheckResult(
                component=ComponentType.VAULT,
                status=HealthStatus.UNHEALTHY,
                message=f"Vault error: {e}",
                latency_ms=(time.perf_counter() - start) * 1000,
            )
    
    async def check_verdict_engine(self) -> HealthCheckResult:
        """Проверка Verdict Engine."""
        start = time.perf_counter()
        
        try:
            engine = self._context.verdict_engine
            if engine is None:
                return HealthCheckResult(
                    component=ComponentType.VERDICT_ENGINE,
                    status=HealthStatus.UNHEALTHY,
                    message="Verdict engine not initialized",
                )
            
            # Проверяем обработку тестового запроса
            # (минимальная проверка — engine существует и доступен)
            
            latency = (time.perf_counter() - start) * 1000
            
            return HealthCheckResult(
                component=ComponentType.VERDICT_ENGINE,
                status=HealthStatus.HEALTHY,
                message="Verdict engine operational",
                latency_ms=latency,
            )
        except Exception as e:
            return HealthCheckResult(
                component=ComponentType.VERDICT_ENGINE,
                status=HealthStatus.UNHEALTHY,
                message=f"Verdict engine error: {e}",
                latency_ms=(time.perf_counter() - start) * 1000,
            )
    
    async def check_flow_logger(self) -> HealthCheckResult:
        """Проверка Flow Logger."""
        start = time.perf_counter()
        
        try:
            flow_logger = self._context.flow_logger
            if flow_logger is None:
                return HealthCheckResult(
                    component=ComponentType.FLOW_LOGGER,
                    status=HealthStatus.DEGRADED,
                    message="Flow logger not initialized (non-critical)",
                )
            
            # Проверяем статистику
            if hasattr(flow_logger, 'get_stats'):
                stats = await flow_logger.get_stats()
            else:
                stats = {}
            
            latency = (time.perf_counter() - start) * 1000
            
            return HealthCheckResult(
                component=ComponentType.FLOW_LOGGER,
                status=HealthStatus.HEALTHY,
                message="Flow logger operational",
                latency_ms=latency,
                details=stats,
            )
        except Exception as e:
            return HealthCheckResult(
                component=ComponentType.FLOW_LOGGER,
                status=HealthStatus.DEGRADED,
                message=f"Flow logger issue: {e}",
                latency_ms=(time.perf_counter() - start) * 1000,
            )


# ════════════════════════════════════════════════════════════════════════════════
# RECOVERY STRATEGY
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class RecoveryAttempt:
    """Информация о попытке восстановления."""
    
    component: ComponentType
    timestamp: datetime
    success: bool
    message: str


class RecoveryManager:
    """
    Управление восстановлением компонентов.
    
    Стратегии восстановления:
    - Перезапуск компонента
    - Переключение на резервный upstream
    - Активация safe-mode
    """
    
    def __init__(
        self,
        context: "BootstrapContext",
        max_attempts: int = DEFAULT_RECOVERY_ATTEMPTS,
        cooldown: int = DEFAULT_RECOVERY_COOLDOWN,
    ):
        self._context = context
        self._max_attempts = max_attempts
        self._cooldown = cooldown
        
        # История попыток
        self._attempts: dict[ComponentType, list[RecoveryAttempt]] = {}
    
    def can_attempt_recovery(self, component: ComponentType) -> bool:
        """Можно ли попытаться восстановить компонент."""
        attempts = self._attempts.get(component, [])
        
        if not attempts:
            return True
        
        # Фильтруем недавние попытки
        cutoff = datetime.now() - timedelta(seconds=self._cooldown)
        recent = [a for a in attempts if a.timestamp > cutoff]
        
        return len(recent) < self._max_attempts
    
    async def recover(self, component: ComponentType) -> RecoveryAttempt:
        """Попытка восстановления компонента."""
        logger.warning("Attempting recovery for %s", component.value)
        
        success = False
        message = ""
        
        try:
            if component == ComponentType.UPSTREAM:
                success, message = await self._recover_upstream()
            elif component == ComponentType.CACHE:
                success, message = await self._recover_cache()
            elif component == ComponentType.VAULT:
                success, message = await self._recover_vault()
            elif component == ComponentType.VERDICT_ENGINE:
                success, message = await self._recover_verdict_engine()
            else:
                message = f"No recovery strategy for {component.value}"
        except Exception as e:
            message = f"Recovery failed: {e}"
        
        # Записываем попытку
        attempt = RecoveryAttempt(
            component=component,
            timestamp=datetime.now(),
            success=success,
            message=message,
        )
        
        if component not in self._attempts:
            self._attempts[component] = []
        self._attempts[component].append(attempt)
        
        # Ограничиваем историю
        self._attempts[component] = self._attempts[component][-10:]
        
        if success:
            logger.info("Recovery successful for %s: %s", component.value, message)
        else:
            logger.error("Recovery failed for %s: %s", component.value, message)
        
        return attempt
    
    async def _recover_upstream(self) -> tuple[bool, str]:
        """Восстановление upstream."""
        upstream = self._context.upstream_manager
        if upstream is None:
            return False, "Upstream manager not available"
        
        # Пробуем переключиться на следующий сервер
        if hasattr(upstream, 'rotate_servers'):
            upstream.rotate_servers()
            return True, "Rotated to next upstream server"
        
        # Сброс статистики и повторное подключение
        if hasattr(upstream, 'reset'):
            await upstream.reset()
            return True, "Reset upstream connections"
        
        return False, "No recovery action available"
    
    async def _recover_cache(self) -> tuple[bool, str]:
        """Восстановление кеша."""
        cache = self._context.dns_cache
        if cache is None:
            return False, "Cache not available"
        
        # Очистка кеша при проблемах
        if hasattr(cache, 'clear'):
            result = cache.clear()
            if asyncio.iscoroutine(result):
                await result
            return True, "Cache cleared"
        
        return False, "No recovery action available"
    
    async def _recover_vault(self) -> tuple[bool, str]:
        """Восстановление vault."""
        vault = self._context.vault_repository
        if vault is None:
            return False, "Vault not available"
        
        # Переподключение к БД
        if hasattr(vault, 'reconnect'):
            await vault.reconnect()
            return True, "Vault reconnected"
        
        return False, "No recovery action available"
    
    async def _recover_verdict_engine(self) -> tuple[bool, str]:
        """Восстановление verdict engine."""
        engine = self._context.verdict_engine
        if engine is None:
            return False, "Verdict engine not available"
        
        # Перезагрузка matchers
        if hasattr(engine, 'reload'):
            await engine.reload()
            return True, "Verdict engine reloaded"
        
        return False, "No recovery action available"
    
    def get_history(self, component: ComponentType | None = None) -> list[dict[str, Any]]:
        """Получение истории восстановлений."""
        if component:
            attempts = self._attempts.get(component, [])
        else:
            attempts = []
            for comp_attempts in self._attempts.values():
                attempts.extend(comp_attempts)
            attempts.sort(key=lambda a: a.timestamp, reverse=True)
        
        return [
            {
                "component": a.component.value,
                "timestamp": a.timestamp.isoformat(),
                "success": a.success,
                "message": a.message,
            }
            for a in attempts
        ]


# ════════════════════════════════════════════════════════════════════════════════
# GUARDIAN
# ════════════════════════════════════════════════════════════════════════════════

class Guardian:
    """
    Watchdog для NetProtection.
    
    Функции:
    - Периодические health-checks
    - Автоматическое восстановление
    - Safe-mode при критических сбоях
    - Уведомления о проблемах
    """
    
    def __init__(
        self,
        context: "BootstrapContext",
        *,
        check_interval: int = DEFAULT_HEALTH_CHECK_INTERVAL,
        safe_mode_on_failure: bool = True,
    ):
        self._context = context
        self._check_interval = check_interval
        self._safe_mode_on_failure = safe_mode_on_failure
        
        # Компоненты
        self._health_checker = HealthChecker(context)
        self._recovery_manager = RecoveryManager(context)
        
        # Состояние
        self._mode = GuardianMode.NORMAL
        self._running = False
        self._check_task: asyncio.Task | None = None
        
        # История health checks
        self._last_results: list[HealthCheckResult] = []
        self._started_at: datetime | None = None
        self._safe_mode_entered_at: datetime | None = None
        
        # Callbacks
        self._on_mode_change: Callable[[GuardianMode, GuardianMode], None] | None = None
        self._on_health_issue: Callable[[HealthCheckResult], None] | None = None
    
    @property
    def mode(self) -> GuardianMode:
        """Текущий режим."""
        return self._mode
    
    @property
    def is_safe_mode(self) -> bool:
        """Активен ли safe mode."""
        return self._mode == GuardianMode.SAFE
    
    @property
    def is_running(self) -> bool:
        """Запущен ли Guardian."""
        return self._running
    
    def on_mode_change(
        self,
        callback: Callable[[GuardianMode, GuardianMode], None],
    ) -> None:
        """Callback при смене режима."""
        self._on_mode_change = callback
    
    def on_health_issue(
        self,
        callback: Callable[[HealthCheckResult], None],
    ) -> None:
        """Callback при проблеме со здоровьем."""
        self._on_health_issue = callback
    
    async def start(self) -> None:
        """Запуск Guardian."""
        if self._running:
            return
        
        self._running = True
        self._started_at = datetime.now()
        self._mode = GuardianMode.NORMAL
        
        self._check_task = asyncio.create_task(self._check_loop())
        
        logger.info("Guardian started (interval=%ds)", self._check_interval)
    
    async def stop(self) -> None:
        """Остановка Guardian."""
        self._running = False
        
        if self._check_task:
            self._check_task.cancel()
            try:
                await self._check_task
            except asyncio.CancelledError:
                pass
        
        logger.info("Guardian stopped")
    
    async def _check_loop(self) -> None:
        """Основной цикл проверок."""
        while self._running:
            try:
                await self._perform_health_check()
            except Exception as e:
                logger.error("Health check error: %s", e)
            
            await asyncio.sleep(self._check_interval)
    
    async def _perform_health_check(self) -> None:
        """Выполнение проверки здоровья."""
        results = await self._health_checker.check_all()
        self._last_results = results
        
        # Анализируем результаты
        unhealthy = [r for r in results if r.status == HealthStatus.UNHEALTHY]
        degraded = [r for r in results if r.status == HealthStatus.DEGRADED]
        
        # Уведомляем о проблемах
        for result in unhealthy + degraded:
            if self._on_health_issue:
                self._on_health_issue(result)
        
        # Критические компоненты
        critical_unhealthy = [
            r for r in unhealthy
            if r.component in (ComponentType.UPSTREAM, ComponentType.DNS_RESOLVER)
        ]
        
        # Решаем, что делать
        if critical_unhealthy:
            if self._mode == GuardianMode.NORMAL:
                # Пытаемся восстановить
                await self._attempt_recovery(critical_unhealthy)
            elif self._mode == GuardianMode.RECOVERY:
                # Восстановление не помогло — safe mode
                if self._safe_mode_on_failure:
                    await self._enter_safe_mode()
        elif unhealthy:
            # Некритичные проблемы — пытаемся восстановить
            await self._attempt_recovery(unhealthy)
        elif self._mode == GuardianMode.SAFE:
            # Всё хорошо — выходим из safe mode
            await self._exit_safe_mode()
        elif self._mode == GuardianMode.RECOVERY:
            # Восстановление успешно
            self._set_mode(GuardianMode.NORMAL)
    
    async def _attempt_recovery(self, unhealthy: list[HealthCheckResult]) -> None:
        """Попытка восстановления."""
        self._set_mode(GuardianMode.RECOVERY)
        
        for result in unhealthy:
            if self._recovery_manager.can_attempt_recovery(result.component):
                await self._recovery_manager.recover(result.component)
    
    async def _enter_safe_mode(self) -> None:
        """Вход в safe mode."""
        logger.warning("Entering SAFE MODE — all queries will be forwarded to upstream")
        
        self._set_mode(GuardianMode.SAFE)
        self._safe_mode_entered_at = datetime.now()
        
        # The DNS server reads Guardian.mode before every verdict and forwards
        # directly to upstream while this state is active. Keeping the state in
        # one place avoids relying on an optional verdict-engine bypass method.
    
    async def _exit_safe_mode(self) -> None:
        """Выход из safe mode."""
        logger.info("Exiting SAFE MODE — resuming normal operation")
        
        self._set_mode(GuardianMode.NORMAL)
        self._safe_mode_entered_at = None
        
        # Normal DNS verdict processing resumes automatically from this state.
    
    def _set_mode(self, new_mode: GuardianMode) -> None:
        """Установка режима."""
        if new_mode == self._mode:
            return
        
        old_mode = self._mode
        self._mode = new_mode
        
        logger.info("Guardian mode: %s -> %s", old_mode.value, new_mode.value)
        
        if self._on_mode_change:
            self._on_mode_change(old_mode, new_mode)
    
    # ─────────────────────────────────────────────────────────────────────────
    # Manual Controls
    # ─────────────────────────────────────────────────────────────────────────
    
    async def force_safe_mode(self) -> None:
        """Принудительный вход в safe mode."""
        await self._enter_safe_mode()
    
    async def force_normal_mode(self) -> None:
        """Принудительный выход из safe mode."""
        await self._exit_safe_mode()
    
    async def trigger_health_check(self) -> list[HealthCheckResult]:
        """Ручной запуск проверки здоровья."""
        results = await self._health_checker.check_all()
        self._last_results = results
        return results
    
    # ─────────────────────────────────────────────────────────────────────────
    # Status
    # ─────────────────────────────────────────────────────────────────────────
    
    def get_status(self) -> dict[str, Any]:
        """Получение статуса Guardian."""
        # Подсчёт по статусам
        healthy = sum(1 for r in self._last_results if r.status == HealthStatus.HEALTHY)
        degraded = sum(1 for r in self._last_results if r.status == HealthStatus.DEGRADED)
        unhealthy = sum(1 for r in self._last_results if r.status == HealthStatus.UNHEALTHY)
        
        # Общий статус
        if unhealthy > 0:
            overall = HealthStatus.UNHEALTHY
        elif degraded > 0:
            overall = HealthStatus.DEGRADED
        elif healthy > 0:
            overall = HealthStatus.HEALTHY
        else:
            overall = HealthStatus.UNKNOWN
        
        return {
            "mode": self._mode.value,
            "running": self._running,
            "overall_health": overall.value,
            "started_at": self._started_at.isoformat() if self._started_at else None,
            "safe_mode_since": self._safe_mode_entered_at.isoformat() if self._safe_mode_entered_at else None,
            "check_interval_seconds": self._check_interval,
            "components": {
                "healthy": healthy,
                "degraded": degraded,
                "unhealthy": unhealthy,
                "total": len(self._last_results),
            },
            "last_check": [r.to_dict() for r in self._last_results],
            "recovery_history": self._recovery_manager.get_history(),
        }
    
    def get_health_summary(self) -> dict[str, HealthStatus]:
        """Краткая сводка здоровья по компонентам."""
        return {
            r.component.value: r.status
            for r in self._last_results
        }


# ════════════════════════════════════════════════════════════════════════════════
# CONVENIENCE FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════════

def is_safe_mode_active(guardian: Guardian | None) -> bool:
    """Проверка, активен ли safe mode."""
    if guardian is None:
        return False
    return guardian.is_safe_mode


async def quick_health_check(context: "BootstrapContext") -> dict[str, HealthStatus]:
    """Быстрая проверка здоровья без Guardian."""
    checker = HealthChecker(context)
    results = await checker.check_all()
    return {r.component.value: r.status for r in results}
