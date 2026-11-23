"""
EasyPi NetProtection — Metrics Module.

Агрегированная статистика без PII (Personally Identifiable Information).
Счётчики, гистограммы, временные ряды.
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any

logger = logging.getLogger(__name__)


# ════════════════════════════════════════════════════════════════════════════════
# CONSTANTS
# ════════════════════════════════════════════════════════════════════════════════

# Интервалы агрегации
INTERVAL_MINUTE = 60
INTERVAL_HOUR = 3600
INTERVAL_DAY = 86400

# Максимальное количество точек в временных рядах
MAX_MINUTE_POINTS = 60      # 1 час по минутам
MAX_HOUR_POINTS = 24        # 1 день по часам
MAX_DAY_POINTS = 30         # 30 дней


# ════════════════════════════════════════════════════════════════════════════════
# ENUMS
# ════════════════════════════════════════════════════════════════════════════════

class MetricType(str, Enum):
    """Тип метрики."""
    
    COUNTER = "counter"       # Только увеличивается
    GAUGE = "gauge"           # Текущее значение
    HISTOGRAM = "histogram"   # Распределение значений
    SUMMARY = "summary"       # Квантили


class TimeGranularity(str, Enum):
    """Гранулярность временных рядов."""
    
    MINUTE = "minute"
    HOUR = "hour"
    DAY = "day"


# ════════════════════════════════════════════════════════════════════════════════
# COUNTER
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class Counter:
    """
    Счётчик — только увеличивается.
    
    Примеры: total_queries, blocked_count, cache_hits
    """
    
    name: str
    value: int = 0
    labels: dict[str, str] = field(default_factory=dict)
    created_at: datetime = field(default_factory=datetime.now)
    
    def inc(self, amount: int = 1) -> None:
        """Увеличение счётчика."""
        self.value += amount
    
    def get(self) -> int:
        """Получение значения."""
        return self.value
    
    def reset(self) -> None:
        """Сброс счётчика (осторожно!)."""
        self.value = 0
    
    def to_dict(self) -> dict[str, Any]:
        """Сериализация."""
        return {
            "name": self.name,
            "type": "counter",
            "value": self.value,
            "labels": self.labels,
        }


# ════════════════════════════════════════════════════════════════════════════════
# GAUGE
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class Gauge:
    """
    Измеритель — текущее значение, может увеличиваться и уменьшаться.
    
    Примеры: active_connections, cache_size, memory_usage
    """
    
    name: str
    value: float = 0.0
    labels: dict[str, str] = field(default_factory=dict)
    
    def set(self, value: float) -> None:
        """Установка значения."""
        self.value = value
    
    def inc(self, amount: float = 1.0) -> None:
        """Увеличение."""
        self.value += amount
    
    def dec(self, amount: float = 1.0) -> None:
        """Уменьшение."""
        self.value -= amount
    
    def get(self) -> float:
        """Получение значения."""
        return self.value
    
    def to_dict(self) -> dict[str, Any]:
        """Сериализация."""
        return {
            "name": self.name,
            "type": "gauge",
            "value": self.value,
            "labels": self.labels,
        }


# ════════════════════════════════════════════════════════════════════════════════
# HISTOGRAM
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class Histogram:
    """
    Гистограмма — распределение значений по bucket'ам.
    
    Примеры: latency_ms, response_size
    """
    
    name: str
    buckets: tuple[float, ...] = (0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0)
    labels: dict[str, str] = field(default_factory=dict)
    
    # Внутреннее состояние
    _bucket_counts: dict[float, int] = field(default_factory=dict)
    _sum: float = 0.0
    _count: int = 0
    
    def __post_init__(self):
        # Инициализация bucket'ов
        for bucket in self.buckets:
            self._bucket_counts[bucket] = 0
        self._bucket_counts[float('inf')] = 0
    
    def observe(self, value: float) -> None:
        """Добавление наблюдения."""
        self._sum += value
        self._count += 1
        
        for bucket in self.buckets:
            if value <= bucket:
                self._bucket_counts[bucket] += 1
        self._bucket_counts[float('inf')] += 1
    
    def get_bucket_counts(self) -> dict[str, int]:
        """Получение counts по bucket'ам."""
        return {
            str(k) if k != float('inf') else '+Inf': v
            for k, v in self._bucket_counts.items()
        }
    
    def get_sum(self) -> float:
        """Сумма всех наблюдений."""
        return self._sum
    
    def get_count(self) -> int:
        """Количество наблюдений."""
        return self._count
    
    def get_mean(self) -> float:
        """Среднее значение."""
        if self._count == 0:
            return 0.0
        return self._sum / self._count
    
    def to_dict(self) -> dict[str, Any]:
        """Сериализация."""
        return {
            "name": self.name,
            "type": "histogram",
            "buckets": self.get_bucket_counts(),
            "sum": self._sum,
            "count": self._count,
            "mean": self.get_mean(),
            "labels": self.labels,
        }


# ════════════════════════════════════════════════════════════════════════════════
# TIME SERIES
# ════════════════════════════════════════════════════════════════════════════════

@dataclass
class TimeSeriesPoint:
    """Точка временного ряда."""
    
    timestamp: datetime
    value: float


class TimeSeries:
    """
    Временной ряд с автоматической агрегацией.
    
    Хранит данные с разной гранулярностью:
    - Минутные данные за последний час
    - Часовые данные за последние сутки
    - Дневные данные за последний месяц
    """
    
    def __init__(self, name: str):
        self.name = name
        
        # Данные по гранулярности
        self._minute_data: list[TimeSeriesPoint] = []
        self._hour_data: list[TimeSeriesPoint] = []
        self._day_data: list[TimeSeriesPoint] = []
        
        # Текущие накопители для агрегации
        self._current_minute_sum = 0.0
        self._current_minute_count = 0
        self._current_minute_start: datetime | None = None
        
        self._current_hour_sum = 0.0
        self._current_hour_count = 0
        self._current_hour_start: datetime | None = None
    
    def add(self, value: float, timestamp: datetime | None = None) -> None:
        """Добавление значения."""
        ts = timestamp or datetime.now()
        
        # Инициализация
        if self._current_minute_start is None:
            self._current_minute_start = ts.replace(second=0, microsecond=0)
        if self._current_hour_start is None:
            self._current_hour_start = ts.replace(minute=0, second=0, microsecond=0)
        
        # Проверяем, нужно ли закрыть минуту
        minute_start = ts.replace(second=0, microsecond=0)
        if minute_start > self._current_minute_start:
            self._close_minute()
            self._current_minute_start = minute_start
        
        # Проверяем, нужно ли закрыть час
        hour_start = ts.replace(minute=0, second=0, microsecond=0)
        if hour_start > self._current_hour_start:
            self._close_hour()
            self._current_hour_start = hour_start
        
        # Добавляем в текущие накопители
        self._current_minute_sum += value
        self._current_minute_count += 1
        self._current_hour_sum += value
        self._current_hour_count += 1
    
    def _close_minute(self) -> None:
        """Закрытие минутного интервала."""
        if self._current_minute_count > 0 and self._current_minute_start:
            avg = self._current_minute_sum / self._current_minute_count
            self._minute_data.append(TimeSeriesPoint(
                timestamp=self._current_minute_start,
                value=avg,
            ))
            
            # Ограничиваем размер
            if len(self._minute_data) > MAX_MINUTE_POINTS:
                self._minute_data = self._minute_data[-MAX_MINUTE_POINTS:]
        
        self._current_minute_sum = 0.0
        self._current_minute_count = 0
    
    def _close_hour(self) -> None:
        """Закрытие часового интервала."""
        if self._current_hour_count > 0 and self._current_hour_start:
            avg = self._current_hour_sum / self._current_hour_count
            self._hour_data.append(TimeSeriesPoint(
                timestamp=self._current_hour_start,
                value=avg,
            ))
            
            # Ограничиваем размер
            if len(self._hour_data) > MAX_HOUR_POINTS:
                self._hour_data = self._hour_data[-MAX_HOUR_POINTS:]
            
            # Агрегация в дневные данные (каждые 24 часа)
            if len(self._hour_data) >= 24:
                day_start = self._hour_data[-24].timestamp.replace(
                    hour=0, minute=0, second=0, microsecond=0
                )
                day_sum = sum(p.value for p in self._hour_data[-24:])
                self._day_data.append(TimeSeriesPoint(
                    timestamp=day_start,
                    value=day_sum / 24,
                ))
                
                if len(self._day_data) > MAX_DAY_POINTS:
                    self._day_data = self._day_data[-MAX_DAY_POINTS:]
        
        self._current_hour_sum = 0.0
        self._current_hour_count = 0
    
    def get_data(self, granularity: TimeGranularity) -> list[dict[str, Any]]:
        """Получение данных с указанной гранулярностью."""
        if granularity == TimeGranularity.MINUTE:
            data = self._minute_data
        elif granularity == TimeGranularity.HOUR:
            data = self._hour_data
        else:
            data = self._day_data
        
        return [
            {"timestamp": p.timestamp.isoformat(), "value": p.value}
            for p in data
        ]
    
    def to_dict(self) -> dict[str, Any]:
        """Сериализация."""
        return {
            "name": self.name,
            "minute": self.get_data(TimeGranularity.MINUTE),
            "hour": self.get_data(TimeGranularity.HOUR),
            "day": self.get_data(TimeGranularity.DAY),
        }


# ════════════════════════════════════════════════════════════════════════════════
# TOP-N TRACKER
# ════════════════════════════════════════════════════════════════════════════════

class TopNTracker:
    """
    Отслеживание Top-N элементов.
    
    Примеры: top_blocked_domains, top_clients, top_query_types
    """
    
    def __init__(self, name: str, max_items: int = 100):
        self.name = name
        self.max_items = max_items
        self._counts: dict[str, int] = defaultdict(int)
    
    def record(self, item: str, count: int = 1) -> None:
        """Запись элемента."""
        self._counts[item] += count
        
        # Очистка, если слишком много элементов
        if len(self._counts) > self.max_items * 2:
            self._prune()
    
    def _prune(self) -> None:
        """Удаление редких элементов."""
        sorted_items = sorted(
            self._counts.items(),
            key=lambda x: x[1],
            reverse=True,
        )
        # Сохраняем как defaultdict, чтобы избежать KeyError
        self._counts = defaultdict(int, dict(sorted_items[:self.max_items]))
    
    def get_top(self, n: int = 10) -> list[dict[str, Any]]:
        """Получение Top-N."""
        sorted_items = sorted(
            self._counts.items(),
            key=lambda x: x[1],
            reverse=True,
        )[:n]
        
        return [
            {"item": item, "count": count}
            for item, count in sorted_items
        ]
    
    def get_count(self, item: str) -> int:
        """Получение count для элемента."""
        return self._counts.get(item, 0)
    
    def to_dict(self) -> dict[str, Any]:
        """Сериализация."""
        return {
            "name": self.name,
            "top": self.get_top(10),
            "total_unique": len(self._counts),
        }


# ════════════════════════════════════════════════════════════════════════════════
# METRICS REGISTRY
# ════════════════════════════════════════════════════════════════════════════════

class MetricsRegistry:
    """
    Реестр метрик.
    
    Централизованное хранилище всех метрик модуля.
    """
    
    def __init__(self):
        self._counters: dict[str, Counter] = {}
        self._gauges: dict[str, Gauge] = {}
        self._histograms: dict[str, Histogram] = {}
        self._time_series: dict[str, TimeSeries] = {}
        self._top_trackers: dict[str, TopNTracker] = {}
        
        self._start_time = time.time()
    
    # ─────────────────────────────────────────────────────────────────────────
    # Counter
    # ─────────────────────────────────────────────────────────────────────────
    
    def counter(self, name: str, labels: dict[str, str] | None = None) -> Counter:
        """Получение или создание счётчика."""
        key = self._make_key(name, labels)
        if key not in self._counters:
            self._counters[key] = Counter(name=name, labels=labels or {})
        return self._counters[key]
    
    # ─────────────────────────────────────────────────────────────────────────
    # Gauge
    # ─────────────────────────────────────────────────────────────────────────
    
    def gauge(self, name: str, labels: dict[str, str] | None = None) -> Gauge:
        """Получение или создание gauge."""
        key = self._make_key(name, labels)
        if key not in self._gauges:
            self._gauges[key] = Gauge(name=name, labels=labels or {})
        return self._gauges[key]
    
    # ─────────────────────────────────────────────────────────────────────────
    # Histogram
    # ─────────────────────────────────────────────────────────────────────────
    
    def histogram(
        self,
        name: str,
        buckets: tuple[float, ...] | None = None,
        labels: dict[str, str] | None = None,
    ) -> Histogram:
        """Получение или создание гистограммы."""
        key = self._make_key(name, labels)
        if key not in self._histograms:
            self._histograms[key] = Histogram(
                name=name,
                buckets=buckets or Histogram.buckets,
                labels=labels or {},
            )
        return self._histograms[key]
    
    # ─────────────────────────────────────────────────────────────────────────
    # Time Series
    # ─────────────────────────────────────────────────────────────────────────
    
    def time_series(self, name: str) -> TimeSeries:
        """Получение или создание временного ряда."""
        if name not in self._time_series:
            self._time_series[name] = TimeSeries(name)
        return self._time_series[name]
    
    # ─────────────────────────────────────────────────────────────────────────
    # Top-N Tracker
    # ─────────────────────────────────────────────────────────────────────────
    
    def top_tracker(self, name: str, max_items: int = 100) -> TopNTracker:
        """Получение или создание Top-N tracker."""
        if name not in self._top_trackers:
            self._top_trackers[name] = TopNTracker(name, max_items)
        return self._top_trackers[name]
    
    # ─────────────────────────────────────────────────────────────────────────
    # Utility
    # ─────────────────────────────────────────────────────────────────────────
    
    def _make_key(self, name: str, labels: dict[str, str] | None) -> str:
        """Создание уникального ключа для метрики с labels."""
        if not labels:
            return name
        label_str = ",".join(f"{k}={v}" for k, v in sorted(labels.items()))
        return f"{name}{{{label_str}}}"
    
    def uptime_seconds(self) -> float:
        """Время работы в секундах."""
        return time.time() - self._start_time
    
    def get_all(self) -> dict[str, Any]:
        """Получение всех метрик."""
        return {
            "uptime_seconds": self.uptime_seconds(),
            "counters": {k: v.to_dict() for k, v in self._counters.items()},
            "gauges": {k: v.to_dict() for k, v in self._gauges.items()},
            "histograms": {k: v.to_dict() for k, v in self._histograms.items()},
            "time_series": {k: v.to_dict() for k, v in self._time_series.items()},
            "top_trackers": {k: v.to_dict() for k, v in self._top_trackers.items()},
        }


# ════════════════════════════════════════════════════════════════════════════════
# NETPROTECTION METRICS
# ════════════════════════════════════════════════════════════════════════════════

class NetProtectionMetrics:
    """
    Метрики специфичные для NetProtection.
    
    Предопределённые счётчики, гистограммы и трекеры.
    """
    
    def __init__(self, registry: MetricsRegistry | None = None):
        self._registry = registry or MetricsRegistry()
        
        # ─────────────────────────────────────────────────────────────────────
        # Counters
        # ─────────────────────────────────────────────────────────────────────
        
        self.total_queries = self._registry.counter("dns_queries_total")
        self.allowed_queries = self._registry.counter("dns_queries_allowed")
        self.blocked_queries = self._registry.counter("dns_queries_blocked")
        self.redirected_queries = self._registry.counter("dns_queries_redirected")
        
        self.cache_hits = self._registry.counter("dns_cache_hits")
        self.cache_misses = self._registry.counter("dns_cache_misses")
        
        self.upstream_queries = self._registry.counter("dns_upstream_queries")
        self.upstream_failures = self._registry.counter("dns_upstream_failures")
        
        self.dnssec_validations = self._registry.counter("dns_dnssec_validations")
        self.dnssec_failures = self._registry.counter("dns_dnssec_failures")
        
        # ─────────────────────────────────────────────────────────────────────
        # Gauges
        # ─────────────────────────────────────────────────────────────────────
        
        self.active_connections = self._registry.gauge("dns_active_connections")
        self.cache_size = self._registry.gauge("dns_cache_size")
        self.cache_memory_bytes = self._registry.gauge("dns_cache_memory_bytes")
        self.matcher_count = self._registry.gauge("dns_matcher_count")
        self.device_count = self._registry.gauge("dns_device_count")
        
        # ─────────────────────────────────────────────────────────────────────
        # Histograms
        # ─────────────────────────────────────────────────────────────────────
        
        # Latency в миллисекундах
        latency_buckets = (1, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000)
        self.query_latency = self._registry.histogram(
            "dns_query_latency_ms",
            buckets=latency_buckets,
        )
        self.upstream_latency = self._registry.histogram(
            "dns_upstream_latency_ms",
            buckets=latency_buckets,
        )
        self.verdict_latency = self._registry.histogram(
            "dns_verdict_latency_ms",
            buckets=(0.1, 0.5, 1, 2, 5, 10, 25, 50),
        )
        
        # ─────────────────────────────────────────────────────────────────────
        # Time Series
        # ─────────────────────────────────────────────────────────────────────
        
        self.qps_series = self._registry.time_series("dns_qps")
        self.blocked_series = self._registry.time_series("dns_blocked_rate")
        self.latency_series = self._registry.time_series("dns_latency_avg")
        
        # ─────────────────────────────────────────────────────────────────────
        # Top-N Trackers
        # ─────────────────────────────────────────────────────────────────────
        
        self.top_queried_domains = self._registry.top_tracker("top_queried_domains")
        self.top_blocked_domains = self._registry.top_tracker("top_blocked_domains")
        self.top_clients = self._registry.top_tracker("top_clients")
        self.top_query_types = self._registry.top_tracker("top_query_types")
        self.top_upstream_servers = self._registry.top_tracker("top_upstream_servers")
        self.top_block_reasons = self._registry.top_tracker("top_block_reasons")
        
        # Счётчик для QPS
        self._last_qps_update = time.time()
        self._queries_since_last_update = 0
        
        logger.info("NetProtectionMetrics initialized")
    
    @property
    def registry(self) -> MetricsRegistry:
        """Доступ к registry."""
        return self._registry
    
    # ─────────────────────────────────────────────────────────────────────────
    # Recording Methods
    # ─────────────────────────────────────────────────────────────────────────
    
    def record_query(
        self,
        domain: str,
        query_type: str,
        client_id: str,
        verdict: str,
        latency_ms: float,
        cached: bool = False,
        upstream_server: str | None = None,
        block_reason: str | None = None,
    ) -> None:
        """
        Запись метрик DNS-запроса.
        
        Вызывается для каждого обработанного запроса.
        """
        # Counters
        self.total_queries.inc()
        self._queries_since_last_update += 1
        
        if verdict == "allow":
            self.allowed_queries.inc()
        elif verdict == "deny":
            self.blocked_queries.inc()
            self.top_blocked_domains.record(domain)
            if block_reason:
                self.top_block_reasons.record(block_reason)
        elif verdict == "redirect":
            self.redirected_queries.inc()
        
        if cached:
            self.cache_hits.inc()
        else:
            self.cache_misses.inc()
        
        if upstream_server:
            self.upstream_queries.inc()
            self.top_upstream_servers.record(upstream_server)
        
        # Histograms
        self.query_latency.observe(latency_ms)
        
        # Top-N
        self.top_queried_domains.record(domain)
        self.top_clients.record(client_id)
        self.top_query_types.record(query_type)
        
        # Time series
        self.latency_series.add(latency_ms)
        
        # Обновление QPS
        self._update_qps()
    
    def record_upstream_query(
        self,
        server: str,
        latency_ms: float,
        success: bool,
    ) -> None:
        """Запись метрик upstream-запроса."""
        self.upstream_latency.observe(latency_ms)
        self.top_upstream_servers.record(server)
        
        if not success:
            self.upstream_failures.inc()
    
    def record_verdict_processing(self, latency_ms: float) -> None:
        """Запись времени обработки вердикта."""
        self.verdict_latency.observe(latency_ms)
    
    def record_dnssec_validation(self, success: bool) -> None:
        """Запись результата DNSSEC-валидации."""
        self.dnssec_validations.inc()
        if not success:
            self.dnssec_failures.inc()
    
    def _update_qps(self) -> None:
        """Обновление QPS в time series."""
        now = time.time()
        elapsed = now - self._last_qps_update
        
        if elapsed >= 1.0:  # Обновляем каждую секунду
            qps = self._queries_since_last_update / elapsed
            self.qps_series.add(qps)
            
            # Обновляем blocked rate
            total = self.total_queries.get()
            blocked = self.blocked_queries.get()
            if total > 0:
                blocked_rate = (blocked / total) * 100
                self.blocked_series.add(blocked_rate)
            
            self._last_qps_update = now
            self._queries_since_last_update = 0
    
    # ─────────────────────────────────────────────────────────────────────────
    # Summary Methods
    # ─────────────────────────────────────────────────────────────────────────
    
    def get_summary(self) -> dict[str, Any]:
        """
        Получение сводки метрик.
        
        Используется для API /metrics и dashboard.
        """
        total = self.total_queries.get()
        blocked = self.blocked_queries.get()
        allowed = self.allowed_queries.get()
        
        cache_hits = self.cache_hits.get()
        cache_misses = self.cache_misses.get()
        cache_total = cache_hits + cache_misses
        
        return {
            "uptime_seconds": self._registry.uptime_seconds(),
            "queries": {
                "total": total,
                "allowed": allowed,
                "blocked": blocked,
                "redirected": self.redirected_queries.get(),
                "block_rate_percent": (blocked / total * 100) if total > 0 else 0,
            },
            "cache": {
                "hits": cache_hits,
                "misses": cache_misses,
                "hit_rate_percent": (cache_hits / cache_total * 100) if cache_total > 0 else 0,
                "size": int(self.cache_size.get()),
            },
            "upstream": {
                "queries": self.upstream_queries.get(),
                "failures": self.upstream_failures.get(),
            },
            "latency": {
                "query_avg_ms": self.query_latency.get_mean(),
                "upstream_avg_ms": self.upstream_latency.get_mean(),
                "verdict_avg_ms": self.verdict_latency.get_mean(),
            },
            "top_blocked": self.top_blocked_domains.get_top(10),
            "top_queried": self.top_queried_domains.get_top(10),
            "top_clients": self.top_clients.get_top(10),
        }
    
    def get_time_series(self, granularity: TimeGranularity) -> dict[str, Any]:
        """Получение временных рядов."""
        return {
            "qps": self.qps_series.get_data(granularity),
            "blocked_rate": self.blocked_series.get_data(granularity),
            "latency": self.latency_series.get_data(granularity),
        }
    
    def get_all_metrics(self) -> dict[str, Any]:
        """Получение всех метрик (полный дамп)."""
        return self._registry.get_all()


# ════════════════════════════════════════════════════════════════════════════════
# GLOBAL INSTANCE
# ════════════════════════════════════════════════════════════════════════════════

# Глобальный экземпляр метрик
_metrics: NetProtectionMetrics | None = None


def get_metrics() -> NetProtectionMetrics:
    """Получение глобального экземпляра метрик."""
    global _metrics
    if _metrics is None:
        _metrics = NetProtectionMetrics()
    return _metrics


def reset_metrics() -> None:
    """Сброс метрик (для тестов)."""
    global _metrics
    _metrics = None
