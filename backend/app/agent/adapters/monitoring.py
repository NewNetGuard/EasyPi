"""Dashboard and monitoring fact adapter."""

from __future__ import annotations

from typing import Any

from app.api.v1.endpoints.monitoring import get_service_metrics, get_system_stats


class MonitoringAdapter:
    """Expose read-only dashboard and monitoring state."""

    async def get_system_stats(self) -> dict[str, Any]:
        stats = await get_system_stats()
        if hasattr(stats, "model_dump"):
            return stats.model_dump(mode="json")
        return dict(stats)

    async def get_service_metrics(self) -> list[dict[str, Any]]:
        metrics = await get_service_metrics()
        normalized: list[dict[str, Any]] = []
        for metric in metrics:
            if hasattr(metric, "model_dump"):
                normalized.append(metric.model_dump(mode="json"))
            elif isinstance(metric, dict):
                normalized.append(dict(metric))
        return normalized
