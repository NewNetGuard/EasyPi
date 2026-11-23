"""Stable composite for NetProtection analytics behavior."""

from app.services.netprotection_components.analytics_parts.blocked_overview import (
    AnalyticsBlockedOverviewMixin,
)
from app.services.netprotection_components.analytics_parts.query_log import (
    AnalyticsQueryLogMixin,
)
from app.services.netprotection_components.analytics_parts.statistics import (
    AnalyticsStatisticsMixin,
)


class AnalyticsMixin(
    AnalyticsBlockedOverviewMixin, AnalyticsStatisticsMixin, AnalyticsQueryLogMixin
):
    """Stable mixin surface composed from focused analytics domains."""
