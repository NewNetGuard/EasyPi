"""Stable composite for NetProtection detection behavior."""

from app.services.netprotection_components.detection_parts.domain_events import (
    DetectionDomainEventsMixin,
)
from app.services.netprotection_components.detection_parts.fail_closed import (
    DetectionFailClosedMixin,
)
from app.services.netprotection_components.detection_parts.network import (
    DetectionNetworkMixin,
)


class DetectionMixin(
    DetectionDomainEventsMixin, DetectionNetworkMixin, DetectionFailClosedMixin
):
    """Stable mixin surface composed from focused detection domains."""
