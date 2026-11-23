"""Shared overlap detection for EasyPi's two outbound routing features.

Stealth and Internet Encryption deliberately use separate routing tables and
firewall chains.  That makes disjoint per-device routing safe, but it does not
make overlapping routing claims deterministic from a user's point of view.
Keep this policy in the backend so direct API callers receive the same guard as
the web UI.
"""

from __future__ import annotations

from typing import Any, Dict, Iterable, Optional


FEATURE_LABELS = {
    "stealth": "Stealth",
    "internet_encryption": "Internet Encryption",
}


def _macs(devices: Iterable[Dict[str, Any]]) -> set[str]:
    return {
        str(device.get("mac", "")).strip().lower()
        for device in devices
        if isinstance(device, dict) and device.get("mac")
    }


def routing_claim(*, enabled: bool, scope: str, devices: Iterable[Dict[str, Any]]) -> Dict[str, Any]:
    """Return the minimum non-secret state needed for conflict detection."""

    return {
        "enabled": bool(enabled),
        "scope": "selected" if scope == "selected" else "all",
        "devices": [{"mac": mac} for mac in sorted(_macs(devices))],
    }


def detect_routing_conflict(
    *,
    feature: str,
    scope: str,
    devices: Iterable[Dict[str, Any]],
    other_feature: str,
    other_claim: Dict[str, Any],
) -> Optional[Dict[str, Any]]:
    """Describe an overlap, or return ``None`` for a safe disjoint setup.

    The caller may let an administrator explicitly acknowledge the result.  We
    intentionally do not auto-disable either feature: doing that behind the
    user's back could remove a kill switch or expose traffic unexpectedly.
    """

    if not other_claim.get("enabled"):
        return None

    candidate_scope = "selected" if scope == "selected" else "all"
    peer_scope = "selected" if other_claim.get("scope") == "selected" else "all"
    candidate_macs = _macs(devices)
    peer_macs = _macs(other_claim.get("devices") or [])

    overlap_count: Optional[int]
    if candidate_scope == "selected" and peer_scope == "selected":
        overlap = candidate_macs & peer_macs
        if not overlap:
            return None
        overlap_count = len(overlap)
        impact = (
            f"{overlap_count} selected device(s) are assigned to both transports. "
            "Internet Encryption currently wins the packet mark, so Stealth may appear enabled "
            "without carrying that device's traffic."
        )
    else:
        overlap_count = len(candidate_macs or peer_macs) or None
        impact = (
            "A Whole network scope overlaps the other transport. Routing priority and VPN type "
            "can make one tunnel bypass the other or create a nested tunnel, which may reduce "
            "performance or interrupt connectivity."
        )

    label = FEATURE_LABELS.get(feature, feature)
    other_label = FEATURE_LABELS.get(other_feature, other_feature)
    return {
        "code": "routing_scope_overlap",
        "title": f"{label} overlaps with {other_label}",
        "message": impact,
        "feature": feature,
        "other_feature": other_feature,
        "overlap_count": overlap_count,
        "requires_confirmation": True,
    }
