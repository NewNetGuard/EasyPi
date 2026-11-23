"""Validation helpers for outbound administrative network connections."""

from __future__ import annotations

import ipaddress


def require_public_ipv4(value: str, *, label: str = "Target") -> str:
    """Return canonical public unicast IPv4 or reject special/internal ranges."""

    try:
        address = ipaddress.ip_address(str(value).strip())
    except ValueError as exc:
        raise ValueError(f"{label} must be a valid IPv4 address") from exc

    if (
        address.version != 4
        or not address.is_global
        or address.is_multicast
        or address.is_reserved
        or address.is_unspecified
    ):
        raise ValueError(f"{label} must be a public IPv4 address")
    return str(address)
