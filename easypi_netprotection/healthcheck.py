"""Internal DNS resolver health-check identity.

The marker is deliberately accepted only from a loopback peer.  A LAN client
must never be able to use it to bypass the normal verdict pipeline.
"""

from __future__ import annotations

import ipaddress


RESOLVER_HEALTHCHECK_DOMAIN = "resolver-health.easypi.invalid"


def is_internal_resolver_healthcheck(client_ip: str, domain: str) -> bool:
    if (domain or "").strip().lower().rstrip(".") != RESOLVER_HEALTHCHECK_DOMAIN:
        return False

    try:
        address = ipaddress.ip_address((client_ip or "").split("%", 1)[0])
    except ValueError:
        return False

    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return address.is_loopback
