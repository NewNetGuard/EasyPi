"""SSRF guard for PTZ camera requests.

PTZ adapters contact cameras over the LAN. This guard makes sure they can only
reach a *camera* on an allowed local subnet — never EasyPi itself, its service
ports, loopback/link-local/multicast, or an arbitrary internet host — and it
pins the resolved IP so a hostname cannot be re-pointed after the check
(DNS rebinding). The camera address always comes from the stored camera row,
never from client input; this is the second line of defence.

Adapters that make HTTP calls MUST connect to the IP returned by
:func:`resolve_and_pin` (not re-resolve the name) and MUST disable redirects.
"""
from __future__ import annotations

import ipaddress
import socket
from typing import Optional, Tuple

from app.services.ptz.errors import PTZSecurityError

# Private LAN ranges EasyPi may reach by default (override via config).
_DEFAULT_ALLOWED_SUBNETS = ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7")
# Common IP-camera HTTP/ONVIF control ports (override via config). Empty => any.
_DEFAULT_ALLOWED_PORTS = (80, 443, 554, 2020, 5000, 8000, 8080, 8081, 8443, 8899, 34567)

_own_cache: Optional[set] = None


def _cfg():
    try:
        from config import get_settings

        return get_settings()
    except Exception:
        return None


def allowed_networks() -> list:
    cfg = _cfg()
    subnets = getattr(cfg, "PTZ_ALLOWED_SUBNETS", None) or list(_DEFAULT_ALLOWED_SUBNETS)
    nets = []
    for s in subnets:
        try:
            nets.append(ipaddress.ip_network(str(s), strict=False))
        except ValueError:
            continue
    return nets


def allowed_ports() -> set:
    cfg = _cfg()
    ports = getattr(cfg, "PTZ_ALLOWED_PORTS", None)
    if ports is None:
        ports = _DEFAULT_ALLOWED_PORTS
    out = set()
    for p in ports:
        try:
            out.add(int(p))
        except (TypeError, ValueError):
            continue
    return out


def own_ip_addresses(refresh: bool = False) -> set:
    """EasyPi's own IP addresses (as ipaddress objects), cached."""
    global _own_cache
    if _own_cache is not None and not refresh:
        return _own_cache

    out: set = set()

    def _add(raw: str) -> None:
        try:
            out.add(ipaddress.ip_address(str(raw).split("%")[0]))
        except ValueError:
            pass

    try:
        import psutil

        for _name, addrs in psutil.net_if_addrs().items():
            for a in addrs:
                if a.family in (socket.AF_INET, socket.AF_INET6):
                    _add(a.address)
    except Exception:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None):
            _add(info[4][0])
    except Exception:
        pass
    _add("127.0.0.1")
    _add("::1")

    _own_cache = out
    return out


def reset_caches() -> None:
    """Clear cached own-IP set (used by tests / after an IP change)."""
    global _own_cache
    _own_cache = None


def _blocked_reason(addr) -> Optional[str]:
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        # treat IPv4-mapped IPv6 as its embedded IPv4
        return _blocked_reason(addr.ipv4_mapped)
    if addr.is_loopback:
        return "loopback"
    if addr.is_link_local:
        return "link-local"
    if addr.is_multicast:
        return "multicast"
    if addr.is_unspecified:
        return "unspecified"
    if addr.is_reserved:
        return "reserved"
    return None


def validate_ip(ip_str: str):
    """Validate a concrete IP; raise :class:`PTZSecurityError` if not allowed."""
    try:
        addr = ipaddress.ip_address(str(ip_str).split("%")[0])
    except ValueError:
        raise PTZSecurityError("invalid camera address")

    reason = _blocked_reason(addr)
    if reason:
        raise PTZSecurityError(f"blocked camera address ({reason})")

    if addr in own_ip_addresses():
        raise PTZSecurityError("target is EasyPi itself")

    nets = allowed_networks()
    if nets and not any(addr in net for net in nets):
        raise PTZSecurityError("camera address is not in an allowed LAN subnet")

    return addr


def validate_port(port: int) -> int:
    try:
        p = int(port)
    except (TypeError, ValueError):
        raise PTZSecurityError("invalid port")
    if not (1 <= p <= 65535):
        raise PTZSecurityError("port out of range")
    ports = allowed_ports()
    if ports and p not in ports:
        raise PTZSecurityError("camera port is not allowed")
    return p


def resolve_and_pin(host: str, port: int) -> Tuple[str, int]:
    """Validate ``host``+``port`` and return the concrete IP to connect to.

    An IP literal is validated directly. A hostname is resolved ONCE, the
    resolved IP is validated, and that pinned IP is returned — the caller must
    connect to it (never re-resolve the name), which defeats DNS rebinding.
    """
    validate_port(port)
    host = (host or "").strip().strip("[]")
    if not host:
        raise PTZSecurityError("missing camera address")

    try:
        ipaddress.ip_address(host.split("%")[0])
        validate_ip(host)
        return host, int(port)
    except ValueError:
        pass  # not a literal IP -> resolve

    try:
        infos = socket.getaddrinfo(host, int(port), proto=socket.IPPROTO_TCP)
    except Exception:
        raise PTZSecurityError("camera host could not be resolved")

    for info in infos:
        ip = str(info[4][0]).split("%")[0]
        try:
            validate_ip(ip)
            return ip, int(port)
        except PTZSecurityError:
            continue
    raise PTZSecurityError("camera host did not resolve to an allowed address")


__all__ = [
    "allowed_networks",
    "allowed_ports",
    "own_ip_addresses",
    "reset_caches",
    "validate_ip",
    "validate_port",
    "resolve_and_pin",
]
