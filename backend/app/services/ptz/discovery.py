"""ONVIF WS-Discovery -- find ONVIF cameras on the local network.

Sends one WS-Discovery Probe (SOAP-over-UDP) to the standard multicast group
239.255.255.250:3702 and collects ProbeMatch replies. Each reply carries the
device's *own* ONVIF service URL(s) (XAddrs), so we learn the correct IP **and
port** from the camera itself -- no port scanning or guessing.

Security: the replies come from unknown devices on the LAN and are fully
untrusted. Every datagram is size-capped and parsed with the defused XML parser
(no XXE / entity expansion), and every discovered address is run through the
SSRF guard (LAN-only, an allowed control port, never EasyPi itself or a
loopback/link-local/multicast/metadata address) before it is returned. Nothing
here authenticates to or controls a device; it only lists candidates for an
admin to add. Probing is bounded by a short timeout.
"""
from __future__ import annotations

import ipaddress
import socket
import time
import uuid
from typing import Dict, List
from urllib.parse import urlsplit

try:  # defused parser: blocks XXE / entity expansion on untrusted datagrams
    from defusedxml.ElementTree import fromstring as _safe_fromstring
except Exception:  # pragma: no cover - defusedxml is a dependency; fail closed
    _safe_fromstring = None

from app.services.ptz.errors import PTZSecurityError
from app.services.ptz.ssrf import own_ip_addresses, validate_ip, validate_port

WSD_MCAST_ADDR = "239.255.255.250"
WSD_PORT = 3702
MAX_DATAGRAM = 64 * 1024
_MAX_DEVICES = 64


def _discovery_timeout() -> float:
    try:
        from config import get_settings

        return float(getattr(get_settings(), "PTZ_DISCOVERY_TIMEOUT_S", 3.0))
    except Exception:
        return 3.0


def _probe_message() -> bytes:
    """A minimal WS-Discovery Probe for ONVIF NetworkVideoTransmitter devices."""
    msg_id = "urn:uuid:%s" % uuid.uuid4()
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope" '
        'xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing" '
        'xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery" '
        'xmlns:dn="http://www.onvif.org/ver10/network/wsdl">'
        "<e:Header>"
        "<w:MessageID>%s</w:MessageID>"
        '<w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>'
        '<w:Action e:mustUnderstand="true">'
        "http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>"
        "</e:Header>"
        "<e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe></e:Body>"
        "</e:Envelope>"
    ) % msg_id


def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _scope_value(scopes: str, key: str) -> str:
    """Pull a value from ONVIF scope URIs, e.g. onvif://www.onvif.org/name/Foo."""
    needle = "/%s/" % key
    for token in (scopes or "").split():
        i = token.find(needle)
        if i != -1:
            from urllib.parse import unquote

            return unquote(token[i + len(needle):]).strip()
    return ""


def _parse(data: bytes) -> List[Dict]:
    if _safe_fromstring is None:
        return []
    try:
        root = _safe_fromstring(data[:MAX_DATAGRAM])
    except Exception:
        return []
    out: List[Dict] = []
    for pm in root.iter():
        if _localname(pm.tag) != "ProbeMatch":
            continue
        xaddrs = scopes = ""
        for c in pm.iter():
            ln = _localname(c.tag)
            if ln == "XAddrs" and c.text:
                xaddrs = c.text
            elif ln == "Scopes" and c.text:
                scopes = c.text
        name = _scope_value(scopes, "name")
        hardware = _scope_value(scopes, "hardware")
        for xa in xaddrs.split():
            parts = urlsplit(xa.strip())
            host = (parts.hostname or "").strip()
            port = parts.port or 80
            if not host:
                continue
            try:  # SSRF: only a real LAN camera on an allowed control port
                ip = str(validate_ip(host))
                validate_port(port)
            except PTZSecurityError:
                continue
            out.append({
                "ip": ip,
                "onvif_port": int(port),
                "xaddr": "http://%s:%d%s" % (ip, int(port), parts.path or "/onvif/device_service"),
                "name": name or hardware or "",
                "hardware": hardware,
            })
    return out


def _local_ipv4s(interface: str | None = None) -> List[str]:
    if interface:
        try:
            import psutil

            addresses = psutil.net_if_addrs().get(interface, [])
            ips = [
                str(item.address)
                for item in addresses
                if item.family == socket.AF_INET
                and item.address
                and not ipaddress.ip_address(item.address).is_loopback
                and not ipaddress.ip_address(item.address).is_link_local
            ]
            return ips
        except (ImportError, OSError, ValueError):
            return []
    ips = [
        str(a) for a in own_ip_addresses()
        if isinstance(a, ipaddress.IPv4Address) and not a.is_loopback and not a.is_link_local
    ]
    return ips or ["0.0.0.0"]


class DiscoveryResult(list[Dict]):
    """Discovered devices plus evidence that the UDP scan actually ran."""

    def __init__(
        self,
        devices: List[Dict],
        *,
        probes_sent: int,
        transport_errors: List[str],
        receive_failed: bool,
    ) -> None:
        super().__init__(devices)
        self.probes_sent = probes_sent
        self.transport_errors = transport_errors
        self.receive_failed = receive_failed
        self.transport_ok = probes_sent > 0 and not receive_failed


def discover(timeout: float = None, targets: List[str] = None, interface: str | None = None) -> DiscoveryResult:
    """Broadcast a WS-Discovery Probe and return the ONVIF devices that answered.

    Sends a link-local multicast Probe (finds cameras on EasyPi's own segment) and,
    for each address in ``targets``, an additional **unicast** Probe -- so a camera
    on another subnet or a network that drops multicast is still reachable when its
    IP is known. Every target is SSRF-validated before a packet is sent.

    Returns a list-compatible :class:`DiscoveryResult`.  Its transport metadata
    distinguishes a successful scan with zero replies from bind/send/receive
    failure, so callers cannot report transport failure as "no cameras found".
    """
    if timeout is None:
        timeout = _discovery_timeout()
    probe = _probe_message().encode("utf-8")
    found: Dict[tuple, Dict] = {}
    probes_sent = 0
    transport_errors: List[str] = []
    receive_failed = False

    unicast: List[str] = []
    for t in targets or []:
        try:
            unicast.append(str(validate_ip(t)))  # SSRF: LAN-only, never EasyPi itself
        except PTZSecurityError:
            continue

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
        sock.settimeout(0.4)
        try:
            sock.bind(("", 0))
        except OSError as exc:
            transport_errors.append(f"bind: {exc}")
        # Send from each local interface so multi-homed hosts (eth0 + wlan0) reach
        # every attached segment.
        for local_ip in _local_ipv4s(interface):
            try:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
            except OSError as exc:
                transport_errors.append(f"interface {local_ip}: {exc}")
            for _ in range(2):  # UDP: send twice to cover a dropped datagram
                try:
                    sock.sendto(probe, (WSD_MCAST_ADDR, WSD_PORT))
                    probes_sent += 1
                except OSError as exc:
                    transport_errors.append(f"multicast send from {local_ip}: {exc}")
                    break
        # Directed unicast probes to known IPs (cross-subnet / multicast-blocked).
        for ip in unicast:
            for _ in range(2):
                try:
                    sock.sendto(probe, (ip, WSD_PORT))
                    probes_sent += 1
                except OSError as exc:
                    transport_errors.append(f"unicast send to {ip}: {exc}")
                    break
        end = time.time() + max(0.5, float(timeout))
        while time.time() < end and len(found) < _MAX_DEVICES:
            try:
                data, _addr = sock.recvfrom(MAX_DATAGRAM)
            except socket.timeout:
                continue
            except OSError as exc:
                receive_failed = True
                transport_errors.append(f"receive: {exc}")
                break
            for m in _parse(data):
                found[(m["ip"], m["onvif_port"])] = m
    finally:
        try:
            sock.close()
        except OSError:
            pass
    return DiscoveryResult(
        list(found.values()),
        probes_sent=probes_sent,
        transport_errors=transport_errors,
        receive_failed=receive_failed,
    )


__all__ = ["DiscoveryResult", "discover"]
