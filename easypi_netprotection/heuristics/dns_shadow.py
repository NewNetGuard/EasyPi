"""DNS-shadow bypass detector (correlation model).

Flags a protected LAN client that pushes meaningful external WAN traffic to
destination IPs it never resolved through EasyPi. This is a no-DPI behavioural
heuristic for tunnels that hide behind HTTPS/QUIC or resolve inside the tunnel.

Why correlation instead of "0 DNS queries":
  A device can defeat a "device made zero EasyPi DNS" test by emitting one
  innocuous decoy query per window. So we do not count queries — we check whether
  the *destinations* of the traffic are explained by DNS answers we actually
  served. A VPN endpoint IP is never resolved through EasyPi, so heavy WAN to it
  stays "unexplained" no matter how many decoy lookups the device sprinkles in.

Design points:
  * WAN bytes are a **delta between conntrack snapshots** (compute_windowed_bytes),
    never cumulative connection totals (which would flag any fat long-lived
    connection like a video stream).
  * A destination counts as "explained" if it appears in the client's recently
    resolved answer IPs (flow_log.response_ips) over a generous window, so ordinary
    DNS caching does not cause false positives while a hardcoded tunnel IP does.
"""

from __future__ import annotations

import hashlib
import ipaddress
import re
import sqlite3
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterable


DNS_SHADOW_GROUP = "dns_shadow"
DNS_SHADOW_DOMAIN = "__dns_shadow__"

DEFAULT_RESOLVED_WINDOW_SEC = 1800.0  # remember resolved IPs for 30 min (covers DNS caching)
DEFAULT_MIN_WAN_BYTES = 1_500_000
DEFAULT_MIN_UNEXPLAINED_FLOWS = 1

_RE_SRC = re.compile(r"\bsrc=(\d{1,3}(?:\.\d{1,3}){3})")
_RE_DST = re.compile(r"\bdst=(\d{1,3}(?:\.\d{1,3}){3})")
_RE_SPORT = re.compile(r"\bsport=(\d+)")
_RE_DPORT = re.compile(r"\bdport=(\d+)")
_RE_BYTES = re.compile(r"\bbytes=(\d+)")


@dataclass(frozen=True)
class WanFlow:
    client_ip: str
    dst_ip: str
    proto: str
    sport: int
    dport: int
    bytes: int


@dataclass(frozen=True)
class DnsShadowObservation:
    ip: str
    unexplained_bytes: int
    unexplained_flows: int
    resolved_count: int
    confidence: float


def hash_client_ip(ip: str) -> str:
    return hashlib.sha256(ip.encode()).hexdigest()[:16]


def _is_non_public(ip: str) -> bool:
    """True unless `ip` is a real, globally-routable public internet address.

    `not is_global` also excludes CGNAT / RFC 6598 (100.64.0.0/10) — the Tailscale
    overlay range — and RFC1918 (the WireGuard-inbound range), so this device's OWN
    Tailscale/WireGuard tunnel traffic is never mistaken for an unexplained WAN tunnel.
    is_global alone is enough on current Python, but the explicit checks stay as a
    version-independent guard.
    """
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return (
        not addr.is_global
        or addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
        or addr.is_unspecified
    )


def _to_epoch(ts: object) -> float | None:
    if ts is None:
        return None
    if isinstance(ts, (int, float)):
        return float(ts)
    value = str(ts).strip()
    if not value:
        return None
    try:
        return float(value)
    except ValueError:
        pass
    value = value.replace("Z", "+00:00").replace(" ", "T", 1)
    try:
        return datetime.fromisoformat(value).timestamp()
    except ValueError:
        return None


def parse_conntrack_snapshot(lines: Iterable[str]) -> list[WanFlow]:
    """Parse `conntrack -L -o extended` into external WAN flows (LAN client -> public).

    Plain DNS (dport 53) is skipped: it is not tunnel payload. The original (pre-NAT)
    destination is used, so a redirected :53 flow is still recognised as DNS.
    """
    flows: list[WanFlow] = []
    for raw in lines:
        line = str(raw or "")
        if " tcp " not in line and " udp " not in line:
            continue
        srcs = _RE_SRC.findall(line)
        dsts = _RE_DST.findall(line)
        if not srcs or not dsts:
            continue
        client_ip = srcs[0]
        dst_ip = dsts[0]
        if not _is_non_public(client_ip) or _is_non_public(dst_ip):
            continue
        dports = _RE_DPORT.findall(line)
        dport = int(dports[0]) if dports else 0
        if dport == 53:
            continue
        byte_total = sum(int(value) for value in _RE_BYTES.findall(line))
        if byte_total <= 0:
            continue
        sports = _RE_SPORT.findall(line)
        sport = int(sports[0]) if sports else 0
        flows.append(
            WanFlow(
                client_ip=client_ip,
                dst_ip=dst_ip,
                proto="tcp" if " tcp " in line else "udp",
                sport=sport,
                dport=dport,
                bytes=byte_total,
            )
        )
    return flows


def flow_key(flow: WanFlow) -> tuple:
    """Identity of a single connection (original tuple), stable across snapshots."""
    return (flow.client_ip, flow.proto, flow.sport, flow.dst_ip, flow.dport)


def compute_windowed_bytes(
    flows: Iterable[WanFlow],
    prev_counters: dict[tuple, int] | None,
) -> tuple[dict[str, dict[str, int]], dict[tuple, int]]:
    """Per-client, per-destination bytes transferred SINCE the previous snapshot.

    Returns (per_client_dst_bytes, new_counters). Pass new_counters back next call.
    On the first call prev_counters is empty, so every flow looks new and returns its
    full total — the caller must treat that first pass as a baseline and not alert.
    """
    prev = prev_counters or {}
    new_counters: dict[tuple, int] = {}
    per_client_dst: dict[str, dict[str, int]] = {}
    for flow in flows:
        key = flow_key(flow)
        cur = int(flow.bytes)
        new_counters[key] = max(new_counters.get(key, 0), cur)
        seen = prev.get(key)
        if seen is None:
            delta = cur
        elif cur >= seen:
            delta = cur - seen
        else:
            delta = cur
        if delta > 0:
            dst_map = per_client_dst.setdefault(flow.client_ip, {})
            dst_map[flow.dst_ip] = dst_map.get(flow.dst_ip, 0) + delta
    return per_client_dst, new_counters


def read_recent_resolved_ips(
    db_path: Path,
    client_ips: Iterable[str],
    *,
    now: float | None = None,
    window_seconds: float = DEFAULT_RESOLVED_WINDOW_SEC,
    limit: int = 50_000,
) -> dict[str, set[str]]:
    """Return {raw client IP: set of answer IPs EasyPi resolved for it recently}."""
    ips = [str(ip).strip() for ip in client_ips if str(ip).strip()]
    resolved: dict[str, set[str]] = {ip: set() for ip in ips}
    if not ips or not Path(db_path).exists():
        return resolved

    now_ts = time.time() if now is None else float(now)
    cutoff = now_ts - float(window_seconds)
    by_client_id = {hash_client_ip(ip): ip for ip in ips}
    placeholders = ",".join("?" for _ in by_client_id)

    try:
        conn = sqlite3.connect(f"file:{Path(db_path)}?mode=ro", uri=True, timeout=3.0)
        try:
            rows = conn.execute(
                f"SELECT client_id, timestamp, response_ips FROM flow_log "
                f"WHERE client_id IN ({placeholders}) "
                f"ORDER BY id DESC LIMIT ?",
                [*by_client_id.keys(), int(limit)],
            ).fetchall()
        finally:
            conn.close()
    except Exception:
        return resolved

    for client_id, ts, response_ips in rows:
        ip = by_client_id.get(str(client_id or ""))
        if not ip:
            continue
        epoch = _to_epoch(ts)
        if epoch is None or epoch < cutoff:
            continue
        for answer in str(response_ips or "").split(","):
            answer = answer.strip()
            if answer and not _is_non_public(answer):
                resolved[ip].add(answer)
    return resolved


def _confidence(unexplained_bytes: int, unexplained_flows: int, resolved_count: int,
                min_wan_bytes: int) -> float:
    byte_score = min(1.0, unexplained_bytes / float(max(int(min_wan_bytes) * 4, 1)))
    # A tunnel concentrates heavy bytes on very few destinations; many distinct
    # unexplained dsts is more likely scraping/caching noise, so it scores lower.
    concentration = 1.0 if unexplained_flows <= 2 else max(0.4, 1.0 - (unexplained_flows - 2) * 0.1)
    dns_score = 1.0 if resolved_count == 0 else 0.8
    return round(max(byte_score, 0.5) * 0.6 + concentration * 0.25 + dns_score * 0.15, 3)


def detect_dns_shadow(
    per_client_dst_bytes: dict[str, dict[str, int]],
    resolved_ips_by_client: dict[str, set[str]],
    *,
    protected_ips: set[str] | None = None,
    min_wan_bytes: int = DEFAULT_MIN_WAN_BYTES,
    min_unexplained_flows: int = DEFAULT_MIN_UNEXPLAINED_FLOWS,
) -> list[DnsShadowObservation]:
    """Flag clients whose recent WAN goes to destinations EasyPi never resolved.

    A destination IP is "explained" if it is in the client's recently resolved answer
    IPs. Heavy WAN to unexplained destinations = talking to IPs obtained out-of-band
    (a tunnel endpoint, a hardcoded proxy), which decoy DNS lookups cannot mask.
    """
    protected = {str(ip).strip() for ip in (protected_ips or set()) if str(ip).strip()}
    observations: list[DnsShadowObservation] = []
    for ip, dst_bytes in per_client_dst_bytes.items():
        if protected and ip not in protected:
            continue
        resolved = resolved_ips_by_client.get(ip, set())
        unexplained_bytes = 0
        unexplained_flows = 0
        for dst, byte_delta in dst_bytes.items():
            if byte_delta <= 0 or dst in resolved:
                continue
            unexplained_bytes += int(byte_delta)
            unexplained_flows += 1
        if unexplained_bytes < int(min_wan_bytes):
            continue
        if unexplained_flows < int(min_unexplained_flows):
            continue
        observations.append(
            DnsShadowObservation(
                ip=ip,
                unexplained_bytes=unexplained_bytes,
                unexplained_flows=unexplained_flows,
                resolved_count=len(resolved),
                confidence=_confidence(unexplained_bytes, unexplained_flows, len(resolved), min_wan_bytes),
            )
        )
    observations.sort(key=lambda item: (item.confidence, item.unexplained_bytes), reverse=True)
    return observations
