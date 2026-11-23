"""
Network Activity API Endpoints

Provides network monitoring and device traffic analysis via NetProtection.
Shows DNS queries, device activity, and traffic statistics.

Security: All endpoints require admin authentication.
"""

from fastapi import APIRouter, HTTPException, Query, Depends
from typing import Dict, Any
from datetime import datetime
import hashlib
import logging
import time
from collections import defaultdict

from app.api.deps import require_admin
from app.models.user import User
from app.services.dhcp_identity import (
    load_dhcp_address_bindings,
    load_dhcp_identities,
)
from app.services.netprotection_service import netprotection_service
from app.utils.sanitize import (
    sanitize_domain,
    sanitize_ip,
    sanitize_mac,
    sanitize_name,
    sanitize_query_type,
    sanitize_reason,
    validate_ip,
)

router = APIRouter()
logger = logging.getLogger(__name__)

# Rate limiting / caching
_cache: dict = {}
CACHE_TTL_SECONDS = 5

# Validation limits
MAX_QUERY_LIMIT = 200
DEFAULT_QUERY_LIMIT = 100


def _get_cached(key: str, ttl: int = CACHE_TTL_SECONDS):
    """Get cached value if not expired"""
    if key in _cache:
        value, timestamp = _cache[key]
        if time.time() - timestamp < ttl:
            return value
    return None


def _set_cache(key: str, value):
    """Set cache value with timestamp"""
    _cache[key] = (value, time.time())


def _resolve_browsing_identity(device_ip: str, raw_mac: str) -> tuple[str, float]:
    """Verify current MAC+IP ownership and return a stable history boundary."""
    device_mac = sanitize_mac(raw_mac)
    if not device_mac:
        raise HTTPException(status_code=400, detail="Invalid device MAC address")

    identities = [
        identity
        for identity in load_dhcp_identities()
        if identity.ip == device_ip
    ]
    identities.sort(key=lambda identity: identity.last_seen_timestamp, reverse=True)
    matching = next(
        (identity for identity in identities if identity.mac == device_mac),
        None,
    )
    bindings = [
        binding
        for binding in load_dhcp_address_bindings()
        if binding.ip == device_ip
    ]
    binding = bindings[0] if bindings else None
    observed_mac = sanitize_mac(netprotection_service._resolve_mac_from_arp(device_ip))
    if observed_mac:
        if observed_mac != device_mac:
            raise HTTPException(
                status_code=409,
                detail="Device IP is currently owned by a different MAC address",
            )
        if (
            binding is None
            or binding.mac != device_mac
            or not binding.recently_observed
        ):
            raise HTTPException(
                status_code=409,
                detail="Device address history is awaiting verified device traffic",
            )
    elif matching is None or not matching.ownership_recently_verified:
        raise HTTPException(
            status_code=409,
            detail="Current device identity cannot be verified",
        )
    if (
        matching is not None
        and identities
        and identities[0].mac != device_mac
        and identities[0].last_seen_timestamp > matching.last_seen_timestamp
        and not observed_mac
    ):
        raise HTTPException(
            status_code=409,
            detail="Current device identity is awaiting DHCP confirmation",
        )

    # ARP proves only who owns an address now; it cannot prove who owned it in
    # the past. Never use clients.json's potentially old registration date as
    # a history boundary when the DHCP ownership journal is unavailable.
    if observed_mac == device_mac and binding is not None:
        binding_start = binding.assigned_at_timestamp
    elif matching is not None and matching.ownership_verified:
        binding_start = matching.ip_first_seen_timestamp
    else:
        raise HTTPException(
            status_code=409,
            detail="Device address history is awaiting DHCP confirmation",
        )
    if binding_start <= 0:
        raise HTTPException(
            status_code=409,
            detail="Device address ownership history is unavailable",
        )

    identity_id = "mac_" + hashlib.sha256(
        device_mac.encode("ascii")
    ).hexdigest()[:20]
    return identity_id, binding_start


@router.get("/status")
async def get_network_status(_admin: User = Depends(require_admin)):
    """Get NetProtection network status"""
    # Check cache first
    cached = _get_cached("network_status", ttl=10)
    if cached:
        return cached

    try:
        status = await netprotection_service.get_status()
        config = await netprotection_service.get_config()

        result = {
            "running": status.get("running", False)
            or status.get("service_status") == "active",
            "protectionEnabled": config.get("protection_enabled", True),
            "version": status.get("version", "1.0.0"),
            "dnsPort": 53,
            "httpPort": 8000,
        }
        _set_cache("network_status", result)
        return result
    except Exception as e:
        logger.error(f"Failed to get network status: {e}")
        # Return safe defaults instead of 503
        return {
            "running": False,
            "protectionEnabled": False,
            "version": "unknown",
            "dnsPort": 53,
            "httpPort": 8000,
        }


@router.get("/devices")
async def get_network_devices(
    active_only: bool = Query(False, description="Show only active devices"),
    _admin: User = Depends(require_admin),
):
    """Get list of network devices with activity counts."""
    try:
        # Devices that actually generated DNS activity (from the real query log).
        devices = await netprotection_service.get_active_devices(hours=24)
        by_ip: Dict[str, Dict[str, Any]] = {d["ip"]: d for d in devices if d.get("ip")}

        # Overlay configured parental clients: give matching devices their nicer
        # name, and include configured clients that currently have no activity.
        clients_data = await netprotection_service.get_clients()
        clients = (
            clients_data.get("clients", clients_data)
            if isinstance(clients_data, dict)
            else []
        )
        for client in clients:
            ip = client.get("ip") or (client.get("ids") or [None])[0]
            if not ip or not validate_ip(ip):
                continue
            safe_ip = sanitize_ip(ip)
            if safe_ip == "unknown":
                continue
            name = sanitize_name(client.get("name"))
            existing = by_ip.get(safe_ip)
            if existing:
                if name:
                    existing["name"] = name
                    existing["hostname"] = name
            else:
                entry = {
                    "id": safe_ip.replace(".", "_").replace(":", "_"),
                    "name": name or safe_ip,
                    "ip": safe_ip,
                    "hostname": name or safe_ip,
                    "lastSeen": None,
                    "status": "offline",
                    "requestsCount": 0,
                    "blockedCount": 0,
                    "allowedCount": 0,
                }
                devices.append(entry)
                by_ip[safe_ip] = entry

        if active_only:
            devices = [d for d in devices if d.get("requestsCount", 0) > 0]

        devices.sort(key=lambda x: x["requestsCount"], reverse=True)
        return {"devices": devices}

    except Exception as e:
        logger.error(f"Failed to get network devices: {e}")
        return {"devices": []}


@router.get("/queries/prism")
async def get_prism_activity(
    limit: int = Query(DEFAULT_QUERY_LIMIT, ge=1, le=MAX_QUERY_LIMIT),
    _admin: User = Depends(require_admin),
):
    """Get bounded PRISM TLS/QUIC observations for the technical query log."""
    activity = await netprotection_service.get_prism_activity(limit=limit)
    rows = []
    for entry in activity:
        client_ip = sanitize_ip(entry.get("client_ip"))
        if client_ip == "unknown":
            continue
        query_type = str(entry.get("queryType") or "TLS").upper()
        if query_type not in {"TLS", "QUIC"}:
            continue
        rows.append(
            {
                "id": str(entry.get("id") or "")[:128],
                "timestamp": str(entry.get("timestamp") or "")[:64],
                "domain": sanitize_domain(entry.get("domain", "unknown")),
                "queryType": query_type,
                "status": "observed",
                "source": "prism",
                "reason": sanitize_reason(entry.get("reason", "")),
                "client_ip": client_ip,
            }
        )
    return {"data": rows, "total": len(rows)}


@router.get("/devices/{device_ip}/traffic")
async def get_device_traffic(
    device_ip: str,
    limit: int = Query(DEFAULT_QUERY_LIMIT, ge=1, le=MAX_QUERY_LIMIT),
    _admin: User = Depends(require_admin),
):
    """Get traffic details for a specific device"""
    # Validate IP address
    if not validate_ip(device_ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format")

    safe_ip = sanitize_ip(device_ip)

    try:
        # Get verdicts filtered by client IP (using search)
        verdicts = await netprotection_service.get_verdicts(
            limit=min(limit * 2, MAX_QUERY_LIMIT),  # Get more to filter
            client_ip=safe_ip,
        )
        try:
            prism_activity = await netprotection_service.get_prism_device_activity(
                safe_ip, limit=limit
            )
        except Exception as prism_error:
            # PRISM activity enriches the DNS log. It must never make the
            # primary DNS history disappear if its telemetry is unavailable.
            logger.warning(
                "PRISM activity unavailable for %s: %s",
                safe_ip,
                type(prism_error).__name__,
            )
            prism_activity = []
        detail = await netprotection_service.get_device_detail(safe_ip, period="24h")

        queries = []
        domain_stats: Dict[str, int] = defaultdict(int)
        blocked_domains: Dict[str, int] = defaultdict(int)
        totals = detail.get("totals", {}) if isinstance(detail, dict) else {}
        total = int(totals.get("total", 0) or 0)
        blocked = int(totals.get("blocked", 0) or 0)
        allowed = int(totals.get("allowed", max(total - blocked, 0)) or 0)

        for entry in verdicts.get("data", []):
            domain = sanitize_domain(entry.get("domain", "unknown"))
            query_type = sanitize_query_type(entry.get("query_type", "A"))
            status_raw = entry.get("status", "allowed")
            verdict = entry.get("verdict", "allow")
            status = (
                "blocked" if status_raw == "blocked" or verdict == "deny" else "allowed"
            )

            if status == "blocked":
                blocked_domains[domain] += 1

            domain_stats[domain] += 1

            # Recent queries
            queries.append(
                {
                    "id": entry.get("flow_id")
                    or entry.get("id")
                    or f"{entry.get('time')}_{domain}",
                    "timestamp": entry.get("time"),
                    "device": safe_ip,
                    "deviceName": safe_ip,
                    "domain": domain,
                    "queryType": query_type,
                    "status": status,
                    "source": "dns",
                    "reason": sanitize_reason(entry.get("reason", "")),
                    "responseTime": entry.get("latency_ms"),
                    "answer": entry.get("response", []),
                }
            )

        # Top domains
        detailed_top = detail.get("topQueried", []) if isinstance(detail, dict) else []
        detailed_blocked = (
            detail.get("topBlocked", []) if isinstance(detail, dict) else []
        )
        top_domains = [
            {
                "domain": sanitize_domain(item.get("domain", "unknown")),
                "count": int(item.get("count", 0) or 0),
                "blocked": int(item.get("blocked", 0) or 0),
                "allowed": max(
                    int(item.get("count", 0) or 0) - int(item.get("blocked", 0) or 0),
                    0,
                ),
                "percentage": round((int(item.get("count", 0) or 0) / total) * 100, 2)
                if total > 0
                else 0,
            }
            for item in detailed_top[:10]
        ]
        if not top_domains:
            top_domains = [
                {
                    "domain": domain,
                    "count": count,
                    "blocked": blocked_domains.get(domain, 0),
                    "allowed": count - blocked_domains.get(domain, 0),
                    "percentage": round((count / total) * 100, 2) if total > 0 else 0,
                }
                for domain, count in sorted(
                    domain_stats.items(), key=lambda x: x[1], reverse=True
                )[:10]
            ]

        # Top blocked
        top_blocked = [
            {
                "domain": sanitize_domain(item.get("domain", "unknown")),
                "count": int(item.get("count", 0) or 0),
                "blocked": int(item.get("count", 0) or 0),
                "allowed": 0,
                "percentage": round((int(item.get("count", 0) or 0) / blocked) * 100, 2)
                if blocked > 0
                else 0,
            }
            for item in detailed_blocked[:10]
        ]
        if not top_blocked:
            top_blocked = [
                {
                    "domain": domain,
                    "count": count,
                    "blocked": count,
                    "allowed": 0,
                    "percentage": round((count / blocked) * 100, 2)
                    if blocked > 0
                    else 0,
                }
                for domain, count in sorted(
                    blocked_domains.items(), key=lambda x: x[1], reverse=True
                )[:10]
            ]

        combined_activity = queries + [
            {
                **entry,
                "domain": sanitize_domain(entry.get("domain", "unknown")),
                "reason": sanitize_reason(entry.get("reason", "")),
                "device": safe_ip,
                "deviceName": safe_ip,
            }
            for entry in prism_activity
        ]
        combined_activity.sort(
            key=lambda entry: str(entry.get("timestamp") or ""), reverse=True
        )

        return {
            "device": safe_ip,
            "deviceName": queries[0]["deviceName"] if queries else safe_ip,
            "totalQueries": total,
            "blockedQueries": blocked,
            "allowedQueries": allowed,
            "topDomains": top_domains,
            "topBlockedDomains": top_blocked,
            "recentQueries": combined_activity[:limit],
            "queryHistory": [],
        }

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Failed to get device traffic for {safe_ip}: {e}")
        return {
            "device": safe_ip,
            "deviceName": safe_ip,
            "totalQueries": 0,
            "blockedQueries": 0,
            "allowedQueries": 0,
            "topDomains": [],
            "topBlockedDomains": [],
            "recentQueries": [],
            "queryHistory": [],
        }


@router.get("/devices/{device_ip}/browsing")
async def get_device_browsing_activity(
    device_ip: str,
    mac: str = Query(..., min_length=11, max_length=32),
    limit: int = Query(200, ge=1, le=200),
    refresh: bool = Query(False),
    _admin: User = Depends(require_admin),
):
    """Return DNS/TLS domain connections for one verified device."""
    if not validate_ip(device_ip):
        raise HTTPException(status_code=400, detail="Invalid IP address format")
    safe_ip = sanitize_ip(device_ip)
    identity_id, binding_start = _resolve_browsing_identity(safe_ip, mac)
    activity = await netprotection_service.get_browsing_activity(
        safe_ip,
        limit=limit,
        force_refresh=refresh,
        device_identity=identity_id,
        since_epoch=binding_start,
    )
    rows = []
    for entry in activity:
        host = sanitize_domain(entry.get("host", "unknown"))
        domain = sanitize_domain(entry.get("domain", host))
        if host == "unknown" or domain == "unknown":
            continue
        source = str(entry.get("source") or "")
        if source not in {"dns", "tls", "dns+tls"}:
            continue
        traffic_class = str(entry.get("traffic_class") or "")
        if traffic_class not in {"site", "service"}:
            continue
        rows.append(
            {
                "id": str(entry.get("id") or "")[:128],
                "timestamp": str(entry.get("timestamp") or "")[:64],
                "domain": domain,
                "host": host,
                "source": source,
                "trafficClass": traffic_class,
                "status": "connected",
            }
        )
    return {
        "device": safe_ip,
        "deviceIdentity": identity_id,
        "historySince": datetime.fromtimestamp(binding_start).isoformat(),
        "activity": rows,
        "total": len(rows),
        "scope": "domain connections observed via DNS and/or TLS; HTTPS paths are unavailable",
    }


@router.get("/stats")
async def get_network_stats(_admin: User = Depends(require_admin)):
    """Get overall network activity statistics"""
    # Check cache first
    cached = _get_cached("network_stats", ttl=10)
    if cached:
        return cached

    try:
        # Get stats from netprotection service
        stats = await netprotection_service.get_stats()

        # Get verdicts to count devices
        verdicts = await netprotection_service.get_verdicts(limit=500)

        # Extract unique devices
        devices = set()
        for entry in verdicts.get("data", []):
            client_ip = entry.get("client_ip")
            if client_ip and validate_ip(client_ip):
                devices.add(sanitize_ip(client_ip))

        total_queries = stats.get("num_dns_queries", 0)
        blocked_queries = stats.get("num_blocked_filtering", 0)

        result = {
            "totalDevices": len(devices),
            "activeDevices": len(devices),
            "totalQueries": total_queries,
            "blockedQueries": blocked_queries,
            "allowedQueries": total_queries - blocked_queries,
            "blockRate": round((blocked_queries / total_queries) * 100, 2)
            if total_queries > 0
            else 0,
            "topDevice": "N/A",
            "topDomain": "N/A",
        }
        _set_cache("network_stats", result)
        return result

    except Exception as e:
        logger.error(f"Failed to get network stats: {e}")
        return {
            "totalDevices": 0,
            "activeDevices": 0,
            "totalQueries": 0,
            "blockedQueries": 0,
            "allowedQueries": 0,
            "blockRate": 0,
            "topDevice": "N/A",
            "topDomain": "N/A",
        }


@router.get("/queries/live")
async def get_live_queries(
    limit: int = Query(20, ge=1, le=MAX_QUERY_LIMIT),
    _admin: User = Depends(require_admin),
):
    """Get live DNS queries across all devices"""
    try:
        verdicts = await netprotection_service.get_verdicts(
            limit=min(limit, MAX_QUERY_LIMIT)
        )

        queries = []
        for entry in verdicts.get("data", []):
            domain = sanitize_domain(entry.get("domain", "unknown"))
            client_ip = sanitize_ip(entry.get("client_ip", "unknown"))
            verdict = entry.get("verdict", "allow")
            status = "blocked" if verdict == "deny" else "allowed"

            queries.append(
                {
                    "id": entry.get(
                        "id", f"{entry.get('timestamp')}_{domain}_{client_ip}"
                    ),
                    "timestamp": entry.get("timestamp"),
                    "device": client_ip,
                    "deviceName": sanitize_name(entry.get("client_name")) or client_ip,
                    "domain": domain,
                    "queryType": sanitize_query_type(entry.get("query_type", "A")),
                    "status": status,
                    "reason": sanitize_reason(entry.get("reason", "")),
                    "responseTime": entry.get("latency_ms"),
                }
            )

        return {"queries": queries}

    except Exception as e:
        logger.error(f"Failed to get live queries: {e}")
        return {"queries": []}
