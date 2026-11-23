import logging
from datetime import datetime, timezone

from fastapi import APIRouter, HTTPException, Query, Depends

from app.api.deps import require_admin
from app.services.operation_event_service import OperationEventService

from app.schemas.network import (
    ArpResponse,
    ConnectionsResponse,
    DnsLookupResponse,
    HostScanResponse,
    NetworkMapResponse,
    PingResponse,
    PortScanResponse,
    PortAlertsResponse,
    SpeedtestResponse,
    TrafficResponse,
)
from app.services.network_tools import NetworkToolError, NetworkToolsService

router = APIRouter(prefix="/api/network", tags=["network"])
service = NetworkToolsService()
logger = logging.getLogger(__name__)
operation_event_service = OperationEventService()


def _record_network_event(
    *,
    action_id: str,
    title: str,
    status: str,
    message: str,
    started_at: str | None = None,
) -> None:
    try:
        operation_event_service.record_event(
            action_id=action_id,
            status=status,
            title=title,
            subtitle="Network Toolkit - Diagnostics",
            route="/network-toolkit",
            message=message,
            started_at=started_at,
            updated_at=datetime.now(timezone.utc).isoformat(),
        )
    except Exception as exc:
        logger.warning("Failed to record network event %s: %s", action_id, exc)


@router.get("/hosts", response_model=HostScanResponse)
async def scan_hosts(
    network: str = Query(..., min_length=3, description="CIDR, e.g. 192.168.1.0/24"),
    deep: bool = Query(False, description="Enable deeper fingerprinting (slower)"),
    admin: dict = Depends(require_admin),
):
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = await service.scan_hosts(network, deep=deep)
        _record_network_event(
            action_id="network.scan.hosts",
            title="Scan network hosts",
            status="success",
            message=f"Scanned {network}{' with deep mode' if deep else ''}",
            started_at=started_at,
        )
        return result
    except NetworkToolError as exc:
        _record_network_event(
            action_id="network.scan.hosts",
            title="Scan network hosts",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.get("/ports/quick", response_model=PortScanResponse)
async def quick_port_scan(
    target: str = Query(..., min_length=1, description="IP or hostname"),
    admin: dict = Depends(require_admin),
):
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = await service.scan_ports(target, mode="quick")
        _record_network_event(
            action_id="network.scan.ports.quick",
            title="Quick port scan",
            status="success",
            message=f"Scanned ports for {target}",
            started_at=started_at,
        )
        return result
    except NetworkToolError as exc:
        _record_network_event(
            action_id="network.scan.ports.quick",
            title="Quick port scan",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.get("/ports/full", response_model=PortScanResponse)
async def full_port_scan(
    target: str = Query(..., min_length=1, description="IP or hostname"),
    admin: dict = Depends(require_admin),
):
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = await service.scan_ports(target, mode="full")
        _record_network_event(
            action_id="network.scan.ports.full",
            title="Full port scan",
            status="success",
            message=f"Scanned ports for {target}",
            started_at=started_at,
        )
        return result
    except NetworkToolError as exc:
        _record_network_event(
            action_id="network.scan.ports.full",
            title="Full port scan",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.get("/ports/deep", response_model=PortScanResponse)
async def deep_port_scan(
    target: str = Query(..., min_length=1, description="IP or hostname"),
    admin: dict = Depends(require_admin),
):
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = await service.scan_ports(target, mode="deep")
        _record_network_event(
            action_id="network.scan.ports.deep",
            title="Deep port scan",
            status="success",
            message=f"Scanned ports for {target}",
            started_at=started_at,
        )
        return result
    except NetworkToolError as exc:
        _record_network_event(
            action_id="network.scan.ports.deep",
            title="Deep port scan",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.get("/ping", response_model=PingResponse)
async def ping_host(
    target: str = Query(..., min_length=1, description="IP or hostname"),
    admin: dict = Depends(require_admin),
):
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = await service.ping_host(target)
        _record_network_event(
            action_id="network.ping",
            title="Ping host",
            status="success",
            message=f"Pinged {target}",
            started_at=started_at,
        )
        return result
    except NetworkToolError as exc:
        _record_network_event(
            action_id="network.ping",
            title="Ping host",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.get("/dns", response_model=DnsLookupResponse)
async def dns_lookup(
    domain: str = Query(..., min_length=2, description="Domain name to resolve"),
    admin: dict = Depends(require_admin),
):
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = await service.dns_lookup(domain)
        _record_network_event(
            action_id="network.dns.lookup",
            title="Resolve DNS record",
            status="success",
            message=f"Resolved {domain}",
            started_at=started_at,
        )
        return result
    except NetworkToolError as exc:
        _record_network_event(
            action_id="network.dns.lookup",
            title="Resolve DNS record",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.get("/speedtest", response_model=SpeedtestResponse)
async def run_speedtest(admin: dict = Depends(require_admin)):
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = await service.speedtest()
        _record_network_event(
            action_id="network.speedtest",
            title="Run speed test",
            status="success",
            message="Speed test completed",
            started_at=started_at,
        )
        return result
    except NetworkToolError as exc:
        _record_network_event(
            action_id="network.speedtest",
            title="Run speed test",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.get("/map", response_model=NetworkMapResponse)
async def network_map(
    network: str | None = Query(None, description="CIDR, e.g. 192.168.1.0/24"),
    admin: dict = Depends(require_admin),
):
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        result = await service.get_network_map(network)
        _record_network_event(
            action_id="network.map",
            title="Build network map",
            status="success",
            message=f"Built network map for {network or 'default network'}",
            started_at=started_at,
        )
        return result
    except NetworkToolError as exc:
        _record_network_event(
            action_id="network.map",
            title="Build network map",
            status="failed",
            message=str(exc),
            started_at=started_at,
        )
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.get("/traffic", response_model=TrafficResponse)
async def traffic_samples(
    sample_count: int = Query(5, ge=1, le=10),
    interval: float = Query(0.2, gt=0.05, le=2.0),
    admin: dict = Depends(require_admin),
):
    try:
        return await service.traffic_samples(sample_count=sample_count, interval=interval)
    except NetworkToolError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.get("/connections", response_model=ConnectionsResponse)
async def active_connections(admin: dict = Depends(require_admin)):
    try:
        return await service.active_connections()
    except NetworkToolError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.get("/arp", response_model=ArpResponse)
async def arp_table(admin: dict = Depends(require_admin)):
    try:
        return await service.arp_table()
    except NetworkToolError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


@router.get("/alerts", response_model=PortAlertsResponse)
async def port_alerts(admin: dict = Depends(require_admin)):
    try:
        return await service.port_alerts()
    except NetworkToolError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc


__all__ = ["router"]
