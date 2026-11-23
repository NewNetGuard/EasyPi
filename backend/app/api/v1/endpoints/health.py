"""
Health Check Endpoint with Detailed Service Status

Provides comprehensive health monitoring for:
- Database connectivity
- Redis cache (if available)
- Redis cache (if available)
- WireGuard VPN
- NetProtection DNS
- Disk space
- Memory usage
- External services
"""

import asyncio
import os
import time
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

import psutil
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.deps import require_admin
from app.core.version import get_version
from app.db.session import get_db
from app.models.user import User
from config import get_settings

settings = get_settings()

router = APIRouter(prefix="/health", tags=["health"])


class HealthStatus(str, Enum):
    """Health status levels."""
    HEALTHY = "healthy"
    DEGRADED = "degraded"
    UNHEALTHY = "unhealthy"
    UNKNOWN = "unknown"


class ServiceHealth(BaseModel):
    """Health status for an individual service."""
    name: str
    status: HealthStatus = HealthStatus.UNKNOWN
    message: Optional[str] = None
    latency_ms: Optional[float] = None
    details: Optional[dict[str, Any]] = None
    last_check: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))


class SystemMetrics(BaseModel):
    """System resource metrics."""
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    memory_used_mb: float = 0.0
    memory_total_mb: float = 0.0
    disk_percent: float = 0.0
    disk_used_gb: float = 0.0
    disk_total_gb: float = 0.0
    uptime_seconds: float = 0.0
    load_average: Optional[list[float]] = None
    

class HealthResponse(BaseModel):
    """Comprehensive health check response."""
    status: HealthStatus = HealthStatus.HEALTHY
    version: str = "1.0.0"
    environment: str = "production"
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    uptime_seconds: float = 0.0
    services: list[ServiceHealth] = []
    system: Optional[SystemMetrics] = None
    checks_passed: int = 0
    checks_failed: int = 0
    checks_total: int = 0


# Track application start time
_start_time = time.time()


def get_app_uptime() -> float:
    """Get application uptime in seconds."""
    return time.time() - _start_time


async def check_database(db: Session) -> ServiceHealth:
    """Check database connectivity and performance."""
    start = time.perf_counter()
    try:
        # Execute a simple query
        result = db.execute(text("SELECT 1"))
        result.fetchone()
        
        latency = (time.perf_counter() - start) * 1000
        
        # Check if latency is acceptable
        if latency > 1000:  # > 1 second
            status = HealthStatus.DEGRADED
            message = f"High latency: {latency:.0f}ms"
        else:
            status = HealthStatus.HEALTHY
            message = "Connected"
        
        return ServiceHealth(
            name="database",
            status=status,
            message=message,
            latency_ms=round(latency, 2),
            details={"type": "sqlite" if "sqlite" in settings.DATABASE_URL else "postgresql"}
        )
    except Exception as e:
        latency = (time.perf_counter() - start) * 1000
        return ServiceHealth(
            name="database",
            status=HealthStatus.UNHEALTHY,
            message=str(e)[:200],
            latency_ms=round(latency, 2)
        )




async def check_wireguard() -> ServiceHealth:
    """Check WireGuard VPN status."""
    start = time.perf_counter()
    try:
        # Check if wg command exists and has interfaces
        proc = await asyncio.create_subprocess_exec(
            "wg", "show",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=5.0)
        latency = (time.perf_counter() - start) * 1000
        
        if proc.returncode == 0:
            output = stdout.decode()
            # Count interfaces
            interfaces = [line.split(":")[0] for line in output.split("\n") if line.startswith("interface:")]
            
            return ServiceHealth(
                name="wireguard",
                status=HealthStatus.HEALTHY if interfaces else HealthStatus.DEGRADED,
                message=f"{len(interfaces)} interface(s) active" if interfaces else "No active interfaces",
                latency_ms=round(latency, 2),
                details={"interfaces": interfaces[:5]}  # Limit to first 5
            )
        else:
            return ServiceHealth(
                name="wireguard",
                status=HealthStatus.DEGRADED,
                message="WireGuard not configured",
                latency_ms=round(latency, 2)
            )
    except FileNotFoundError:
        return ServiceHealth(
            name="wireguard",
            status=HealthStatus.UNKNOWN,
            message="WireGuard not installed"
        )
    except asyncio.TimeoutError:
        latency = (time.perf_counter() - start) * 1000
        return ServiceHealth(
            name="wireguard",
            status=HealthStatus.UNHEALTHY,
            message="WireGuard check timed out",
            latency_ms=round(latency, 2)
        )
    except Exception as e:
        latency = (time.perf_counter() - start) * 1000
        return ServiceHealth(
            name="wireguard",
            status=HealthStatus.UNKNOWN,
            message=str(e)[:200],
            latency_ms=round(latency, 2)
        )


async def check_NetProtection() -> ServiceHealth:
    """Check NetProtection status."""
    import aiohttp
    
    start = time.perf_counter()
    NETPROTECTION_URL = settings.NETPROTECTION_URL
    
    if not NETPROTECTION_URL:
        return ServiceHealth(
            name="NetProtection",
            status=HealthStatus.UNKNOWN,
            message="NetProtection not configured"
        )
    
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
            async with session.get(f"{NETPROTECTION_URL}/control/status") as response:
                latency = (time.perf_counter() - start) * 1000
                
                if response.status == 200:
                    data = await response.json()
                    return ServiceHealth(
                        name="NetProtection",
                        status=HealthStatus.HEALTHY,
                        message="NetProtection running",
                        latency_ms=round(latency, 2),
                        details={
                            "protection_enabled": data.get("protection_enabled", False),
                            "dns_port": data.get("dns_port"),
                            "version": data.get("version")
                        }
                    )
                elif response.status == 401:
                    return ServiceHealth(
                        name="NetProtection",
                        status=HealthStatus.DEGRADED,
                        message="NetProtection requires authentication",
                        latency_ms=round(latency, 2)
                    )
                else:
                    return ServiceHealth(
                        name="NetProtection",
                        status=HealthStatus.UNHEALTHY,
                        message=f"HTTP {response.status}",
                        latency_ms=round(latency, 2)
                    )
    except asyncio.TimeoutError:
        latency = (time.perf_counter() - start) * 1000
        return ServiceHealth(
            name="NetProtection",
            status=HealthStatus.UNHEALTHY,
            message="Connection timed out",
            latency_ms=round(latency, 2)
        )
    except aiohttp.ClientError as e:
        latency = (time.perf_counter() - start) * 1000
        return ServiceHealth(
            name="NetProtection",
            status=HealthStatus.UNHEALTHY,
            message=f"Connection error: {type(e).__name__}",
            latency_ms=round(latency, 2)
        )
    except Exception as e:
        latency = (time.perf_counter() - start) * 1000
        return ServiceHealth(
            name="NetProtection",
            status=HealthStatus.UNKNOWN,
            message=str(e)[:200],
            latency_ms=round(latency, 2)
        )


async def check_netprotection() -> ServiceHealth:
    """Check EasyPi NetProtection DNS engine status."""
    start = time.perf_counter()
    
    try:
        from app.services.netprotection_service import netprotection_service
        
        status = await netprotection_service.get_status()
        latency = (time.perf_counter() - start) * 1000
        
        if status.get("running", False):
            config = await netprotection_service.get_config()
            return ServiceHealth(
                name="netprotection",
                status=HealthStatus.HEALTHY,
                message="NetProtection DNS engine running",
                latency_ms=round(latency, 2),
                details={
                    "protection_enabled": config.get("protection_enabled", True),
                    "dns_port": status.get("dns_port", 53),
                    "version": status.get("version", "1.0.0"),
                    "shield_profile": config.get("shield_profile", "balanced"),
                    "available": status.get("available", False),
                }
            )
        else:
            return ServiceHealth(
                name="netprotection",
                status=HealthStatus.DEGRADED,
                message="NetProtection not running",
                latency_ms=round(latency, 2)
            )
    except ImportError:
        latency = (time.perf_counter() - start) * 1000
        return ServiceHealth(
            name="netprotection",
            status=HealthStatus.UNKNOWN,
            message="NetProtection module not installed",
            latency_ms=round(latency, 2)
        )
    except Exception as e:
        latency = (time.perf_counter() - start) * 1000
        return ServiceHealth(
            name="netprotection",
            status=HealthStatus.UNKNOWN,
            message=str(e)[:200],
            latency_ms=round(latency, 2)
        )


async def check_redis() -> ServiceHealth:
    """Check Redis cache status (optional)."""
    start = time.perf_counter()
    try:
        import redis.asyncio as redis
        
        # Try to connect to local Redis
        client = redis.Redis(host='localhost', port=6379, decode_responses=True)
        await asyncio.wait_for(client.ping(), timeout=2.0)
        info = await client.info("memory")
        await client.close()
        
        latency = (time.perf_counter() - start) * 1000
        
        return ServiceHealth(
            name="redis",
            status=HealthStatus.HEALTHY,
            message="Connected",
            latency_ms=round(latency, 2),
            details={
                "used_memory_mb": round(info.get("used_memory", 0) / 1024 / 1024, 2),
                "connected_clients": info.get("connected_clients", 0)
            }
        )
    except ImportError:
        return ServiceHealth(
            name="redis",
            status=HealthStatus.UNKNOWN,
            message="Redis client not installed"
        )
    except Exception:
        latency = (time.perf_counter() - start) * 1000
        return ServiceHealth(
            name="redis",
            status=HealthStatus.UNKNOWN,
            message="Redis not available",
            latency_ms=round(latency, 2)
        )


async def check_ollama() -> ServiceHealth:
    """Check Ollama AI service status."""
    import aiohttp
    
    start = time.perf_counter()
    ollama_url = settings.OLLAMA_URL
    
    try:
        async with aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=5)) as session:
            async with session.get(f"{ollama_url}/api/version") as response:
                latency = (time.perf_counter() - start) * 1000
                
                if response.status == 200:
                    data = await response.json()
                    return ServiceHealth(
                        name="ollama",
                        status=HealthStatus.HEALTHY,
                        message="Ollama running",
                        latency_ms=round(latency, 2),
                        details={"version": data.get("version", "unknown")}
                    )
                else:
                    return ServiceHealth(
                        name="ollama",
                        status=HealthStatus.UNHEALTHY,
                        message=f"HTTP {response.status}",
                        latency_ms=round(latency, 2)
                    )
    except asyncio.TimeoutError:
        latency = (time.perf_counter() - start) * 1000
        return ServiceHealth(
            name="ollama",
            status=HealthStatus.UNKNOWN,
            message="Connection timed out",
            latency_ms=round(latency, 2)
        )
    except Exception:
        latency = (time.perf_counter() - start) * 1000
        return ServiceHealth(
            name="ollama",
            status=HealthStatus.UNKNOWN,
            message="Ollama not available",
            latency_ms=round(latency, 2)
        )


def get_system_metrics() -> SystemMetrics:
    """Get current system resource metrics."""
    try:
        # CPU
        cpu_percent = psutil.cpu_percent(interval=0.1)
        
        # Memory
        memory = psutil.virtual_memory()
        
        # Disk
        disk = psutil.disk_usage('/')
        
        # Uptime
        boot_time = psutil.boot_time()
        uptime = time.time() - boot_time
        
        # Load average (not available on Windows)
        load_avg = None
        if hasattr(os, 'getloadavg'):
            try:
                load_avg = list(os.getloadavg())
            except OSError:
                pass
        
        return SystemMetrics(
            cpu_percent=round(cpu_percent, 1),
            memory_percent=round(memory.percent, 1),
            memory_used_mb=round(memory.used / 1024 / 1024, 2),
            memory_total_mb=round(memory.total / 1024 / 1024, 2),
            disk_percent=round(disk.percent, 1),
            disk_used_gb=round(disk.used / 1024 / 1024 / 1024, 2),
            disk_total_gb=round(disk.total / 1024 / 1024 / 1024, 2),
            uptime_seconds=round(uptime, 0),
            load_average=load_avg
        )
    except Exception:
        return SystemMetrics()


def check_disk_space() -> ServiceHealth:
    """Check disk space availability."""
    try:
        disk = psutil.disk_usage('/')
        percent_used = disk.percent
        free_gb = disk.free / 1024 / 1024 / 1024
        
        if percent_used > 95 or free_gb < 1:
            status = HealthStatus.UNHEALTHY
            message = f"Critical: {free_gb:.1f}GB free ({percent_used:.0f}% used)"
        elif percent_used > 85 or free_gb < 5:
            status = HealthStatus.DEGRADED
            message = f"Warning: {free_gb:.1f}GB free ({percent_used:.0f}% used)"
        else:
            status = HealthStatus.HEALTHY
            message = f"{free_gb:.1f}GB free ({percent_used:.0f}% used)"
        
        return ServiceHealth(
            name="disk",
            status=status,
            message=message,
            details={
                "percent_used": percent_used,
                "free_gb": round(free_gb, 2),
                "total_gb": round(disk.total / 1024 / 1024 / 1024, 2)
            }
        )
    except Exception as e:
        return ServiceHealth(
            name="disk",
            status=HealthStatus.UNKNOWN,
            message=str(e)[:200]
        )


def check_memory() -> ServiceHealth:
    """Check memory availability."""
    try:
        memory = psutil.virtual_memory()
        percent_used = memory.percent
        available_mb = memory.available / 1024 / 1024
        
        if percent_used > 95 or available_mb < 100:
            status = HealthStatus.UNHEALTHY
            message = f"Critical: {available_mb:.0f}MB available ({percent_used:.0f}% used)"
        elif percent_used > 85 or available_mb < 500:
            status = HealthStatus.DEGRADED
            message = f"Warning: {available_mb:.0f}MB available ({percent_used:.0f}% used)"
        else:
            status = HealthStatus.HEALTHY
            message = f"{available_mb:.0f}MB available ({percent_used:.0f}% used)"
        
        return ServiceHealth(
            name="memory",
            status=status,
            message=message,
            details={
                "percent_used": percent_used,
                "available_mb": round(available_mb, 2),
                "total_mb": round(memory.total / 1024 / 1024, 2)
            }
        )
    except Exception as e:
        return ServiceHealth(
            name="memory",
            status=HealthStatus.UNKNOWN,
            message=str(e)[:200]
        )


@router.get(
    "",
    response_model=HealthResponse,
    summary="Comprehensive health check",
    description="Get detailed health status of all services and system resources"
)
async def comprehensive_health_check(
    db: Session = Depends(get_db),
    include_system: bool = True,
    include_optional: bool = False,
    _admin: User = Depends(require_admin),
) -> HealthResponse:
    """
    Comprehensive health check endpoint.
    
    - **include_system**: Include system metrics (CPU, memory, disk)
    - **include_optional**: Include optional services (Redis, Ollama)
    
    Returns detailed status for:
    - Database connectivity
    - WireGuard VPN
    - NetProtection DNS (replaces NetProtection)
    - Disk space
    - Memory usage
    - Optional: Redis, Ollama
    """
    services: list[ServiceHealth] = []
    
    # Core service checks (run in parallel)
    core_checks = await asyncio.gather(
        check_database(db),
        check_wireguard(),
        check_netprotection(),
        check_NetProtection(),  # Keep NetProtection for legacy/transition
        return_exceptions=True
    )
    
    for check in core_checks:
        if isinstance(check, ServiceHealth):
            services.append(check)
        elif isinstance(check, Exception):
            # Handle unexpected errors
            services.append(ServiceHealth(
                name="unknown",
                status=HealthStatus.UNHEALTHY,
                message=str(check)[:200]
            ))
    
    # System resource checks
    if include_system:
        services.append(check_disk_space())
        services.append(check_memory())
    
    # Optional service checks
    if include_optional:
        optional_checks = await asyncio.gather(
            check_redis(),
            check_ollama(),
            return_exceptions=True
        )
        for check in optional_checks:
            if isinstance(check, ServiceHealth):
                services.append(check)
    
    # Calculate overall status
    checks_passed = sum(1 for s in services if s.status == HealthStatus.HEALTHY)
    checks_failed = sum(1 for s in services if s.status == HealthStatus.UNHEALTHY)
    checks_total = len(services)
    
    # Core services that must be healthy
    core_service_names = {"database", "disk", "memory"}
    core_unhealthy = any(
        s.status == HealthStatus.UNHEALTHY 
        for s in services 
        if s.name in core_service_names
    )
    
    if core_unhealthy or checks_failed > checks_total // 2:
        overall_status = HealthStatus.UNHEALTHY
    elif checks_failed > 0 or any(s.status == HealthStatus.DEGRADED for s in services):
        overall_status = HealthStatus.DEGRADED
    else:
        overall_status = HealthStatus.HEALTHY
    
    return HealthResponse(
        status=overall_status,
        version=get_version(),
        environment=settings.ENV,
        uptime_seconds=round(get_app_uptime(), 0),
        services=services,
        system=get_system_metrics() if include_system else None,
        checks_passed=checks_passed,
        checks_failed=checks_failed,
        checks_total=checks_total
    )


@router.get(
    "/live",
    summary="Liveness probe",
    description="Simple liveness check"
)
async def liveness() -> dict[str, str]:
    """
    Liveness probe.
    
    Returns 200 if the application is running.
    Used to detect if the application needs to be restarted.
    """
    return {"status": "alive"}


@router.get(
    "/ready",
    summary="Readiness probe",
    description="Readiness check"
)
async def readiness(db: Session = Depends(get_db)) -> dict[str, str]:
    """
    Readiness probe.
    
    Returns 200 if the application is ready to receive traffic.
    Checks critical dependencies (database).
    """
    try:
        # Check database
        db.execute(text("SELECT 1"))
        return {"status": "ready"}
    except Exception as e:
        raise HTTPException(status_code=503, detail=f"Not ready: {str(e)[:100]}")


@router.get(
    "/services/{service_name}",
    response_model=ServiceHealth,
    summary="Check specific service",
    description="Get health status of a specific service"
)
async def check_service(
    service_name: str,
    db: Session = Depends(get_db),
    _admin: User = Depends(require_admin),
) -> ServiceHealth:
    """
    Check health of a specific service.
    
    Available services:
    - database
    - wireguard
    - netprotection
    - NetProtection (legacy)
    - redis
    - ollama
    - disk
    - memory
    """
    # Sync functions wrapped as async
    async def async_disk():
        return check_disk_space()
    
    async def async_memory():
        return check_memory()
    
    checkers = {
        "database": lambda: check_database(db),
        "wireguard": check_wireguard,
        "netprotection": check_netprotection,
        "NetProtection": check_NetProtection,
        "redis": check_redis,
        "ollama": check_ollama,
        "disk": async_disk,
        "memory": async_memory,
    }
    
    if service_name not in checkers:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown service: {service_name}. Available: {', '.join(checkers.keys())}"
        )
    
    checker = checkers[service_name]
    result = await checker()
    
    return result


@router.get(
    "/metrics",
    response_model=SystemMetrics,
    summary="System metrics",
    description="Get current system resource metrics"
)
async def system_metrics(
    _admin: User = Depends(require_admin),
) -> SystemMetrics:
    """
    Get current system resource metrics.
    
    Returns CPU, memory, disk usage and system uptime.
    """
    return get_system_metrics()
