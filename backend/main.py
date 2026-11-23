# ruff: noqa: E402

import logging
import os
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from threading import Lock

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
import asyncio

# Environment validation at startup
from app.core.env_validator import validate_environment, validate_settings
from config import Settings

# Validate environment before anything else
# In development, just warn; in production, exit on errors
_env = os.environ.get("ENV", "production").lower()
_exit_on_error = _env in ("production", "prod")
validate_environment(exit_on_error=_exit_on_error, print_report=True)
validate_settings(Settings, exit_on_error=_exit_on_error)


def _env_flag(name: str, default: bool) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


IS_PRODUCTION = _exit_on_error
ENABLE_API_DOCS = _env_flag("ENABLE_API_DOCS", not IS_PRODUCTION)
ALLOW_DEV_CORS = _env_flag("ALLOW_DEV_CORS", not IS_PRODUCTION)
API_BIND_HOST = os.environ.get("API_HOST", "127.0.0.1" if IS_PRODUCTION else "0.0.0.0")

logger = logging.getLogger(__name__)

from app.api.v1.router import router as api_v1_router
from app.api.network_routes import router as network_router
from app.api.endpoints.setup import router as setup_router
from app.api.endpoints.system import router as system_router
from app.api.endpoints.netprotection import router as netprotection_router
from app.api.websocket.monitoring import monitoring_websocket
from app.api.websocket.cameras import camera_live_websocket
from app.api.websocket.tasks import task_logs
from app.api.websocket.terminal import router as terminal_router
from app.api.network_toolkit import router as network_toolkit_router
from app.api.remote_access.tailscale_api import router as tailscale_router
from app.api.remote_access.tailscale_admin import router as tailscale_admin_router
from app.api.remote_access.tailscale_relay import router as tailscale_relay_router
from app.api.v1.endpoints.cameras import router as cameras_router
from app.api.v1.endpoints.health import router as health_router
from app.db.init_db import init_db
from app.db.session import engine
from app.services.threat_service import threat_service
from app.services.netprotection_service import netprotection_service
from app.services.operation_event_service import OperationEventService
from app.core.csrf import CSRFMiddleware, get_csrf_token_from_request, CSRF_HEADER_NAME
from app.core.secure_headers import SecureHeadersMiddleware, get_default_api_config
from app.core.validation_errors import request_validation_exception_handler

try:
    from app.core.logging import LoggingMiddleware
except ImportError:  # pragma: no cover
    LoggingMiddleware = None  # type: ignore[misc,assignment]


# API Metadata
from app.core.version import get_version  # single source of truth: repo-root VERSION file

API_TITLE = "EasyPi API"
API_VERSION = get_version()
API_DESCRIPTION = """
## 🥧 EasyPi - Raspberry Pi Management Platform

EasyPi provides a comprehensive API for managing your Raspberry Pi server.

### 🔐 Authentication
The web UI uses secure httpOnly session cookies plus CSRF protection. API clients may
send the same access token as `Authorization: Bearer <token>`. Use
`/api/v1/auth/login` to authenticate.

### 📚 Main Features

* **🔒 Security** - Firewall, fail2ban, threat detection, 2FA
* **🌐 VPN** - WireGuard and Cloud VPN management  
* **Services** - Service management
* **💾 Backup** - Manual backup creation and restore
* **🤖 AI Assistant** - Intelligent system management
* **📊 Monitoring** - Real-time system metrics
* **🎥 Cameras** - RTSP camera management
* **👥 Users** - Multi-user management with roles

### 🔑 Roles
- **admin** - Full access to all features
- **user** - Limited access (read-only for sensitive operations)
"""

API_TAGS = [
    {"name": "auth", "description": "Authentication & authorization (login, register, 2FA, sessions)"},
    {"name": "users", "description": "User management (admin only)"},
    {"name": "security", "description": "Security settings, firewall, fail2ban, threats"},
    {"name": "system", "description": "System info, metrics, services"},
    {"name": "health", "description": "Health check endpoints with detailed service status"},
    {"name": "wireguard", "description": "WireGuard VPN configuration"},
    {"name": "cloud-vpn", "description": "Cloud VPN (Outline) management"},
    {"name": "backup", "description": "Backup creation and restore"},
    {"name": "ai", "description": "AI Assistant for system management"},
    {"name": "cameras", "description": "RTSP camera management"},
    {"name": "network", "description": "Network configuration and diagnostics"},
    {"name": "piguard", "description": "Pi-hole / DNS management"},
    {"name": "tailscale", "description": "Tailscale VPN integration"},
    {"name": "terminal", "description": "Web terminal access"},
    {"name": "monitoring", "description": "Real-time monitoring WebSocket"},
    {"name": "csrf", "description": "CSRF token management"},
]

app = FastAPI(
    title=API_TITLE,
    version=API_VERSION,
    description=API_DESCRIPTION,
    openapi_tags=API_TAGS,
    docs_url="/docs" if ENABLE_API_DOCS else None,
    redoc_url="/redoc" if ENABLE_API_DOCS else None,
    openapi_url="/openapi.json" if ENABLE_API_DOCS else None,
    license_info={
        "name": "EasyPi Proprietary License",
        "url": "https://github.com/NewNetGuard/EasyPi/blob/master/LICENSE",
    },
    contact={
        "name": "EasyPi Support",
        "url": "https://github.com/NewNetGuard/EasyPi",
    },
)
app.add_exception_handler(RequestValidationError, request_validation_exception_handler)

# Initialize database on startup
init_db(engine)

app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:3000",
        "http://localhost:5173",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:5173",
    ] if ALLOW_DEV_CORS else [],
    # In production EasyPi is same-origin behind nginx, so broad LAN CORS is not needed.
    allow_origin_regex=(
        r"https?://(localhost|127\.0\.0\.1|192\.168\.\d+\.\d+|100\.\d+\.\d+\.\d+)(:\d+)?"
        if ALLOW_DEV_CORS else None
    ),
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*", "X-CSRF-Token"],  # Explicitly allow CSRF header
)

if LoggingMiddleware is not None:
    logging_middleware_impl = LoggingMiddleware(app)
else:  # pragma: no cover
    logging_middleware_impl = None

# Instantiate middleware helpers directly and route them through FastAPI's
# function middleware. This preserves the current behavior while avoiding the
# per-request latency that can appear when stacking multiple BaseHTTPMiddleware
# wrappers in production.
csrf_middleware_impl = CSRFMiddleware(
    app,
    cookie_secure=None,  # Auto-detect HTTPS/proxy context per request
    cookie_samesite="lax",
)
secure_headers_middleware_impl = SecureHeadersMiddleware(
    app,
    config=get_default_api_config(),
)


@app.middleware("http")
async def csrf_http_middleware(request: Request, call_next):
    return await csrf_middleware_impl.dispatch(request, call_next)


@app.middleware("http")
async def secure_headers_http_middleware(request: Request, call_next):
    return await secure_headers_middleware_impl.dispatch(request, call_next)


if logging_middleware_impl is not None:
    @app.middleware("http")
    async def logging_http_middleware(request: Request, call_next):
        return await logging_middleware_impl.dispatch(request, call_next)


_auth_operation_events = OperationEventService()
_AUTH_WORKFLOW_PATHS = {
    "/api/v1/auth/login": "login",
    "/api/v1/auth/register": "register",
    "/api/v1/auth/recovery-login": "recovery",
    "/api/v1/auth/refresh": "refresh",
}
_AUTH_EVENT_MIN_INTERVAL_SECONDS = 10.0
_auth_event_last_write: dict[tuple[str, str], float] = {}
_auth_event_lock = Lock()


def _should_record_auth_event(workflow: str, outcome: str) -> bool:
    """Globally throttle public auth telemetry before it touches the disk."""

    now = time.monotonic()
    key = (workflow, outcome)
    with _auth_event_lock:
        previous = _auth_event_last_write.get(key, 0.0)
        if now - previous < _AUTH_EVENT_MIN_INTERVAL_SECONDS:
            return False
        _auth_event_last_write[key] = now
        return True


@app.middleware("http")
async def auth_workflow_event_middleware(request: Request, call_next):
    """Record auth workflow outcomes without persisting credentials or tokens."""

    workflow = _AUTH_WORKFLOW_PATHS.get(request.url.path) if request.method == "POST" else None
    if workflow is None:
        return await call_next(request)
    started_at = datetime.now(timezone.utc).isoformat()
    try:
        response = await call_next(request)
    except Exception as exc:
        try:
            if _should_record_auth_event(workflow, "failed"):
                _auth_operation_events.record_event(
                    event_id=f"auth-workflow-{workflow}-failed",
                    action_id=f"auth.workflow.{workflow}",
                    status="failed",
                    title=f"Authentication {workflow} workflow",
                    subtitle=f"Auth · {workflow}",
                    route="/auth",
                    message=f"Authentication workflow failed with {type(exc).__name__}.",
                    started_at=started_at,
                    updated_at=datetime.now(timezone.utc).isoformat(),
                )
        except Exception as record_exc:
            logger.warning("Failed to record auth workflow event: %s", record_exc)
        raise
    try:
        succeeded = 200 <= response.status_code < 400
        outcome = "success" if succeeded else "failed"
        if _should_record_auth_event(workflow, outcome):
            _auth_operation_events.record_event(
                # These endpoints are public. Reuse one record per outcome so
                # an unauthenticated caller cannot allocate unbounded files.
                event_id=f"auth-workflow-{workflow}-{outcome}",
                action_id=f"auth.workflow.{workflow}",
                status=outcome,
                title=f"Authentication {workflow} workflow",
                subtitle=f"Auth · {workflow}",
                route="/auth",
                message=f"Authentication {workflow} returned HTTP {response.status_code}.",
                started_at=started_at,
                updated_at=datetime.now(timezone.utc).isoformat(),
            )
    except Exception as exc:
        logger.warning("Failed to record auth workflow event: %s", exc)
    return response

# Import recording service for startup/shutdown
try:
    from app.services.recording_service import recording_service
except ImportError:
    recording_service = None


async def startup_event():
    """Initialize services on startup"""
    # Validate critical paths and permissions
    from pathlib import Path
    import subprocess
    settings = Settings()

    # A RUNNING row belongs to an in-memory task in one backend process. At a
    # fresh startup no such task exists, so retain an honest interrupted result
    # instead of displaying a job that can never finish or be cancelled.
    try:
        from app.services.backup_service import BackupService

        BackupService.reconcile_interrupted_backups()
    except Exception as e:
        logger.warning("Could not reconcile interrupted backup jobs: %s", e)
    
    # Check scripts directory permissions
    scripts_dir = Path(settings.SCRIPTS_ROOT)
    if scripts_dir.exists():
        if not os.access(scripts_dir, os.R_OK | os.X_OK):
            logger.error(
                "❌ CRITICAL: Cannot access scripts directory: %s\n"
                "   Current user: %s\n"
                "   Fix: sudo chmod 750 %s && sudo chown root:easypi %s\n"
                "   And add user to easypi group: sudo usermod -aG easypi %s",
                scripts_dir, os.getenv('USER', 'unknown'), scripts_dir, scripts_dir, os.getenv('USER', 'unknown')
            )
        else:
            logger.info("✅ Scripts directory accessible: %s", scripts_dir)
    else:
        logger.warning("⚠️  Scripts directory not found: %s", scripts_dir)
    
    # The runner is intentionally root-owned and may not be directly executable
    # by the service account. Verify the reviewed sudo policy without changing
    # filesystem permissions or expanding the backend's privileges.
    runner_path = Path(settings.SCRIPTS_ROOT) / "runner"
    if runner_path.exists():
        if not os.access(runner_path, os.X_OK):
            logger.info("Runner uses the reviewed sudo boundary: %s", runner_path)
            try:
                result = subprocess.run(
                    ["sudo", "-n", "-l", str(runner_path)],
                    capture_output=True,
                    text=True,
                    timeout=5
                )
                if result.returncode == 0:
                    logger.info("✅ Runner is authorized by the reviewed sudo policy")
                else:
                    logger.error(
                        "❌ Runner is not directly executable and sudo policy verification failed: %s",
                        (result.stderr or "permission denied").strip(),
                    )
            except Exception as e:
                logger.error("❌ Runner sudo policy verification failed: %s", e)
        else:
            logger.info("✅ Runner is executable: %s", runner_path)

    # One-time migration: Stealth Domain HTTPS no longer accepts a DuckDNS
    # token. Delete the obsolete encrypted credential and metadata without
    # making backend availability depend on this best-effort cleanup. A failed
    # attempt is deliberately retried at the next startup.
    try:
        from app.services.stealth_service import get_stealth_service

        cleaned = await asyncio.to_thread(
            get_stealth_service().cleanup_legacy_duckdns_token
        )
        if cleaned:
            logger.info("Legacy Stealth DuckDNS credential removed")
    except Exception as e:
        logger.warning(
            "Legacy Stealth DuckDNS credential cleanup will retry on next startup: %s",
            e,
        )
    
    # Print access information
    import socket
    
    print("\n" + "="*60)
    print("  🥧 EasyPi Web Panel")
    print("="*60)
    
    # Get local IP addresses using socket
    ips = []
    try:
        # Method 1: Get all IPs by connecting to external address (doesn't actually connect)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(('8.8.8.8', 80))
            local_ip = s.getsockname()[0]
            if local_ip and not local_ip.startswith('127.'):
                ips.append(local_ip)
        finally:
            s.close()
    except Exception:
        pass
    
    # Method 2: Fallback - get hostname IP
    if not ips:
        try:
            hostname = socket.gethostname()
            ip = socket.gethostbyname(hostname)
            if ip and not ip.startswith('127.'):
                ips.append(ip)
        except Exception:
            pass
    
    # Print access URLs
    print("\n📍 Access at:")
    if ips:
        for ip in ips[:3]:  # Show max 3 IPs
            print(f"   https://{ip}")
    else:
        print("   http://localhost:8000")
    
    if ENABLE_API_DOCS:
        print("\n💡 Backend API: http://localhost:8000/docs")
    else:
        print("\n💡 Backend API docs are disabled in production")
    print("="*60 + "\n")
    
    # Start threat monitoring (auto-start based on saved config)
    try:
        await threat_service.auto_start_if_enabled()
    except Exception as e:
        logger.warning(f"Threat monitoring not started: {e}")

    # Re-apply persisted IP bans to the firewall (survives restart + reboot)
    try:
        await threat_service.restore_bans()
    except Exception as e:
        logger.warning(f"Could not restore persisted bans: {e}")
    
    # Initialize NetProtection service
    try:
        await netprotection_service.initialize()
        logger.info("NetProtection service initialized")
    except Exception as e:
        logger.warning(f"NetProtection not fully initialized: {e}")
    
    # Sync go2rtc config with cameras from database
    try:
        from app.db.session import SessionLocal
        from app.api.v1.endpoints.cameras import sync_go2rtc_config
        
        db = SessionLocal()
        try:
            if sync_go2rtc_config(db):
                logger.info("go2rtc config synced with cameras on startup")
        finally:
            db.close()
    except Exception as e:
        logger.warning(f"go2rtc sync not completed: {e}")
    
    # Start recording monitor
    if recording_service:
        try:
            await recording_service.start_monitor()
        except Exception as e:
            logger.warning(f"Recording monitor not started: {e}")

    # Wire up alert channels so the watchdog can push to phones: generate/load VAPID
    # for web push, and load the Telegram-alerts config.
    try:
        from app.core.paths import get_netprotection_data_dir
        _alert_dir = str(get_netprotection_data_dir())
        from app.services.push_notification_service import get_push_service
        get_push_service().ensure_configured(_alert_dir)
        from app.services.telegram_alert_service import get_telegram_alerts
        get_telegram_alerts().load(_alert_dir)
    except Exception as e:
        logger.warning(f"Alert channels init failed: {e}")

    # Start proactive watchdog monitor (new device / disk / bypass / service down)
    try:
        from app.services.proactive_monitor import get_proactive_monitor
        get_proactive_monitor().start()
    except Exception as e:
        logger.warning(f"Proactive monitor not started: {e}")

    # Restore the Cloud Telegram bot only when it was running before this
    # backend restart. A bot stopped by the user stays stopped.
    try:
        from app.services.picloud_service import pi_cloud_service

        if pi_cloud_service.auto_start_telegram_bot():
            logger.info("Cloud Telegram bot restart requested from persisted state")
    except Exception as e:
        logger.warning(f"Cloud Telegram bot not restored: {e}")


async def shutdown_event():
    """Cleanup on shutdown"""
    async def stop_component(name, operation, timeout: float) -> None:
        try:
            await asyncio.wait_for(operation(), timeout=timeout)
            logger.info("%s stopped", name)
        except asyncio.TimeoutError:
            logger.warning("Timed out stopping %s after %.1fs", name, timeout)
        except Exception as e:
            logger.warning("Error stopping %s: %s", name, e)

    # Stop independent producers concurrently. Each operation and the overall
    # systemd shutdown stay bounded, so one faulty optional component cannot
    # hold the unit open until systemd has to kill it.
    shutdown_operations = []
    try:
        from app.services.proactive_monitor import get_proactive_monitor

        shutdown_operations.append(
            stop_component("Proactive monitor", get_proactive_monitor().stop, 3.0)
        )
    except Exception as e:
        logger.warning("Error locating proactive monitor during shutdown: %s", e)

    shutdown_operations.extend(
        (
            stop_component("NetProtection background tasks", netprotection_service.stop, 6.0),
            stop_component("Threat monitor", threat_service.stop_monitoring, 3.0),
        )
    )

    try:
        from app.api.v1.endpoints.backup import backup_service

        shutdown_operations.append(
            stop_component("Backup jobs", backup_service.shutdown, 12.0)
        )
    except Exception as e:
        logger.warning("Error locating backup service during shutdown: %s", e)

    if recording_service:
        shutdown_operations.append(
            stop_component("Recording monitor", recording_service.stop_monitor, 8.0)
        )

    await asyncio.gather(*shutdown_operations)

    # Best-effort Stop of any active PTZ sessions. Never blocks shutdown, and one
    # camera failing to stop does not prevent the others from stopping.
    try:
        from app.services.ptz.session import session_manager

        await asyncio.wait_for(asyncio.to_thread(session_manager.stop_all), timeout=3.0)
    except asyncio.TimeoutError:
        logger.warning("Timed out stopping PTZ sessions after 3.0s")
    except Exception as e:
        logger.warning(f"Error stopping PTZ sessions: {e}")


@asynccontextmanager
async def app_lifespan(_app: FastAPI):
    await startup_event()
    try:
        yield
    finally:
        await shutdown_event()


app.router.lifespan_context = app_lifespan


# Include health router with detailed service checks
app.include_router(health_router, prefix="/api", tags=["health"])


# Legacy health endpoints for backward compatibility
@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok"}


# ============================================================================
# CSRF Token Endpoint
# ============================================================================

@app.get("/api/v1/csrf-token", tags=["csrf"],
         summary="Get CSRF token",
         description="Get a CSRF token for form submissions. Include this token in the X-CSRF-Token header or _csrf_token form field.")
async def get_csrf_token(request: Request) -> dict:
    """
    Get a CSRF token.
    
    The token is also set as a cookie. For form submissions:
    - Include token in `X-CSRF-Token` header, OR
    - Include as `_csrf_token` hidden form field
    
    Note: API endpoints using Bearer tokens are exempt from CSRF validation.
    """
    token = get_csrf_token_from_request(request)
    return {
        "csrf_token": token,
        "header_name": CSRF_HEADER_NAME,
        "form_field": "_csrf_token",
        "expires_in": 14400,  # 4 hours
    }


app.include_router(api_v1_router)
app.include_router(network_router, tags=["network"])
app.include_router(network_toolkit_router, tags=["network"])
app.include_router(netprotection_router, prefix="/api/v1", tags=["netprotection"])
app.include_router(setup_router, prefix="/api", tags=["system"])
app.include_router(system_router, prefix="/api", tags=["system"])
app.include_router(tailscale_router, prefix="/api", tags=["tailscale"])
app.include_router(tailscale_admin_router, prefix="/api", tags=["tailscale-admin"])
app.include_router(tailscale_relay_router, prefix="/api", tags=["tailscale-relay"])
app.include_router(cameras_router, prefix="/api", tags=["cameras"])
app.include_router(terminal_router, tags=["terminal"])
app.add_api_websocket_route("/ws/monitoring", monitoring_websocket)
app.add_api_websocket_route("/ws/tasks/{task_id}", task_logs)
app.add_api_websocket_route("/ws/cameras/{camera_id}/live", camera_live_websocket)


if __name__ == "__main__":
    import uvicorn
    
    # Configure uvicorn logging to use our custom format
    log_config = uvicorn.config.LOGGING_CONFIG
    log_config["formatters"]["access"]["fmt"] = '%(asctime)s | %(levelname)s | %(client_addr)s - "%(request_line)s" %(status_code)s'
    log_config["formatters"]["default"]["fmt"] = '%(asctime)s | %(levelname)s | %(name)s | %(message)s'

    uvicorn.run(
        "main:app", 
        host=API_BIND_HOST,
        port=8000, 
        reload=False,
        proxy_headers=True,  # Trust X-Forwarded-* headers from nginx
        forwarded_allow_ips="*",  # Allow all IPs (nginx is on localhost)
        access_log=True,
        log_config=log_config
    )
