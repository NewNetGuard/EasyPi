"""
EasyPi Logging Module with File Rotation

Features:
- JSON and text format support
- File rotation with size limits
- Console and file handlers
- Request ID tracking
- Structured logging with extra fields
"""

import logging
import sys
import time
import uuid
from contextvars import ContextVar
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Optional

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

try:
    from pythonjsonlogger import jsonlogger
    HAS_JSON_LOGGER = True
except ImportError:
    HAS_JSON_LOGGER = False

from config import get_settings
from app.core.rate_limit import get_client_ip

_settings = get_settings()

_request_id_ctx: ContextVar[str | None] = ContextVar("request_id", default=None)


def get_request_id() -> Optional[str]:
    """Get the current request ID from context."""
    return _request_id_ctx.get()


class _RequestIdFilter(logging.Filter):
    """Filter that adds request_id to log records."""
    
    def filter(self, record: logging.LogRecord) -> bool:
        record.request_id = _request_id_ctx.get() or "-"
        return True


class _ExtraFieldsFilter(logging.Filter):
    """Filter that ensures all extra fields have default values."""
    
    def filter(self, record: logging.LogRecord) -> bool:
        # Ensure all expected fields exist
        if not hasattr(record, 'method'):
            record.method = "-"
        if not hasattr(record, 'path'):
            record.path = "-"
        if not hasattr(record, 'status'):
            record.status = "-"
        if not hasattr(record, 'duration_ms'):
            record.duration_ms = "-"
        if not hasattr(record, 'client_ip'):
            record.client_ip = "-"
        if not hasattr(record, 'user_id'):
            record.user_id = "-"
        return True


class ColoredFormatter(logging.Formatter):
    """Colored console formatter for better readability."""
    
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
    }
    RESET = '\033[0m'
    
    def format(self, record: logging.LogRecord) -> str:
        # Add color to levelname
        color = self.COLORS.get(record.levelname, '')
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


class StructuredTextFormatter(logging.Formatter):
    """Structured text formatter for file logging."""
    
    def format(self, record: logging.LogRecord) -> str:
        # Build structured log line
        timestamp = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        
        # Base message
        message = f"{timestamp} | {record.levelname:8} | {record.name} | {record.getMessage()}"
        
        # Add request context if available
        request_id = getattr(record, 'request_id', '-')
        if request_id != '-':
            message += f" | req_id={request_id}"
        
        method = getattr(record, 'method', '-')
        path = getattr(record, 'path', '-')
        if method != '-' and path != '-':
            message += f" | {method} {path}"
        
        status = getattr(record, 'status', '-')
        if status != '-':
            message += f" | status={status}"
        
        duration_ms = getattr(record, 'duration_ms', '-')
        if duration_ms != '-':
            message += f" | {duration_ms}ms"
        
        client_ip = getattr(record, 'client_ip', '-')
        if client_ip != '-':
            message += f" | ip={client_ip}"
        
        # Add exception info if present
        if record.exc_info:
            message += f"\n{self.formatException(record.exc_info)}"
        
        return message


def _ensure_log_dir() -> Path:
    """Ensure log directory exists."""
    log_dir = _settings.LOG_DIR
    
    # On Windows, use a local path for development
    if sys.platform == 'win32' and not log_dir.exists():
        log_dir = Path(__file__).parent.parent.parent / 'logs'
    
    log_dir.mkdir(parents=True, exist_ok=True)
    return log_dir


def _create_file_handler(log_file: Path) -> RotatingFileHandler:
    """Create a rotating file handler."""
    handler = RotatingFileHandler(
        filename=str(log_file),
        maxBytes=_settings.LOG_FILE_MAX_BYTES,
        backupCount=_settings.LOG_FILE_BACKUP_COUNT,
        encoding='utf-8',
    )
    return handler


def _configure_logger() -> logging.Logger:
    """Configure the main EasyPi logger with rotation and formatting."""
    logger = logging.getLogger("easypi")
    
    # Avoid duplicate handlers
    if logger.handlers:
        return logger
    
    log_level = getattr(logging, _settings.LOG_LEVEL.upper(), logging.INFO)
    logger.setLevel(log_level)
    logger.propagate = False
    
    # Common filters
    request_id_filter = _RequestIdFilter()
    extra_fields_filter = _ExtraFieldsFilter()
    
    # Console handler
    if _settings.LOG_TO_CONSOLE:
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(log_level)
        console_handler.addFilter(request_id_filter)
        console_handler.addFilter(extra_fields_filter)
        
        if _settings.LOG_FORMAT == "json" and HAS_JSON_LOGGER:
            console_formatter = jsonlogger.JsonFormatter(
                "%(asctime)s %(levelname)s %(name)s %(message)s %(request_id)s "
                "%(method)s %(path)s %(status)s %(duration_ms)s %(client_ip)s %(user_id)s"
            )
        else:
            # Use colored formatter for console in dev, plain for production
            if _settings.ENV == "development" and sys.stdout.isatty():
                console_formatter = ColoredFormatter(
                    "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
                    datefmt='%H:%M:%S'
                )
            else:
                console_formatter = logging.Formatter(
                    "%(asctime)s | %(levelname)s | %(name)s | %(message)s",
                    datefmt='%Y-%m-%d %H:%M:%S'
                )
        
        console_handler.setFormatter(console_formatter)
        logger.addHandler(console_handler)
    
    # File handler with rotation
    if _settings.LOG_TO_FILE:
        try:
            log_dir = _ensure_log_dir()
            
            # Main application log
            app_log_file = log_dir / "easypi.log"
            app_handler = _create_file_handler(app_log_file)
            app_handler.setLevel(log_level)
            app_handler.addFilter(request_id_filter)
            app_handler.addFilter(extra_fields_filter)
            
            if _settings.LOG_FORMAT == "json" and HAS_JSON_LOGGER:
                app_formatter = jsonlogger.JsonFormatter(
                    "%(asctime)s %(levelname)s %(name)s %(message)s %(request_id)s "
                    "%(method)s %(path)s %(status)s %(duration_ms)s %(client_ip)s %(user_id)s",
                    timestamp=True
                )
            else:
                app_formatter = StructuredTextFormatter()
            
            app_handler.setFormatter(app_formatter)
            logger.addHandler(app_handler)
            
            # Error log (only ERROR and above)
            error_log_file = log_dir / "easypi-error.log"
            error_handler = _create_file_handler(error_log_file)
            error_handler.setLevel(logging.ERROR)
            error_handler.addFilter(request_id_filter)
            error_handler.addFilter(extra_fields_filter)
            error_handler.setFormatter(app_formatter)
            logger.addHandler(error_handler)
            
        except Exception as e:
            # Fall back to console only if file logging fails
            print(f"Warning: Could not set up file logging: {e}", file=sys.stderr)
    
    return logger


def _configure_security_logger() -> logging.Logger:
    """Configure a separate logger for security events."""
    security_logger = logging.getLogger("easypi.security")
    
    if security_logger.handlers:
        return security_logger
    
    security_logger.setLevel(logging.INFO)
    security_logger.propagate = False
    
    # Common filters
    request_id_filter = _RequestIdFilter()
    extra_fields_filter = _ExtraFieldsFilter()
    
    if _settings.LOG_TO_FILE:
        try:
            log_dir = _ensure_log_dir()
            security_log_file = log_dir / "security.log"
            handler = _create_file_handler(security_log_file)
            handler.setLevel(logging.INFO)
            handler.addFilter(request_id_filter)
            handler.addFilter(extra_fields_filter)
            
            if _settings.LOG_FORMAT == "json" and HAS_JSON_LOGGER:
                formatter = jsonlogger.JsonFormatter(
                    "%(asctime)s %(levelname)s %(name)s %(message)s %(request_id)s "
                    "%(event_type)s %(client_ip)s %(user_id)s %(details)s",
                    timestamp=True
                )
            else:
                formatter = StructuredTextFormatter()
            
            handler.setFormatter(formatter)
            security_logger.addHandler(handler)
            
        except Exception as e:
            print(f"Warning: Could not set up security logging: {e}", file=sys.stderr)
    
    # Also log to main logger
    security_logger.parent = logging.getLogger("easypi")
    
    return security_logger


def _configure_access_logger() -> logging.Logger:
    """Configure a separate logger for access logs (requests)."""
    access_logger = logging.getLogger("easypi.access")
    
    if access_logger.handlers:
        return access_logger
    
    access_logger.setLevel(logging.INFO)
    access_logger.propagate = False
    
    # Common filters
    request_id_filter = _RequestIdFilter()
    extra_fields_filter = _ExtraFieldsFilter()
    
    if _settings.LOG_TO_FILE:
        try:
            log_dir = _ensure_log_dir()
            access_log_file = log_dir / "access.log"
            handler = _create_file_handler(access_log_file)
            handler.setLevel(logging.INFO)
            handler.addFilter(request_id_filter)
            handler.addFilter(extra_fields_filter)
            
            if _settings.LOG_FORMAT == "json" and HAS_JSON_LOGGER:
                formatter = jsonlogger.JsonFormatter(
                    "%(asctime)s %(method)s %(path)s %(status)s %(duration_ms)s "
                    "%(client_ip)s %(user_agent)s %(request_id)s",
                    timestamp=True
                )
            else:
                # Apache-like access log format
                formatter = logging.Formatter(
                    '%(asctime)s | %(client_ip)s | %(method)s %(path)s | %(status)s | %(duration_ms)sms | %(user_agent)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )
            
            handler.setFormatter(formatter)
            access_logger.addHandler(handler)
            
        except Exception as e:
            print(f"Warning: Could not set up access logging: {e}", file=sys.stderr)
    
    return access_logger


# Initialize loggers
logger = _configure_logger()
security_logger = _configure_security_logger()
access_logger = _configure_access_logger()


def log_security_event(
    event_type: str,
    message: str,
    client_ip: Optional[str] = None,
    user_id: Optional[str] = None,
    level: int = logging.WARNING,
    **extra: Any
) -> None:
    """
    Log a security-related event.
    
    Args:
        event_type: Type of security event (e.g., 'login_failed', 'rate_limited', 'unauthorized')
        message: Human-readable message
        client_ip: Client IP address if available
        user_id: User ID if authenticated
        level: Logging level (default WARNING)
        **extra: Additional context
    """
    security_logger.log(
        level,
        message,
        extra={
            'event_type': event_type,
            'client_ip': client_ip or '-',
            'user_id': user_id or '-',
            'details': extra,
        }
    )


class LoggingMiddleware(BaseHTTPMiddleware):
    """Middleware for request/response logging with timing and request IDs."""
    
    # Paths to exclude from detailed logging (health checks, etc.)
    EXCLUDE_PATHS = {'/health', '/api/health', '/favicon.ico', '/robots.txt'}
    
    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        # Generate request ID
        request_id = request.headers.get('X-Request-ID') or str(uuid.uuid4())
        token = _request_id_ctx.set(request_id)
        start_time = time.perf_counter()
        
        # Get client info
        client_ip = self._get_client_ip(request)
        user_agent = request.headers.get('User-Agent', '-')
        
        try:
            response = await call_next(request)
            duration_ms = (time.perf_counter() - start_time) * 1000
            
            # Add request ID to response headers
            response.headers["X-Request-ID"] = request_id
            
            # Log request (skip excluded paths for cleaner logs)
            if request.url.path not in self.EXCLUDE_PATHS:
                extra = self._build_extra(
                    request=request,
                    status=response.status_code,
                    duration_ms=duration_ms,
                    client_ip=client_ip,
                    user_agent=user_agent,
                )
                
                # Log to access logger
                access_logger.info(
                    f"{request.method} {request.url.path}",
                    extra=extra
                )
                
                # Log to main logger for errors
                if response.status_code >= 400:
                    # 401 on polling endpoints is expected (token refresh) - log as DEBUG
                    polling_endpoints = [
                        "/api/remote/tailscale/status",
                        "/api/v1/monitoring/stats",
                        "/api/system/info",
                    ]
                    is_polling_401 = (
                        response.status_code == 401 and 
                        any(request.url.path.endswith(ep) for ep in polling_endpoints)
                    )
                    
                    if is_polling_401:
                        log_level = logging.DEBUG
                    elif response.status_code < 500:
                        log_level = logging.WARNING
                    else:
                        log_level = logging.ERROR
                        
                    logger.log(
                        log_level,
                        f"Request failed: {request.method} {request.url.path} - {response.status_code}",
                        extra=extra
                    )
            
            return response
            
        except Exception:
            duration_ms = (time.perf_counter() - start_time) * 1000
            
            logger.exception(
                "Unhandled exception",
                extra=self._build_extra(
                    request=request,
                    status=500,
                    duration_ms=duration_ms,
                    client_ip=client_ip,
                    user_agent=user_agent,
                ),
            )
            raise
            
        finally:
            _request_id_ctx.reset(token)
    
    def _get_client_ip(self, request: Request) -> str:
        """Extract client IP while trusting only configured reverse proxies."""
        client_ip = get_client_ip(request)
        return "-" if client_ip == "unknown" else client_ip
    
    def _build_extra(
        self,
        request: Request,
        status: int,
        duration_ms: float,
        client_ip: str,
        user_agent: str,
    ) -> dict[str, Any]:
        """Build extra fields for log record."""
        return {
            "method": request.method,
            "path": str(request.url.path),
            "status": status,
            "duration_ms": round(duration_ms, 2),
            "client_ip": client_ip,
            "user_agent": user_agent[:200] if user_agent else '-',  # Truncate long user agents
            "query": str(request.url.query) if request.url.query else None,
        }


# Convenience functions
def get_logger(name: str = "easypi") -> logging.Logger:
    """Get a logger instance with the given name."""
    child_logger = logging.getLogger(name)
    if not child_logger.handlers and name != "easypi":
        # Inherit from parent
        child_logger.parent = logger
    return child_logger


def set_log_level(level: str) -> None:
    """Dynamically change the log level."""
    log_level = getattr(logging, level.upper(), logging.INFO)
    logger.setLevel(log_level)
    for handler in logger.handlers:
        if not isinstance(handler, RotatingFileHandler) or handler.level != logging.ERROR:
            handler.setLevel(log_level)
