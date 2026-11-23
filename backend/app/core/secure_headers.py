"""
Secure HTTP Headers Middleware.

Implements security headers including:
- HSTS (HTTP Strict Transport Security)
- X-Frame-Options
- Content-Security-Policy (CSP)
- X-Content-Type-Options
- X-XSS-Protection
- Referrer-Policy
- Permissions-Policy
"""

from typing import Optional, List, Dict
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response
from dataclasses import dataclass, field


@dataclass
class CSPDirectives:
    """Content Security Policy directives configuration."""
    
    default_src: List[str] = field(default_factory=lambda: ["'self'"])
    script_src: List[str] = field(default_factory=lambda: ["'self'"])
    style_src: List[str] = field(default_factory=lambda: ["'self'", "'unsafe-inline'"])
    img_src: List[str] = field(default_factory=lambda: ["'self'", "data:", "blob:"])
    font_src: List[str] = field(default_factory=lambda: ["'self'"])
    connect_src: List[str] = field(default_factory=lambda: ["'self'", "ws:", "wss:"])
    frame_src: List[str] = field(default_factory=lambda: ["'none'"])
    frame_ancestors: List[str] = field(default_factory=lambda: ["'self'"])
    object_src: List[str] = field(default_factory=lambda: ["'none'"])
    base_uri: List[str] = field(default_factory=lambda: ["'self'"])
    form_action: List[str] = field(default_factory=lambda: ["'self'"])
    media_src: List[str] = field(default_factory=lambda: ["'self'", "blob:"])
    worker_src: List[str] = field(default_factory=lambda: ["'self'", "blob:"])
    manifest_src: List[str] = field(default_factory=lambda: ["'self'"])
    upgrade_insecure_requests: bool = True
    block_all_mixed_content: bool = True
    
    def build(self) -> str:
        """Build CSP header value from directives."""
        parts = []
        
        directive_map = {
            "default-src": self.default_src,
            "script-src": self.script_src,
            "style-src": self.style_src,
            "img-src": self.img_src,
            "font-src": self.font_src,
            "connect-src": self.connect_src,
            "frame-src": self.frame_src,
            "frame-ancestors": self.frame_ancestors,
            "object-src": self.object_src,
            "base-uri": self.base_uri,
            "form-action": self.form_action,
            "media-src": self.media_src,
            "worker-src": self.worker_src,
            "manifest-src": self.manifest_src,
        }
        
        for directive, values in directive_map.items():
            if values:
                parts.append(f"{directive} {' '.join(values)}")
        
        if self.upgrade_insecure_requests:
            parts.append("upgrade-insecure-requests")
        
        if self.block_all_mixed_content:
            parts.append("block-all-mixed-content")
        
        return "; ".join(parts)


@dataclass
class HSTSConfig:
    """HSTS (HTTP Strict Transport Security) configuration."""
    
    max_age: int = 31536000  # 1 year in seconds
    include_subdomains: bool = True
    preload: bool = False
    
    def build(self) -> str:
        """Build HSTS header value."""
        parts = [f"max-age={self.max_age}"]
        
        if self.include_subdomains:
            parts.append("includeSubDomains")
        
        if self.preload:
            parts.append("preload")
        
        return "; ".join(parts)


@dataclass
class PermissionsPolicyConfig:
    """Permissions Policy (formerly Feature-Policy) configuration."""
    
    # Disable potentially dangerous features by default
    accelerometer: List[str] = field(default_factory=list)
    ambient_light_sensor: List[str] = field(default_factory=list)
    autoplay: List[str] = field(default_factory=lambda: ["self"])
    battery: List[str] = field(default_factory=list)
    camera: List[str] = field(default_factory=list)
    display_capture: List[str] = field(default_factory=list)
    document_domain: List[str] = field(default_factory=list)
    encrypted_media: List[str] = field(default_factory=lambda: ["self"])
    fullscreen: List[str] = field(default_factory=lambda: ["self"])
    geolocation: List[str] = field(default_factory=list)
    gyroscope: List[str] = field(default_factory=list)
    magnetometer: List[str] = field(default_factory=list)
    microphone: List[str] = field(default_factory=list)
    midi: List[str] = field(default_factory=list)
    payment: List[str] = field(default_factory=list)
    picture_in_picture: List[str] = field(default_factory=lambda: ["self"])
    publickey_credentials_get: List[str] = field(default_factory=lambda: ["self"])
    screen_wake_lock: List[str] = field(default_factory=list)
    sync_xhr: List[str] = field(default_factory=list)
    usb: List[str] = field(default_factory=list)
    web_share: List[str] = field(default_factory=lambda: ["self"])
    xr_spatial_tracking: List[str] = field(default_factory=list)
    
    def build(self) -> str:
        """Build Permissions-Policy header value."""
        parts = []
        
        directive_map = {
            "accelerometer": self.accelerometer,
            "ambient-light-sensor": self.ambient_light_sensor,
            "autoplay": self.autoplay,
            "battery": self.battery,
            "camera": self.camera,
            "display-capture": self.display_capture,
            "document-domain": self.document_domain,
            "encrypted-media": self.encrypted_media,
            "fullscreen": self.fullscreen,
            "geolocation": self.geolocation,
            "gyroscope": self.gyroscope,
            "magnetometer": self.magnetometer,
            "microphone": self.microphone,
            "midi": self.midi,
            "payment": self.payment,
            "picture-in-picture": self.picture_in_picture,
            "publickey-credentials-get": self.publickey_credentials_get,
            "screen-wake-lock": self.screen_wake_lock,
            "sync-xhr": self.sync_xhr,
            "usb": self.usb,
            "web-share": self.web_share,
            "xr-spatial-tracking": self.xr_spatial_tracking,
        }
        
        for directive, values in directive_map.items():
            if values:
                formatted_values = " ".join(values)
                parts.append(f"{directive}=({formatted_values})")
            else:
                parts.append(f"{directive}=()")
        
        return ", ".join(parts)


@dataclass 
class SecureHeadersConfig:
    """Configuration for all security headers."""
    
    # Enable/disable individual headers
    enable_hsts: bool = True
    enable_csp: bool = True
    enable_x_frame_options: bool = True
    enable_x_content_type_options: bool = True
    enable_x_xss_protection: bool = True
    enable_referrer_policy: bool = True
    enable_permissions_policy: bool = True
    enable_cache_control: bool = True
    enable_cross_origin_headers: bool = True
    
    # Header configurations
    hsts: HSTSConfig = field(default_factory=HSTSConfig)
    csp: CSPDirectives = field(default_factory=CSPDirectives)
    permissions_policy: PermissionsPolicyConfig = field(default_factory=PermissionsPolicyConfig)
    
    # X-Frame-Options: DENY, SAMEORIGIN, or ALLOW-FROM uri
    x_frame_options: str = "SAMEORIGIN"
    
    # Referrer-Policy options
    referrer_policy: str = "strict-origin-when-cross-origin"
    
    # Cache-Control for sensitive responses
    cache_control: str = "no-store, no-cache, must-revalidate, private"
    
    # Cross-Origin headers
    cross_origin_embedder_policy: str = "require-corp"
    cross_origin_opener_policy: str = "same-origin"
    cross_origin_resource_policy: str = "same-origin"
    
    # Paths to exclude from security headers (e.g., static assets)
    exclude_paths: List[str] = field(default_factory=list)
    
    # Use report-only mode for CSP (for testing)
    csp_report_only: bool = False
    csp_report_uri: Optional[str] = None


class SecureHeadersMiddleware(BaseHTTPMiddleware):
    """
    Middleware that adds security headers to all responses.
    
    Implements OWASP recommended security headers:
    - HSTS: Forces HTTPS connections
    - CSP: Prevents XSS and data injection attacks
    - X-Frame-Options: Prevents clickjacking
    - X-Content-Type-Options: Prevents MIME sniffing
    - X-XSS-Protection: Legacy XSS filter (for older browsers)
    - Referrer-Policy: Controls referrer information
    - Permissions-Policy: Controls browser features
    """
    
    def __init__(self, app, config: Optional[SecureHeadersConfig] = None):
        super().__init__(app)
        self.config = config or SecureHeadersConfig()
        
        # Pre-build static header values for performance
        self._headers_cache: Dict[str, str] = {}
        self._build_headers_cache()
    
    def _build_headers_cache(self) -> None:
        """Pre-build header values that don't change per-request."""
        config = self.config
        
        if config.enable_hsts:
            self._headers_cache["Strict-Transport-Security"] = config.hsts.build()
        
        if config.enable_csp:
            csp_value = config.csp.build()
            if config.csp_report_uri:
                csp_value += f"; report-uri {config.csp_report_uri}"
            
            header_name = "Content-Security-Policy-Report-Only" if config.csp_report_only else "Content-Security-Policy"
            self._headers_cache[header_name] = csp_value
        
        if config.enable_x_frame_options:
            self._headers_cache["X-Frame-Options"] = config.x_frame_options
        
        if config.enable_x_content_type_options:
            self._headers_cache["X-Content-Type-Options"] = "nosniff"
        
        if config.enable_x_xss_protection:
            self._headers_cache["X-XSS-Protection"] = "1; mode=block"
        
        if config.enable_referrer_policy:
            self._headers_cache["Referrer-Policy"] = config.referrer_policy
        
        if config.enable_permissions_policy:
            self._headers_cache["Permissions-Policy"] = config.permissions_policy.build()
        
        if config.enable_cache_control:
            self._headers_cache["Cache-Control"] = config.cache_control
            self._headers_cache["Pragma"] = "no-cache"
            self._headers_cache["Expires"] = "0"
        
        if config.enable_cross_origin_headers:
            self._headers_cache["Cross-Origin-Embedder-Policy"] = config.cross_origin_embedder_policy
            self._headers_cache["Cross-Origin-Opener-Policy"] = config.cross_origin_opener_policy
            self._headers_cache["Cross-Origin-Resource-Policy"] = config.cross_origin_resource_policy
    
    def _should_apply_headers(self, request: Request) -> bool:
        """Check if security headers should be applied to this request."""
        path = request.url.path
        
        # Check exclude paths
        for exclude_path in self.config.exclude_paths:
            if path.startswith(exclude_path):
                return False
        
        return True
    
    async def dispatch(self, request: Request, call_next) -> Response:
        """Process request and add security headers to response."""
        response = await call_next(request)
        
        if self._should_apply_headers(request):
            # Add all cached headers
            for header_name, header_value in self._headers_cache.items():
                # Don't override existing headers
                if header_name not in response.headers:
                    response.headers[header_name] = header_value
        
        return response


def get_default_api_config() -> SecureHeadersConfig:
    """
    Get secure headers configuration optimized for API endpoints.
    
    Less restrictive than full web app config since APIs typically
    don't serve HTML content.
    """
    return SecureHeadersConfig(
        enable_hsts=True,
        enable_csp=False,  # APIs don't serve HTML, CSP not needed
        enable_x_frame_options=True,
        enable_x_content_type_options=True,
        enable_x_xss_protection=False,  # Not relevant for JSON APIs
        enable_referrer_policy=True,
        enable_permissions_policy=False,  # Not relevant for APIs
        enable_cache_control=True,
        enable_cross_origin_headers=False,  # May interfere with CORS
        hsts=HSTSConfig(
            max_age=31536000,
            include_subdomains=True,
            preload=False
        ),
        x_frame_options="DENY",
        referrer_policy="no-referrer",
        cache_control="no-store, no-cache, must-revalidate, private"
    )


def get_default_web_config() -> SecureHeadersConfig:
    """
    Get secure headers configuration for web applications.
    
    Full security headers for HTML content.
    """
    return SecureHeadersConfig(
        enable_hsts=True,
        enable_csp=True,
        enable_x_frame_options=True,
        enable_x_content_type_options=True,
        enable_x_xss_protection=True,
        enable_referrer_policy=True,
        enable_permissions_policy=True,
        enable_cache_control=True,
        enable_cross_origin_headers=True,
        hsts=HSTSConfig(
            max_age=31536000,
            include_subdomains=True,
            preload=False
        ),
        csp=CSPDirectives(
            default_src=["'self'"],
            script_src=["'self'"],
            style_src=["'self'", "'unsafe-inline'"],
            img_src=["'self'", "data:", "blob:"],
            font_src=["'self'"],
            connect_src=["'self'", "ws:", "wss:"],
            frame_src=["'none'"],
            frame_ancestors=["'self'"],
            object_src=["'none'"],
            base_uri=["'self'"],
            form_action=["'self'"],
            upgrade_insecure_requests=True,
            block_all_mixed_content=True
        ),
        x_frame_options="SAMEORIGIN",
        referrer_policy="strict-origin-when-cross-origin"
    )


def get_relaxed_csp_for_development() -> CSPDirectives:
    """
    Get a more relaxed CSP configuration for development.
    
    Allows inline scripts/styles and eval for hot reloading.
    """
    return CSPDirectives(
        default_src=["'self'"],
        script_src=["'self'", "'unsafe-inline'", "'unsafe-eval'"],
        style_src=["'self'", "'unsafe-inline'"],
        img_src=["'self'", "data:", "blob:", "*"],
        font_src=["'self'", "data:"],
        connect_src=["'self'", "ws:", "wss:", "http:", "https:"],
        frame_src=["'self'"],
        frame_ancestors=["'self'"],
        object_src=["'none'"],
        base_uri=["'self'"],
        form_action=["'self'"],
        upgrade_insecure_requests=False,
        block_all_mixed_content=False
    )
