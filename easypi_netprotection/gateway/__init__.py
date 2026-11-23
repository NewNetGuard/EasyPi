"""
EasyPi NetProtection — Gateway Package.

REST API for EasyPi Dashboard integration.
"""

from .routes import (
    NetProtectionAPI,
    APIResponse,
    PaginatedResponse,
    BASE_PATH,
    API_VERSION,
    get_routes,
    create_api,
)

__all__ = [
    # API
    "NetProtectionAPI",
    "APIResponse",
    "PaginatedResponse",
    
    # Constants
    "BASE_PATH",
    "API_VERSION",
    
    # Factory
    "get_routes",
    "create_api",
]
