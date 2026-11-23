#!/usr/bin/env python3
"""
EasyPi Backend Entrypoint for PyInstaller Binary

This is the main entry point when running as a compiled binary.
It properly initializes the environment and starts uvicorn.
"""

import os

# Set environment variables BEFORE any imports that use paths
# These can be overridden by systemd/external configuration
if "EASYPI_ROOT" not in os.environ:
    os.environ["EASYPI_ROOT"] = "/opt/EasyPi"

if "EASYPI_DATA_DIR" not in os.environ:
    os.environ["EASYPI_DATA_DIR"] = "/opt/EasyPi/data"

if "EASYPI_BACKEND_DIR" not in os.environ:
    os.environ["EASYPI_BACKEND_DIR"] = "/opt/EasyPi/backend"

if "EASYPI_BACKEND_DATA_DIR" not in os.environ:
    os.environ["EASYPI_BACKEND_DATA_DIR"] = "/opt/EasyPi/backend/data"


def main():
    """Main entry point for the backend binary."""
    import sys
    from prism_tls_bridge.entrypoint import dispatch

    result = dispatch(sys.argv[1:])
    if result is not None:
        return result

    import uvicorn
    
    # Import app after environment is configured
    from main import app  # noqa: E402
    
    # Get configuration from environment
    env = os.getenv("ENV", "production").lower()
    default_host = "127.0.0.1" if env in ("production", "prod") else "0.0.0.0"
    host = os.getenv("API_HOST", default_host)
    port = int(os.getenv("API_PORT", "8000"))
    log_level = os.getenv("LOG_LEVEL", "info").lower()
    
    # Ensure required directories exist
    from app.core.paths import ensure_directories
    ensure_directories()
    
    print(f"Starting EasyPi Backend on {host}:{port}")
    print(f"EASYPI_ROOT: {os.environ.get('EASYPI_ROOT')}")
    print(f"EASYPI_DATA_DIR: {os.environ.get('EASYPI_DATA_DIR')}")
    
    # Run uvicorn
    uvicorn.run(
        app,
        host=host,
        port=port,
        log_level=log_level,
        access_log=True,
    )


if __name__ == "__main__":
    raise SystemExit(main())
