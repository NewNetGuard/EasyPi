"""
Centralized path management for EasyPi.

This module provides all project paths through environment variables,
making the codebase compatible with PyInstaller binary builds.

Environment Variables:
    EASYPI_ROOT: Root installation directory (default: /opt/EasyPi)
    EASYPI_BACKEND_DIR: Backend directory (default: $EASYPI_ROOT/backend)
    EASYPI_DATA_DIR: Data directory (default: $EASYPI_ROOT/data)
    EASYPI_SCRIPTS_DIR: Scripts directory (default: $EASYPI_ROOT/scripts)
    EASYPI_LOGS_DIR: Logs directory (default: $EASYPI_ROOT/logs)
    EASYPI_CONFIG_DIR: Config directory (default: $EASYPI_ROOT/config)
"""

import os
import sys
from pathlib import Path
from functools import lru_cache


def _is_frozen() -> bool:
    """Check if running as PyInstaller bundle."""
    return getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS')


def _get_default_root() -> Path:
    """
    Get default root directory.
    
    In development: parent of backend directory (EasyPi repo root)
    In production/binary: /opt/EasyPi
    """
    if _is_frozen():
        # Running as PyInstaller binary - use /opt/EasyPi
        return Path("/opt/EasyPi")
    
    # Development mode - find repo root from this file's location
    # This file is at: backend/app/core/paths.py
    # Repo root is 4 levels up
    try:
        return Path(__file__).resolve().parents[3]
    except (IndexError, TypeError):
        return Path("/opt/EasyPi")


def _get_default_backend_dir() -> Path:
    """Get default backend directory."""
    if _is_frozen():
        return Path("/opt/EasyPi/backend")
    
    try:
        # This file is at: backend/app/core/paths.py
        # Backend dir is 2 levels up
        return Path(__file__).resolve().parents[2]
    except (IndexError, TypeError):
        return Path("/opt/EasyPi/backend")


@lru_cache(maxsize=1)
def get_easypi_root() -> Path:
    """
    Get EasyPi root directory.
    
    Uses EASYPI_ROOT environment variable if set,
    otherwise falls back to default detection.
    """
    env_root = os.environ.get("EASYPI_ROOT")
    if env_root:
        return Path(env_root)
    return _get_default_root()


@lru_cache(maxsize=1)
def get_backend_dir() -> Path:
    """
    Get backend directory.
    
    Uses EASYPI_BACKEND_DIR environment variable if set,
    otherwise uses $EASYPI_ROOT/backend.
    """
    env_dir = os.environ.get("EASYPI_BACKEND_DIR")
    if env_dir:
        return Path(env_dir)
    
    # Check if EASYPI_ROOT is set
    env_root = os.environ.get("EASYPI_ROOT")
    if env_root:
        return Path(env_root) / "backend"
    
    return _get_default_backend_dir()


@lru_cache(maxsize=1)
def get_data_dir() -> Path:
    """
    Get main data directory ($EASYPI_ROOT/data).
    
    This is for project-level data files like parental.json.
    """
    env_dir = os.environ.get("EASYPI_DATA_DIR")
    if env_dir:
        return Path(env_dir)
    return get_easypi_root() / "data"


@lru_cache(maxsize=1)
def get_backend_data_dir() -> Path:
    """
    Get backend data directory ($EASYPI_ROOT/backend/data).
    
    This is for backend-specific data like services.json.
    """
    env_dir = os.environ.get("EASYPI_BACKEND_DATA_DIR")
    if env_dir:
        return Path(env_dir)
    return get_backend_dir() / "data"


@lru_cache(maxsize=1)
def get_scripts_dir() -> Path:
    """Get scripts directory."""
    env_dir = os.environ.get("EASYPI_SCRIPTS_DIR")
    if env_dir:
        return Path(env_dir)
    return get_easypi_root() / "scripts"


@lru_cache(maxsize=1)
def get_logs_dir() -> Path:
    """Get logs directory."""
    env_dir = os.environ.get("EASYPI_LOGS_DIR")
    if env_dir:
        return Path(env_dir)
    return get_easypi_root() / "logs"


@lru_cache(maxsize=1)
def get_privileged_logs_dir() -> Path:
    """Get the root-owned log directory readable by the EasyPi service group."""
    env_dir = os.environ.get("EASYPI_PRIVILEGED_LOGS_DIR")
    if env_dir:
        return Path(env_dir)
    return Path("/var/log/easypi")


@lru_cache(maxsize=1)
def get_config_dir() -> Path:
    """Get config directory."""
    env_dir = os.environ.get("EASYPI_CONFIG_DIR")
    if env_dir:
        return Path(env_dir)
    return get_easypi_root() / "config"


@lru_cache(maxsize=1)
def get_env_file() -> Path:
    """Get .env file path."""
    # Check in root first, then backend
    root_env = get_easypi_root() / ".env"
    if root_env.exists():
        return root_env
    
    backend_env = get_backend_dir() / ".env"
    if backend_env.exists():
        return backend_env
    
    # Default to root
    return root_env


def get_templates_dir() -> Path:
    """Get templates directory."""
    return get_easypi_root() / "templates"


def get_user_data_dir() -> Path:
    """Get user data directory (avatars, etc.)."""
    return get_data_dir() / "user"


def get_netprotection_data_dir() -> Path:
    """Get NetProtection data directory."""
    return get_data_dir() / "netprotection"


def get_picloud_data_dir() -> Path:
    """Get PiCloud data directory."""
    return get_backend_data_dir() / "picloud"


def get_db_dir() -> Path:
    """Get database directory."""
    return get_data_dir() / "db"


def ensure_directories() -> None:
    """Create all required directories if they don't exist."""
    dirs = [
        get_data_dir(),
        get_backend_data_dir(),
        get_logs_dir(),
        get_user_data_dir(),
        get_db_dir(),
        get_logs_dir() / "tasks",
    ]
    
    for d in dirs:
        d.mkdir(parents=True, exist_ok=True)


# Convenience exports
EASYPI_ROOT = get_easypi_root()
BACKEND_DIR = get_backend_dir()
DATA_DIR = get_data_dir()
BACKEND_DATA_DIR = get_backend_data_dir()
SCRIPTS_DIR = get_scripts_dir()
LOGS_DIR = get_logs_dir()
CONFIG_DIR = get_config_dir()


def is_frozen() -> bool:
    """Public check if running as PyInstaller bundle."""
    return _is_frozen()
