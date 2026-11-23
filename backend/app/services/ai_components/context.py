"""
AI Service

Handles Ollama integration, installation, and chat functionality.
"""

import os
import re
import logging
import json
import asyncio
import uuid
import subprocess
from app.utils.time import utc_now
from pathlib import Path
from typing import Optional, AsyncGenerator, List

import httpx
from sqlalchemy import text
from sqlalchemy.orm import Session
from fastapi.concurrency import run_in_threadpool


from app.models.ai import AIConversation, AIConfig
from app.schemas.ai import (
    ChatResponse,
    AIInstallStatus,
    AIModelInfo,
    AISettingsUpdate,
)
from app.core.installer import (
    create_install_job,
    start_install_job,
    get_installer_log_path,
    read_installer_log,
)
from config import get_settings

logger = logging.getLogger(__name__)


__all__ = [
    "AIConfig",
    "AIConversation",
    "AIInstallStatus",
    "AIModelInfo",
    "AISettingsUpdate",
    "AsyncGenerator",
    "ChatResponse",
    "List",
    "Optional",
    "Path",
    "Session",
    "asyncio",
    "create_install_job",
    "get_installer_log_path",
    "get_settings",
    "httpx",
    "json",
    "logger",
    "logging",
    "os",
    "re",
    "read_installer_log",
    "run_in_threadpool",
    "start_install_job",
    "subprocess",
    "text",
    "utc_now",
    "uuid",
]
