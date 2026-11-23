"""
Stealth VPN service (Privacy -> Stealth, anti-DPI / Chameleon engine).

Full self-service model mirroring the Chameleon Android app's three tabs:

* Client  — generate the PSK and public visibility marker locally, plus client settings
            (shield preset, DoH, buffer, reconnect). No keys to obtain externally.
* Server  — SSH into the user's VPS and deploy + start ``chameleon-server`` with the
            SAME keys (so client and server match without any manual copying).
* Profile — live status / stats / runtime log.

The headless ``chameleon-client`` daemon owns cham0; the root-owned
``scripts/settings/stealth_vpn.sh`` (via the secure runner) runs it and wires the
policy routing + kill-switch on its OWN table (51821) / chain (EASYPI_STEALTH),
so Stealth coexists with the outbound VPN ([[vpn-outbound-client-plan]]).
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import io
import ipaddress
import json
import logging
import os
import posixpath
import re
import socket
import ssl
import subprocess
import time
from functools import wraps
from pathlib import Path
from typing import Any, Dict, List, Optional

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from app.core.paths import get_easypi_root, get_netprotection_data_dir
from app.services.routing_conflict_service import detect_routing_conflict, routing_claim
from app.utils.network_security import require_public_ipv4

logger = logging.getLogger(__name__)

CONFIG_NAME = "stealth_client.conf"
META_NAME = "stealth_meta.json"
SCRIPT_REL = "settings/stealth_vpn.sh"
SECRET_SCRIPT_REL = "settings/stealth_secrets.sh"
SERVER_BIN = "/opt/EasyPi/bin/chameleon-server-amd64"  # uploaded to the VPS
REMOTE_SERVER_DIR = "/opt/chameleon-server"
# VPS nginx maintenance tool (chameleon/server/nginx) and its patch.
NGINX_TOOL = "/usr/local/sbin/easypi-chameleon-nginx"
NGINX_TOOL_SHARE = "/usr/local/share/easypi-chameleon-nginx"
NGINX_PATCH_NAME = "h2-unbuffered-window-update-threshold.patch"
CLIENT_LOG = "/var/log/easypi/stealth.log"

_HEX32 = re.compile(r"^[0-9a-fA-F]{64}$")
_DUCKDNS_DOMAIN = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.duckdns\.org$")


class _DeploymentLease:
    """Advisory inter-process lease held for the lifetime of a VPS mutation."""

    def __init__(self, path: Path, operation: str) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        flags = (
            os.O_RDWR
            | os.O_CREAT
            | getattr(os, "O_CLOEXEC", 0)
            | getattr(os, "O_NOFOLLOW", 0)
        )
        self.fd = os.open(path, flags, 0o600)
        try:
            if hasattr(os, "fchmod"):
                try:
                    os.fchmod(self.fd, 0o600)
                except OSError:
                    pass
            if os.name == "nt":
                import msvcrt

                os.lseek(self.fd, 0, os.SEEK_SET)
                if os.fstat(self.fd).st_size == 0:
                    os.write(self.fd, b"\0")
                os.lseek(self.fd, 0, os.SEEK_SET)
                msvcrt.locking(self.fd, msvcrt.LK_NBLCK, 1)
                self._unlock = lambda: msvcrt.locking(self.fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                self._unlock = lambda: fcntl.flock(self.fd, fcntl.LOCK_UN)
            payload = json.dumps(
                {
                    "pid": os.getpid(),
                    "operation": operation,
                    "started_at": int(time.time()),
                }
            )
            os.ftruncate(self.fd, 0)
            os.lseek(self.fd, 0, os.SEEK_SET)
            os.write(self.fd, payload.encode("utf-8"))
            os.fsync(self.fd)
        except Exception:
            os.close(self.fd)
            raise

    def close(self) -> None:
        if self.fd < 0:
            return
        try:
            os.lseek(self.fd, 0, os.SEEK_SET)
            self._unlock()
        finally:
            os.close(self.fd)
            self.fd = -1


def _deployment_locked(operation: str):
    def decorator(func):
        @wraps(func)
        async def wrapped(self, *args, **kwargs):
            try:
                lease = _DeploymentLease(
                    self._data_dir / ".stealth-deployment.lock", operation
                )
            except (BlockingIOError, OSError):
                return {
                    "success": False,
                    "busy": True,
                    "log": "Another Stealth Deployment operation is already running. Wait for it to finish.",
                }
            try:
                return await func(self, *args, **kwargs)
            finally:
                lease.close()

        return wrapped

    return decorator


def _gen_psk() -> str:
    return os.urandom(32).hex()


def _gen_x25519_public() -> str:
    """Return a public marker value; the unused X25519 private value is discarded."""
    priv = X25519PrivateKey.generate()
    pub_raw = priv.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return pub_raw.hex()


def _normalize_server_addr(addr: str) -> str:
    """The tunnel endpoint is host:443 by default. Append :443 when no port is
    given, and rewrite the SSH port :22 (a common mix-up) to :443 — :22 is never
    the REALITY listener."""
    addr = (addr or "").strip().rstrip("/")
    for pre in ("https://", "http://"):
        if addr.startswith(pre):
            addr = addr[len(pre) :]
    if not addr:
        return ""
    m = re.search(r":(\d+)$", addr)
    if not m:
        return addr + ":443"
    if m.group(1) == "22":
        return addr[: m.start()] + ":443"
    return addr


def _friendly_ssh_err(err: str) -> str:
    low = err.lower()
    if any(
        k in low for k in ("not allowed", "reset", "eof during negotiation", "banner")
    ):
        return (
            " — the VPS is rate-limiting new SSH connections (OpenSSH 10 "
            "PerSourcePenalties). Wait ~2-3 minutes, then click Deploy ONCE — "
            "don't repeat Check/Deploy quickly."
        )
    if "authentication" in low:
        return " — check the saved SSH credentials."
    return ""


__all__ = [
    "Any",
    "CLIENT_LOG",
    "CONFIG_NAME",
    "Dict",
    "Ed25519PrivateKey",
    "List",
    "META_NAME",
    "NGINX_PATCH_NAME",
    "NGINX_TOOL",
    "NGINX_TOOL_SHARE",
    "Optional",
    "Path",
    "REMOTE_SERVER_DIR",
    "SCRIPT_REL",
    "SECRET_SCRIPT_REL",
    "SERVER_BIN",
    "X25519PrivateKey",
    "_DUCKDNS_DOMAIN",
    "_DeploymentLease",
    "_HEX32",
    "_deployment_locked",
    "_friendly_ssh_err",
    "_gen_psk",
    "_gen_x25519_public",
    "_normalize_server_addr",
    "asyncio",
    "base64",
    "detect_routing_conflict",
    "get_easypi_root",
    "get_netprotection_data_dir",
    "hashlib",
    "hmac",
    "httpx",
    "io",
    "ipaddress",
    "json",
    "logger",
    "logging",
    "os",
    "posixpath",
    "re",
    "require_public_ipv4",
    "routing_claim",
    "serialization",
    "socket",
    "ssl",
    "subprocess",
    "time",
    "wraps",
]
