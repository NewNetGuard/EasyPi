"""Loopback verdict channel for EasyPi Mobile's on-phone PRISM.

Outside the home tunnel a linked phone filters its own traffic and asks the
EasyPi backend for a decision on every new domain. The backend forwards that
question here so the phone gets the complete NetProtection policy (schedules,
parental categories, streaming rules, shadow-mode blocks, heuristics, ...)
instead of a reduced copy.

The channel is a Unix socket inside the NetProtection data directory, so only
processes running as the EasyPi service account can reach it; nothing listens
on the network. A caller may only ask on behalf of an enrolled home-tunnel
phone address, which the server resolves to that phone's identity exactly as
it does for the phone's own DNS queries.
"""

from __future__ import annotations

import logging
import os
import re
import stat
from pathlib import Path
from typing import Awaitable, Callable

from aiohttp import web

logger = logging.getLogger(__name__)

SOCKET_NAME = "verdict.sock"
VERDICT_PATH = "/v1/mobile-verdict"
MAX_REQUEST_BYTES = 1024

_LABEL = re.compile(r"(?!-)[a-z0-9-]{1,63}(?<!-)")

# (domain, client_ip) -> (blocked, status) for a phone the server recognises,
# or None when client_ip is not an enrolled home-tunnel phone.
Resolver = Callable[[str, str], Awaitable["tuple[bool, str] | None"]]


def normalize_domain(value: object) -> str | None:
    """Return a lowercase ASCII hostname, or None when it is not one."""
    if not isinstance(value, str):
        return None
    name = value.strip().rstrip(".").lower()
    if not name or len(name) > 253 or not name.isascii():
        return None
    labels = name.split(".")
    if len(labels) < 2 or not all(_LABEL.fullmatch(label) for label in labels):
        return None
    return name


class MobileVerdictListener:
    """Serves POST /v1/mobile-verdict on a private Unix socket."""

    def __init__(self, data_dir: str | Path, resolver: Resolver):
        self._path = Path(data_dir) / SOCKET_NAME
        self._resolver = resolver
        self._runner: web.AppRunner | None = None

    @property
    def path(self) -> Path:
        return self._path

    def build_app(self) -> web.Application:
        app = web.Application(client_max_size=MAX_REQUEST_BYTES)
        app.router.add_post(VERDICT_PATH, self._handle)
        return app

    async def start(self) -> None:
        self._remove_stale_socket()
        self._runner = web.AppRunner(self.build_app(), access_log=None)
        await self._runner.setup()
        previous = os.umask(0o177)
        try:
            await web.UnixSite(self._runner, str(self._path)).start()
        finally:
            os.umask(previous)
        os.chmod(self._path, 0o600)
        logger.info("Mobile verdict socket started on %s", self._path)

    async def stop(self) -> None:
        if self._runner is not None:
            await self._runner.cleanup()
            self._runner = None
        self._remove_stale_socket()

    def _remove_stale_socket(self) -> None:
        try:
            info = self._path.lstat()
        except FileNotFoundError:
            return
        if not stat.S_ISSOCK(info.st_mode):
            raise RuntimeError(f"Refusing to replace non-socket {self._path}")
        self._path.unlink()

    async def _handle(self, request: web.Request) -> web.Response:
        try:
            payload = await request.json()
        except Exception:
            return web.json_response({"error": "invalid request"}, status=400)
        if not isinstance(payload, dict) or set(payload) != {"domain", "client_ip"}:
            return web.json_response({"error": "invalid request"}, status=400)
        domain = normalize_domain(payload.get("domain"))
        client_ip = payload.get("client_ip")
        if domain is None or not isinstance(client_ip, str):
            return web.json_response({"error": "invalid request"}, status=400)
        try:
            outcome = await self._resolver(domain, client_ip)
        except Exception:
            logger.exception("Mobile verdict failed")
            return web.json_response({"error": "verdict unavailable"}, status=503)
        if outcome is None:
            return web.json_response({"error": "unknown mobile client"}, status=403)
        blocked, status = outcome
        return web.json_response({"domain": domain, "blocked": blocked, "status": status})
