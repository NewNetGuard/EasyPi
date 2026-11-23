"""Privileged lifecycle bridge for the local Mobile Link agent."""

from __future__ import annotations

import json
import re
import subprocess
from typing import Any

from app.core.paths import get_scripts_dir


class MobileLinkAgentError(RuntimeError):
    """A safe Mobile Link lifecycle error suitable for the admin UI."""


class MobileLinkAgentService:
    def __init__(self) -> None:
        scripts = get_scripts_dir()
        self.runner = scripts / "runner"
        self.script = "settings/mobile_link_agent.sh"

    def run(self, action: str, *arguments: str) -> dict[str, Any]:
        if action not in {"configure", "enable", "disable", "status", "rotate-secret", "registration", "ensure-endpoint", "ensure-home", "home-profile"}:
            raise MobileLinkAgentError("Unsupported Mobile Link action")
        command = ["sudo", "-n", str(self.runner), self.script, action, *arguments]
        try:
            completed = subprocess.run(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=30,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise MobileLinkAgentError("Mobile Link service control is unavailable") from exc
        if completed.returncode != 0:
            # Never expose runner output: it may contain host details or future
            # diagnostics that are inappropriate for an API response.
            raise MobileLinkAgentError("Mobile Link service rejected the operation")
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError as exc:
            raise MobileLinkAgentError("Mobile Link service returned an invalid status") from exc
        if not isinstance(payload, dict):
            raise MobileLinkAgentError("Mobile Link service returned an invalid status")
        return payload

    def home_profile(self, device_id: str, address: str, server_name: str, port: int) -> dict[str, Any]:
        payload = self.run("home-profile", device_id, address, server_name, str(port))
        required = {
            "address", "server_address", "server_dial_address", "psk_key", "transport_key",
            "reality_server_public_key", "prism_link_relay_address", "prism_link_relay_installation_id",
            "prism_link_relay_route_key",
        }
        if not required.issubset(payload):
            raise MobileLinkAgentError("Mobile home tunnel profile is unavailable")
        return payload

    def registration(self) -> tuple[str, str, str, str]:
        payload = self.run("registration")
        installation_id = payload.get("installation_id")
        secret = payload.get("secret")
        tunnel_installation_id = payload.get("tunnel_installation_id")
        tunnel_secret = payload.get("tunnel_secret")
        if (
            not isinstance(installation_id, str)
            or re.fullmatch(r"[0-9a-f]{32}", installation_id) is None
            or not isinstance(secret, str)
            or re.fullmatch(r"[0-9a-f]{64}", secret) is None
            or not isinstance(tunnel_installation_id, str)
            or re.fullmatch(r"[0-9a-f]{32}", tunnel_installation_id) is None
            or not isinstance(tunnel_secret, str)
            or re.fullmatch(r"[0-9a-f]{64}", tunnel_secret) is None
        ):
            raise MobileLinkAgentError("Mobile Link registration is unavailable")
        return installation_id, secret, tunnel_installation_id, tunnel_secret


mobile_link_agent_service = MobileLinkAgentService()
