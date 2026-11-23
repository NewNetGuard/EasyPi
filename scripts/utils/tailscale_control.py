#!/usr/bin/python3
from __future__ import annotations

import ipaddress
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

MAX_REQUEST_BYTES = 16 * 1024
AUTH_KEY_RE = re.compile(
    r"^tskey-(?!(?:api|client|scim|webhook)-)[A-Za-z0-9_-]{16,480}$"
)
HOSTNAME_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
TAILSCALE_PATHS = (Path("/usr/bin/tailscale"), Path("/usr/sbin/tailscale"))


def fail(message: str) -> None:
    raise SystemExit(f"ERROR: {message}")


def read_request() -> dict[str, Any]:
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        fail("request is too large")
    try:
        value = json.loads(raw)
    except (UnicodeDecodeError, json.JSONDecodeError):
        fail("request must be valid JSON")
    if not isinstance(value, dict):
        fail("request must be a JSON object")
    return value


def require_keys(request: dict[str, Any], allowed: set[str]) -> None:
    unknown = set(request) - allowed
    if unknown:
        fail(f"unsupported fields: {', '.join(sorted(unknown))}")


def boolean(request: dict[str, Any], name: str, default: bool = False) -> bool:
    value = request.get(name, default)
    if not isinstance(value, bool):
        fail(f"{name} must be boolean")
    return value


def routes(request: dict[str, Any]) -> list[str]:
    value = request.get("routes", [])
    if not isinstance(value, list) or len(value) > 32:
        fail("routes must be a list with at most 32 entries")
    result: list[str] = []
    for item in value:
        if not isinstance(item, str):
            fail("each route must be a CIDR string")
        try:
            network = ipaddress.ip_network(item, strict=True)
        except ValueError:
            fail(f"invalid route: {item}")
        canonical = str(network)
        if canonical in result:
            fail(f"duplicate route: {item}")
        result.append(canonical)
    return result


def tailscale_binary() -> str:
    for path in TAILSCALE_PATHS:
        try:
            details = path.stat()
        except OSError:
            continue
        if (
            path.is_file()
            and details.st_uid == 0
            and details.st_mode & 0o022 == 0
        ):
            return str(path)
    fail("trusted tailscale binary not found")


def build_command(request: dict[str, Any]) -> list[str]:
    action = request.get("action")
    if not isinstance(action, str):
        fail("action is required")

    if action == "status":
        require_keys(request, {"action"})
        return ["status", "--json"]
    if action == "prefs":
        require_keys(request, {"action"})
        return ["debug", "prefs"]
    if action in {"down", "logout"}:
        require_keys(request, {"action"})
        return [action]
    if action == "funnel":
        require_keys(request, {"action", "port", "off"})
        if boolean(request, "off"):
            if "port" in request:
                fail("port cannot be combined with off")
            return ["funnel", "off"]
        port = request.get("port")
        if not isinstance(port, int) or isinstance(port, bool) or not 1 <= port <= 65535:
            fail("port must be between 1 and 65535")
        return ["funnel", str(port), "--bg"]
    if action == "up":
        require_keys(
            request,
            {
                "action",
                "auth_key",
                "routes",
                "accept_routes",
                "advertise_exit_node",
                "accept_dns",
                "hostname",
                "timeout",
                "reset",
            },
        )
        command = ["up"]
        auth_key = request.get("auth_key")
        if auth_key is not None:
            if not isinstance(auth_key, str) or not AUTH_KEY_RE.fullmatch(auth_key):
                fail("invalid Tailscale auth key")
            command.append(f"--authkey={auth_key}")
        if "routes" in request:
            command.append(f"--advertise-routes={','.join(routes(request))}")
        if "accept_routes" in request:
            command.append(
                f"--accept-routes={str(boolean(request, 'accept_routes')).lower()}"
            )
        if "advertise_exit_node" in request:
            command.append(
                f"--advertise-exit-node={str(boolean(request, 'advertise_exit_node')).lower()}"
            )
        if "accept_dns" in request:
            command.append(f"--accept-dns={str(boolean(request, 'accept_dns')).lower()}")
        hostname = request.get("hostname")
        if hostname is not None:
            if not isinstance(hostname, str) or not HOSTNAME_RE.fullmatch(hostname):
                fail("invalid hostname")
            command.append(f"--hostname={hostname}")
        timeout = request.get("timeout", 30)
        if timeout not in {5, 30, 60}:
            fail("timeout must be 5, 30, or 60 seconds")
        command.append(f"--timeout={timeout}s")
        if boolean(request, "reset"):
            command.append("--reset")
        return command
    if action == "set":
        require_keys(
            request,
            {
                "action",
                "routes",
                "accept_routes",
                "advertise_exit_node",
                "accept_dns",
            },
        )
        command = ["set"]
        changed = False
        if "routes" in request:
            command.append(f"--advertise-routes={','.join(routes(request))}")
            changed = True
        if "accept_routes" in request:
            enabled = boolean(request, "accept_routes")
            command.append(f"--accept-routes={str(enabled).lower()}")
            changed = True
        if "advertise_exit_node" in request:
            enabled = boolean(request, "advertise_exit_node")
            command.append(f"--advertise-exit-node={str(enabled).lower()}")
            changed = True
        if "accept_dns" in request:
            enabled = boolean(request, "accept_dns")
            command.append(f"--accept-dns={str(enabled).lower()}")
            changed = True
        if not changed:
            fail("set requires at least one setting")
        return command

    fail("unsupported action")


def protect_auth_key_argument(command: list[str]) -> str | None:
    """Replace a plaintext auth-key argument with a root-only file reference."""
    for index, argument in enumerate(command):
        if not argument.startswith("--authkey="):
            continue

        auth_key = argument.split("=", 1)[1]
        fd, path = tempfile.mkstemp(prefix="easypi-tailscale-auth.", dir="/run")
        try:
            os.fchmod(fd, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                fd = -1
                handle.write(auth_key)
                handle.flush()
                os.fsync(handle.fileno())
        except Exception:
            if fd >= 0:
                os.close(fd)
            Path(path).unlink(missing_ok=True)
            raise

        command[index] = f"--authkey=file:{path}"
        return path
    return None


def main() -> None:
    request = read_request()
    command = [tailscale_binary(), *build_command(request)]
    auth_key_path = protect_auth_key_argument(command)
    env = {
        "PATH": "/usr/sbin:/usr/bin:/sbin:/bin",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "HOME": "/root",
    }
    try:
        result = subprocess.run(
            command,
            stdin=subprocess.DEVNULL,
            env=env,
            check=False,
            timeout=90,
        )
    except subprocess.TimeoutExpired:
        fail("tailscale command timed out")
    finally:
        if auth_key_path:
            Path(auth_key_path).unlink(missing_ok=True)
    raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
