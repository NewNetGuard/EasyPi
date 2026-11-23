"""Secure VPS deployment for the standalone Chameleon Mobile Link relay."""

from __future__ import annotations

import asyncio
import json
import logging
import os
import secrets
import shlex
import stat
import subprocess
from pathlib import Path
from typing import Any

import paramiko

from app.core.paths import get_data_dir, get_easypi_root, get_scripts_dir
from app.services.mobile_link_agent_service import MobileLinkAgentError, mobile_link_agent_service
from app.services.remote_access.tailscale_relay_service import (
    RelayBusyError,
    RelayOperationError,
    TailscaleRelayService,
    _utc_now,
)
from app.utils.ssh_host_trust import SSHHostTrustError, SSHHostTrustStore

logger = logging.getLogger("easypi.mobile_link_relay")
_SECRET_SCRIPT_REL = "settings/mobile_link_relay_secrets.sh"


class MobileLinkRelayService(TailscaleRelayService):
    """Deploy only the Mobile Link relay while reusing hardened SSH plumbing."""

    def __init__(self) -> None:
        super().__init__(
            state_path=Path(get_data_dir()) / "user" / "mobile_link_relay.json",
            script_path=Path(get_scripts_dir()) / "services" / "chameleon_mobile_link_relay.sh",
            trust_store=SSHHostTrustStore(
                Path(get_data_dir()) / "ssh-trust" / "mobile-link-relay-host-keys.json"
            ),
        )
        try:
            self._repair_existing_trust_store_permissions(self.trust_store)
        except (OSError, SSHHostTrustError):
            logger.warning("Mobile Link SSH trust-store permissions could not be repaired", exc_info=True)
        self.binary_path = Path(get_easypi_root()) / "bin" / "chameleon-mobile-link-relay-amd64"

    @staticmethod
    def _repair_existing_trust_store_permissions(trust_store: SSHHostTrustStore) -> None:
        """Repair installer-widened modes without accepting unsafe paths or owners."""
        expected_uid = os.geteuid() if hasattr(os, "geteuid") else None
        directory = trust_store.path.parent
        if not directory.exists():
            return
        directory_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        directory_fd = os.open(directory, directory_flags)
        try:
            directory_info = os.fstat(directory_fd)
            if not stat.S_ISDIR(directory_info.st_mode):
                raise SSHHostTrustError("SSH trust-store directory is unsafe")
            if expected_uid is not None and directory_info.st_uid != expected_uid:
                raise SSHHostTrustError("SSH trust-store directory has an unexpected owner")
            os.fchmod(directory_fd, 0o700)
        finally:
            os.close(directory_fd)

        for path in (trust_store.path, trust_store.lock_path):
            if not path.exists():
                continue
            file_flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
            file_fd = os.open(path, file_flags)
            try:
                file_info = os.fstat(file_fd)
                if not stat.S_ISREG(file_info.st_mode):
                    raise SSHHostTrustError("SSH trust-store path is unsafe")
                if expected_uid is not None and file_info.st_uid != expected_uid:
                    raise SSHHostTrustError("SSH trust-store path has an unexpected owner")
                os.fchmod(file_fd, 0o600)
            finally:
                os.close(file_fd)

    def _default_state(self) -> dict[str, Any]:
        return {
            "version": 1,
            "configured": False,
            "installed": False,
            "enabled": False,
            "active": False,
            "host": None,
            "ssh_port": 22,
            "ssh_user": "root",
            "credential_configured": False,
            "credential_type": None,
            "credential_protection": None,
            "host_key_trusted": False,
            "domain": None,
            "agent_port": 9443,
            "mobile_port": 9444,
            "last_checked_at": None,
            "last_error": None,
        }

    def _secret_command(self, action: str, name: str, value: str | None = None) -> str:
        command = [
            "sudo", "-n", str(Path(get_scripts_dir()) / "runner"),
            _SECRET_SCRIPT_REL, action, name,
        ]
        try:
            completed = subprocess.run(
                command,
                input=None if value is None else value.encode("utf-8"),
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=20,
                check=False,
            )
        except Exception as exc:
            raise RelayOperationError("Secure Mobile Link SSH credential storage is unavailable") from exc
        if completed.returncode != 0:
            raise RelayOperationError("Secure Mobile Link SSH credential storage rejected the operation")
        return completed.stdout.decode("utf-8", errors="strict").rstrip("\n")

    def public_status(self) -> dict[str, Any]:
        try:
            state = self.load_state()
        except RelayOperationError:
            # Never trust or parse an unsafe state file, but a status card must
            # not take down the entire Mobile Assistant page.  The installer
            # repairs private state modes during a signed update.
            logger.warning("Mobile Link relay state failed its security checks", exc_info=True)
            state = self._default_state()
            state["last_error"] = (
                "Mobile Link relay state is unavailable; run a signed EasyPi update to repair it"
            )
        state["host_key_trusted"] = self._host_key_trusted(
            state.get("host"), int(state.get("ssh_port") or 22)
        )
        return state

    def _host_key_trusted(self, host: str | None, port: int) -> bool:
        if not host:
            return False
        try:
            self.trust_store.pinned_key(host, port)
            return True
        except (SSHHostTrustError, ValueError):
            return False

    @staticmethod
    def _parse_result(stdout: str) -> dict[str, Any]:
        line = next(
            (item for item in reversed(stdout.splitlines()) if item.startswith("EASYPI_MOBILE_LINK_RESULT ")),
            None,
        )
        if line is None:
            raise RelayOperationError("The VPS did not return a valid Mobile Link status")
        result: dict[str, str] = {}
        for token in shlex.split(line.removeprefix("EASYPI_MOBILE_LINK_RESULT ")):
            key, separator, value = token.partition("=")
            if separator:
                result[key] = value
        return {
            "installed": result.get("installed") == "true",
            "enabled": result.get("enabled") == "true",
            "active": result.get("active") == "true",
            "agent_port": int(result.get("agent_port") or 9443),
            "mobile_port": int(result.get("mobile_port") or 9444),
            "domain": result.get("domain") or None,
        }

    def _run_remote(
        self,
        *,
        action: str,
        host: str,
        port: int,
        user: str,
        password: str | None,
        private_key: str | None,
        domain: str = "",
        agent_port: int = 9443,
        mobile_port: int = 9444,
    ) -> dict[str, Any]:
        if action not in {"deploy", "status", "restart", "disable", "uninstall"}:
            raise RelayOperationError("Unsupported Mobile Link relay operation")
        try:
            script = self.script_path.read_bytes()
        except OSError as exc:
            raise RelayOperationError("Mobile Link relay installer is missing") from exc
        binary = b""
        registration: dict[str, str] | None = None
        if action == "deploy":
            try:
                binary = self.binary_path.read_bytes()
                installation_id, transport_secret, tunnel_id, tunnel_secret = mobile_link_agent_service.registration()
            except (OSError, MobileLinkAgentError) as exc:
                raise RelayOperationError("Configure the local Mobile Link agent before deploying the VPS") from exc
            registration = {
                "domain": domain,
                "agent_port": str(agent_port),
                "mobile_port": str(mobile_port),
                "installation_id": installation_id,
                "secret": transport_secret,
                "tunnel_installation_id": tunnel_id,
                "tunnel_secret": tunnel_secret,
            }
        client = self._connect(
            host=host, port=port, user=user, password=password, private_key=private_key
        )
        token = secrets.token_hex(16)
        remote_script = f"/tmp/easypi-mobile-link-{token}.sh"
        remote_config = f"/tmp/easypi-mobile-link-{token}.json"
        remote_binary = f"/tmp/easypi-mobile-link-{token}.bin"
        try:
            prefix = self._privilege_prefix(client)
            sftp = client.open_sftp()
            try:
                with sftp.file(remote_script, "wb") as handle:
                    handle.write(script)
                sftp.chmod(remote_script, 0o700)
                if action == "deploy" and registration is not None:
                    with sftp.file(remote_config, "w") as handle:
                        handle.write(json.dumps(registration, separators=(",", ":")))
                    sftp.chmod(remote_config, 0o600)
                    with sftp.file(remote_binary, "wb") as handle:
                        handle.write(binary)
                    sftp.chmod(remote_binary, 0o700)
            finally:
                sftp.close()
            arguments = ""
            if action == "deploy":
                arguments = f" {shlex.quote(remote_config)} {shlex.quote(remote_binary)}"
            command = (
                f"{prefix}timeout --signal=TERM --kill-after=15s 360s "
                f"bash {shlex.quote(remote_script)} {shlex.quote(action)}{arguments}"
            )
            stdout, stderr, exit_code = self._read_command(client, command, timeout=390)
            if exit_code != 0:
                message = next(
                    (
                        line.removeprefix("EASYPI_MOBILE_LINK_ERROR:").strip()
                        for line in reversed(stderr.splitlines())
                        if line.startswith("EASYPI_MOBILE_LINK_ERROR:")
                    ),
                    "Mobile Link relay operation failed on the VPS",
                )
                raise RelayOperationError(message)
            return self._parse_result(stdout)
        except RelayOperationError:
            raise
        except (OSError, EOFError, paramiko.SSHException) as exc:
            raise RelayOperationError("Could not stage the Mobile Link relay operation") from exc
        finally:
            try:
                self._read_command(
                    client,
                    f"rm -f -- {shlex.quote(remote_script)} {shlex.quote(remote_config)} {shlex.quote(remote_binary)}",
                    timeout=15,
                )
            except RelayOperationError:
                logger.warning("Could not remove temporary Mobile Link files from %s", host)
            client.close()

    async def operate(self, action: str, **request: Any) -> dict[str, Any]:
        if self._operation_lock.locked():
            raise RelayBusyError("Another Mobile Link relay operation is already running")
        async with self._operation_lock:
            previous = self.load_state()
            try:
                remote = await asyncio.to_thread(self._run_remote, action=action, **request)
                stored = self._store_credentials(
                    password=request.get("password"), private_key=request.get("private_key")
                )
                if action == "uninstall":
                    self._delete_credentials()
                    state = self._default_state()
                else:
                    state = {**self._default_state(), **previous, **remote}
                    state.update({
                        "configured": True,
                        "host": request["host"],
                        "ssh_port": request["port"],
                        "ssh_user": request["user"],
                        "host_key_trusted": True,
                    })
                    if stored:
                        state.update({
                            "credential_configured": True,
                            "credential_type": stored[0],
                            "credential_protection": stored[1],
                        })
                state["last_checked_at"] = _utc_now()
                state["last_error"] = None
                self._save_state(state)
                return state
            except RelayOperationError as exc:
                failed = dict(previous)
                failed["last_checked_at"] = _utc_now()
                failed["last_error"] = str(exc)
                self._save_state(failed)
                raise
mobile_link_relay_service = MobileLinkRelayService()
