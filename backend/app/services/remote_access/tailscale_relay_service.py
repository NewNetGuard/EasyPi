"""Secure deployment and lifecycle management for a Tailscale Peer Relay VPS."""

from __future__ import annotations

import asyncio
import io
import json
import logging
import os
import secrets
import shlex
import stat
import subprocess
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import paramiko

from app.core.paths import get_data_dir, get_scripts_dir
from app.utils.ssh_host_trust import SSHHostTrustError, SSHHostTrustStore


logger = logging.getLogger("easypi.tailscale_relay")
_MAX_STATE_BYTES = 64 * 1024
_MAX_OUTPUT_BYTES = 128 * 1024
_SECRET_SCRIPT_REL = "settings/tailscale_relay_secrets.sh"
_RELAY_TAG = "tag:easypi-relay"


class RelayOperationError(RuntimeError):
    """A safe error that can be shown to an administrator."""


class RelayBusyError(RelayOperationError):
    pass


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_private_key(private_key: str) -> paramiko.PKey:
    for key_class in (paramiko.Ed25519Key, paramiko.ECDSAKey, paramiko.RSAKey):
        try:
            return key_class.from_private_key(io.StringIO(private_key))
        except (paramiko.SSHException, ValueError):
            continue
    raise RelayOperationError("SSH private key is invalid or unsupported")


class TailscaleRelayService:
    """Deploy a relay while keeping its reusable SSH credential encrypted."""

    def __init__(
        self,
        *,
        state_path: Path | None = None,
        script_path: Path | None = None,
        trust_store: SSHHostTrustStore | None = None,
    ) -> None:
        self.state_path = state_path or (Path(get_data_dir()) / "user" / "tailscale_relay.json")
        self.script_path = script_path or (Path(get_scripts_dir()) / "services" / "tailscale_peer_relay.sh")
        self.trust_store = trust_store or SSHHostTrustStore(
            Path(get_data_dir()) / "ssh-trust" / "tailscale-relay-host-keys.json"
        )
        self._operation_lock = asyncio.Lock()

    def _default_state(self) -> dict[str, Any]:
        return {
            "version": 1,
            "configured": False,
            "installed": False,
            "enabled": False,
            "daemon_active": False,
            "listening": False,
            "managed_install": False,
            "firewall_managed": False,
            "isolation_active": False,
            "relay_tagged": False,
            "shields_up": False,
            "host": None,
            "ssh_port": 22,
            "ssh_user": "root",
            "credential_configured": False,
            "credential_type": None,
            "credential_protection": None,
            "host_key_trusted": False,
            "relay_name": "easypi-fast-relay",
            "relay_port": 40000,
            "public_endpoint": None,
            "tailscale_ip": None,
            "tailscale_version": None,
            "policy_grant": None,
            "policy_required": False,
            "last_checked_at": None,
            "last_error": None,
        }

    def load_state(self) -> dict[str, Any]:
        state = self._default_state()
        try:
            info = self.state_path.lstat()
        except FileNotFoundError:
            return state
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise RelayOperationError("Fast Mobile Relay state storage is unsafe")
        if info.st_size > _MAX_STATE_BYTES:
            raise RelayOperationError("Fast Mobile Relay state is invalid")
        if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
            raise RelayOperationError("Fast Mobile Relay state permissions are too broad")
        try:
            saved = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RelayOperationError("Fast Mobile Relay state is corrupted") from exc
        if not isinstance(saved, dict) or saved.get("version") != 1:
            raise RelayOperationError("Fast Mobile Relay state schema is invalid")
        state.update(saved)
        # Secrets are never valid state fields, even if a hand-edited file adds them.
        for forbidden in ("ssh_password", "ssh_key", "auth_key", "password", "private_key"):
            state.pop(forbidden, None)
        return state

    def _save_state(self, state: dict[str, Any]) -> None:
        clean = self._default_state()
        clean.update(state)
        clean["version"] = 1
        for forbidden in ("ssh_password", "ssh_key", "auth_key", "password", "private_key"):
            clean.pop(forbidden, None)
        payload = (json.dumps(clean, sort_keys=True, indent=2) + "\n").encode("utf-8")
        if len(payload) > _MAX_STATE_BYTES:
            raise RelayOperationError("Fast Mobile Relay state is too large")
        directory = self.state_path.parent
        directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        if directory.is_symlink():
            raise RelayOperationError("Fast Mobile Relay state directory is unsafe")
        if os.name != "nt":
            os.chmod(directory, 0o700)
        descriptor, temporary_name = tempfile.mkstemp(prefix=".tailscale-relay.", dir=directory)
        temporary = Path(temporary_name)
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(descriptor, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as handle:
                handle.write(payload)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(temporary, self.state_path)
            if os.name != "nt":
                os.chmod(self.state_path, 0o600)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise

    @staticmethod
    def _policy_grant() -> str:
        return json.dumps(
            {
                "tagOwners": {_RELAY_TAG: ["autogroup:admin"]},
                "grants": [
                    {
                        "src": ["autogroup:member"],
                        "dst": ["autogroup:self"],
                        "ip": ["*"],
                    },
                    {
                        "src": ["autogroup:member"],
                        "dst": ["autogroup:internet"],
                        "ip": ["*"],
                    },
                    {
                        "src": ["autogroup:member"],
                        "dst": [_RELAY_TAG],
                        "app": {"tailscale.com/cap/relay": []},
                    }
                ],
            },
            indent=2,
        )

    def public_status(self) -> dict[str, Any]:
        state = self.load_state()
        state["host_key_trusted"] = self._host_key_trusted(
            state.get("host"), int(state.get("ssh_port") or 22)
        )
        state["policy_grant"] = self._policy_grant()
        state["policy_required"] = True
        return state

    def _host_key_trusted(self, host: str | None, port: int) -> bool:
        if not host:
            return False
        try:
            self.trust_store.pinned_key(host, port)
            return True
        except (SSHHostTrustError, ValueError):
            return False

    def _secret_command(
        self, action: str, name: str, value: str | None = None
    ) -> str:
        command = [
            "sudo",
            "-n",
            str(Path(get_scripts_dir()) / "runner"),
            _SECRET_SCRIPT_REL,
            action,
            name,
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
            raise RelayOperationError("Secure SSH credential storage is unavailable") from exc
        if completed.returncode != 0:
            raise RelayOperationError("Secure SSH credential storage rejected the operation")
        return completed.stdout.decode("utf-8", errors="strict").rstrip("\n")

    def _secret_store(self, name: str, value: str) -> str:
        self._secret_command("store", name, value)
        return self._secret_command("mode", name)

    def _secret_read(self, name: str) -> str:
        return self._secret_command("read", name)

    def _secret_delete(self, name: str) -> None:
        self._secret_command("delete", name)

    @staticmethod
    def _credential_label(mode: str) -> str:
        return "TPM + system encryption" if "tpm2" in mode else "system encryption"

    def _stored_credentials(
        self, *, host: str, port: int, user: str
    ) -> tuple[str | None, str | None]:
        state = self.load_state()
        matches = (
            state.get("credential_configured")
            and state.get("host") == host
            and int(state.get("ssh_port") or 22) == port
            and state.get("ssh_user") == user
        )
        if not matches:
            raise RelayOperationError(
                "Enter the VPS SSH credential once and test the connection"
            )
        credential_type = state.get("credential_type")
        if credential_type == "password":
            return self._secret_read("ssh-password"), None
        if credential_type == "key":
            return None, self._secret_read("ssh-private-key")
        raise RelayOperationError("The saved VPS SSH credential is unavailable")

    def _store_credentials(
        self, *, password: str | None, private_key: str | None
    ) -> tuple[str, str] | None:
        if not password and not private_key:
            return None
        if password and private_key:
            raise RelayOperationError("Provide only one SSH credential")
        if password:
            mode = self._secret_store("ssh-password", password)
            self._secret_delete("ssh-private-key")
            return "password", self._credential_label(mode)
        mode = self._secret_store("ssh-private-key", private_key or "")
        self._secret_delete("ssh-password")
        return "key", self._credential_label(mode)

    def _delete_credentials(self) -> None:
        self._secret_delete("ssh-password")
        self._secret_delete("ssh-private-key")

    def _connect(
        self,
        *,
        host: str,
        port: int,
        user: str,
        password: str | None,
        private_key: str | None,
    ) -> paramiko.SSHClient:
        if password and private_key:
            raise RelayOperationError("Provide only one SSH credential")
        if not password and not private_key:
            password, private_key = self._stored_credentials(
                host=host, port=port, user=user
            )
        client = paramiko.SSHClient()
        canonical_host, canonical_port = self.trust_store.configure_client(client, host, port)
        kwargs: dict[str, Any] = {
            "hostname": canonical_host,
            "port": canonical_port,
            "username": user,
            "timeout": 30,
            "banner_timeout": 20,
            "auth_timeout": 30,
            "look_for_keys": False,
            "allow_agent": False,
        }
        if private_key:
            kwargs["pkey"] = _parse_private_key(private_key)
        else:
            kwargs["password"] = password
        try:
            client.connect(**kwargs)
        except (OSError, EOFError, paramiko.SSHException) as exc:
            client.close()
            raise RelayOperationError("SSH authentication failed or the VPS is unreachable") from exc
        return client

    @staticmethod
    def _read_command(
        client: paramiko.SSHClient, command: str, *, timeout: int
    ) -> tuple[str, str, int]:
        try:
            _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
            exit_code = stdout.channel.recv_exit_status()
            out = stdout.read(_MAX_OUTPUT_BYTES + 1)
            err = stderr.read(_MAX_OUTPUT_BYTES + 1)
        except (OSError, EOFError, paramiko.SSHException) as exc:
            raise RelayOperationError("The VPS operation did not complete") from exc
        if len(out) > _MAX_OUTPUT_BYTES or len(err) > _MAX_OUTPUT_BYTES:
            raise RelayOperationError("The VPS returned too much output")
        return out.decode("utf-8", "replace"), err.decode("utf-8", "replace"), exit_code

    def _privilege_prefix(self, client: paramiko.SSHClient) -> str:
        stdout, _stderr, exit_code = self._read_command(client, "id -u", timeout=15)
        if exit_code != 0:
            raise RelayOperationError("Could not determine the SSH account privileges")
        if stdout.strip() == "0":
            return ""
        _out, _err, sudo_code = self._read_command(client, "sudo -n true", timeout=15)
        if sudo_code != 0:
            raise RelayOperationError("The SSH account needs passwordless sudo access")
        return "sudo -n "

    def check_connection(self, **credentials: Any) -> dict[str, Any]:
        supplied_password = credentials.get("password")
        supplied_private_key = credentials.get("private_key")
        client = self._connect(**credentials)
        try:
            prefix = self._privilege_prefix(client)
            stdout, _stderr, exit_code = self._read_command(
                client,
                f"{prefix}sh -c 'test -r /etc/os-release && . /etc/os-release && printf \"%s %s\" \"$ID\" \"${{VERSION_ID:-unknown}}\"'",
                timeout=20,
            )
            if exit_code != 0:
                raise RelayOperationError("The VPS operating system could not be identified")
            if stdout.split(maxsplit=1)[0] not in {"debian", "ubuntu"}:
                raise RelayOperationError("Only Debian or Ubuntu VPS systems are supported")
            stored = self._store_credentials(
                password=supplied_password, private_key=supplied_private_key
            )
            state = self.load_state()
            state.update(
                {
                    "host": credentials["host"],
                    "ssh_port": credentials["port"],
                    "ssh_user": credentials["user"],
                    "host_key_trusted": True,
                    "last_checked_at": _utc_now(),
                    "last_error": None,
                }
            )
            if stored:
                state.update(
                    {
                        "credential_configured": True,
                        "credential_type": stored[0],
                        "credential_protection": stored[1],
                    }
                )
            self._save_state(state)
            return {
                "success": True,
                "message": "SSH connection and privileges verified",
                "os": stdout.strip(),
                "credential_configured": bool(state.get("credential_configured")),
                "credential_type": state.get("credential_type"),
                "credential_protection": state.get("credential_protection"),
            }
        finally:
            client.close()

    @staticmethod
    def _config_text(config: dict[str, Any]) -> str:
        values = {
            "RELAY_NAME": config.get("relay_name", "easypi-fast-relay"),
            "RELAY_PORT": str(config.get("relay_port", 40000)),
            "PUBLIC_ENDPOINT": config.get("public_endpoint") or "",
            "AUTH_KEY": config.get("auth_key") or "",
        }
        return "".join(f"{name}={shlex.quote(str(value))}\n" for name, value in values.items())

    @staticmethod
    def _parse_result(stdout: str) -> dict[str, Any]:
        result_line = next(
            (line for line in reversed(stdout.splitlines()) if line.startswith("EASYPI_RELAY_RESULT ")),
            None,
        )
        if not result_line:
            raise RelayOperationError("The VPS did not return a valid relay status")
        result: dict[str, str] = {}
        for token in shlex.split(result_line.removeprefix("EASYPI_RELAY_RESULT ")):
            key, separator, value = token.partition("=")
            if separator:
                result[key] = value
        return {
            "installed": result.get("installed") == "true",
            "daemon_active": result.get("daemon") == "true",
            "enabled": result.get("enabled") == "true",
            "listening": result.get("listening") == "true",
            "managed_install": result.get("managed") == "true",
            "firewall_managed": result.get("firewall") == "true",
            "isolation_active": result.get("isolated") == "true",
            "relay_tagged": result.get("relay_tagged") == "true",
            "shields_up": result.get("shields_up") == "true",
            "tailscale_version": result.get("version") or None,
            "tailscale_ip": result.get("tailscale_ip") or None,
            "relay_name": result.get("relay_name") or "easypi-fast-relay",
            "relay_port": int(result.get("relay_port") or 40000),
            "public_endpoint": result.get("public_endpoint") or None,
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
        relay_name: str = "easypi-fast-relay",
        relay_port: int = 40000,
        public_endpoint: str | None = None,
        auth_key: str | None = None,
    ) -> dict[str, Any]:
        if action not in {"deploy", "status", "restart", "disable", "uninstall"}:
            raise RelayOperationError("Unsupported relay operation")
        try:
            script = self.script_path.read_bytes()
        except OSError as exc:
            raise RelayOperationError("Fast Mobile Relay installer is missing") from exc
        client = self._connect(
            host=host,
            port=port,
            user=user,
            password=password,
            private_key=private_key,
        )
        token = secrets.token_hex(16)
        remote_script = f"/tmp/easypi-relay-{token}.sh"
        remote_config = f"/tmp/easypi-relay-{token}.env"
        try:
            prefix = self._privilege_prefix(client)
            sftp = client.open_sftp()
            try:
                with sftp.file(remote_script, "wb") as handle:
                    handle.write(script)
                sftp.chmod(remote_script, 0o700)
                with sftp.file(remote_config, "w") as handle:
                    handle.write(
                        self._config_text(
                            {
                                "relay_name": relay_name,
                                "relay_port": relay_port,
                                "public_endpoint": public_endpoint,
                                "auth_key": auth_key,
                            }
                        )
                    )
                sftp.chmod(remote_config, 0o600)
            finally:
                sftp.close()
            command = (
                f"{prefix}timeout --signal=TERM --kill-after=15s 360s "
                f"bash {shlex.quote(remote_script)} {shlex.quote(action)} {shlex.quote(remote_config)}"
            )
            stdout, stderr, exit_code = self._read_command(client, command, timeout=390)
            if exit_code != 0:
                message = next(
                    (
                        line.removeprefix("EASYPI_RELAY_ERROR:").strip()
                        for line in reversed(stderr.splitlines())
                        if line.startswith("EASYPI_RELAY_ERROR:")
                    ),
                    "Fast Mobile Relay operation failed on the VPS",
                )
                raise RelayOperationError(message)
            return self._parse_result(stdout)
        except RelayOperationError:
            raise
        except (OSError, EOFError, paramiko.SSHException) as exc:
            raise RelayOperationError("Could not stage the Fast Mobile Relay operation on the VPS") from exc
        finally:
            try:
                self._read_command(
                    client,
                    f"rm -f -- {shlex.quote(remote_script)} {shlex.quote(remote_config)}",
                    timeout=15,
                )
            except RelayOperationError:
                logger.warning("Could not remove temporary Fast Mobile Relay files from %s", host)
            client.close()

    async def operate(self, action: str, **request: Any) -> dict[str, Any]:
        if self._operation_lock.locked():
            raise RelayBusyError("Another Fast Mobile Relay operation is already running")
        async with self._operation_lock:
            previous = self.load_state()
            try:
                remote = await asyncio.to_thread(self._run_remote, action=action, **request)
                stored = self._store_credentials(
                    password=request.get("password"),
                    private_key=request.get("private_key"),
                )
                state = self._default_state()
                state.update(previous)
                state.update(remote)
                state.update(
                    {
                        "configured": action != "uninstall",
                        "host": request["host"] if action != "uninstall" else None,
                        "ssh_port": request["port"] if action != "uninstall" else 22,
                        "ssh_user": request["user"] if action != "uninstall" else "root",
                        "host_key_trusted": action != "uninstall",
                        "last_checked_at": _utc_now(),
                        "last_error": None,
                    }
                )
                if stored and action != "uninstall":
                    state.update(
                        {
                            "credential_configured": True,
                            "credential_type": stored[0],
                            "credential_protection": stored[1],
                        }
                    )
                if action == "uninstall":
                    self._delete_credentials()
                    state = self._default_state()
                    state["last_checked_at"] = _utc_now()
                state["policy_grant"] = self._policy_grant()
                state["policy_required"] = True
                self._save_state(state)
                return state
            except RelayOperationError as exc:
                if action == "deploy":
                    try:
                        await asyncio.to_thread(
                            self._run_remote,
                            action="disable" if previous.get("configured") else "uninstall",
                            host=request["host"],
                            port=request["port"],
                            user=request["user"],
                            password=request.get("password"),
                            private_key=request.get("private_key"),
                        )
                    except RelayOperationError:
                        logger.warning(
                            "Fast Mobile Relay rollback could not be confirmed for %s",
                            request.get("host"),
                        )
                failed = dict(previous)
                failed["last_checked_at"] = _utc_now()
                failed["last_error"] = str(exc)
                self._save_state(failed)
                raise


tailscale_relay_service = TailscaleRelayService()

