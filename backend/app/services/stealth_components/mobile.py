"""Authenticated VPS synchronization for individual mobile VPN credentials."""
from __future__ import annotations

from contextlib import contextmanager
import hashlib
import hmac
import ipaddress
import json
import os
import uuid

from app.services.stealth_components.context import REMOTE_SERVER_DIR, _DeploymentLease


class StealthMobileMixin:
    @contextmanager
    def mobile_credentials_update(self):
        try:
            lease = _DeploymentLease(self._data_dir / ".stealth-deployment.lock", "mobile-credentials")
        except (BlockingIOError, OSError) as exc:
            raise ValueError("Chameleon deployment is busy; retry the operation") from exc
        try:
            yield
        finally:
            lease.close()

    def sync_mobile_clients(self, devices: list[dict[str, str]]) -> None:
        """Caller holds the deployment lease across the DB and remote update."""
        clean: list[dict[str, str]] = []
        seen_ids: set[str] = set()
        seen_ips: set[str] = set()
        for device in devices:
            identity = str(uuid.UUID(device["id"]))
            address = ipaddress.ip_interface(device["address"])
            if identity != device["id"] or identity in seen_ids or address.version != 4 or address.network.prefixlen != 32:
                raise ValueError("Invalid mobile credential registry")
            ip = str(address.ip)
            if address.ip not in ipaddress.ip_network("10.10.0.0/24") or int(ip.rsplit(".", 1)[1]) not in range(3, 255) or ip in seen_ips:
                raise ValueError("Invalid mobile address registry")
            seen_ids.add(identity)
            seen_ips.add(ip)
            clean.append({"id": identity, "address": ip})
        if len(clean) > 200:
            raise ValueError("Too many mobile VPN devices")
        meta = self._meta()
        master = str(meta.get("client_auth_key") or "")
        if len(master) != 64:
            raise ValueError("Redeploy Chameleon with individual credentials first")
        registry = json.dumps({"version": 1, "devices": clean}, separators=(",", ":"))
        # Every phone connection enrols; reaching the VPS over SSH each time
        # made the VPN depend on the home EasyPi and risked SSH throttling.
        # Publish only when the registry for this VPS actually changes. A
        # (re)deployment clears the digest so a new VPS is always populated.
        ssh = meta["ssh"]
        digest = hashlib.sha256(
            "|".join(
                (str(ssh.get("host") or ""), str(ssh.get("port") or ""), registry)
            ).encode("utf-8")
        ).hexdigest()
        if hmac.compare_digest(str(meta.get("mobile_registry_digest") or ""), digest):
            return
        connection = self._connect(meta["ssh"])
        temporary = f"{REMOTE_SERVER_DIR}/.mobile-clients-{os.urandom(12).hex()}"
        try:
            sftp = connection.open_sftp()
            try:
                with sftp.file(f"{REMOTE_SERVER_DIR}/server_config.json", "r") as stream:
                    config = json.loads(stream.read(65537))
                if not hmac.compare_digest(str(config.get("client_auth_key") or ""), master):
                    raise ValueError("VPS credentials are not migrated; redeploy Chameleon first")
                if config.get("mobile_clients_file") != f"{REMOTE_SERVER_DIR}/mobile_clients.json":
                    raise ValueError("VPS mobile credential registry path is not configured")
                with sftp.file(temporary, "w") as stream:
                    stream.write(registry)
                sftp.chmod(temporary, 0o600)
                # Paths are constants plus a locally generated hex suffix.
                _, stdout, _ = connection.exec_command(
                    f"chown root:chameleon {temporary} && chmod 0640 {temporary} && "
                    f"mv -f -- {temporary} {REMOTE_SERVER_DIR}/mobile_clients.json",
                    timeout=20,
                )
                if stdout.channel.recv_exit_status() != 0:
                    raise ValueError("Could not publish VPS mobile credential registry")
                published = self._meta()
                published["mobile_registry_digest"] = digest
                self._save_meta(published)
            finally:
                try:
                    sftp.remove(temporary)
                except OSError:
                    pass
                sftp.close()
        finally:
            connection.close()
