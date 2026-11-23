"""Pinned SSH host identities for one-click remote administration.

The first connection is deliberately unauthenticated and only observes the
server public key.  An administrator must confirm the SHA-256 fingerprint.
Subsequent SSH authentication uses only the exact key stored for the canonical
``public IPv4 + port`` tuple; changed keys fail closed.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import stat
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

import paramiko

from app.core.paths import get_data_dir
from app.utils.network_security import require_public_ipv4


_FINGERPRINT_RE = re.compile(r"^SHA256:[A-Za-z0-9+/]{43}$")
_MAX_STORE_BYTES = 1024 * 1024
_STRONG_HOST_KEY_ALGORITHMS = {
    "ssh-ed25519",
    "ecdsa-sha2-nistp256",
    "ecdsa-sha2-nistp384",
    "ecdsa-sha2-nistp521",
    "rsa-sha2-256",
    "rsa-sha2-512",
}


class SSHHostTrustError(RuntimeError):
    """Base class for safe, user-facing host identity failures."""


class SSHHostKeyUnknown(SSHHostTrustError):
    pass


class SSHHostKeyChanged(SSHHostTrustError):
    pass


class SSHHostKeyScanError(SSHHostTrustError):
    pass


class SSHHostTrustStoreError(SSHHostTrustError):
    pass


@dataclass(frozen=True)
class SSHHostKeyObservation:
    host: str
    port: int
    key_type: str
    key_data: str
    fingerprint: str
    bits: int

    @property
    def endpoint(self) -> str:
        return f"{self.host}:{self.port}"

    def public_dict(self, *, trust_status: str, trusted_fingerprint: str | None = None) -> dict[str, Any]:
        return {
            "host": self.host,
            "port": self.port,
            "key_type": self.key_type,
            "fingerprint": self.fingerprint,
            "bits": self.bits,
            "trust_status": trust_status,
            "trusted_fingerprint": trusted_fingerprint,
        }


def ssh_host_key_fingerprint(key: paramiko.PKey) -> str:
    digest = base64.b64encode(hashlib.sha256(key.asbytes()).digest()).decode("ascii").rstrip("=")
    return f"SHA256:{digest}"


def _validate_port(port: int) -> int:
    value = int(port)
    if not 1 <= value <= 65535:
        raise ValueError("SSH port must be between 1 and 65535")
    return value


def _validate_observed_key(key: paramiko.PKey) -> tuple[str, int]:
    key_type = key.get_name()
    bits = int(key.get_bits() or 0)
    if key_type == "ssh-rsa":
        if bits < 3072:
            raise SSHHostKeyScanError("The VPS uses an RSA SSH host key smaller than 3072 bits")
        return key_type, bits
    if key_type not in {
        "ssh-ed25519",
        "ecdsa-sha2-nistp256",
        "ecdsa-sha2-nistp384",
        "ecdsa-sha2-nistp521",
    }:
        raise SSHHostKeyScanError(f"The VPS offered an unsupported SSH host key type: {key_type}")
    return key_type, bits


def observe_ssh_host_key(host: str, port: int, *, timeout: float = 12.0) -> SSHHostKeyObservation:
    """Observe one strongly negotiated host key without sending credentials."""

    canonical_host = require_public_ipv4(host, label="VPS target")
    canonical_port = _validate_port(port)
    sock: socket.socket | None = None
    transport: paramiko.Transport | None = None
    try:
        sock = socket.create_connection((canonical_host, canonical_port), timeout=timeout)
        sock.settimeout(timeout)
        transport = paramiko.Transport(sock)
        security = transport.get_security_options()
        strong = tuple(name for name in security.key_types if name in _STRONG_HOST_KEY_ALGORITHMS)
        if not strong:
            raise SSHHostKeyScanError("No strong SSH host-key algorithms are available")
        security.key_types = strong
        transport.start_client(timeout=timeout)
        key = transport.get_remote_server_key()
        key_type, bits = _validate_observed_key(key)
        return SSHHostKeyObservation(
            host=canonical_host,
            port=canonical_port,
            key_type=key_type,
            key_data=key.get_base64(),
            fingerprint=ssh_host_key_fingerprint(key),
            bits=bits,
        )
    except SSHHostTrustError:
        raise
    except (OSError, EOFError, paramiko.SSHException) as exc:
        raise SSHHostKeyScanError("Could not read the VPS SSH identity; check the address, port, and firewall") from exc
    finally:
        if transport is not None:
            transport.close()
        elif sock is not None:
            sock.close()


class _ExclusiveFileLock:
    def __init__(self, path: Path) -> None:
        self.fd = -1
        try:
            flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
            self.fd = os.open(path, flags, 0o600)
            if hasattr(os, "fchmod"):
                os.fchmod(self.fd, 0o600)
            info = os.fstat(self.fd)
            if not stat.S_ISREG(info.st_mode):
                raise SSHHostTrustStoreError("SSH trust-store lock is not a regular file")
            if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
                raise SSHHostTrustStoreError("SSH trust-store lock has an unexpected owner")
            if os.name == "nt":
                import msvcrt

                if info.st_size == 0:
                    os.write(self.fd, b"\0")
                os.lseek(self.fd, 0, os.SEEK_SET)
                msvcrt.locking(self.fd, msvcrt.LK_LOCK, 1)
                self._unlock = lambda: msvcrt.locking(self.fd, msvcrt.LK_UNLCK, 1)
            else:
                import fcntl

                fcntl.flock(self.fd, fcntl.LOCK_EX)
                self._unlock = lambda: fcntl.flock(self.fd, fcntl.LOCK_UN)
        except Exception as exc:
            if self.fd >= 0:
                os.close(self.fd)
                self.fd = -1
            if isinstance(exc, SSHHostTrustStoreError):
                raise
            raise SSHHostTrustStoreError("SSH trust-store lock is unavailable") from exc

    def __enter__(self) -> "_ExclusiveFileLock":
        return self

    def __exit__(self, _exc_type, _exc, _tb) -> None:
        try:
            os.lseek(self.fd, 0, os.SEEK_SET)
            self._unlock()
        finally:
            os.close(self.fd)


class SSHHostTrustStore:
    """Symlink-safe, atomic store of pinned public SSH host keys."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = path or (Path(get_data_dir()) / "ssh-trust" / "dns-host-keys.json")
        self.lock_path = self.path.with_name(f".{self.path.name}.lock")

    @staticmethod
    def _endpoint(host: str, port: int) -> tuple[str, int, str]:
        canonical_host = require_public_ipv4(host, label="VPS target")
        canonical_port = _validate_port(port)
        return canonical_host, canonical_port, f"{canonical_host}:{canonical_port}"

    def _ensure_directory(self) -> None:
        directory = self.path.parent
        try:
            info = directory.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise SSHHostTrustStoreError("SSH trust-store directory is unsafe")
        except FileNotFoundError:
            try:
                directory.mkdir(parents=True, mode=0o700, exist_ok=False)
            except FileExistsError:
                # Another worker may have created it between lstat() and mkdir().
                pass
            info = directory.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
                raise SSHHostTrustStoreError("SSH trust-store directory is unsafe")
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            raise SSHHostTrustStoreError("SSH trust-store directory has an unexpected owner")
        os.chmod(directory, 0o700)

    def _locked(self) -> _ExclusiveFileLock:
        self._ensure_directory()
        return _ExclusiveFileLock(self.lock_path)

    def _read_unlocked(self) -> dict[str, Any]:
        try:
            info = self.path.lstat()
        except FileNotFoundError:
            return {"version": 1, "hosts": {}}
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
            raise SSHHostTrustStoreError("SSH trust store is not a regular file")
        if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
            raise SSHHostTrustStoreError("SSH trust store permissions are too broad")
        if hasattr(os, "geteuid") and info.st_uid != os.geteuid():
            raise SSHHostTrustStoreError("SSH trust store has an unexpected owner")
        flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(self.path, flags)
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or opened.st_size > _MAX_STORE_BYTES:
                raise SSHHostTrustStoreError("SSH trust store is invalid")
            if (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
                raise SSHHostTrustStoreError("SSH trust store changed while it was opened")
            if hasattr(os, "geteuid") and opened.st_uid != os.geteuid():
                raise SSHHostTrustStoreError("SSH trust store has an unexpected owner")
            chunks: list[bytes] = []
            remaining = _MAX_STORE_BYTES + 1
            while remaining:
                chunk = os.read(fd, remaining)
                if not chunk:
                    break
                chunks.append(chunk)
                remaining -= len(chunk)
            payload = b"".join(chunks)
        finally:
            os.close(fd)
        try:
            data = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SSHHostTrustStoreError("SSH trust store is corrupted") from exc
        if data.get("version") != 1 or not isinstance(data.get("hosts"), dict):
            raise SSHHostTrustStoreError("SSH trust store schema is invalid")
        return data

    def _write_unlocked(self, data: dict[str, Any]) -> None:
        payload = (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8")
        if len(payload) > _MAX_STORE_BYTES:
            raise SSHHostTrustStoreError("SSH trust store is too large")
        temp = self.path.with_name(f".{self.path.name}.{secrets.token_hex(12)}.tmp")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(temp, flags, 0o600)
        try:
            if hasattr(os, "fchmod"):
                os.fchmod(fd, 0o600)
            view = memoryview(payload)
            while view:
                written = os.write(fd, view)
                if written <= 0:
                    raise OSError("Short write while saving SSH trust store")
                view = view[written:]
            os.fsync(fd)
        except Exception:
            os.close(fd)
            temp.unlink(missing_ok=True)
            raise
        else:
            os.close(fd)
        try:
            os.replace(temp, self.path)
        except Exception:
            temp.unlink(missing_ok=True)
            raise
        os.chmod(self.path, 0o600)
        if os.name != "nt":
            directory_fd = os.open(self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)

    def inspect(self, host: str, port: int) -> dict[str, Any]:
        observed = observe_ssh_host_key(host, port)
        with self._locked():
            record = self._read_unlocked()["hosts"].get(observed.endpoint)
        if not record:
            return observed.public_dict(trust_status="unknown")
        trusted_fingerprint, _key = self._decode_record(observed.endpoint, record)
        if hmac.compare_digest(trusted_fingerprint, observed.fingerprint):
            return observed.public_dict(
                trust_status="trusted", trusted_fingerprint=trusted_fingerprint
            )
        return observed.public_dict(
            trust_status="changed", trusted_fingerprint=trusted_fingerprint
        )

    def trust(self, host: str, port: int, expected_fingerprint: str) -> dict[str, Any]:
        expected = expected_fingerprint.strip()
        if not _FINGERPRINT_RE.fullmatch(expected):
            raise ValueError("Invalid SSH SHA-256 fingerprint")
        observed = observe_ssh_host_key(host, port)
        if not hmac.compare_digest(observed.fingerprint, expected):
            raise SSHHostKeyChanged(
                "The SSH host key changed before confirmation. Do not trust it; verify the VPS console."
            )
        with self._locked():
            data = self._read_unlocked()
            existing = data["hosts"].get(observed.endpoint)
            if existing:
                previous, _key = self._decode_record(observed.endpoint, existing)
                if not hmac.compare_digest(previous, observed.fingerprint):
                    raise SSHHostKeyChanged(
                        "The saved SSH host key differs from the VPS. Deployment is blocked."
                    )
                return observed.public_dict(
                    trust_status="trusted", trusted_fingerprint=previous
                )
            record = asdict(observed)
            record["trusted_at"] = int(time.time())
            data["hosts"][observed.endpoint] = record
            self._write_unlocked(data)
        return observed.public_dict(
            trust_status="trusted", trusted_fingerprint=observed.fingerprint
        )

    @staticmethod
    def _decode_record(endpoint: str, record: Any) -> tuple[str, paramiko.PKey]:
        if not isinstance(record, dict):
            raise SSHHostTrustStoreError("Stored SSH host-key record is invalid")
        try:
            record_host = require_public_ipv4(record["host"], label="Stored VPS target")
            record_port = _validate_port(record["port"])
            if f"{record_host}:{record_port}" != endpoint:
                raise ValueError("endpoint mismatch")
            key_type = str(record["key_type"])
            key = paramiko.PKey.from_type_string(
                key_type, base64.b64decode(str(record["key_data"]), validate=True)
            )
            validated_type, _bits = _validate_observed_key(key)
            fingerprint = str(record["fingerprint"])
        except SSHHostTrustError:
            raise
        except Exception as exc:
            raise SSHHostTrustStoreError("Stored SSH host key is invalid") from exc
        if key_type != validated_type:
            raise SSHHostTrustStoreError("Stored SSH host-key type is invalid")
        if not _FINGERPRINT_RE.fullmatch(fingerprint) or not hmac.compare_digest(
            ssh_host_key_fingerprint(key), fingerprint
        ):
            raise SSHHostTrustStoreError("Stored SSH host-key fingerprint is invalid")
        return fingerprint, key

    def pinned_key(self, host: str, port: int) -> tuple[str, int, str, paramiko.PKey]:
        canonical_host, canonical_port, endpoint = self._endpoint(host, port)
        with self._locked():
            record = self._read_unlocked()["hosts"].get(endpoint)
        if not record:
            raise SSHHostKeyUnknown(
                "SSH host key is not trusted. Check the VPS fingerprint and approve it first."
            )
        _fingerprint, key = self._decode_record(endpoint, record)
        key_type = key.get_name()
        return canonical_host, canonical_port, key_type, key

    def configure_client(self, client: paramiko.SSHClient, host: str, port: int) -> tuple[str, int]:
        canonical_host, canonical_port, key_type, key = self.pinned_key(host, port)
        host_key_name = canonical_host if canonical_port == 22 else f"[{canonical_host}]:{canonical_port}"
        client.get_host_keys().add(host_key_name, key_type, key)
        client.set_missing_host_key_policy(paramiko.RejectPolicy())
        return canonical_host, canonical_port


__all__ = [
    "SSHHostKeyChanged",
    "SSHHostKeyObservation",
    "SSHHostKeyScanError",
    "SSHHostKeyUnknown",
    "SSHHostTrustError",
    "SSHHostTrustStore",
    "SSHHostTrustStoreError",
    "observe_ssh_host_key",
    "ssh_host_key_fingerprint",
]
