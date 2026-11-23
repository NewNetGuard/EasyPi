"""Atomic, derived registry for routed mobile identities on the local Pi."""

from __future__ import annotations

import ipaddress
import json
import os
import stat
import tempfile
import uuid
from pathlib import Path
from typing import Iterable

from app.core.paths import get_data_dir


class MobileHomeTunnelRegistryError(RuntimeError):
    pass


def _registry_path() -> Path:
    return Path(get_data_dir()) / "netprotection" / "mobile-home-tunnel-peers.json"


def _normalized_entries(devices: Iterable[object]) -> list[dict[str, str]]:
    entries: list[dict[str, str]] = []
    seen_ids: set[str] = set()
    seen_addresses: set[str] = set()
    seen_keys: set[str] = set()
    network = ipaddress.ip_network("10.77.0.0/24")
    for device in devices:
        identity = str(uuid.UUID(str(getattr(device, "id"))))
        address = ipaddress.ip_interface(str(getattr(device, "home_tunnel_address")))
        public_key = str(getattr(device, "home_tunnel_public_key"))
        epoch = int(getattr(device, "home_tunnel_credential_epoch"))
        if (
            identity != getattr(device, "id")
            or identity in seen_ids
            or address.version != 4
            or address.network.prefixlen != 32
            or address.ip not in network
            or str(address.ip) in seen_addresses
            or len(public_key) not in range(80, 513)
            or public_key in seen_keys
            or str(getattr(device, "home_tunnel_state")) != "active"
            or epoch < 1
        ):
            raise MobileHomeTunnelRegistryError("Invalid mobile home-tunnel registry")
        seen_ids.add(identity)
        seen_addresses.add(str(address.ip))
        seen_keys.add(public_key)
        entries.append(
            {
                "id": identity,
                "address": str(address.ip),
            }
        )
    if len(entries) > 253:
        raise MobileHomeTunnelRegistryError("Too many mobile home-tunnel devices")
    return sorted(entries, key=lambda item: item["id"])


def sync_mobile_home_tunnel_registry(devices: Iterable[object]) -> Path:
    """Publish only active peer IDs/addresses; private keys never leave Android."""
    path = _registry_path()
    parent = path.parent
    try:
        parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if path.exists() or path.is_symlink():
            info = path.lstat()
            if stat.S_ISLNK(info.st_mode) or not stat.S_ISREG(info.st_mode):
                raise MobileHomeTunnelRegistryError("Unsafe mobile registry path")
        payload = json.dumps(
            {"version": 1, "devices": _normalized_entries(devices)},
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8") + b"\n"
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=".mobile-home-tunnel-", dir=parent
        )
        temporary = Path(temporary_name)
        try:
            os.chmod(temporary, 0o600)
            with os.fdopen(descriptor, "wb", closefd=True) as stream:
                descriptor = -1
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, path)
            os.chmod(path, 0o600)
            if hasattr(os, "O_DIRECTORY"):
                directory_fd = os.open(parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(directory_fd)
                finally:
                    os.close(directory_fd)
        finally:
            if descriptor >= 0:
                os.close(descriptor)
            temporary.unlink(missing_ok=True)
    except MobileHomeTunnelRegistryError:
        raise
    except (OSError, TypeError, ValueError) as exc:
        raise MobileHomeTunnelRegistryError(
            "Could not publish mobile home-tunnel registry"
        ) from exc
    return path
