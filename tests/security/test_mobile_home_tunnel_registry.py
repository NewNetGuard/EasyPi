from __future__ import annotations

import json
import os
from types import SimpleNamespace

import pytest

from app.services import mobile_home_tunnel_registry as registry


def _device(*, identity: str, address: str, key: str, state: str = "active"):
    return SimpleNamespace(
        id=identity,
        home_tunnel_address=address,
        home_tunnel_public_key=key,
        home_tunnel_state=state,
        home_tunnel_credential_epoch=1,
    )


def test_registry_is_atomic_private_and_contains_no_private_material(tmp_path, monkeypatch):
    path = tmp_path / "netprotection" / "peers.json"
    monkeypatch.setattr(registry, "_registry_path", lambda: path)
    device = _device(
        identity="12345678-1234-1234-1234-123456789abc",
        address="10.77.0.2/32",
        key="A" * 120,
    )

    assert registry.sync_mobile_home_tunnel_registry([device]) == path
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload == {
        "devices": [
            {
                "address": "10.77.0.2",
                "id": device.id,
            }
        ],
        "version": 1,
    }
    if os.name != "nt":
        assert os.stat(path).st_mode & 0o777 == 0o600
    assert "private" not in path.read_text(encoding="utf-8").lower()
    assert not list(path.parent.glob(".mobile-home-tunnel-*"))


def test_registry_rejects_duplicates_invalid_networks_and_symlinks(tmp_path, monkeypatch):
    path = tmp_path / "peers.json"
    monkeypatch.setattr(registry, "_registry_path", lambda: path)
    first = _device(
        identity="12345678-1234-1234-1234-123456789abc",
        address="10.77.0.2/32",
        key="A" * 120,
    )
    duplicate = _device(
        identity="12345678-1234-1234-1234-123456789abd",
        address="10.77.0.2/32",
        key="B" * 120,
    )
    with pytest.raises(registry.MobileHomeTunnelRegistryError):
        registry.sync_mobile_home_tunnel_registry([first, duplicate])
    first.home_tunnel_address = "192.0.2.2/32"
    with pytest.raises(registry.MobileHomeTunnelRegistryError):
        registry.sync_mobile_home_tunnel_registry([first])

    target = tmp_path / "target"
    target.write_text("do not replace", encoding="utf-8")
    try:
        path.symlink_to(target)
    except OSError:
        pytest.skip("symlinks are unavailable")
    with pytest.raises(registry.MobileHomeTunnelRegistryError):
        registry.sync_mobile_home_tunnel_registry([])
    assert target.read_text(encoding="utf-8") == "do not replace"
