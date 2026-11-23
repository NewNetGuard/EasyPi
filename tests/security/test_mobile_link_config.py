from __future__ import annotations

import json
import os

import pytest

from app.services import mobile_link_config
from app.services.mobile_link_config import MobileLinkConfig


def test_mobile_link_config_round_trip_is_private_and_atomic(tmp_path, monkeypatch) -> None:
    path = tmp_path / "user" / "mobile_link.json"
    monkeypatch.setattr(mobile_link_config, "_config_path", lambda: path)

    saved = mobile_link_config.save_mobile_link_config(
        MobileLinkConfig(enabled=True, public_url="https://mobile.example.org:8443/")
    )

    assert saved.public_url == "https://mobile.example.org:8443"
    assert mobile_link_config.load_mobile_link_config() == saved
    if os.name == "posix":
        assert path.stat().st_mode & 0o077 == 0
    assert json.loads(path.read_text(encoding="utf-8"))["enabled"] is True


def test_mobile_link_config_refuses_symlink(tmp_path, monkeypatch) -> None:
    target = tmp_path / "target.json"
    target.write_text("{}", encoding="utf-8")
    path = tmp_path / "user" / "mobile_link.json"
    path.parent.mkdir()
    try:
        path.symlink_to(target)
    except OSError:
        pytest.skip("Symlinks are unavailable on this platform")
    monkeypatch.setattr(mobile_link_config, "_config_path", lambda: path)

    with pytest.raises(RuntimeError, match="Unsafe"):
        mobile_link_config.load_mobile_link_config()
