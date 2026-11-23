from __future__ import annotations

import os
import stat
from pathlib import Path

import pytest

from app.services.mobile_link_relay_service import MobileLinkRelayService
from app.services.remote_access.tailscale_relay_service import RelayOperationError
from app.utils.ssh_host_trust import SSHHostTrustStore


def test_mobile_link_relay_default_state_contains_no_credentials_or_transport_secret() -> None:
    state = MobileLinkRelayService()._default_state()
    serialized = repr(state).lower()
    assert "password" not in serialized
    assert "private_key" not in serialized
    assert "transport_secret" not in serialized
    assert "secret" not in serialized


def test_mobile_link_relay_status_parser_accepts_only_public_runtime_state() -> None:
    status = MobileLinkRelayService._parse_result(
        "noise\nEASYPI_MOBILE_LINK_RESULT installed=true enabled=true active=true "
        "agent_port=9443 mobile_port=9444 domain=myrelay.duckdns.org\n"
    )
    assert status == {
        "installed": True,
        "enabled": True,
        "active": True,
        "agent_port": 9443,
        "mobile_port": 9444,
        "domain": "myrelay.duckdns.org",
    }


def test_mobile_link_public_status_does_not_parse_or_expose_unsafe_state(monkeypatch) -> None:
    service = MobileLinkRelayService()
    monkeypatch.setattr(
        service,
        "load_state",
        lambda: (_ for _ in ()).throw(RelayOperationError("unsafe state")),
    )

    status = service.public_status()

    assert status["configured"] is False
    assert status["host"] is None
    assert "signed EasyPi update" in status["last_error"]


def test_installer_restores_private_ssh_trust_store_permissions() -> None:
    installer = Path("install.sh").read_text(encoding="utf-8")

    assert 'ssh_trust_dir="${EASYPI_PREFIX}/data/ssh-trust"' in installer
    assert 'chmod 0700 "${ssh_trust_dir}"' in installer
    assert 'chmod 0600 "${trust_file}"' in installer


@pytest.mark.skipif(os.name == "nt", reason="POSIX ownership and mode repair")
def test_mobile_link_repairs_existing_trust_store_permissions(tmp_path: Path) -> None:
    directory = tmp_path / "ssh-trust"
    directory.mkdir(mode=0o750)
    store_path = directory / "mobile-link-relay-host-keys.json"
    store_path.write_text('{"version":1,"hosts":{}}\n', encoding="utf-8")
    lock_path = directory / ".mobile-link-relay-host-keys.json.lock"
    lock_path.write_text("", encoding="utf-8")
    store_path.chmod(0o640)
    lock_path.chmod(0o640)
    trust_store = SSHHostTrustStore(store_path)

    MobileLinkRelayService._repair_existing_trust_store_permissions(trust_store)

    assert stat.S_IMODE(directory.stat().st_mode) == 0o700
    assert stat.S_IMODE(store_path.stat().st_mode) == 0o600
    assert stat.S_IMODE(lock_path.stat().st_mode) == 0o600
