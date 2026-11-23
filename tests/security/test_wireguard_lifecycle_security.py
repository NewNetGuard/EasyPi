from __future__ import annotations

from pathlib import Path

import pytest
from app.api.deps import require_admin
from app.api.v1.endpoints import wireguard
from app.schemas.wireguard import WireGuardInstallRequest, WireGuardPeerRequest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError


@pytest.fixture
def wireguard_client(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[TestClient, Path]:
    clients = tmp_path / "clients"
    clients.mkdir()
    monkeypatch.setattr(wireguard, "CLIENTS_DIR", str(clients))
    app = FastAPI()
    app.include_router(wireguard.router, prefix="/wireguard")
    app.dependency_overrides[require_admin] = lambda: object()
    return TestClient(app), clients


@pytest.mark.parametrize(
    "payload",
    [
        {"endpoint": "vpn.example:0"},
        {"endpoint": "vpn.example:65536"},
        {"endpoint": "bad_host.example:51820"},
        {"endpoint": "2001:db8::1:51820"},
        {"endpoint": "vpn.example:51820", "cidr": "10.8.0.1/24"},
        {"endpoint": "vpn.example:51820", "cidr": "999.8.0.0/24"},
        {"endpoint": "vpn.example:51820", "dns": "999.1.1.1"},
    ],
)
def test_wireguard_install_rejects_values_the_shell_cannot_safely_use(payload: dict[str, object]) -> None:
    with pytest.raises(ValidationError):
        WireGuardInstallRequest.model_validate(payload)


def test_wireguard_install_normalizes_supported_values() -> None:
    request = WireGuardInstallRequest(
        endpoint="[2001:0db8::1]:51820",
        cidr="10.8.0.0/24",
        dns="1.1.1.1, 9.9.9.9",
    )

    assert request.endpoint == "[2001:db8::1]:51820"
    assert request.dns == "1.1.1.1,9.9.9.9"


def test_wireguard_allowed_ips_are_parsed_as_networks() -> None:
    request = WireGuardPeerRequest(name="phone", allowed="10.0.0.7/24, ::/0")
    assert request.allowed == "10.0.0.0/24,::/0"

    with pytest.raises(ValidationError):
        WireGuardPeerRequest(name="phone", allowed="999.0.0.0/24")


def test_wireguard_config_download_is_private_and_forced_to_attachment(
    wireguard_client: tuple[TestClient, Path],
) -> None:
    client, clients = wireguard_client
    secret = b"[Interface]\nPrivateKey = test-secret\n"
    (clients / "phone.conf").write_bytes(secret)

    response = client.get("/wireguard/peers/phone/config")

    assert response.status_code == 200
    assert response.content == secret
    assert response.headers["content-disposition"].startswith("attachment;")
    assert response.headers["cache-control"] == "private, no-store"
    assert response.headers["pragma"] == "no-cache"
    assert response.headers["x-content-type-options"] == "nosniff"
    assert response.headers["cross-origin-resource-policy"] == "same-origin"


def test_wireguard_qr_is_inline_but_never_cacheable(
    wireguard_client: tuple[TestClient, Path],
) -> None:
    client, clients = wireguard_client
    (clients / "phone.png").write_bytes(b"fake-png")

    response = client.get("/wireguard/peers/phone/qr")

    assert response.status_code == 200
    assert response.headers["content-disposition"].startswith("inline;")
    assert response.headers["cache-control"] == "private, no-store"
    assert response.headers["x-content-type-options"] == "nosniff"


def test_wireguard_artifact_lookup_rejects_symlinks(
    wireguard_client: tuple[TestClient, Path],
    tmp_path: Path,
) -> None:
    client, clients = wireguard_client
    target = tmp_path / "outside.conf"
    target.write_text("PrivateKey = outside", encoding="utf-8")
    link = clients / "phone.conf"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Creating symlinks is unavailable on this platform")

    response = client.get("/wireguard/peers/phone/config")
    assert response.status_code == 404
    assert b"outside" not in response.content


def test_wireguard_script_revokes_persistent_peers_and_serializes_mutations() -> None:
    script = (Path(__file__).resolve().parents[2] / "scripts/services/wireguard.sh").read_text(
        encoding="utf-8"
    )

    assert "flock -x 9" in script
    assert 'systemctl is-active --quiet wg-quick@wg0' in script
    assert 'remove_peer_from_config "$peer_pubkey"' in script
    assert 'wg set wg0 peer "$peer_pubkey" remove || true' not in script
    assert 'rollback_new_peer "$client_pubkey"' in script
