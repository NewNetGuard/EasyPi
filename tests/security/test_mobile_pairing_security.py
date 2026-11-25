from __future__ import annotations

import asyncio
import base64
from contextlib import nullcontext
import hashlib
import os
from types import SimpleNamespace

import pytest
from fastapi import FastAPI, Response
from fastapi.testclient import TestClient
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import create_engine, inspect, select, text
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.deps import get_db, require_admin
from app.api.v1.endpoints import mobile
from app.db.base import Base
from app.models.mobile_device import MobileDevice
from app.models.camera import Camera
from app.models.user import User
from app.schemas.picloud import UploadResponse
from app.services.remote_access.tailscale_admin_api import TailscaleAdminAPI
from app.services.mobile_prism_broker import MobilePrismBroker
from app.services.mobile_link_config import MobileLinkConfig
from app.db.init_db import ensure_mobile_device_columns
from app.services.netprotection_components.parental import ParentalMixin
from app.services.unknown_device_admission_service import UnknownDeviceAdmissionService
from app.utils.sanitize import sanitize_mac


def _pair_security_phone(client):
    code = client.post("/mobile/pairing/start").json()["pairing_code"]
    paired = client.post("/mobile/pairing/complete", json={"pairing_code": code, "device_name": "Security regression phone", "provision_tailscale": False}).json()
    return paired, {"Authorization": f"Bearer {paired['mobile_token']}"}


def _home_tunnel_identity(device_id: str, private_key=None) -> tuple[object, str, str]:
    private_key = private_key or ec.generate_private_key(ec.SECP256R1())
    public_key = base64.b64encode(
        private_key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    ).decode("ascii")
    statement = f"easypi/home-tunnel/enroll/v1\n{device_id}\n{public_key}".encode("ascii")
    signature = base64.b64encode(
        private_key.sign(statement, ec.ECDSA(hashes.SHA256()))
    ).decode("ascii")
    return private_key, public_key, signature


def test_upload_auth_check_rejects_missing_invalid_and_revoked_tokens(mobile_client):
    client, engine = mobile_client
    assert client.get("/mobile/auth-check").status_code == 401
    assert client.get("/mobile/auth-check", headers={"Authorization": "Bearer invalid"}).status_code == 401
    paired, headers = _pair_security_phone(client)
    response = client.get("/mobile/auth-check", headers=headers)
    assert response.status_code == 204
    assert response.content == b""
    assert response.headers["cache-control"] == "no-store"
    with Session(engine) as db:
        db.get(MobileDevice, paired["device_id"]).is_active = False
        db.commit()
    assert client.get("/mobile/auth-check", headers=headers).status_code == 401


def test_chrome_bridge_requires_pairing_and_does_not_echo_body(mobile_client):
    client,_=mobile_client
    secret=secrets_for_chrome_test()
    response=client.post("/mobile/prism/chrome/keys",json={"lines":[secret]})
    assert response.status_code==401 and secret not in response.text


def secrets_for_chrome_test():
    import secrets
    return secrets.token_hex(32)


def test_chrome_bridge_authenticated_identity_and_no_store(mobile_client,monkeypatch):
    from app.services import chrome_bridge_service
    client,_=mobile_client
    paired,headers=_pair_security_phone(client)
    seen=[]
    monkeypatch.setattr(chrome_bridge_service,"call",lambda device,op,payload: seen.append((device,op)) or {"accepted":True})
    response=client.post("/mobile/prism/chrome/keys",headers=headers,json={"device":"other-device","lines":[]})
    assert response.status_code==200 and response.headers["cache-control"]=="no-store"
    assert seen==[(paired["device_id"],"keys")]


def test_chrome_bridge_limits_and_sanitizes_failures(mobile_client,monkeypatch):
    from app.services import chrome_bridge_service
    client,_=mobile_client
    _,headers=_pair_security_phone(client)
    secret=secrets_for_chrome_test()
    def reject(*_):raise ValueError(secret)
    monkeypatch.setattr(chrome_bridge_service,"call",reject)
    response=client.post("/mobile/prism/chrome/keys",headers=headers,json={"lines":[secret]})
    assert response.status_code==409 and secret not in response.text
    assert client.post("/mobile/prism/chrome/keys",headers=headers,content=b"x"*11001).status_code==413


@pytest.mark.parametrize("relative", [".meta/telegram_config.json", ".trash/item", ".thumbnails/item", "Photos/.internal/item"])
def test_mobile_cannot_read_preview_or_delete_internal_cloud(mobile_client, monkeypatch, tmp_path, relative):
    from app.services import picloud_service as cloud
    client, _ = mobile_client
    _, headers = _pair_security_phone(client)
    root = tmp_path / "cloud"
    secret = root / relative
    secret.parent.mkdir(parents=True)
    secret.write_bytes(b"synthetic internal state")
    monkeypatch.setattr(cloud, "STORAGE_ROOT", root)
    for endpoint in ("file", "thumbnail"):
        assert client.get(f"/mobile/cloud/{endpoint}/{relative}", headers=headers).status_code == 404
    assert client.delete(f"/mobile/cloud/file/{relative}", headers=headers).status_code == 404
    assert secret.read_bytes() == b"synthetic internal state"


def test_mobile_media_isolated_by_folder(mobile_client, monkeypatch, tmp_path):
    from app.services import picloud_service as cloud

    client, engine = mobile_client
    paired, headers = _pair_security_phone(client)
    root = tmp_path / "cloud"
    thumb_root = root / ".thumbnails"
    thumb_root.mkdir(parents=True)
    monkeypatch.setattr(cloud, "STORAGE_ROOT", root)
    monkeypatch.setattr(cloud, "THUMB_ROOT", thumb_root)
    with Session(engine) as db:
        db.get(MobileDevice, paired["device_id"]).photo_folder = "Test2"
        db.commit()

    for folder in ("Test2", "Test20", "NewNetGuard", "Photos"):
        photo = root / folder / "photo.jpg"
        photo.parent.mkdir()
        photo.write_bytes(folder.encode())
    (root / "Test2" / "video.mp4").write_bytes(b"own video")
    (root / "Test2" / "alias.jpg").symlink_to(root / "NewNetGuard" / "photo.jpg")
    (thumb_root / "photo.jpg.jpg").write_bytes(b"legacy preview from another folder")
    own_thumb = mobile.pi_cloud_service._thumbnail_path("Test2/photo.jpg")
    monkeypatch.setattr(mobile.pi_cloud_service, "_generate_thumbnail", lambda *_: None)

    for category, expected in (("photos", "Test2/photo.jpg"), ("videos", "Test2/video.mp4")):
        listing = client.get("/mobile/cloud/files", headers=headers, params={"category": category})
        assert listing.status_code == 200
        assert listing.headers["cache-control"] == "no-store"
        assert listing.json()["total_count"] == 1
        assert [item["id"].replace(chr(92), "/") for item in listing.json()["items"]] == [expected]

    assert client.get("/mobile/cloud/file/Test2/photo.jpg", headers=headers).content == b"Test2"
    assert client.get("/mobile/cloud/thumbnail/Test2/photo.jpg", headers=headers).status_code == 404
    own_thumb.write_bytes(b"own preview")
    assert client.get("/mobile/cloud/thumbnail/Test2/photo.jpg", headers=headers).content == b"own preview"

    deleted = []
    monkeypatch.setattr(mobile.pi_cloud_service, "delete_file", deleted.append)
    for path in ("NewNetGuard/photo.jpg", "Test20/photo.jpg", "Photos/photo.jpg",
                 "Test2/alias.jpg", "Test2/%2e%2e/NewNetGuard/photo.jpg", "Test2"):
        for endpoint in ("file", "thumbnail"):
            assert client.get(f"/mobile/cloud/{endpoint}/{path}", headers=headers).status_code == 404
        assert client.delete(f"/mobile/cloud/file/{path}", headers=headers).status_code == 404
    assert client.delete("/mobile/cloud/file/Test2/photo.jpg", headers=headers).status_code == 204
    assert deleted == ["Test2/photo.jpg"]

    # An unassigned folder with existing data cannot be claimed by a phone.
    assert client.put(
        "/mobile/config/photo-folder", headers=headers, json={"photo_folder": "NewNetGuard"}
    ).status_code == 409
    prior_phone, _ = _pair_security_phone(client)
    with Session(engine) as db:
        previous = db.get(MobileDevice, prior_phone["device_id"])
        previous.photo_folder = "ArchivedPhone"
        previous.is_active = False
        db.commit()
    # A revoked phone's saved assignment remains reserved even if its folder is absent.
    assert client.put(
        "/mobile/config/photo-folder", headers=headers, json={"photo_folder": "ArchivedPhone"}
    ).status_code == 409
    assert client.get("/mobile/config", headers=headers).json()["photo_folder"] == "Test2"


def test_failed_vps_revocation_closes_api_and_remains_retryable(mobile_client, monkeypatch):
    client, engine = mobile_client
    paired, headers = _pair_security_phone(client)
    with Session(engine) as db:
        device = db.get(MobileDevice, paired["device_id"])
        device.chameleon_address = "10.10.0.3/32"
        db.commit()
    registries = []
    fail = [True]
    def sync(devices):
        registries.append(devices)
        if fail[0]:
            raise OSError("simulated unavailable VPS")
    monkeypatch.setattr(mobile, "get_stealth_service", lambda: SimpleNamespace(mobile_credentials_update=nullcontext, sync_mobile_clients=sync))
    assert client.delete(f"/mobile/devices/{paired['device_id']}").status_code == 503
    assert client.get("/mobile/config", headers=headers).status_code == 401
    with Session(engine) as db:
        device = db.get(MobileDevice, paired["device_id"])
        assert device is not None and not device.is_active and device.revoked_at is not None
    fail[0] = False
    assert client.delete(f"/mobile/devices/{paired['device_id']}").status_code == 204
    assert registries == [[], []]


def test_mobile_address_assignment_repairs_duplicate_or_reserved_addresses(mobile_client):
    client, engine = mobile_client
    first, _ = _pair_security_phone(client)
    second, _ = _pair_security_phone(client)
    with Session(engine) as db:
        a, b = db.get(MobileDevice, first["device_id"]), db.get(MobileDevice, second["device_id"])
        a.chameleon_address = b.chameleon_address = "10.10.0.3/32"
        db.commit()
        assert mobile._mobile_chameleon_address(a, db) == "10.10.0.4/32"
        a.chameleon_address = "10.10.0.2/32"
        assert mobile._mobile_chameleon_address(a, db) == "10.10.0.4/32"


def test_home_tunnel_enrollment_is_stable_and_cannot_replace_identity(mobile_client):
    client, engine = mobile_client
    first, first_headers = _pair_security_phone(client)
    second, second_headers = _pair_security_phone(client)
    first_private, first_key, first_signature = _home_tunnel_identity(first["device_id"])
    _, second_key, second_signature = _home_tunnel_identity(first["device_id"])

    assert client.post(
        "/mobile/home-tunnel/enroll",
        json={"public_key": first_key, "signature": first_signature},
    ).status_code == 401
    enrolled = client.post(
        "/mobile/home-tunnel/enroll",
        headers=first_headers,
        json={"public_key": first_key, "signature": first_signature},
    )
    assert enrolled.status_code == 200
    assert enrolled.headers["cache-control"] == "no-store"
    assert enrolled.json() == {
        "address": "10.77.0.3/32",
        "state": "active",
        "credential_epoch": 1,
        "server_address": "myrelay.duckdns.org:9446",
        "server_dial_address": "",
        "psk_key": "11" * 32,
        "transport_key": "22" * 32,
        "reality_server_public_key": "33" * 32,
        "certificate_sha256": "ab" * 32,
        "buffer_size": 1000,
        "reconnect_interval": 5,
        "mtu": 1200,
        "prism_link_relay_address": "myrelay.duckdns.org:9447",
        "prism_link_relay_installation_id": "44" * 16,
        "prism_link_relay_route_key": "55" * 32,
        "prism_link_direct_address": "",
    }
    assert client.post(
        "/mobile/home-tunnel/enroll",
        headers=first_headers,
        json={"public_key": first_key, "signature": first_signature},
    ).json() == enrolled.json()

    replacement = client.post(
        "/mobile/home-tunnel/enroll",
        headers=first_headers,
        json={"public_key": second_key, "signature": second_signature},
    )
    assert replacement.status_code == 409
    assert first_key not in replacement.text and second_key not in replacement.text

    # A key cannot be claimed with a signature made for another device ID.
    stolen = client.post(
        "/mobile/home-tunnel/enroll",
        headers=second_headers,
        json={"public_key": first_key, "signature": first_signature},
    )
    assert stolen.status_code == 422
    assert first_key not in stolen.text

    _, second_key, second_signature = _home_tunnel_identity(second["device_id"])
    second_enrolled = client.post(
        "/mobile/home-tunnel/enroll",
        headers=second_headers,
        json={"public_key": second_key, "signature": second_signature},
    )
    assert second_enrolled.status_code == 200
    assert second_enrolled.json()["address"] == "10.77.0.4/32"

    with Session(engine) as db:
        first_device = db.get(MobileDevice, first["device_id"])
        assert first_device.home_tunnel_public_key == first_key
        assert first_device.home_tunnel_address == "10.77.0.3/32"
        assert first_device.home_tunnel_state == "active"
        assert first_device.protection_client_id == mobile._protection_client_id("10.77.0.3")


@pytest.mark.parametrize(
    "payload",
    [
        {"public_key": "x" * 80, "signature": "eA==eA=="},
        {
            "public_key": base64.b64encode(b"not a public key" * 8).decode("ascii"),
            "signature": base64.b64encode(b"not a signature").decode("ascii"),
        },
    ],
)
def test_home_tunnel_rejects_invalid_public_keys(mobile_client, payload):
    client, _engine = mobile_client
    _, headers = _pair_security_phone(client)
    response = client.post(
        "/mobile/home-tunnel/enroll",
        headers=headers,
        json=payload,
    )
    assert response.status_code == 422


def test_mobile_deletion_removes_home_tunnel_credential(mobile_client, monkeypatch):
    client, _ = mobile_client
    paired, headers = _pair_security_phone(client)
    device_id = paired["device_id"]
    _, key, signature = _home_tunnel_identity(device_id)
    registries = []
    monkeypatch.setattr(
        mobile, "sync_mobile_home_tunnel_registry",
        lambda devices: registries.append([device.id for device in devices]),
    )
    assert client.post(
        "/mobile/home-tunnel/enroll", headers=headers,
        json={"public_key": key, "signature": signature},
    ).status_code == 200
    assert client.delete(f"/mobile/devices/{device_id}").status_code == 204
    assert registries == [[device_id], []]


@pytest.fixture()
def mobile_client(monkeypatch: pytest.MonkeyPatch, tmp_path):
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(User(id=1, username="admin", password_hash="unused", role="admin", is_active=True))
        db.commit()

    def session_override():
        with Session(engine) as db:
            yield db

    async def exit_node_override() -> str:
        return "easypi"

    issued_tailscale_keys: list[str] = []

    async def auth_key_override() -> str:
        key = f"tskey-auth-test-{len(issued_tailscale_keys) + 1}"
        issued_tailscale_keys.append(key)
        return key

    monkeypatch.setattr(mobile, "_current_exit_node", exit_node_override)
    monkeypatch.setattr(mobile, "_create_mobile_tailscale_auth_key", auth_key_override)
    monkeypatch.setattr(mobile, "_tls_certificate_fingerprint", lambda: "ab" * 32)
    from app.services import mobile_home_tunnel_registry

    monkeypatch.setattr(
        mobile_home_tunnel_registry,
        "_registry_path",
        lambda: tmp_path / "mobile-home-tunnel-peers.json",
    )

    async def mobile_link_ready_override(
        _public_url: str, _certificate_sha256: str
    ) -> bool:
        return True

    monkeypatch.setattr(mobile, "_mobile_link_transport_ready", mobile_link_ready_override)
    monkeypatch.setattr(mobile, "mobile_prism_broker", MobilePrismBroker())
    mobile_link_state = {"config": MobileLinkConfig()}
    monkeypatch.setattr(mobile, "load_mobile_link_config", lambda: mobile_link_state["config"])

    def save_mobile_link(config: MobileLinkConfig) -> MobileLinkConfig:
        from app.services.mobile_link_config import validate_public_url

        public_url = validate_public_url(config.public_url)
        if config.enabled and public_url is None:
            raise ValueError("Enter the public Mobile Link address before enabling it")
        mobile_link_state["config"] = MobileLinkConfig(enabled=config.enabled, public_url=public_url)
        return mobile_link_state["config"]

    monkeypatch.setattr(mobile, "save_mobile_link_config", save_mobile_link)
    agent_state = {
        "configured": False,
        "enabled": False,
        "active": False,
        "installation_id": None,
        "relay_address": None,
        "server_name": None,
    }

    def run_agent(action: str, *arguments: str):
        if action == "configure":
            agent_state.update({
                "configured": True,
                "relay_address": arguments[0],
                "server_name": arguments[1],
                "installation_id": "0123456789abcdef0123456789abcdef",
            })
        elif action == "enable":
            agent_state.update({"enabled": True, "active": True})
        elif action == "disable":
            agent_state.update({"enabled": False, "active": False})
        return dict(agent_state)

    monkeypatch.setattr(mobile.mobile_link_agent_service, "run", run_agent)
    monkeypatch.setattr(
        mobile.mobile_link_agent_service,
        "home_profile",
        lambda _device_id, address, domain, port: {
            "address": address,
            "server_address": f"{domain}:{port}",
            "server_dial_address": "",
            "psk_key": "11" * 32,
            "transport_key": "22" * 32,
            "reality_server_public_key": "33" * 32,
            "buffer_size": 1000,
            "reconnect_interval": 5,
            "mtu": 1200,
            "prism_link_relay_address": f"{domain}:{port + 1}",
            "prism_link_relay_installation_id": "44" * 16,
            "prism_link_relay_route_key": "55" * 32,
            "prism_link_direct_address": "",
        },
    )
    monkeypatch.setattr(
        mobile.mobile_link_relay_service,
        "public_status",
        lambda: {"domain": "myrelay.duckdns.org", "mobile_port": 9444},
    )
    async def operate_relay(action: str, **arguments):
        return {
            "configured": action != "uninstall",
            "installed": action != "uninstall",
            "enabled": action not in {"disable", "uninstall"},
            "active": action not in {"disable", "uninstall"},
            "domain": arguments.get("domain", "myrelay.duckdns.org"),
            "agent_port": arguments.get("agent_port", 9443),
            "mobile_port": arguments.get("mobile_port", 9444),
        }

    monkeypatch.setattr(mobile.mobile_link_relay_service, "operate", operate_relay)
    policy = _ManagedDevicePolicy()
    for method in ("get_clients", "approve_client_transactional", "delete_client"):
        monkeypatch.setattr(mobile.netprotection_service, method, getattr(policy, method))
    app = FastAPI()
    app.include_router(mobile.router, prefix="/mobile")
    app.dependency_overrides[get_db] = session_override
    app.dependency_overrides[require_admin] = lambda: SimpleNamespace(id=1, role="admin")
    with TestClient(app) as client:
        client.policy = policy
        yield client, engine


class _ManagedDevicePolicy:
    """In-memory stand-in for the transactional managed-device policy."""

    def __init__(self) -> None:
        self.clients: list[dict] = []
        self.calls: list[tuple] = []
        self.fail_approval = False

    async def get_clients(self) -> dict:
        return {"clients": [dict(item) for item in self.clients]}

    async def approve_client_transactional(
        self, data: dict, *, require_existing: bool = False,
        existing_client_id: str | None = None,
        release_persistent_block: bool = False,
    ) -> dict:
        self.calls.append(("approve", dict(data), existing_client_id))
        if self.fail_approval:
            raise RuntimeError("simulated firewall activation failure")
        mac = sanitize_mac(data["mac"])
        if existing_client_id is not None:
            target = next(c for c in self.clients if c["id"] == existing_client_id)
        else:
            target = next((c for c in self.clients if sanitize_mac(c["mac"]) == mac), None)
        if target is None:
            if require_existing:
                raise ValueError("Managed device no longer exists")
            target = {"id": f"dev_{len(self.clients) + 1}", **data}
            self.clients.append(target)
        target.update({"ip": data["ip"], "ids": data["ids"], "mac": mac})
        return {"success": True, "client": dict(target)}

    async def delete_client(self, name: str) -> dict:
        self.calls.append(("delete", name))
        self.clients = [item for item in self.clients if item["name"] != name]
        return {"success": True}


def _tunnel_mac(device_id: str) -> str:
    return sanitize_mac(UnknownDeviceAdmissionService.mobile_tunnel_mac(device_id))


def _enroll(client, paired, headers, private_key=None):
    private_key, key, signature = _home_tunnel_identity(paired["device_id"], private_key)
    response = client.post(
        "/mobile/home-tunnel/enroll", headers=headers,
        json={"public_key": key, "signature": signature},
    )
    return private_key, response


def test_qr_paired_phone_gets_one_managed_device_without_banner(mobile_client):
    client, _ = mobile_client
    paired, headers = _pair_security_phone(client)
    private_key, enrolled = _enroll(client, paired, headers)
    assert enrolled.status_code == 200
    assert client.policy.clients == [{
        **ParentalMixin.managed_client_record(
            "Security regression phone (mobile)", "10.77.0.3",
            _tunnel_mac(paired["device_id"]), "balanced",
        ),
        "id": "dev_1",
    }]
    # Every later Protection start re-enrolls; it must not touch the policy.
    assert _enroll(client, paired, headers, private_key)[1].status_code == 200
    assert len(client.policy.calls) == 1


def test_repairing_the_same_phone_moves_its_identity_and_policy(mobile_client):
    client, engine = mobile_client
    first, first_headers = _pair_security_phone(client)
    private_key, enrolled = _enroll(client, first, first_headers)
    assert enrolled.status_code == 200
    client.policy.clients[0]["shield_profile"] = "kids"

    second, second_headers = _pair_security_phone(client)
    _, again = _enroll(client, second, second_headers, private_key)
    assert again.status_code == 200
    assert again.json()["address"] == "10.77.0.3/32"
    assert client.get("/mobile/config", headers=first_headers).status_code == 401
    with Session(engine) as db:
        assert db.get(MobileDevice, first["device_id"]) is None
    assert client.policy.calls[-1][2] == "dev_1"
    assert len(client.policy.clients) == 1
    assert client.policy.clients[0]["mac"] == _tunnel_mac(second["device_id"])
    assert client.policy.clients[0]["shield_profile"] == "kids"


def test_deleting_a_phone_removes_its_managed_device(mobile_client):
    client, _ = mobile_client
    paired, headers = _pair_security_phone(client)
    assert _enroll(client, paired, headers)[1].status_code == 200
    assert client.delete(f"/mobile/devices/{paired['device_id']}").status_code == 204
    assert client.policy.calls[-1] == ("delete", "Security regression phone (mobile)")
    assert client.policy.clients == []


def test_new_phone_never_receives_an_address_held_by_a_stale_policy(mobile_client):
    client, _ = mobile_client
    client.policy.clients.append({
        "id": "dev_old", "name": "Former phone", "ip": "10.77.0.3",
        "ids": ["10.77.0.3"], "mac": "02:11:22:33:44:55",
    })
    paired, headers = _pair_security_phone(client)
    _, enrolled = _enroll(client, paired, headers)
    assert enrolled.status_code == 200
    assert enrolled.json()["address"] == "10.77.0.4/32"
    assert client.policy.clients[-1]["ip"] == "10.77.0.4"


def test_failed_policy_activation_keeps_the_phone_fail_closed(mobile_client):
    client, _ = mobile_client
    client.policy.fail_approval = True
    paired, headers = _pair_security_phone(client)
    assert _enroll(client, paired, headers)[1].status_code == 200
    assert client.policy.clients == []


def test_mobile_link_probe_requires_exact_certificate_pin(monkeypatch) -> None:
    peer_certificate = b"peer-certificate-der"

    class FakeSocket:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

    class FakeTls(FakeSocket):
        def getpeercert(self, *, binary_form: bool):
            assert binary_form is True
            return peer_certificate

        def settimeout(self, _timeout: float) -> None:
            return None

        def sendall(self, request: bytes) -> None:
            assert request.startswith(b"GET /api/v1/mobile/ping HTTP/1.1\r\n")

        def recv(self, _size: int) -> bytes:
            return b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"

    class FakeContext:
        minimum_version = None
        check_hostname = True
        verify_mode = None

        def wrap_socket(self, _raw, *, server_hostname: str):
            assert server_hostname == "relay.example"
            return FakeTls()

    monkeypatch.setattr(mobile.socket, "create_connection", lambda *_args, **_kwargs: FakeSocket())
    monkeypatch.setattr(mobile.ssl, "SSLContext", lambda _protocol: FakeContext())
    fingerprint = mobile.hashlib.sha256(peer_certificate).hexdigest()

    assert mobile._probe_pinned_mobile_link("https://relay.example:9444", fingerprint) is True
    assert mobile._probe_pinned_mobile_link("https://relay.example:9444", "00" * 32) is False


def test_pairing_code_is_single_use_and_token_is_not_stored_plaintext(mobile_client) -> None:
    client, engine = mobile_client
    started = client.post("/mobile/pairing/start")
    assert started.status_code == 200
    assert started.json()["expires_at"].endswith("Z")
    pairing_code = started.json()["pairing_code"]

    completed = client.post(
        "/mobile/pairing/complete",
        json={"pairing_code": pairing_code, "device_name": "Test Phone"},
    )
    assert completed.status_code == 200
    assert completed.headers["cache-control"] == "no-store"
    token = completed.json()["mobile_token"]
    tailscale_auth_key = completed.json()["tailscale_auth_key"]
    assert len(token) >= 48
    assert tailscale_auth_key is None

    replay = client.post(
        "/mobile/pairing/complete",
        json={"pairing_code": pairing_code, "device_name": "Replay"},
    )
    assert replay.status_code == 400

    with Session(engine) as db:
        device = db.execute(select(MobileDevice)).scalar_one()
        assert device.token_hash != token
        assert pairing_code not in device.token_hash
        assert "tskey-auth-" not in repr(device.__dict__)


def test_mobile_link_address_is_admin_configured_and_added_to_pairing_qr(mobile_client) -> None:
    client, _engine = mobile_client

    saved = client.put(
        "/mobile/link/settings",
        json={"enabled": True, "public_url": "https://myrelay.duckdns.org:9444/"},
    )
    assert saved.status_code == 200
    assert saved.json() == {
        "enabled": True,
        "public_url": "https://myrelay.duckdns.org:9444",
    }
    configured = client.put(
        "/mobile/link/agent",
        json={
            "relay_address": "myrelay.duckdns.org:9443",
            "server_name": "myrelay.duckdns.org",
        },
    )
    assert configured.status_code == 200

    started = client.post("/mobile/pairing/start")
    assert started.status_code == 200
    assert started.json()["server_url"] == "https://myrelay.duckdns.org:9444"
    assert client.get("/mobile/link/agent").json()["active"] is True


def test_pairing_refuses_to_publish_unconfigured_mobile_link(mobile_client) -> None:
    client, _engine = mobile_client
    saved = client.put(
        "/mobile/link/settings",
        json={"enabled": True, "public_url": "https://myrelay.duckdns.org:9444"},
    )
    assert saved.status_code == 200

    started = client.post("/mobile/pairing/start")

    assert started.status_code == 503
    assert started.json()["detail"] == "Remote Mobile Link is enabled but not configured"


def test_pairing_refuses_qr_until_public_mobile_link_is_reachable(
    mobile_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _engine = mobile_client
    saved = client.put(
        "/mobile/link/settings",
        json={"enabled": True, "public_url": "https://myrelay.duckdns.org:9444"},
    )
    assert saved.status_code == 200
    configured = client.put(
        "/mobile/link/agent",
        json={
            "relay_address": "myrelay.duckdns.org:9443",
            "server_name": "myrelay.duckdns.org",
        },
    )
    assert configured.status_code == 200

    async def unavailable(_public_url: str, _certificate_sha256: str) -> bool:
        return False

    monkeypatch.setattr(mobile, "_mobile_link_transport_ready", unavailable)
    started = client.post("/mobile/pairing/start")

    assert started.status_code == 503
    assert started.json()["detail"] == "Remote Mobile Link is still starting or unavailable"


@pytest.mark.parametrize(
    "unsafe_url",
    [
        "http://myrelay.duckdns.org:9444",
        "https://user:password@myrelay.duckdns.org:9444",
        "https://myrelay.duckdns.org:9444/api",
        "https://myrelay.duckdns.org:9444?token=secret",
    ],
)
def test_mobile_link_rejects_unsafe_public_addresses(mobile_client, unsafe_url: str) -> None:
    client, _engine = mobile_client
    response = client.put(
        "/mobile/link/settings",
        json={"enabled": True, "public_url": unsafe_url},
    )
    assert response.status_code == 422


def test_mobile_link_agent_configuration_and_lifecycle_are_admin_endpoints(mobile_client) -> None:
    client, _engine = mobile_client
    configured = client.put(
        "/mobile/link/agent",
        json={
            "relay_address": "myrelay.duckdns.org:9443",
            "server_name": "myrelay.duckdns.org",
        },
    )
    assert configured.status_code == 200
    assert configured.json()["configured"] is True
    assert configured.json()["relay_address"] == "myrelay.duckdns.org:9443"
    assert configured.json()["installation_id"] == "0123456789abcdef0123456789abcdef"

    enabled = client.post("/mobile/link/agent/enable")
    assert enabled.status_code == 200
    assert enabled.json()["enabled"] is True
    assert enabled.json()["active"] is True

    disabled = client.post("/mobile/link/agent/disable")
    assert disabled.status_code == 200
    assert disabled.json()["enabled"] is False
    assert disabled.json()["active"] is False

    assert client.post("/mobile/link/agent/reformat-disk").status_code == 404


def test_relay_deployment_configures_agent_and_remote_pairing_address(mobile_client) -> None:
    client, _engine = mobile_client
    response = client.post(
        "/mobile/link/relay/deploy",
        json={
            "host": "93.184.216.34",
            "ssh_port": 22,
            "ssh_user": "root",
            "auth_method": "password",
            "domain": "myrelay.duckdns.org",
            "agent_port": 9443,
            "mobile_port": 9444,
        },
    )
    assert response.status_code == 200
    assert response.json()["active"] is True

    agent = client.get("/mobile/link/agent").json()
    assert agent["relay_address"] == "myrelay.duckdns.org:9443"
    assert agent["active"] is True

    pairing = client.post("/mobile/pairing/start").json()
    assert pairing["server_url"] == "https://myrelay.duckdns.org:9444"


def test_pairing_succeeds_when_optional_tailscale_key_creation_fails(
    mobile_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, engine = mobile_client
    pairing_code = client.post("/mobile/pairing/start").json()["pairing_code"]

    async def unavailable() -> str:
        raise RuntimeError("Admin API unavailable")

    monkeypatch.setattr(mobile, "_create_mobile_tailscale_auth_key", unavailable)
    failed = client.post(
        "/mobile/pairing/complete",
        json={"pairing_code": pairing_code, "device_name": "Test Phone"},
    )
    assert failed.status_code == 200
    assert failed.json()["tailscale_auth_key"] is None
    assert failed.json()["tailscale_exit_node"] == "easypi"
    replay = client.post(
        "/mobile/pairing/complete",
        json={"pairing_code": pairing_code, "device_name": "Test Phone"},
    )
    assert replay.status_code == 400
    with Session(engine) as db:
        assert db.execute(select(MobileDevice)).scalar_one().name == "Test Phone"


def test_mobile_ping_requires_device_authentication(mobile_client) -> None:
    client, _engine = mobile_client
    assert client.get("/mobile/ping").status_code == 401
    pairing_code = client.post("/mobile/pairing/start").json()["pairing_code"]
    paired = client.post(
        "/mobile/pairing/complete",
        json={"pairing_code": pairing_code, "device_name": "Link Test Phone"},
    ).json()

    response = client.get(
        "/mobile/ping",
        headers={"Authorization": f"Bearer {paired['mobile_token']}"},
    )

    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.json()["status"] == "ok"
    assert response.json()["device_id"] == paired["device_id"]
    assert response.json()["device_name"] == "Link Test Phone"
    assert response.json()["server_time"].endswith("Z")


def test_mobile_config_identifies_direct_and_mobile_link_paths(mobile_client) -> None:
    client, _engine = mobile_client
    pairing_code = client.post("/mobile/pairing/start").json()["pairing_code"]
    paired = client.post(
        "/mobile/pairing/complete",
        json={"pairing_code": pairing_code, "device_name": "Path Test Phone"},
    ).json()
    authorization = {"Authorization": f"Bearer {paired['mobile_token']}"}

    direct = client.get(
        "/mobile/config",
        headers={**authorization, "X-Real-IP": "10.23.1.10"},
    )
    tunneled = client.get(
        "/mobile/config",
        headers={**authorization, "X-Real-IP": "127.0.0.1"},
    )

    assert direct.status_code == 200
    assert direct.json()["connection_path"] == "direct"
    assert tunneled.status_code == 200
    assert tunneled.json()["connection_path"] == "mobile_link"

    spoofed = SimpleNamespace(
        headers={"x-real-ip": "127.0.0.1"},
        client=SimpleNamespace(host="198.51.100.10"),
    )
    assert mobile._mobile_connection_path(spoofed) == "direct"

    packaged_mobile_link = SimpleNamespace(
        headers={"x-real-ip": "127.0.0.1"},
        client=None,
    )
    packaged_direct = SimpleNamespace(
        headers={"x-real-ip": "10.23.1.15"},
        client=None,
    )
    assert mobile._mobile_connection_path(packaged_mobile_link) == "mobile_link"
    assert mobile._mobile_connection_path(packaged_direct) == "direct"
    assert mobile._observed_client_ip(packaged_direct) == "10.23.1.15"


def test_pairing_can_skip_optional_tailscale_provisioning(mobile_client, monkeypatch: pytest.MonkeyPatch) -> None:
    client, _engine = mobile_client
    pairing_code = client.post("/mobile/pairing/start").json()["pairing_code"]

    async def must_not_run() -> str:
        raise AssertionError("Tailscale provisioning must be opt-in for the new Mobile Link client")

    monkeypatch.setattr(mobile, "_create_mobile_tailscale_auth_key", must_not_run)
    response = client.post(
        "/mobile/pairing/complete",
        json={
            "pairing_code": pairing_code,
            "device_name": "Mobile Link Phone",
            "provision_tailscale": False,
        },
    )

    assert response.status_code == 200
    assert response.json()["tailscale_auth_key"] is None


def test_tailscale_enrollment_is_separate_and_device_authenticated(mobile_client) -> None:
    client, engine = mobile_client
    pairing_code = client.post("/mobile/pairing/start").json()["pairing_code"]
    paired = client.post(
        "/mobile/pairing/complete",
        json={"pairing_code": pairing_code, "device_name": "Optional VPN Phone"},
    ).json()
    endpoint = "/mobile/tailscale/enrollment"
    assert client.post(endpoint).status_code == 401

    response = client.post(
        endpoint,
        headers={"Authorization": f"Bearer {paired['mobile_token']}"},
    )

    assert response.status_code == 410
    assert "Chameleon" in response.json()["detail"]
    with Session(engine) as db:
        device = db.get(MobileDevice, paired["device_id"])
        assert device is not None
        assert device.tailscale_exit_node == "easypi"


def test_mobile_token_has_narrow_access_and_deletion_is_permanent(mobile_client) -> None:
    client, engine = mobile_client
    pairing_code = client.post("/mobile/pairing/start").json()["pairing_code"]
    paired = client.post(
        "/mobile/pairing/complete",
        json={"pairing_code": pairing_code, "device_name": "Child Phone"},
    ).json()
    headers = {"Authorization": f"Bearer {paired['mobile_token']}"}

    config = client.get("/mobile/config", headers=headers)
    assert config.status_code == 200
    assert config.json()["device_name"] == "Child Phone"
    assert config.json()["tailscale_exit_node"] == "easypi"

    deleted = client.delete(f"/mobile/devices/{paired['device_id']}")
    assert deleted.status_code == 204
    assert client.get("/mobile/config", headers=headers).status_code == 401
    assert client.get("/mobile/devices").json() == []
    with Session(engine) as db:
        assert db.get(MobileDevice, paired["device_id"]) is None


def test_invalid_mobile_tokens_are_rejected(mobile_client) -> None:
    client, _engine = mobile_client
    assert client.get("/mobile/config").status_code == 401
    assert client.get("/mobile/config", headers={"Authorization": "Bearer invalid"}).status_code == 401


def test_prism_dns_uses_easypi_policy_and_mobile_auth(
    mobile_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _engine = mobile_client
    pairing_code = client.post("/mobile/pairing/start").json()["pairing_code"]
    paired = client.post(
        "/mobile/pairing/complete",
        json={"pairing_code": pairing_code, "device_name": "PRISM Phone"},
    ).json()

    class FakeBlocklist:
        def __init__(self) -> None:
            self.reloaded = False
            self.observed: list[tuple[str, bool]] = []

        def reload_if_changed(self) -> bool:
            self.reloaded = True
            return True

        def is_blocked(self, domain: str, check_allowlist: bool = True) -> bool:
            self.observed.append((domain, check_allowlist))
            return domain == "ads.example.com"

    policy = FakeBlocklist()
    monkeypatch.setattr(mobile, "get_blocklist_filter", lambda: policy)
    endpoint = "/mobile/prism/dns/check"
    assert client.post(endpoint, json={"domain": "ads.example.com"}).status_code == 401

    headers = {"Authorization": f"Bearer {paired['mobile_token']}"}
    blocked = client.post(
        endpoint,
        headers=headers,
        json={"domain": "ADS.Example.com.", "package_name": "com.example.app"},
    )
    assert blocked.status_code == 200
    body = blocked.json()
    assert len(body.pop("policy_version")) == 16
    assert body == {
        "domain": "ads.example.com",
        "blocked": True,
        "reason": "easypi_blocklist",
        "cache_ttl_seconds": 60,
    }
    allowed = client.post(endpoint, headers=headers, json={"domain": "example.org"})
    assert allowed.status_code == 200
    assert allowed.json()["blocked"] is False
    assert policy.reloaded
    assert policy.observed == [("ads.example.com", True), ("example.org", True)]


def test_prism_dns_uses_authenticated_phones_parental_profile(mobile_client, monkeypatch, tmp_path):
    from easypi_netprotection.profiles.manager import ProfileManager

    client, engine = mobile_client
    phone, headers = _pair_security_phone(client)
    _, other_headers = _pair_security_phone(client)
    with Session(engine) as db:
        device = db.get(MobileDevice, phone["device_id"])
        device.home_tunnel_address = "10.77.0.3/32"
        device.home_tunnel_state = "active"
        db.commit()
    manager = ProfileManager(str(tmp_path / "profiles"))
    profile = manager.create_profile(
        name="Phone parental profile", blacklist=["blocked.example.com"],
    )
    manager.update_profile(profile.id, parental_enabled=True)
    manager.create_binding(profile.id, "ip", "10.23.1.13", name="Home Wi-Fi")
    manager.create_binding(profile.id, "ip", "10.77.0.3", name="Home tunnel")
    assert manager.lookup_profile("10.23.1.13").id == profile.id
    assert manager.lookup_profile("10.77.0.3").id == profile.id
    monkeypatch.setattr(mobile, "get_profile_manager", lambda: manager)
    monkeypatch.setattr(mobile, "get_blocklist_filter", lambda: SimpleNamespace(
        reload_if_changed=lambda: None, is_blocked=lambda *_args, **_kwargs: False,
    ))
    endpoint = "/mobile/prism/dns/check"
    payload = {"domain": "blocked.example.com"}
    assert client.post(endpoint, headers=headers, json=payload).json()["reason"] == "parental_profile"
    assert client.post(endpoint, headers=other_headers, json=payload).json()["blocked"] is False


def test_prism_dns_rejects_invalid_domain_and_package(mobile_client) -> None:
    client, _engine = mobile_client
    pairing_code = client.post("/mobile/pairing/start").json()["pairing_code"]
    paired = client.post(
        "/mobile/pairing/complete",
        json={"pairing_code": pairing_code, "device_name": "PRISM Phone"},
    ).json()
    headers = {"Authorization": f"Bearer {paired['mobile_token']}"}
    endpoint = "/mobile/prism/dns/check"

    assert client.post(endpoint, headers=headers, json={"domain": "localhost"}).status_code == 422
    assert client.post(
        endpoint,
        headers=headers,
        json={"domain": "example.com", "package_name": "bad package"},
    ).status_code == 422


def test_prism_flow_commands_are_authenticated_addressed_and_short_lived(
    mobile_client, monkeypatch: pytest.MonkeyPatch
) -> None:
    client, _engine = mobile_client
    pairing_code = client.post("/mobile/pairing/start").json()["pairing_code"]
    paired = client.post(
        "/mobile/pairing/complete",
        json={"pairing_code": pairing_code, "device_name": "PRISM Phone"},
    ).json()
    headers = {"Authorization": f"Bearer {paired['mobile_token']}"}

    assert client.post("/mobile/prism/presence", json={"addresses": ["10.23.1.16"]}).status_code == 401
    monkeypatch.setattr(mobile, "_observed_client_ip", lambda _request: "10.23.1.16")
    presence = client.post(
        "/mobile/prism/presence", headers=headers, json={"addresses": ["10.23.1.16", "127.0.0.1"]}
    )
    assert presence.status_code == 204

    candidate = SimpleNamespace(
        client_ip="10.23.1.16",
        client_port=43120,
        server_ip="157.240.241.17",
        server_port=443,
        protocol="tcp",
        policy="facebook",
        confidence=0.93,
    )
    assert mobile.mobile_prism_broker.enqueue_candidate(candidate) == 1
    commands = client.get("/mobile/prism/commands", headers=headers)
    assert commands.status_code == 200
    assert len(commands.json()) == 1
    command = commands.json()[0]
    assert command["client_port"] == 43120
    assert command["server_ip"] == "157.240.241.17"
    assert command["policy"] == "facebook"

    ack = client.post(
        "/mobile/prism/commands/ack",
        headers=headers,
        json={"command_id": command["id"], "result": "matched", "package_name": "com.facebook.katana"},
    )
    assert ack.status_code == 204
    confirmations = mobile.mobile_prism_broker.pop_confirmed()
    assert len(confirmations) == 1
    assert confirmations[0].command.id == command["id"]
    assert confirmations[0].package_name == "com.facebook.katana"
    assert client.post(
        "/mobile/prism/commands/ack",
        headers=headers,
        json={"command_id": command["id"], "result": "matched"},
    ).status_code == 404


def test_prism_broker_only_promotes_owned_home_flow_confirmation() -> None:
    broker = MobilePrismBroker()
    broker.register("phone", ["192.168.1.10"], now=100.0)
    candidate = SimpleNamespace(
        client_ip="192.168.1.10",
        client_port=1234,
        server_ip="203.0.113.7",
        server_port=443,
        protocol="tcp",
        policy="test",
        confidence=0.9,
    )
    assert broker.enqueue_candidate(candidate, now=101.0) == 1
    command = broker.claim("phone", now=101.0)[0]
    assert broker.acknowledge(
        "phone",
        command.id,
        result="matched",
        package_name="com.example.app",
        now=101.1,
    )
    confirmation = broker.pop_confirmed(now=101.2)
    assert len(confirmation) == 1
    assert confirmation[0].package_name == "com.example.app"

    assert broker.enqueue_candidate(candidate, now=102.0) == 1
    unsupported = broker.claim("phone", now=102.0)[0]
    assert broker.acknowledge(
        "phone",
        unsupported.id,
        result="unsupported",
        package_name="com.example.app",
        now=102.1,
    )
    assert broker.pop_confirmed(now=102.2) == []


def test_prism_broker_does_not_cross_address_devices() -> None:
    broker = MobilePrismBroker()
    broker.register("phone-a", ["192.168.1.10"], now=100.0)
    broker.register("phone-b", ["192.168.1.11"], now=100.0)
    candidate = SimpleNamespace(
        client_ip="192.168.1.10",
        client_port=1234,
        server_ip="203.0.113.7",
        server_port=443,
        protocol="tcp",
        policy="test",
        confidence=0.9,
    )
    assert broker.enqueue_candidate(candidate, now=101.0) == 1
    assert len(broker.claim("phone-a", now=101.0)) == 1
    assert broker.claim("phone-b", now=101.0) == []
    assert broker.claim("phone-a", now=110.0) == []


def test_blank_device_names_are_rejected(mobile_client) -> None:
    client, _engine = mobile_client
    pairing_code = client.post("/mobile/pairing/start").json()["pairing_code"]
    response = client.post(
        "/mobile/pairing/complete",
        json={"pairing_code": pairing_code, "device_name": "   "},
    )
    assert response.status_code == 422


def test_existing_mobile_devices_table_gets_current_columns() -> None:
    engine = create_engine("sqlite://", poolclass=StaticPool)
    with engine.begin() as connection:
        connection.execute(text("CREATE TABLE mobile_devices (id VARCHAR(36) PRIMARY KEY)"))

    ensure_mobile_device_columns(engine, strict=True)
    ensure_mobile_device_columns(engine, strict=True)

    columns = {column["name"] for column in inspect(engine).get_columns("mobile_devices")}
    assert columns == {
        "id",
        "photo_folder",
        "protection_client_id",
        "chameleon_address",
        "home_tunnel_public_key",
        "home_tunnel_address",
        "home_tunnel_state",
        "home_tunnel_credential_epoch",
        "home_tunnel_last_handshake_at",
    }


def test_mobile_chameleon_enrollment_assigns_an_independent_tunnel_address(
    mobile_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, engine = mobile_client
    pairing_code = client.post("/mobile/pairing/start").json()["pairing_code"]
    paired = client.post(
        "/mobile/pairing/complete",
        json={"pairing_code": pairing_code, "device_name": "Chameleon Phone"},
    ).json()
    observed: dict[str, str] = {}

    def profile(address: str, device_id: str) -> dict[str, object]:
        observed["device_id"] = device_id
        observed["address"] = address
        return {
            "address": address,
            "server_address": "vpn.example.test:443",
            "server_dial_address": "192.0.2.3:443",
            "psk_key": "11" * 32,
            "transport_key": "33" * 32,
            "protocol": "http2",
            "reality_server_public_key": "22" * 32,
            "verify_server_certificate": True,
            "doh_domain": "",
            "buffer_size": 1000,
            "reconnect_interval": 5,
            "fingerprint_mode": "mobile",
            "mtu": 1420,
        }

    monkeypatch.setattr(
        mobile,
        "get_stealth_service",
        lambda: SimpleNamespace(mobile_client_profile=profile, mobile_credentials_update=nullcontext, sync_mobile_clients=lambda items: observed.update(registry=items)),
    )
    assert client.post("/mobile/chameleon/enroll").status_code == 401
    response = client.post(
        "/mobile/chameleon/enroll",
        headers={"Authorization": f"Bearer {paired['mobile_token']}"},
    )
    assert response.status_code == 200
    assert observed["address"] == "10.10.0.3/32"
    assert observed["device_id"] == paired["device_id"]
    assert observed["registry"] == [{"id": paired["device_id"], "address": "10.10.0.3/32"}]
    assert response.json() == {
        "address": "10.10.0.3/32",
        "server_address": "vpn.example.test:443",
        "server_dial_address": "192.0.2.3:443",
        "server_dial_address6": "",
        "psk_key": "11" * 32,
        "transport_key": "33" * 32,
        "protocol": "http2",
        "reality_server_public_key": "22" * 32,
        "verify_server_certificate": True,
        "doh_domain": "",
        "buffer_size": 1000,
        "reconnect_interval": 5,
        "fingerprint_mode": "mobile",
        "mtu": 1420,
    }
    with Session(engine) as db:
        device = db.execute(select(MobileDevice)).scalar_one()
        assert device.chameleon_address == "10.10.0.3/32"
        assert device.protection_client_id == hashlib.sha256(b"10.10.0.3").hexdigest()[:16]


def test_mobile_upload_uses_cloud_auto_sort(mobile_client, monkeypatch: pytest.MonkeyPatch) -> None:
    client, _engine = mobile_client
    pairing_code = client.post("/mobile/pairing/start").json()["pairing_code"]
    paired = client.post(
        "/mobile/pairing/complete",
        json={"pairing_code": pairing_code, "device_name": "Upload Phone"},
    ).json()
    observed: dict[str, object] = {}

    async def upload_override(files, target: str, auto_sort: bool):
        observed["filename"] = files[0].filename
        observed["target"] = target
        observed["auto_sort"] = auto_sort
        return UploadResponse(uploaded=[])

    monkeypatch.setattr(mobile.pi_cloud_service, "upload_files", upload_override)
    response = client.post(
        "/mobile/upload",
        headers={"Authorization": f"Bearer {paired['mobile_token']}"},
        files={"file": ("document.pdf", b"content", "application/pdf")},
    )
    assert response.status_code == 200
    assert observed == {
        "filename": "document.pdf",
        "target": "/",
        "auto_sort": True,
    }


def test_phone_photo_folder_is_used_for_photo_and_video_uploads(
    mobile_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, engine = mobile_client
    pairing_code = client.post("/mobile/pairing/start").json()["pairing_code"]
    paired = client.post(
        "/mobile/pairing/complete",
        json={"pairing_code": pairing_code, "device_name": "Test Phone"},
    ).json()
    headers = {"Authorization": f"Bearer {paired['mobile_token']}"}
    created: list[str] = []
    uploads: list[tuple[str, bool]] = []

    monkeypatch.setattr(mobile.pi_cloud_service, "create_folder", lambda path, **_kwargs: created.append(path))

    async def upload_override(files, target: str, auto_sort: bool, *, require_target: bool, deduplicate: bool = False, generate_preview: bool = True, source_modified: float | None = None):
        assert require_target
        assert generate_preview is not deduplicate
        uploads.append((target, auto_sort, deduplicate))
        return UploadResponse(uploaded=[])

    monkeypatch.setattr(mobile.pi_cloud_service, "upload_files", upload_override)
    configured = client.put(
        "/mobile/config/photo-folder",
        headers=headers,
        json={"photo_folder": " Фотографии "},
    )
    assert configured.status_code == 200
    assert configured.json() == {"photo_folder": "Фотографии", "backup_videos": False}
    assert created == ["Фотографии"]
    assert client.get("/mobile/config", headers=headers).json()["photo_folder"] == "Фотографии"
    with Session(engine) as db:
        assert db.execute(select(MobileDevice.photo_folder)).scalar_one() == "Фотографии"

    photo = client.post(
        "/mobile/upload",
        headers=headers,
        data={"photo_backup": "true"},
        files={"file": ("photo.jpg", b"content", "image/jpeg")},
    )
    video = client.post(
        "/mobile/upload",
        headers=headers,
        files={"file": ("clip.mp4", b"content", "video/mp4")},
    )
    assert photo.status_code == 200
    assert video.status_code == 200
    assert uploads == [("Фотографии", False, True), ("Фотографии", False, False)]


def test_mobile_photo_retry_reuses_identical_content(mobile_client, monkeypatch, tmp_path):
    from app.services import picloud_service as cloud

    client, engine = mobile_client
    paired, headers = _pair_security_phone(client)
    root = tmp_path / "cloud"
    folder = root / "Test2"
    folder.mkdir(parents=True)
    (folder / "existing.jpg").write_bytes(b"original")
    monkeypatch.setattr(cloud, "STORAGE_ROOT", root)
    monkeypatch.setattr(mobile.pi_cloud_service, "_generate_thumbnail", lambda *_: None)
    with Session(engine) as db:
        db.get(MobileDevice, paired["device_id"]).photo_folder = "Test2"
        db.commit()

    def upload(name, contents):
        return client.post(
            "/mobile/upload", headers=headers, data={"photo_backup": "true"},
            files={"file": (name, contents, "image/jpeg")},
        )

    same = upload("renamed.jpg", b"original")
    assert same.status_code == 200
    assert same.json()["uploaded"][0]["name"] == "existing.jpg"
    assert len(list(folder.iterdir())) == 1

    different = upload("existing.jpg", b"different"[:8])
    assert different.status_code == 200
    assert different.json()["uploaded"][0]["name"] != "existing.jpg"
    assert len(list(folder.iterdir())) == 2
    assert (folder / "existing.jpg").read_bytes() == b"original"

    video = client.post(
        "/mobile/upload", headers=headers, data={"photo_backup": "true"},
        files={"file": ("clip.mp4", b"video", "video/mp4")},
    )
    assert video.status_code == 400


def test_mobile_video_opt_in_and_capture_date_order(mobile_client, tmp_path, monkeypatch):
    from app.services import picloud_service as cloud

    client, _engine = mobile_client
    _paired, headers = _pair_security_phone(client)
    root = tmp_path / "cloud"
    root.mkdir()
    monkeypatch.setattr(cloud, "STORAGE_ROOT", root)

    def configure(enable):
        return client.put(
            "/mobile/config/photo-folder", headers=headers,
            json={"photo_folder": "Test2", "backup_videos": enable},
        )

    def upload(name, media_type, timestamp):
        backup = "video_backup" if media_type.startswith("video/") else "photo_backup"
        return client.post(
            "/mobile/upload", headers=headers,
            data={backup: "true", "captured_at_ms": timestamp},
            files={"file": (name, name.encode(), media_type)},
        )

    assert configure(False).status_code == 200
    assert not (root / "Test2" / "Videos").exists()
    assert upload("blocked.mp4", "video/mp4", 1700000000000).status_code == 409
    legacy_video = root / "Test2" / "legacy.mp4"
    legacy_video.write_bytes(b"legacy")
    os.utime(legacy_video, (1500000000, 1500000000))
    assert configure(True).json()["backup_videos"] is True
    assert not legacy_video.exists()
    assert (root / "Test2" / "Videos" / "legacy.mp4").is_file()

    for extension, mime, category, directory in (
        ("mp4", "video/mp4", "videos", root / "Test2" / "Videos"),
        ("jpg", "image/jpeg", "photos", root / "Test2"),
    ):
        assert upload(f"new.{extension}", mime, 1700000000000).status_code == 200
        assert upload(f"old.{extension}", mime, 1600000000000).status_code == 200
        result = client.get("/mobile/cloud/files", headers=headers, params={"category": category})
        expected = [f"new.{extension}", f"old.{extension}"]
        if category == "videos":
            expected.append("legacy.mp4")
        assert [item["name"] for item in result.json()["items"]] == expected
        assert (directory / f"new.{extension}").stat().st_mtime == 1700000000
        assert (directory / f"old.{extension}").stat().st_mtime == 1600000000

    phone_folder = mobile.pi_cloud_service.list_files(
        "Test2", sort_by="modified", sort_order="desc"
    )
    assert [item.name for item in phone_folder.items] == ["Videos", "new.jpg", "old.jpg"]
    video_folder = mobile.pi_cloud_service.list_files(
        "Test2/Videos", sort_by="modified", sort_order="desc"
    )
    assert [item.name for item in video_folder.items] == ["new.mp4", "old.mp4", "legacy.mp4"]


@pytest.mark.parametrize("folder_name", [".hidden", "../escape", "Photos", "Videos", "name\\child"])
def test_phone_photo_folder_rejects_hidden_reserved_and_nested_names(mobile_client, folder_name: str) -> None:
    client, _engine = mobile_client
    pairing_code = client.post("/mobile/pairing/start").json()["pairing_code"]
    paired = client.post(
        "/mobile/pairing/complete",
        json={"pairing_code": pairing_code, "device_name": "Folder Test"},
    ).json()
    response = client.put(
        "/mobile/config/photo-folder",
        headers={"Authorization": f"Bearer {paired['mobile_token']}"},
        json={"photo_folder": folder_name},
    )
    assert response.status_code == 422


@pytest.mark.parametrize("folder", [None, "Missing", "Alias"])
def test_mobile_cloud_list_never_falls_back_to_shared_root(mobile_client, monkeypatch, tmp_path, folder):
    from app.services import picloud_service as cloud

    client, engine = mobile_client
    paired, headers = _pair_security_phone(client)
    root = tmp_path / "cloud"
    other = root / "NewNetGuard"
    other.mkdir(parents=True)
    (other / "photo.jpg").write_bytes(b"other phone")
    (root / "Alias").symlink_to(other, target_is_directory=True)
    monkeypatch.setattr(cloud, "STORAGE_ROOT", root)
    with Session(engine) as db:
        db.get(MobileDevice, paired["device_id"]).photo_folder = folder
        db.commit()

    assert client.get("/mobile/cloud/files").status_code == 401
    response = client.get("/mobile/cloud/files", headers=headers)
    assert response.status_code == 200
    assert response.json()["total_count"] == 0
    assert response.json()["items"] == []
    assert client.get("/mobile/cloud/file/Alias/photo.jpg", headers=headers).status_code == 404


def test_mobile_camera_access_exposes_no_network_credentials(
    mobile_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, engine = mobile_client
    with Session(engine) as db:
        db.add(Camera(
            id="camera-1",
            name="Front Door",
            ip="192.168.1.50",
            port=554,
            username="camera-admin",
            password="encrypted-secret",
            location="Entrance",
            status="online",
        ))
        db.commit()
    pairing_code = client.post("/mobile/pairing/start").json()["pairing_code"]
    paired = client.post(
        "/mobile/pairing/complete",
        json={"pairing_code": pairing_code, "device_name": "Camera Phone"},
    ).json()
    headers = {"Authorization": f"Bearer {paired['mobile_token']}"}

    cameras = client.get("/mobile/cameras", headers=headers)
    assert cameras.status_code == 200
    assert cameras.json() == [{
        "id": "camera-1",
        "name": "Front Door",
        "location": "Entrance",
        "status": "online",
    }]
    assert "192.168.1.50" not in cameras.text
    assert "camera-admin" not in cameras.text
    assert "encrypted-secret" not in cameras.text

    observed: list[str] = []

    async def snapshot_override(camera: Camera) -> Response:
        observed.append(camera.id)
        return Response(content=b"jpeg-frame", media_type="image/jpeg")

    monkeypatch.setattr(mobile, "capture_camera_snapshot", snapshot_override)
    assert client.get("/mobile/cameras/camera-1/snapshot").status_code == 401
    snapshot = client.get("/mobile/cameras/camera-1/snapshot", headers=headers)
    assert snapshot.status_code == 200
    assert snapshot.headers["content-type"] == "image/jpeg"
    assert snapshot.content == b"jpeg-frame"
    assert observed == ["camera-1"]


def test_mobile_protection_stats_are_bounded_and_device_authenticated(
    mobile_client,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client, _engine = mobile_client
    assert client.get("/mobile/protection/stats").status_code == 401
    pairing_code = client.post("/mobile/pairing/start").json()["pairing_code"]
    paired = client.post(
        "/mobile/pairing/complete",
        json={"pairing_code": pairing_code, "device_name": "Dashboard Phone"},
    ).json()

    observed_client_ids: list[str] = []

    async def stats_override(client_id: str):
        observed_client_ids.append(client_id)
        return {
            "num_dns_queries": 200,
            "num_blocked_filtering": 50,
            "dns_queries": [10, 20, 30],
            "blocked_filtering": [1, 5, 10],
            "top_blocked_domains": {"ads.example": 2, "tracker.example": 1},
        }

    monkeypatch.setattr(mobile.netprotection_service, "get_mobile_client_stats_by_id", stats_override)
    monkeypatch.setattr(mobile, "_mobile_connection_path", lambda _request: "mobile_link")
    monkeypatch.setattr(
        mobile,
        "_observed_client_ip",
        lambda _request: pytest.fail("Remote Mobile Link must not use the server loopback address"),
    )
    unassociated = client.get(
        "/mobile/protection/stats",
        headers={"Authorization": f"Bearer {paired['mobile_token']}"},
    )
    assert unassociated.status_code == 409
    assert observed_client_ids == []

    monkeypatch.setattr(mobile, "_mobile_connection_path", lambda _request: "direct")
    monkeypatch.setattr(mobile, "_observed_client_ip", lambda _request: "10.23.1.15")
    response = client.get(
        "/mobile/protection/stats",
        headers={"Authorization": f"Bearer {paired['mobile_token']}"},
    )

    assert response.status_code == 200
    expected_client_id = hashlib.sha256(b"10.23.1.15").hexdigest()[:16]
    assert observed_client_ids == [expected_client_id]
    payload = response.json()
    assert payload["total_queries"] == 200
    assert payload["blocked_queries"] == 50
    assert payload["block_percentage"] == 25.0
    assert len(payload["hourly"]) == 24
    assert payload["hourly"][:3] == [
        {"hour": 0, "total": 10, "blocked": 1},
        {"hour": 1, "total": 20, "blocked": 5},
        {"hour": 2, "total": 30, "blocked": 10},
    ]
    assert payload["top_blocked"] == [
        {"domain": "ads.example", "hits": 2},
        {"domain": "tracker.example", "hits": 1},
    ]
    assert "private-client" not in response.text

    monkeypatch.setattr(mobile, "_mobile_connection_path", lambda _request: "mobile_link")
    monkeypatch.setattr(
        mobile,
        "_observed_client_ip",
        lambda _request: pytest.fail("Remote Mobile Link must not use the server loopback address"),
    )
    remote_response = client.get(
        "/mobile/protection/stats",
        headers={"Authorization": f"Bearer {paired['mobile_token']}"},
    )
    assert remote_response.status_code == 200
    assert observed_client_ids == [expected_client_id, expected_client_id]


def test_slow_tailscale_status_does_not_block_pairing(mobile_client, monkeypatch: pytest.MonkeyPatch) -> None:
    client, _engine = mobile_client

    async def slow_exit_node() -> str:
        await asyncio.sleep(1)
        return "late-exit-node"

    monkeypatch.setattr(mobile, "_current_exit_node", slow_exit_node)
    monkeypatch.setattr(mobile, "PAIRING_EXIT_NODE_TIMEOUT_SECONDS", 0.01)

    response = client.post("/mobile/pairing/start")

    assert response.status_code == 200
    assert response.json()["pairing_code"]
    assert response.json()["tailscale_exit_node"] is None


def test_tailscale_mobile_key_is_short_lived_single_use_and_preauthorized() -> None:
    observed: dict[str, object] = {}

    class FakeResponse:
        def raise_for_status(self) -> None:
            return None

        def json(self) -> dict[str, str]:
            return {"key": "tskey-auth-one-time"}

    class FakeClient:
        async def post(self, url: str, *, headers, json):
            observed.update(url=url, headers=headers, json=json)
            return FakeResponse()

    api = TailscaleAdminAPI()
    api.config.api_key = "tskey-api-secret"
    api.config.tailnet = "example.ts.net"
    api._client = FakeClient()  # type: ignore[assignment]

    key = asyncio.run(api.create_mobile_auth_key(expiry_seconds=600))

    assert key == "tskey-auth-one-time"
    payload = observed["json"]
    create = payload["capabilities"]["devices"]["create"]  # type: ignore[index]
    assert create == {
        "reusable": False,
        "ephemeral": False,
        "preauthorized": True,
        "tags": [],
    }
    assert payload["expirySeconds"] == 600  # type: ignore[index]


def test_home_profile_route_key_matches_the_relay_derivation(tmp_path) -> None:
    import hmac
    import json
    import re
    import subprocess
    import sys
    from pathlib import Path

    script = Path("scripts/settings/mobile_link_agent.sh").read_text(encoding="utf-8")
    body = script[script.index("home_profile() {") :]
    snippet = re.search(r"<<'PY'\n(.*?)\nPY\n", body, re.S).group(1)
    config = tmp_path / "server_config.json"
    config.write_text(json.dumps({
        "client_auth_key": "33" * 32, "psk_key": "44" * 32, "reality_public_key": "66" * 32,
    }), encoding="utf-8")
    secret_file = tmp_path / "tunnel.secret"
    secret_file.write_text("11" * 32, encoding="ascii")
    device = "eb4613c0-3146-47e9-878c-788c48a3713f"
    result = subprocess.run(
        [sys.executable, "-c", snippet, str(config), str(secret_file), device,
         "10.77.0.3/32", "relay.example", "9446"],
        capture_output=True, text=True, check=True,
    )
    profile = json.loads(result.stdout)

    def route_key(secret: bytes, psk_hex: str) -> str:
        client_id = hmac.new(
            bytes.fromhex(psk_hex), b"chameleon-client-identity-v1", hashlib.sha256
        ).digest()[:16]
        return hmac.new(
            secret, b"easypi/prismlink/mobile-route-key/v1\x00" + client_id, hashlib.sha256
        ).hexdigest()

    # Same vector as chameleon/prismlink TestMobileRouteKeyCrossLanguageVector.
    assert route_key(bytes([0x11] * 32), "22" * 32) == (
        "91000311317042bf77b84dd6f37f3ebc93a7f1d1880b8045422be92562990ed1"
    )
    assert profile["prism_link_relay_route_key"] == route_key(
        bytes([0x11] * 32), profile["psk_key"]
    )
    assert profile["prism_link_relay_route_key"] != profile["psk_key"]
    assert profile["prism_link_direct_address"] == ""


def _run_home_profile_snippet(tmp_path, listen: str, direct: str) -> dict:
    import json
    import re
    import subprocess
    import sys
    from pathlib import Path

    script = Path("scripts/settings/mobile_link_agent.sh").read_text(encoding="utf-8")
    body = script[script.index("home_profile() {") :]
    snippet = re.search(r"<<'PY'\n(.*?)\nPY\n", body, re.S).group(1)
    config = tmp_path / "server_config.json"
    config.write_text(json.dumps({
        "client_auth_key": "33" * 32, "psk_key": "44" * 32, "reality_public_key": "66" * 32,
        "prism_link_listen": listen,
    }), encoding="utf-8")
    secret_file = tmp_path / "tunnel.secret"
    secret_file.write_text("11" * 32, encoding="ascii")
    result = subprocess.run(
        [sys.executable, "-c", snippet, str(config), str(secret_file),
         "eb4613c0-3146-47e9-878c-788c48a3713f", "10.77.0.3/32", "relay.example", "9446", direct],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr)
    return json.loads(result.stdout)


def test_home_profile_offers_the_direct_lan_path_when_listening_on_the_lan(tmp_path) -> None:
    profile = _run_home_profile_snippet(tmp_path, "0.0.0.0:9083", "192.168.1.20:9083")

    assert profile["prism_link_direct_address"] == "192.168.1.20:9083"


def test_home_profile_hides_a_loopback_only_listener(tmp_path) -> None:
    profile = _run_home_profile_snippet(tmp_path, "127.0.0.1:9083", "192.168.1.20:9083")

    assert profile["prism_link_direct_address"] == ""


def test_home_profile_rejects_a_public_direct_endpoint(tmp_path) -> None:
    import pytest

    with pytest.raises(RuntimeError, match="invalid direct endpoint"):
        _run_home_profile_snippet(tmp_path, "0.0.0.0:9083", "203.0.113.5:9083")


def test_home_tunnel_lan_listener_is_firewalled_to_the_home_subnet() -> None:
    from pathlib import Path

    script = Path("scripts/settings/mobile_link_agent.sh").read_text(encoding="utf-8")
    assert 'PRISM_LINK_LISTEN="0.0.0.0:${PRISM_LINK_PORT}"' in script
    assert (
        'ufw allow in on "${lan[0]}" from "${lan[2]}" to any port "$PRISM_LINK_PORT" proto udp'
        in script
    )
    # Tunnel and overlay interfaces are never treated as the home LAN.
    assert "tailscale|easypi-mobile|wg|tun|cham|docker|br-|veth" in script


def test_vps_mobile_registry_is_published_only_when_it_changes(tmp_path) -> None:
    import json
    from app.services.stealth_service import StealthService

    service = StealthService()
    service._data_dir = tmp_path
    service._meta_path = tmp_path / "stealth_meta.json"
    master = "ab" * 32
    meta = service._meta()
    meta["client_auth_key"] = master
    meta["ssh"]["host"] = "203.0.113.10"
    service._save_meta(meta)
    published: list[str] = []

    class Stream:
        def __init__(self, path):
            self.path = path
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return False
        def read(self, _size):
            return json.dumps({
                "client_auth_key": master,
                "mobile_clients_file": "/opt/chameleon-server/mobile_clients.json",
            })
        def write(self, data):
            published.append(data)

    class Channel:
        def recv_exit_status(self):
            return 0

    class Connection:
        def open_sftp(self):
            return SimpleNamespace(file=lambda path, mode: Stream(path), chmod=lambda *a: None,
                                   remove=lambda *a: None, close=lambda: None)
        def exec_command(self, *args, **kwargs):
            return None, SimpleNamespace(channel=Channel()), None
        def close(self):
            pass

    connections: list[str] = []
    service._connect = lambda ssh: connections.append(ssh["host"]) or Connection()
    phone = [{"id": "eb4613c0-3146-47e9-878c-788c48a3713f", "address": "10.10.0.3/32"}]
    service.sync_mobile_clients(phone)
    service.sync_mobile_clients(phone)
    assert connections == ["203.0.113.10"]  # unchanged registry: no second SSH session
    second = phone + [{"id": "789587d2-3f23-4323-8fb4-e76962f0b3a4", "address": "10.10.0.4/32"}]
    service.sync_mobile_clients(second)
    assert len(connections) == 2 and len(published) == 2
    # A redeployment may install an empty registry, so it must republish.
    asyncio.run(service._finish_deploy({"success": True, "log": ""}, False))
    service.sync_mobile_clients(second)
    assert len(connections) == 3
