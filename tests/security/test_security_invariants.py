from __future__ import annotations

import asyncio
import hashlib
import hmac
import io
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
import tarfile
import time
from pathlib import Path

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.rate_limit import RateLimitConfig, RateLimiter
from app.services.netprotection_components.settings import SettingsMixin
from app.services.netprotection_components.parental import ParentalMixin
from app.services.unknown_device_admission_service import (
    UnknownDeviceAdmissionService,
)
from app.services.proactive_monitor import ProactiveMonitor
from app.services.stealth_service import StealthService
from app.api.endpoints.netprotection_api.devices import UnknownDeviceApproval
from app.api.v1.endpoints.dns import (
    DNSSSHCredentialCheckRequest,
    _dns_status_query,
    _safe_remote_deploy_error,
    _validate_dns_status_response,
    check_dns_ssh_credentials,
)
from app.api.v1.endpoints import dns as dns_endpoint
from app.api.endpoints.netprotection_api.dashboard import StealthServerCfg
from app.api.deps import require_admin
from app.api.v1.endpoints.camera_discovery_admin import CameraDetectRequest
from app.schemas.camera import CameraCreate, CameraUpdate
from easypi_netprotection.profiles.manager import ProfileManager
from scripts.utils.backup_crypto import (
    decrypt_file,
    encrypt_file,
    verify_encrypted_backup,
)
from scripts.utils.secure_restore import validate_archive_contents


def test_new_camera_requires_a_password() -> None:
    payload = {
        "name": "Front door",
        "ip": "192.168.1.50",
        "port": 554,
        "username": "admin",
        "rtspPath": "/stream1",
    }

    with pytest.raises(ValidationError) as missing:
        CameraCreate.model_validate(payload)
    assert missing.value.errors()[0]["loc"] == ("password",)
    assert missing.value.errors()[0]["type"] == "missing"

    with pytest.raises(ValidationError) as empty:
        CameraCreate.model_validate({**payload, "password": ""})
    assert empty.value.errors()[0]["loc"] == ("password",)
    assert empty.value.errors()[0]["type"] == "string_too_short"

    camera = CameraCreate.model_validate({**payload, "password": "camera-secret"})
    assert camera.password == "camera-secret"


def test_validation_http_responses_never_echo_submitted_values(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ENV", "testing")
    from main import app as easypi_app

    submitted_password = "camera-secret-" * 12
    submitted_authkey = "tskey-" + ("a" * 600)
    easypi_app.dependency_overrides[require_admin] = lambda: object()
    try:
        client = TestClient(easypi_app)
        response = client.post(
            "/api/cameras",
            headers={"Authorization": "Bearer validation-test"},
            json={
                "name": "Front door",
                "ip": "192.168.1.50",
                "port": 554,
                "username": "admin",
                "password": submitted_password,
                "rtspPath": "/stream1",
            },
        )
        authkey_response = client.post(
            "/api/remote/tailscale/config",
            headers={"Authorization": "Bearer validation-test"},
            json={"authkey": submitted_authkey},
        )
    finally:
        easypi_app.dependency_overrides.pop(require_admin, None)

    assert response.status_code == 422
    assert submitted_password not in response.text
    password_error = next(
        error for error in response.json()["detail"] if error["loc"][-1] == "password"
    )
    assert "input" not in password_error

    assert authkey_response.status_code == 422
    assert submitted_authkey not in authkey_response.text
    assert all(
        "input" not in error and "ctx" not in error
        for error in authkey_response.json()["detail"]
    )


def test_camera_update_and_detection_reject_empty_passwords() -> None:
    with pytest.raises(ValidationError) as update_error:
        CameraUpdate.model_validate({"password": ""})
    assert update_error.value.errors()[0]["type"] == "string_too_short"

    with pytest.raises(ValidationError) as detect_missing:
        CameraDetectRequest.model_validate({"ip": "192.168.1.50"})
    assert detect_missing.value.errors()[0]["loc"] == ("password",)

    with pytest.raises(ValidationError) as detect_empty:
        CameraDetectRequest.model_validate({"ip": "192.168.1.50", "password": ""})
    assert detect_empty.value.errors()[0]["type"] == "string_too_short"


class _SettingsHarness(SettingsMixin):
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir


class _ParentalHarness(ParentalMixin):
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self._client_policy_lock = asyncio.Lock()
        self.actions: list[str] = []

    @staticmethod
    def _first_client_ip(client: dict) -> str:
        return str(client.get("ip") or "")

    @staticmethod
    def _normalize_client_id(value: object) -> str:
        return str(value or "device-id")

    @staticmethod
    def _resolve_ipv4_from_mac(_mac: str) -> str:
        # Simulate a stale ARP entry. Admission approval must prefer the exact
        # IP from the server-side quarantine observation.
        return "192.168.1.55"

    @staticmethod
    def _resolve_mac_from_arp(_ip: str) -> str:
        return ""

    async def _run_vpn_blocking_action(
        self, action: str, *_args: object, **_kwargs: object
    ) -> dict:
        self.actions.append(action)
        return {"success": True}

    async def _sync_blocklist(self) -> dict:
        return {"ok": True, "warnings": []}

    async def _sync_ip_blocking(self, _clients: list[dict]) -> dict:
        return {"ok": True, "warnings": []}


class _FailingApprovalHarness(_ParentalHarness):
    async def _add_client_unlocked(self, _client_data: dict) -> dict:
        for name in ("clients.json", "devices.json", "profiles.json", "bindings.json"):
            (self.data_dir / name).write_text("changed", encoding="utf-8")
        return {"success": True, "sync": {"ok": False, "warnings": ["sync failed"]}}

    async def sync_unknown_device_admission_policy(self) -> bool:
        return True


def test_auth_rate_limit_survives_process_recreation(tmp_path: Path) -> None:
    database = tmp_path / "rate-limits.sqlite3"
    config = RateLimitConfig(requests=1, window=60, block_duration=300)

    first = RateLimiter(database)
    assert first.is_rate_limited("login:192.0.2.1", config) == (False, None)
    assert first.is_rate_limited("login:192.0.2.1", config)[0] is True

    restarted = RateLimiter(database)
    assert restarted.is_rate_limited("login:192.0.2.1", config)[0] is True


def test_backup_encryption_roundtrip_and_tamper_rejection(tmp_path: Path) -> None:
    source = tmp_path / "source.tar.gz"
    encrypted = tmp_path / "source.epibak"
    restored = tmp_path / "restored.tar.gz"
    source.write_bytes((bytes(range(256)) * 8193) + b"tail")
    source.chmod(0o600)
    key = bytes(range(32))

    encrypt_file(source, encrypted, key)
    decrypt_file(encrypted, restored, key)
    assert restored.read_bytes() == source.read_bytes()

    payload = bytearray(encrypted.read_bytes())
    payload[len(payload) // 2] ^= 1
    encrypted.write_bytes(payload)
    encrypted.chmod(0o600)
    with pytest.raises(ValueError, match="authentication failed"):
        decrypt_file(encrypted, tmp_path / "tampered.tar.gz", key)


def test_encrypted_backup_verifier_authenticates_and_reads_tar(tmp_path: Path) -> None:
    source = tmp_path / "source.tar.gz"
    encrypted = tmp_path / "source.epibak"
    content = b"verified configuration"
    with tarfile.open(source, "w:gz") as archive:
        member = tarfile.TarInfo("etc/easypi/config.json")
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))
    source.chmod(0o600)
    key = bytes(range(32))
    encrypt_file(source, encrypted, key)

    verify_encrypted_backup(encrypted, key, work_dir=tmp_path / "verify")

    payload = bytearray(encrypted.read_bytes())
    payload[len(payload) // 2] ^= 1
    encrypted.write_bytes(payload)
    encrypted.chmod(0o600)
    with pytest.raises(ValueError, match="authentication failed"):
        verify_encrypted_backup(encrypted, key, work_dir=tmp_path / "verify-bad")


def test_restore_validator_reads_complete_allowed_archive(tmp_path: Path) -> None:
    archive_path = tmp_path / "restore.tar.gz"
    content = b"restorable configuration"
    with tarfile.open(archive_path, "w:gz") as archive:
        member = tarfile.TarInfo("opt/EasyPi/config/settings.json")
        member.size = len(content)
        archive.addfile(member, io.BytesIO(content))

    validate_archive_contents(archive_path)


def test_restore_validator_rejects_symlink_before_any_apply(tmp_path: Path) -> None:
    archive_path = tmp_path / "symlink.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        member = tarfile.TarInfo("opt/EasyPi/data/linked-state")
        member.type = tarfile.SYMTYPE
        member.linkname = "state.json"
        archive.addfile(member)

    with pytest.raises(SystemExit, match="unsafe archive member"):
        validate_archive_contents(archive_path)


def test_unknown_devices_fail_closed_on_fresh_install_and_upgrade(
    tmp_path: Path,
) -> None:
    fresh = _SettingsHarness(tmp_path / "fresh")
    fresh_settings = asyncio.run(fresh.get_unknown_device_settings())
    assert fresh_settings["data"]["mode"] == "block"
    assert fresh_settings["data"]["identity_assurance"] == "observed_mac_ip_pair"
    assert fresh_settings["data"]["spoof_resistant"] is False
    assert fresh_settings["data"]["requires_trusted_lan"] is True

    legacy_dir = tmp_path / "legacy"
    legacy_dir.mkdir()
    (legacy_dir / "settings.json").write_text("{}", encoding="utf-8")
    legacy = _SettingsHarness(legacy_dir)
    legacy_settings = asyncio.run(legacy.get_unknown_device_settings())
    assert legacy_settings["data"]["mode"] == "block"

    manager = ProfileManager(tmp_path / "manager-fresh")
    assert manager.block_unknown_devices is True
    assert manager.is_known_device("192.168.1.55", "02:00:00:00:00:55") is False

    profile = manager.create_profile("Managed device")
    manager.create_binding(
        profile.id, "mac", "02:00:00:00:00:55", name="Managed phone"
    )
    assert manager.is_known_device("192.168.1.55", "02:00:00:00:00:55") is False
    manager.create_binding(profile.id, "ip", "192.168.1.55", name="Managed phone")
    assert manager.is_known_device("192.168.1.55", "02:00:00:00:00:55") is True
    assert manager.is_known_device("192.168.1.55", "02:00:00:00:00:56") is False
    assert manager.is_known_device("192.168.1.56", "02:00:00:00:00:55") is False
    manager.create_binding(
        profile.id, "mac", "02:00:00:00:00:66", name="Managed tablet"
    )
    manager.create_binding(profile.id, "ip", "192.168.1.66", name="Managed tablet")
    assert manager.is_known_device("192.168.1.66", "02:00:00:00:00:66") is True
    assert manager.is_known_device("192.168.1.66", "02:00:00:00:00:55") is False
    assert manager.is_known_device("192.168.1.55", "02:00:00:00:00:66") is False
    manager.update_profile(profile.id, enabled=False)
    assert manager.is_known_device("192.168.1.55") is False


def test_personal_dns_explicitly_disables_only_lan_admission_quarantine(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NETPROTECTION_UNKNOWN_DEVICE_MODE", "default")
    remote_manager = ProfileManager(tmp_path / "remote-personal-dns")
    assert remote_manager.block_unknown_devices is False

    deployment = Path(
        "backend/app/api/v1/endpoints/dns_deployment_scripts.py"
    ).read_text(encoding="utf-8")
    assert "-e NETPROTECTION_UNKNOWN_DEVICE_MODE=default" in deployment


def test_personal_dns_firewall_update_remains_fail_closed() -> None:
    deployment = Path(
        "backend/app/api/v1/endpoints/dns_deployment_scripts.py"
    ).read_text(encoding="utf-8")
    firewall = deployment.split(
        "cat > /usr/local/sbin/easypi-personal-dns-firewall <<'FIREWALL'", 1
    )[1].split("\nFIREWALL", 1)[0]

    guard_hook = '"${IPT[@]}" -I DOCKER-USER 1 -j "$GUARD_CHAIN"'
    next_hook = '"${IPT[@]}" -I DOCKER-USER 1 -j "$NEXT_CHAIN"'
    retire_live = 'remove_hooks "$LIVE_CHAIN"'
    remove_guard = 'remove_hooks "$GUARD_CHAIN"'
    assert '"${IPT[@]}" -F EASYPI_PERSONAL_DNS' not in firewall
    assert firewall.index(guard_hook) < firewall.index('"${IPT[@]}" -N "$NEXT_CHAIN"')
    assert firewall.index(next_hook) < firewall.index(retire_live)
    assert firewall.index(retire_live) < firewall.index(remove_guard)
    assert firewall.index('"${IPT[@]}" -E "$NEXT_CHAIN" "$LIVE_CHAIN"') < firewall.index(
        remove_guard
    )

    cleanup = deployment.split('CLEANUP_SCRIPT = r"""', 1)[1]
    assert "EASYPI_PERSONAL_DNS_NEXT" in cleanup
    assert "EASYPI_PERSONAL_DNS_GUARD" in cleanup
    assert 'iptables -D DOCKER-USER -j "$chain"' in cleanup


def test_personal_dns_certificate_temporarily_opens_existing_vps_guard() -> None:
    deployment = Path(
        "backend/app/api/v1/endpoints/dns_deployment_scripts.py"
    ).read_text(encoding="utf-8")
    helper = deployment.split(
        "run_certbot_with_optional_vps_guard() (", 1
    )[1].split("\n)\n", 1)[0]
    certificate_stage = deployment.split('STAGE="certificate-setup"', 1)[1].split(
        'STAGE="firewall-preinstall"', 1
    )[0]

    assert 'guard="/usr/local/sbin/easypi-vps-guard"' in helper
    assert 'trap close_acme_port EXIT' in helper
    assert 'trap \'exit 129\' HUP' in helper
    assert 'trap \'exit 130\' INT' in helper
    assert 'trap \'exit 143\' TERM' in helper
    assert '"$guard" acme-open' in helper
    assert '"$guard" acme-close' in helper
    assert helper.index('"$guard" acme-close') < helper.index('exit "$rc"')
    assert 'certbot_lock="/run/easypi-certbot.lock"' in helper
    assert 'flock -w 180 9' in helper
    assert 'grep -Fq "Another instance of Certbot is already running."' in helper
    assert 'if [ "$attempt" -ge 24 ]' in helper
    assert 'sleep 5' in helper
    assert helper.index('"$guard" acme-close') < helper.index('sleep 5')
    assert "run_certbot_with_optional_vps_guard" in certificate_stage
    assert certificate_stage.index("run_certbot_with_optional_vps_guard") < (
        certificate_stage.index("certbot certonly --webroot")
    )


def test_personal_dns_container_readiness_uses_listener_and_reports_stage() -> None:
    deployment = Path(
        "backend/app/api/v1/endpoints/dns_deployment_scripts.py"
    ).read_text(encoding="utf-8")
    container_stage = deployment.split('STAGE="container-start"', 1)[1].split(
        'STAGE="nginx-doh-routing"', 1
    )[0]

    assert "for _attempt in $(seq 1 60)" in container_stage
    assert "socket.create_connection" in container_stage
    assert "docker exec netprotectionhome python" in container_stage
    assert "readiness-timeout" in container_stage
    assert "State.OOMKilled" in container_stage


def test_personal_dns_nginx_http2_syntax_matches_installed_version() -> None:
    deployment = Path(
        "backend/app/api/v1/endpoints/dns_deployment_scripts.py"
    ).read_text(encoding="utf-8")
    nginx_stage = deployment.split('STAGE="nginx-doh-routing"', 1)[1].split(
        'STAGE="complete"', 1
    )[0]

    assert 'dpkg --compare-versions "$NGINX_VERSION" ge 1.25.1' in nginx_stage
    assert 'NGINX_HTTP2_LISTEN="listen __VPS_IP__:8443 ssl http2;"' in nginx_stage
    assert 'NGINX_HTTP2_LISTEN="listen __VPS_IP__:8443 ssl;"' in nginx_stage
    assert 'NGINX_HTTP2_DIRECTIVE="    http2 on;"' in nginx_stage
    assert "$NGINX_HTTP2_LISTEN" in nginx_stage
    assert "$NGINX_HTTP2_DIRECTIVE" in nginx_stage


def test_personal_dns_remote_error_prefers_actionable_line_over_info_noise() -> None:
    stderr = "\n".join(
        [
            "ERROR: TLS key could not be loaded",
            *[f"[INFO] normal startup line {index}" for index in range(20)],
        ]
    )
    diagnostic = _safe_remote_deploy_error("", stderr)
    assert "TLS key could not be loaded" in diagnostic
    assert "normal startup line" not in diagnostic


def test_personal_dns_ssh_credential_check_reports_authentication_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    def reject_credentials(*_args, **_kwargs):
        raise HTTPException(status_code=400, detail="SSH authentication failed")

    monkeypatch.setattr(dns_endpoint, "check_rate_limit", lambda *_args: None)
    monkeypatch.setattr(dns_endpoint, "create_ssh_client", reject_credentials)
    body = DNSSSHCredentialCheckRequest(
        vps_ip="8.8.8.8",
        ssh_port=22,
        ssh_user="root",
        ssh_password="incorrect-password",
    )

    with pytest.raises(HTTPException, match="SSH authentication failed"):
        asyncio.run(check_dns_ssh_credentials(body, object(), object()))


def test_personal_dns_ui_separates_host_key_and_credential_checks() -> None:
    page = Path("frontend/src/pages/PersonalDNS.tsx").read_text(encoding="utf-8")

    assert "This checks only the VPS host key" in page
    assert "SSH login not tested" in page
    assert "'/dns/ssh/check-credentials'" in page
    assert "SSH login failed" in page


def test_netprotection_cache_preparation_never_runs_as_root() -> None:
    unit = Path("templates/systemd/easypi-netprotection.service").read_text(
        encoding="utf-8"
    )
    prestart = next(
        line for line in unit.splitlines() if line.startswith("ExecStartPre=")
    )
    assert not prestart.startswith("ExecStartPre=+")
    assert "chown" not in prestart
    assert "User=easypi" in unit


def test_invalid_unknown_device_override_stays_fail_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("NETPROTECTION_UNKNOWN_DEVICE_MODE", "allow-everything")
    manager = ProfileManager(tmp_path / "invalid-override")
    assert manager.block_unknown_devices is True


def test_personal_dns_health_rejects_sinkhole_answers() -> None:
    query = _dns_status_query()

    def response(address: str) -> bytes:
        return (
            query[:2]
            + b"\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00"
            + query[12:]
            + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04"
            + ipaddress.ip_address(address).packed
        )

    _validate_dns_status_response(query, response("93.184.216.34"))
    with pytest.raises(ValueError, match="blocked or non-public"):
        _validate_dns_status_response(query, response("0.0.0.0"))


def test_stealth_client_can_be_saved_before_server_ssh_configuration() -> None:
    client_first = {
        "server_address": "8.8.8.8:443",
        "ssh": {"host": ""},
    }
    assert StealthService._ip_shield_address(client_first) == "8.8.8.8"

    mismatched_server = {
        "server_address": "8.8.8.8:443",
        "ssh": {"host": "1.1.1.1"},
    }
    with pytest.raises(ValueError, match="must match"):
        StealthService._ip_shield_address(mismatched_server)

    premature_domain = {
        "server_address": "stealth.example.org:443",
        "ssh": {"host": ""},
    }
    with pytest.raises(ValueError, match="Save the Stealth VPS IPv4"):
        StealthService._ip_shield_address(premature_domain)


def test_nginx_limits_large_bodies_to_upload_routes() -> None:
    config = Path("templates/nginx/easypi.conf").read_text(encoding="utf-8")
    assert "client_max_body_size 1M;" in config
    assert "picloud/upload|files/upload" in config
    # Two upload routes plus the mobile auth subrequest, which inherits the
    # declared length of the upload it guards.
    assert config.count("client_max_body_size 5G;") == 3
    assert config.count("client_max_body_size 4G;") == 3
    assert config.count("auth_request /_easypi_auth;") == 3
    assert "location = /_easypi_auth {" in config
    assert "location = /_easypi_admin_auth {" in config
    assert "location = /_easypi_mobile_auth {" in config
    assert config.count("proxy_pass_request_body off;") == 3
    mobile_upload = config.split("location = /api/v1/mobile/upload", 1)[1].split("}", 1)[0]
    assert "client_max_body_size 5G;" in mobile_upload
    assert "client_body_timeout 60s;" in mobile_upload
    assert "proxy_request_buffering off;" in mobile_upload
    # The device token is checked before nginx accepts the large body.
    assert "auth_request /_easypi_mobile_auth;" in mobile_upload
    assert "Browser media goes through /ws/cameras/<id>/live" in config
    assert "location /go2rtc/ {" in config
    assert "auth_request /_easypi_go2rtc_auth;" not in config

    mobile_link = Path("templates/nginx/easypi-mobile-link.conf").read_text(encoding="utf-8")
    assert "client_max_body_size 5G;" in mobile_link
    assert "client_body_timeout 60s;" in mobile_link


def test_installer_establishes_firewall_before_netprotection() -> None:
    installer = Path("install.sh").read_text(encoding="utf-8")
    call_region = installer[installer.index("verify_ipv6_policy_invariant\n") :]
    assert call_region.index("setup_firewall\n") < call_region.index(
        "setup_netprotection\n"
    )
    assert call_region.index("setup_firewall\n") < call_region.index(
        "setup_go2rtc\n"
    )
    assert "Firewall setup failed; NetProtection has been stopped (fail closed)" in installer
    assert call_region.index("setup_firewall\n") < call_region.index(
        "setup_ipv6_runtime_guard\n"
    )
    assert call_region.index("setup_ipv6_runtime_guard\n") < call_region.index(
        "setup_netprotection\n"
    )


def test_installer_keeps_netprotection_runtime_readable_and_fail_closed() -> None:
    installer = Path("install.sh").read_text(encoding="utf-8")
    service_installer = Path(
        "scripts/services/install_netprotection.sh"
    ).read_text(encoding="utf-8")

    assert 'chown -R root:"${EASYPI_GROUP}" "${venv_path}"' in installer
    assert 'find "${venv_path}" -type d -exec chmod 0750 {} +' in installer
    assert 'find "${venv_path}" -type f -exec chmod 0640 {} +' in installer
    assert 'entrypoint_magic="$(head -c 2 -- "${entrypoint}"' in installer
    assert '"${entrypoint_magic}" == \'#!\'' in installer
    assert 'chmod 0750 "${entrypoint}"' in installer
    assert installer.count('secure_runtime_venv "${VENV_PATH}"') == 2
    assert installer.count('-o -path "${EASYPI_PREFIX}/backend/.venv"') == 2
    assert installer.count('"${VENV_PATH}/bin/python" -m pip install') == 3
    assert '"${VENV_PATH}/bin/pip" install' not in installer
    assert 'error "NetProtection installation failed"' in installer
    assert 'error "NetProtection failed to start correctly."' in installer
    assert "NetProtection service cannot start due to port 53 conflict." in service_installer
    assert "NetProtection did not remain active after startup." in service_installer


def test_installer_displays_setup_token_once_without_logging_or_retrieval_hint() -> None:
    installer = Path("install.sh").read_text(encoding="utf-8")

    assert "discard_imported_setup_token_on_fresh_install()" in installer
    assert '"${EASYPI_PREFIX}/data/.setup_token"' in installer
    assert '"${EASYPI_PREFIX}/backend/data/.setup_token"' in installer
    assert installer.index("deploy_runner_scripts\n") < installer.index(
        "discard_imported_setup_token_on_fresh_install\n"
    )
    assert "Retrieve it locally with:" not in installer
    assert "sudo cat ${SETUP_TOKEN_FILE}" not in installer
    assert "setup-token-sha256:" in installer
    assert '"${SETUP_TOKEN}" != setup-token-sha256:*' in installer
    assert '"${SETUP_TOKEN}" != recovery-token-sha256:*' in installer
    assert "sha256sum" in installer
    assert "systemctl restart easypi-backend.service" in installer
    assert "} > /dev/tty" in installer
    assert "the undisclosed token was removed" in installer


def test_certificate_generator_preserves_valid_installation_trust() -> None:
    generator = Path("scripts/setup/generate_certs.sh").read_text(encoding="utf-8")
    privileged_wrapper = Path("scripts/settings/generate_tls_certs.sh").read_text(
        encoding="utf-8"
    )
    runtime = Path(
        "backend/app/services/netprotection_components/runtime.py"
    ).read_text(encoding="utf-8")

    assert 'if [ -L "$CERT_DIR" ]' in generator
    assert "certificate_key_matches()" in generator
    assert 'openssl x509 -checkend "$RENEWAL_WINDOW_SECONDS"' in generator
    assert 'openssl verify -CAfile "$CERT_DIR/ca.pem"' in generator
    assert "Existing CA and server certificate are valid; preserving installation trust" in generator
    assert "renew_ca_signed_server_certificate()" in generator
    assert "rotate_ca()" in generator
    assert "EASYPI_FORCE_CERT_RENEWAL" not in generator
    assert "Externally managed Let's Encrypt certificate preserved." in generator
    assert "/opt/EasyPi/scripts/setup/generate_certs.sh ca-signed" in generator
    assert 'CERT_ACTION="${2:-ca-signed}"' in privileged_wrapper
    assert '"${CERT_ACTION}" != "ca-signed"' in privileged_wrapper
    assert 'cert_action = "renew" if force and ca_material_exists else "ca-signed"' in runtime


@pytest.mark.skipif(
    shutil.which("bash") is None,
    reason="bash is required for the certificate lifecycle test",
)
def test_certificate_lifecycle_renews_leaf_without_rotating_ca(tmp_path: Path) -> None:
    generator = Path("scripts/setup/generate_certs.sh").resolve()
    cert_dir = tmp_path / "certs"

    def bash_path(path: Path) -> str:
        resolved = path.resolve().as_posix()
        if os.name == "nt":
            drive, remainder = resolved.split(":", 1)
            return f"/mnt/{drive.lower()}{remainder}"
        return resolved

    def run_generator(
        command: str, *, days: int = 365, check: bool = True
    ) -> subprocess.CompletedProcess[str]:
        shell_command = " ".join(
            [
                f"EASYPI_CERT_DIR={shlex.quote(bash_path(cert_dir))}",
                "EASYPI_GROUP=easypi-test-group-that-does-not-exist",
                "CERT_BITS=2048",
                f"CERT_DAYS={days}",
                "EASYPI_CA_DAYS=3650",
                "bash",
                shlex.quote(bash_path(generator)),
                shlex.quote(command),
            ]
        )
        return subprocess.run(
            [str(shutil.which("bash")), "-lc", shell_command],
            capture_output=True,
            text=True,
            timeout=60,
            check=check,
        )

    def digest(name: str) -> str:
        return hashlib.sha256((cert_dir / name).read_bytes()).hexdigest()

    run_generator("ca-signed")
    original_ca = digest("ca.pem")
    original_ca_key = digest("ca-key.pem")
    original_server_key = digest("key.pem")
    original_server_cert = digest("cert.pem")

    run_generator("ca-signed")
    assert digest("ca.pem") == original_ca
    assert digest("ca-key.pem") == original_ca_key
    assert digest("key.pem") == original_server_key
    assert digest("cert.pem") == original_server_cert

    (cert_dir / ".letsencrypt").write_text("example.invalid\n", encoding="utf-8")
    run_generator("ca-signed")
    refused_renewal = run_generator("renew", check=False)
    assert refused_renewal.returncode != 0
    assert digest("ca.pem") == original_ca
    assert digest("cert.pem") == original_server_cert
    (cert_dir / ".letsencrypt").unlink()

    run_generator("renew", days=1)
    short_lived_server_cert = digest("cert.pem")
    assert digest("ca.pem") == original_ca
    assert digest("ca-key.pem") == original_ca_key
    assert digest("key.pem") == original_server_key
    assert short_lived_server_cert != original_server_cert

    run_generator("ca-signed")
    assert digest("ca.pem") == original_ca
    assert digest("ca-key.pem") == original_ca_key
    assert digest("key.pem") == original_server_key
    assert digest("cert.pem") != short_lived_server_cert
    subprocess.run(
        [
            str(shutil.which("bash")),
            "-lc",
            (
                "openssl verify -CAfile "
                f"{shlex.quote(bash_path(cert_dir / 'ca.pem'))} "
                f"{shlex.quote(bash_path(cert_dir / 'cert.pem'))}"
            ),
        ],
        capture_output=True,
        text=True,
        timeout=15,
        check=True,
    )

    run_generator("rotate-ca")
    assert digest("ca.pem") != original_ca
    assert digest("ca-key.pem") != original_ca_key


def test_clean_install_requires_stealth_binaries_even_from_install_prefix() -> None:
    installer = Path("install.sh").read_text(encoding="utf-8")
    assert "die() {" in installer
    assert installer.index("Validate existing privileged Stealth inputs") < installer.index(
        "Fixing code ownership"
    )
    stealth_region = installer[
        installer.index("# Stealth (Chameleon) binaries") : installer.index(
            "# Explicit runtime state."
        )
    ]
    assert 'realpath "${BASE_DIR}"' not in stealth_region
    assert 'install -o root -g root -m 0755' in stealth_region
    assert "refusing to report an incomplete installation" in stealth_region
    assert "Stealth build failed; Stealth section will be unavailable" not in stealth_region
    assert "env -u GO -u GOPATH -u GOMODCACHE -u GOCACHE" in stealth_region
    assert 'directory "${EASYPI_PREFIX}/bin"' in installer
    assert 'file "${chameleon_server_source}"' in stealth_region
    assert 'file "${chameleon_client_source}"' in stealth_region


def test_stealth_certbot_wrapper_restores_nginx_and_rejects_unknown_listener() -> None:
    wrapper = StealthService._standalone_certbot_wrapper()
    assert "trap cleanup EXIT" in wrapper
    assert "systemctl is-active --quiet nginx.service" in wrapper
    assert "systemctl stop nginx.service" in wrapper
    assert "systemctl start nginx.service" in wrapper
    assert "non-nginx process; refusing to stop it" in wrapper
    assert 'rm -f -- "$marker"' in wrapper
    assert "runtime_dir=/run/chameleon-certbot" in wrapper
    assert 'install -d -o root -g root -m 0700 "$runtime_dir"' in wrapper
    assert 'if [ "${1:-}" = "--restore" ]' in wrapper
    assert '"$guard" acme-open' in wrapper
    assert '"$guard" acme-close' in wrapper
    assert "certbot_lock=/run/easypi-certbot.lock" in wrapper
    assert "flock -w 180 9" in wrapper

    guard = StealthService._vps_guard_script()
    assert "--dport 80 -j DROP" in guard
    assert 'apply_base iptables icmp --icmp-type echo-request' in guard
    assert 'apply_base ip6tables ipv6-icmp --icmpv6-type echo-request' in guard
    assert "echo-request" in guard
    assert "destination-unreachable" not in guard
    assert "packet-too-big" not in guard
    assert "acme-open" in guard
    assert "acme-close" in guard

    guard_unit = StealthService._vps_guard_unit()
    assert "Before=network.target nginx.service chameleon-server.service" in guard_unit
    assert "CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW" in guard_unit
    assert "ReadWritePaths=/run/xtables.lock" in guard_unit

    certbot_override = StealthService._certbot_guard_override()
    assert "ExecStartPre=/usr/local/sbin/easypi-vps-guard acme-open" in certbot_override
    assert "ExecStopPost=/usr/local/sbin/easypi-vps-guard acme-close" in certbot_override

    deployment = Path(
        "backend/app/services/stealth_components/deployment.py"
    ).read_text(encoding="utf-8")
    assert '"/usr/local/sbin/easypi-vps-guard remove"' in deployment
    assert '"rm -f /etc/systemd/system/easypi-vps-guard.service"' in deployment
    assert (
        '"rm -f /etc/systemd/system/certbot.service.d/easypi-vps-guard.conf"'
        in deployment
    )
    assert '"rm -f /etc/tmpfiles.d/easypi-vps-guard.conf"' in deployment
    assert "systemd-tmpfiles --create /etc/tmpfiles.d/easypi-vps-guard.conf" in deployment
    assert '"Certificate operation lock"' in deployment
    assert '"util-linux >/dev/null 2>&1; }; command -v flock' in deployment

    issue = StealthService._ip_certificate_issue_command("8.8.8.8")
    assert issue.startswith("/usr/local/sbin/chameleon-certbot-standalone ")
    assert "--ip-address 8.8.8.8" in issue
    assert "--cert-name 8.8.8.8" in issue

    domain_setup = StealthService._domain_certificate_setup_command(
        "example.duckdns.org"
    )
    assert "test -s /etc/letsencrypt/renewal/example.duckdns.org.conf" in domain_setup
    assert "authenticator" in domain_setup
    assert "standalone[[:space:]]*$" in domain_setup
    assert "certbot reconfigure" in domain_setup
    assert "--standalone --preferred-challenges http" in domain_setup
    assert "certbot certonly" in domain_setup
    assert "--standalone -d example.duckdns.org" in domain_setup
    assert "--cert-name example.duckdns.org" in domain_setup

    ip_renewal = StealthService._certificate_renewal_service(
        identity="8.8.8.8"
    )
    assert "ExecStart=/usr/local/sbin/chameleon-certbot-standalone " in ip_renewal
    assert "RuntimeDirectory=chameleon-certbot" in ip_renewal
    assert "RuntimeDirectoryMode=0700" in ip_renewal
    assert "RuntimeDirectoryPreserve=yes" in ip_renewal
    assert "ReadWritePaths=" in ip_renewal
    assert "/run/chameleon-certbot" in ip_renewal
    assert "/run/easypi-certbot.lock" in ip_renewal
    assert (
        "ExecStopPost=/usr/local/sbin/chameleon-certbot-standalone --restore"
        in ip_renewal
    )

    domain_renewal = StealthService._certificate_renewal_service(
        identity="example.duckdns.org"
    )
    assert "ExecStart=/usr/local/sbin/chameleon-certbot-standalone " in domain_renewal
    assert "RuntimeDirectory=chameleon-certbot" in domain_renewal
    assert "/run/chameleon-certbot" in domain_renewal
    assert "/run/easypi-certbot.lock" in domain_renewal
    assert "ExecStopPost=/usr/local/sbin/chameleon-certbot-standalone --restore" in domain_renewal

    deployment = Path(
        "backend/app/services/stealth_components/deployment.py"
    ).read_text(encoding="utf-8")
    assert "duckdns=" not in deployment
    assert '"f /run/easypi-certbot.lock 0600 root root -\\n"' in deployment
    assert "_legacy_duckdns_cleanup_command()" in deployment
    assert deployment.index("_domain_certificate_setup_command(cert_identity)") < deployment.index(
        '"Legacy DuckDNS cleanup"'
    )
    assert deployment.index('"HTTP renewal activation"') < deployment.index(
        '"Legacy DuckDNS cleanup"'
    )

    tls_service = Path(
        "backend/app/services/stealth_components/tls.py"
    ).read_text(encoding="utf-8")
    assert tls_service.index("_domain_certificate_setup_command(domain)") < tls_service.index(
        '"Legacy DuckDNS cleanup"'
    )
    assert tls_service.index('"HTTP renewal activation"') < tls_service.index(
        '"Legacy DuckDNS cleanup"'
    )

    stealth_page = Path("frontend/src/pages/Stealth.tsx").read_text(encoding="utf-8")
    assert 'Field label="DuckDNS token"' not in stealth_page
    assert "duckdns_token:" not in stealth_page
    assert "(!duckdnsToken && !st?.has_duckdns_token)" not in stealth_page

    dashboard = Path(
        "backend/app/api/endpoints/netprotection_api/dashboard.py"
    ).read_text(encoding="utf-8")
    stealth_api = Path("frontend/src/api/stealth.ts").read_text(encoding="utf-8")
    ssh_service = Path(
        "backend/app/services/stealth_components/ssh.py"
    ).read_text(encoding="utf-8")
    assert "duckdns_token" not in dashboard
    assert "duckdns_token" not in stealth_api
    assert '_secret_store("duckdns-token"' not in ssh_service

    with pytest.raises(ValidationError) as rejected:
        StealthServerCfg.model_validate(
            {
                "host": "8.8.8.8",
                "duckdns_token": "must-not-be-accepted",
            }
        )
    assert any(
        error["loc"] == ("duckdns_token",)
        and error["type"] == "extra_forbidden"
        for error in rejected.value.errors()
    )


def test_stealth_legacy_duckdns_cleanup_runs_once_and_scrubs_metadata(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = StealthService()
    service._data_dir = tmp_path
    service._meta_path = tmp_path / "stealth_meta.json"
    service._conf_path = tmp_path / "stealth_client.conf"
    service._meta_path.write_text(
        json.dumps(
            {
                "enabled": False,
                "ssh": {
                    "host": "8.8.8.8",
                    "duckdns_token": "legacy-secret",
                    "duckdns_token_stored": True,
                    "domain": "example.duckdns.org",
                },
            }
        ),
        encoding="utf-8",
    )
    deleted: list[str] = []
    monkeypatch.setattr(service, "_secret_delete", deleted.append)

    assert service.cleanup_legacy_duckdns_token() is True
    assert deleted == ["duckdns-token"]
    stored = json.loads(service._meta_path.read_text(encoding="utf-8"))
    assert "duckdns_token" not in stored["ssh"]
    assert "duckdns_token_stored" not in stored["ssh"]
    assert stored["ssh"]["host"] == "8.8.8.8"
    assert stored["ssh"]["domain"] == "example.duckdns.org"

    assert service.cleanup_legacy_duckdns_token() is False
    assert deleted == ["duckdns-token"]


def test_stealth_host_key_trust_reports_later_ssh_auth_failure_separately(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    service = StealthService()
    service._data_dir = tmp_path
    fingerprint = "SHA256:" + "a" * 43
    meta = {
        "ssh": {
            "host": "8.8.8.8",
            "port": 22,
            "host_key_type": "",
            "host_key_data": "",
            "host_key_sha256": "",
        }
    }
    monkeypatch.setattr(service, "_meta", lambda: meta)
    monkeypatch.setattr(service, "_save_meta", lambda updated: meta.update(updated))
    monkeypatch.setattr(
        service,
        "_read_remote_host_key",
        lambda _ssh: {
            "key_type": "ssh-ed25519",
            "key_data": "public-key-data",
            "fingerprint": fingerprint,
        },
    )

    def fail_credentials() -> dict[str, object]:
        raise RuntimeError("Authentication failed")

    monkeypatch.setattr(service, "_ensure_secure_credentials", fail_credentials)

    result = asyncio.run(service.trust_ssh_host_key(fingerprint))

    assert result["success"] is False
    assert result["host_key_trusted"] is True
    assert result["credentials_ready"] is False
    assert "SSH credential setup failed" in result["error"]
    assert "check the saved SSH credentials" in result["error"]
    assert meta["ssh"]["host_key_data"] == "public-key-data"
    assert meta["ssh"]["host_key_sha256"] == fingerprint


def test_stealth_network_setup_detects_absent_tun_by_link_status() -> None:
    script = StealthService._network_setup_script()
    assert 'if ! ip link show dev "$TUN"' in script
    assert 'ip tuntap add dev "$TUN" mode tun user chameleon' in script
    assert 'ip tuntap show dev "$TUN"' not in script
    assert 'ip -j tuntap show dev "$TUN"' in script
    assert 'matches = [row for row in rows if row.get("ifname") == name]' in script
    assert "len(matches) == 1" in script
    assert 'and "tun" in matches[0].get("flags", [])' in script
    assert 'and matches[0].get("user") == uid' in script
    assert "refusing firewall changes" in script
    assert script.index('ip -j tuntap show dev "$TUN"') < script.index(
        'ip addr replace "$CIDR"'
    )


def test_restricted_stealth_server_receives_best_effort_tcp_tuning() -> None:
    script = StealthService._network_setup_script()

    assert "net.core.rmem_max=67108864 || true" in script
    assert "net.core.wmem_max=67108864 || true" in script
    assert "'net.ipv4.tcp_rmem=4096 87380 67108864' || true" in script
    assert "'net.ipv4.tcp_wmem=4096 65536 67108864' || true" in script
    assert "if modprobe tcp_bbr >/dev/null 2>&1; then" in script
    assert "net.core.default_qdisc=fq || true" in script
    assert "net.ipv4.tcp_congestion_control=bbr || true" in script


def test_stealth_server_restart_recreates_tun_and_fails_closed() -> None:
    server_unit = StealthService._server_systemd_unit()
    network_unit = StealthService._network_systemd_unit()
    assert "DeviceAllow=/dev/net/tun rw" in server_unit
    assert "DeviceAllow=/dev/net/tun rw" in network_unit
    certificate_hook = StealthService._certificate_install_script()
    deployment = Path(
        "backend/app/services/stealth_components/deployment.py"
    ).read_text(encoding="utf-8")
    server_main = Path("chameleon/server/main.go").read_text(encoding="utf-8")

    assert "BindsTo=chameleon-network.service" in server_unit
    assert "PartOf=chameleon-server.service" in network_unit
    assert "Before=chameleon-server.service" in network_unit
    assert (
        "systemctl restart chameleon-network.service chameleon-server.service"
        in certificate_hook
    )
    assert "if systemctl is-active --quiet nginx.service; then" in certificate_hook
    assert "systemctl reload nginx.service" in certificate_hook
    assert "systemctl try-restart chameleon-server.service" not in certificate_hook
    assert "ip link show dev chameleon0" in certificate_hook
    assert "TUN_MISSING" in deployment
    assert "required kernel tunnel unavailable" in server_main


def test_initial_vps_deploy_installs_certificate_before_starting_services() -> None:
    certificate_hook = StealthService._certificate_install_script()
    initial_install = StealthService._tls_material_install_command(
        "203.0.113.10", install_only=True
    )
    renewal_install = StealthService._tls_material_install_command("203.0.113.10")
    deployment = Path(
        "backend/app/services/stealth_components/deployment.py"
    ).read_text(encoding="utf-8")

    assert 'if [ "${CHAMELEON_CERT_INSTALL_ONLY:-0}" = 1 ]; then\n  exit 0' in certificate_hook
    assert certificate_hook.index("CHAMELEON_CERT_INSTALL_ONLY") < certificate_hook.index(
        "systemctl restart chameleon-network.service"
    )
    assert "CHAMELEON_CERT_INSTALL_ONLY=1" in initial_install
    assert "CHAMELEON_CERT_INSTALL_ONLY" not in renewal_install
    assert "cert_identity, install_only=True" in deployment
    assert deployment.index("cert_identity, install_only=True") < deployment.index(
        'run_checked("systemctl daemon-reload"'
    )


def test_vps_nginx_keeps_the_patch_without_losing_ubuntu_security_fixes() -> None:
    tool = Path("chameleon/server/nginx/easypi-chameleon-nginx").read_text(encoding="utf-8")
    patch = Path(
        "chameleon/server/nginx/h2-unbuffered-window-update-threshold.patch"
    ).read_text(encoding="utf-8")
    deployment = Path(
        "backend/app/services/stealth_components/deployment.py"
    ).read_text(encoding="utf-8")
    refresh = tool[tool.index("do_refresh() {") : tool.index("do_status() {")]

    # Package updates land beside the patched binary instead of replacing it.
    assert "dpkg-divert --package easypi-chameleon --divert \"$DISTRIB\" --rename --add" in tool
    assert 'DPkg::Post-Invoke { "if [ -x $SELF ]; then $SELF refresh || true; fi"; };' in tool
    # Security first: a changed package binary runs before any rebuild, and a
    # failed build leaves the packaged binary in place.
    assert refresh.index("use_packaged") < refresh.index("systemctl start --no-block")
    assert 'use_packaged "patch build failed for $version"' in tool
    # The patch is built from the installed package's own source and options.
    assert 'apt_source source -qq "nginx=$version"' in tool
    assert '"$DISTRIB" -V 2>&1' in tool
    assert "ngx_min(window / 2, NGX_HTTP_V2_UNBUFFERED_WINDOW_UPDATE)" in patch
    # Limits with a memory ceiling.
    assert "WORKER_CONNECTIONS=4096" in tool and "WORKER_NOFILE=16384" in tool
    assert "MemoryHigh=25%" in tool and "MemoryMax=35%" in tool
    # Deployed on every Deploy & Start after the frontend configuration, and
    # undone before nginx may be removed.
    assert deployment.index('"nginx frontend configuration"') < deployment.index(
        f"{{NGINX_TOOL}} install"
    ) < deployment.index('"systemctl restart chameleon-server"')
    assert deployment.index(f"{{NGINX_TOOL}} remove") < deployment.index(
        "systemctl disable --now nginx.service"
    )


def test_chameleon_uses_real_nginx_and_keeps_the_go_backend_private() -> None:
    service = StealthService()
    meta = {
        "server_address": "8.8.8.8:443",
        "psk_key": "11" * 32,
        "reality_public": "22" * 32,
        "block_quic": True,
        "ssh": {
            "host": "8.8.8.8",
            "domain": "",
            "domain_tls_deployed": False,
        },
    }
    server_config = json.loads(service._server_config_json(meta))
    nginx_config = service._nginx_frontend_config(meta)
    server_unit = service._server_systemd_unit()
    middleware = Path("chameleon/server/middleware.go").read_text(encoding="utf-8")
    deployment = Path(
        "backend/app/services/stealth_components/deployment.py"
    ).read_text(encoding="utf-8")

    assert server_config["frontend_mode"] == "nginx"
    assert server_config["backend_address"] == "127.0.0.1:9080"
    digest = hmac.new(
        bytes.fromhex(meta["psk_key"]),
        b"chameleon-route-prefix-v1",
        hashlib.sha256,
    ).digest()
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    expected_prefix = "".join(
        alphabet[int.from_bytes(digest[index : index + 2], "big") % len(alphabet)]
        for index in range(0, 16, 2)
    )
    assert "listen 0.0.0.0:443 ssl http2 default_server;" in nginx_config
    assert f"location ^~ /{expected_prefix}/" in nginx_config
    assert "proxy_pass http://127.0.0.1:9080;" in nginx_config
    assert "proxy_request_buffering off;" in nginx_config
    assert "proxy_buffering off;" in nginx_config
    assert "proxy_buffer_size 16k;" in nginx_config
    assert "proxy_buffers 8 16k;" in nginx_config
    assert "client_body_timeout 24h;" in nginx_config
    assert "client_body_buffer_size 1m;" in nginx_config
    assert server_config["max_connections"] == 4096
    assert server_config["max_sessions_per_source"] == 8
    assert "keepalive_requests 1000000;" in nginx_config
    assert "access_log off;" in nginx_config
    assert 'proxy_set_header X-Real-IP "";' in nginx_config
    assert 'proxy_set_header X-Forwarded-For "";' in nginx_config
    assert "nginx/1.24.0" not in middleware
    assert "AmbientCapabilities=CAP_NET_BIND_SERVICE" not in server_unit
    assert "CapabilityBoundingSet=\n" in server_unit
    assert "/etc/nginx/conf.d/.easypi-chameleon.conf.upload" in deployment
    assert "nginx frontend configuration" in deployment
    assert "nginx public frontend activation" in deployment
    assert "/var/lib/easypi-chameleon/nginx-installed" in deployment
    assert "rm -f /etc/nginx/sites-enabled/default" in deployment
    assert "rm -f /etc/nginx/conf.d/easypi-chameleon.conf" in deployment
    # The cover page's assets must resolve through nginx exactly as through
    # the server's own frontend: a flat site directory under /assets/.
    site = Path("chameleon/server/site")
    for asset in re.findall(r'(?:href|src)="/assets/([^"]+)"', (site / "index.html").read_text(encoding="utf-8")):
        assert (site / asset).is_file(), asset
    assert "location ^~ /assets/ {\n        alias /opt/chameleon-server/site/;" in nginx_config
    # Tunnel authentication failures are indistinguishable from other 404s.
    assert "proxy_intercept_errors on;" in nginx_config
    assert "error_page 401 403 404 405 =404 @not_found;" in nginx_config
    for page in ("index.html", "robots.txt", "favicon.ico"):
        assert f"location = /{page} {{" in nginx_config
        assert (site / page).is_file(), page
    # Certificate renewal must stay scheduled across redeploys and restarts.
    assert "OnCalendar=*-*-* 00/12:00:00" in deployment
    assert "OnUnitActiveSec=12h" not in deployment


def test_vps_tunnel_clients_cannot_reach_the_vps_or_its_internal_networks() -> None:
    script = StealthService._network_setup_script()
    start = script[script.index('test "$ACTION" = start') :]
    stop = script[script.index('if [ "$ACTION" = stop ]; then') : script.index('test "$ACTION" = start')]

    # Installed on every start, removed on stop.
    assert 'install_tunnel_isolation "$iface"' in start
    assert "remove_tunnel_isolation" in stop
    # Both the VPS itself (INPUT) and everything it routes to (FORWARD).
    assert 'iptables -I INPUT 1 -i "$TUN" -j "$TUN_IN_CHAIN"' in script
    assert 'iptables -I FORWARD 1 -i "$TUN" -j "$TUN_FWD_CHAIN"' in script
    assert 'iptables -I DOCKER-USER 1 -i "$TUN" -j "$TUN_FWD_CHAIN"' in script
    assert 'iptables -A "$TUN_IN_CHAIN" -j DROP' in script
    assert 'iptables -A "$TUN_FWD_CHAIN" ! -o "$uplink" -j DROP' in script
    # Same denied destinations as the TCP stream server.
    server_policy = Path("chameleon/server/tcp_stream.go").read_text(encoding="utf-8")
    denied = re.search(r'DENIED_DESTINATIONS="([^"]+)"', script).group(1).split()
    assert sorted(denied) == sorted(re.findall(r'MustParsePrefix\("([0-9./]+)"\)', server_policy))


def test_vps_tunnel_isolation_in_linux_namespaces(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("network-namespace behavior is verified on Linux")
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash is unavailable")
    rendered = tmp_path / "chameleon-network-setup"
    rendered.write_text(StealthService._network_setup_script(), encoding="utf-8")
    command = [bash, "tests/acceptance/chameleon_vps_isolation_regression.sh", str(rendered)]
    if os.geteuid() != 0:
        sudo = shutil.which("sudo")
        if not sudo or subprocess.run([sudo, "-n", "true"], capture_output=True, check=False).returncode:
            pytest.skip("passwordless root network-namespace privileges are unavailable")
        command = [sudo, "-n", *command]
    result = subprocess.run(command, capture_output=True, text=True, check=False, timeout=180)
    if result.returncode == 77:
        pytest.skip(result.stderr.strip() or "network-namespace prerequisites unavailable")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "CHAMELEON_VPS_ISOLATION_REGRESSION=PASS" in result.stdout


def test_stealth_tun_validator_ignores_other_tun_interfaces(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    script = StealthService._network_setup_script()
    validator = script.split("python3 -c '\n", 1)[1].split("\n' \"$TUN\"", 1)[0]
    rows = [
        {"ifname": "openvpn0", "flags": ["tun", "persist"], "user": 998},
        {"ifname": "chameleon0", "flags": ["tun", "persist"], "user": 995},
    ]
    monkeypatch.setattr(sys, "stdin", io.StringIO(json.dumps(rows)))
    monkeypatch.setattr(sys, "argv", ["validator", "chameleon0", "995"])

    with pytest.raises(SystemExit) as result:
        exec(validator, {})

    assert result.value.code == 0


def test_installer_rejects_real_stealth_binary_symlinks() -> None:
    bash = shutil.which("bash")
    if bash is None:
        pytest.skip("bash is required for the installer security test")
    result = subprocess.run(
        [bash, "tests/security/test_install_binary_trust.sh"],
        cwd=Path.cwd(),
        capture_output=True,
        text=True,
        timeout=30,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_ipv6_policy_is_rechecked_and_enforced_at_runtime() -> None:
    guard = Path("scripts/security/ipv6_policy_guard.sh").read_text(encoding="utf-8")
    service = Path(
        "templates/systemd/easypi-ipv6-policy-guard.service"
    ).read_text(encoding="utf-8")
    dispatcher = Path(
        "templates/networkmanager/90-easypi-ipv6-policy-guard"
    ).read_text(encoding="utf-8")
    netprotection = Path(
        "templates/systemd/easypi-netprotection.service"
    ).read_text(encoding="utf-8")
    backend = Path("templates/systemd/easypi-backend.service").read_text(
        encoding="utf-8"
    )
    binary_backend = Path(
        "templates/systemd/easypi-backend-binary.service"
    ).read_text(encoding="utf-8")

    assert 'readonly CHAIN="EASYPI_IPV6_GUARD"' in guard
    assert 'readonly EMERGENCY="EASYPI_IPV6_EMERGENCY"' in guard
    assert "EASYPI_IPV6_STATE_DIR:-/var/lib/easypi/security" in guard
    assert 'ip6tables -w 5 -I FORWARD 1 -j "${EMERGENCY}"' in guard
    assert "disable_kernel_forwarding" in guard
    assert "CHECK_INTERVAL_SECONDS=15" in guard
    assert "route show default" in guard
    assert "--ctdir REPLY" in guard
    assert "Before=easypi-netprotection.service easypi-backend.service" in service
    assert "ExecStartPre=" in service and "--establish" in service
    assert "ExecStart=" in service and "--monitor" in service
    assert "Restart=on-failure" in service
    assert "StateDirectory=easypi/security" in service
    assert "ReadWritePaths=/run/lock" in service
    assert "SIGUSR1" in dispatcher and "dhcp6-change" in dispatcher
    assert not Path("templates/systemd/easypi-ipv6-policy-guard.timer").exists()
    installer = Path("install.sh").read_text(encoding="utf-8")
    assert "disable --now easypi-ipv6-policy-guard.timer" in installer
    for dependent in (netprotection, backend, binary_backend):
        assert "Requires=easypi-ipv6-policy-guard.service" in dependent
        assert "BindsTo=easypi-ipv6-policy-guard.service" in dependent
        assert any(
            line.startswith("After=")
            and "easypi-ipv6-policy-guard.service" in line.split("=", 1)[1].split()
            for line in dependent.splitlines()
        )


def test_unknown_device_assurance_limit_is_explicit() -> None:
    model = Path("docs/NETWORK_SECURITY_MODEL.md").read_text(encoding="utf-8")
    settings = Path(
        "backend/app/services/netprotection_components/settings.py"
    ).read_text(encoding="utf-8")
    assert "not cryptographic device" in model
    assert "authentication" in model
    assert "802.1X or WPA-Enterprise" in model
    assert '"spoof_resistant": False' in settings


def test_unknown_device_firewall_uses_profile_bindings() -> None:
    script = Path("scripts/settings/setup_vpn_blocking.sh").read_text(encoding="utf-8")
    assert 'profiles_file="/opt/EasyPi/data/netprotection/profiles.json"' in script
    assert 'bindings_file="/opt/EasyPi/data/netprotection/bindings.json"' in script
    assert "refusing partial admission policy" in script
    assert 'staging="EASYPI_ADMISSION_NEXT"' in script
    assert 'iptables -E "$staging" "$chain"' in script
    assert '-s "$known_ip" -m mac --mac-source "$known_mac"' in script
    assert 'print(f"PAIR|{mac}|{network}")' in script


def test_unknown_device_approval_uses_durable_fail_closed_hold() -> None:
    script = Path("scripts/settings/setup_vpn_blocking.sh").read_text(encoding="utf-8")
    assert 'ADMISSION_HOLD_FILE="$STATE_DIR/admission_holds.json"' in script
    assert 'ADMISSION_HOLD_CHAIN="EASYPI_ADMISSION_HOLD"' in script
    assert 'STATE_GROUP="easypi"' in script
    assert "EASYPI_STATE_GROUP" not in script
    assert "hold-admission)" in script
    assert "release-admission)" in script
    assert 'sync_admission_holds "$CLIENT_MAC"' in script
    release = script[script.index("    release-admission)") :]
    assert release.index('sync_admission_holds "$CLIENT_MAC"') < release.index(
        'admission_hold_state_cmd remove "$CLIENT_IP" "$CLIENT_MAC"'
    )
    sync_body = script[script.index("sync_from_devices() {") :]
    assert sync_body.index("sync_admission_holds") < sync_body.index(
        "ensure_conntrack_acct"
    )


def test_unknown_device_quarantine_is_passive_persistent_and_fail_closed(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "netprotection"
    data_dir.mkdir()
    arp_path = tmp_path / "arp"
    dhcp_path = tmp_path / "dhcp.json"
    observed_at = time.time()
    dhcp_path.write_text(
        json.dumps(
            {
                "version": 5,
                "devices": [
                    {
                        "ipv4": "192.168.1.55",
                        "mac": "02:00:00:00:00:55",
                        "last_seen_timestamp": observed_at,
                    }
                ],
                "address_bindings": {
                    "192.168.1.55": {
                        "mac": "02:00:00:00:00:55",
                        "assigned_at_timestamp": observed_at,
                        "last_seen_timestamp": observed_at,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    arp_path.write_text(
        "IP address HW type Flags HW address Mask Device\n"
        "192.168.1.55 0x1 0x2 02:00:00:00:00:55 * eth0\n",
        encoding="utf-8",
    )
    service = UnknownDeviceAdmissionService(
        data_dir, arp_path=arp_path, dhcp_paths=(dhcp_path,)
    )

    discovered = service.refresh()
    assert len(discovered) == 1
    device_id = discovered[0]["id"]
    assert discovered[0]["status"] == "pending"
    assert discovered[0]["sources"] == ["arp", "dhcp", "traffic"]
    assert service.refresh() == []

    blocked = service.block(device_id)
    assert blocked["status"] == "blocked"
    assert service.list_devices() == []
    assert service.list_devices(include_blocked=True)[0]["status"] == "blocked"

    # A DHCP address change never converts a Block decision into access.
    changed_at = time.time()
    dhcp_path.write_text(
        json.dumps(
            {
                "version": 5,
                "devices": [
                    {
                        "ipv4": "192.168.1.77",
                        "mac": "02:00:00:00:00:55",
                        "last_seen_timestamp": changed_at,
                    }
                ],
                "address_bindings": {
                    "192.168.1.77": {
                        "mac": "02:00:00:00:00:55",
                        "assigned_at_timestamp": changed_at,
                        "last_seen_timestamp": changed_at,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    arp_path.write_text(
        "IP address HW type Flags HW address Mask Device\n"
        "192.168.1.77 0x1 0x2 02:00:00:00:00:55 * eth0\n",
        encoding="utf-8",
    )
    assert service.refresh() == []
    assert service.list_devices(include_blocked=True)[0]["ip"] == "192.168.1.77"


def test_approved_pair_is_not_quarantined_and_browser_cannot_replace_identity(
    tmp_path: Path,
) -> None:
    data_dir = tmp_path / "netprotection"
    data_dir.mkdir()
    arp_path = tmp_path / "arp"
    arp_path.write_text(
        "IP address HW type Flags HW address Mask Device\n"
        "192.168.1.55 0x1 0x2 02:00:00:00:00:55 * eth0\n",
        encoding="utf-8",
    )
    (data_dir / "clients.json").write_text(
        '{"clients":[{"name":"Phone","ip":"192.168.1.55",'
        '"mac":"02:00:00:00:00:55"}]}',
        encoding="utf-8",
    )
    service = UnknownDeviceAdmissionService(
        data_dir, arp_path=arp_path, dhcp_paths=(tmp_path / "missing.json",)
    )
    assert service.refresh() == []
    assert service.list_devices(include_blocked=True) == []

    # The same managed MAC at a new address is updated only after real IPv4
    # source traffic confirms the pair. A stale old ARP entry must not override
    # the traffic-observed binding.
    dhcp_path = tmp_path / "dhcp.json"
    observed_at = time.time()
    dhcp_path.write_text(
        json.dumps(
            {
                "version": 5,
                "devices": [
                    {
                        "ipv4": "192.168.1.77",
                        "mac": "02:00:00:00:00:55",
                        "hostname": "Phone",
                        "last_seen_timestamp": observed_at,
                    }
                ],
                "address_bindings": {
                    "192.168.1.77": {
                        "mac": "02:00:00:00:00:55",
                        "assigned_at_timestamp": observed_at,
                        "last_seen_timestamp": observed_at,
                    }
                },
            }
        ),
        encoding="utf-8",
    )
    arp_path.write_text(
        "IP address HW type Flags HW address Mask Device\n"
        "192.168.1.55 0x1 0x2 02:00:00:00:00:55 * eth0\n",
        encoding="utf-8",
    )
    service.dhcp_paths = (dhcp_path,)
    changed = service.refresh()
    assert len(changed) == 1
    assert changed[0]["managed_device"] is True
    assert changed[0]["managed_name"] == "Phone"
    assert changed[0]["managed_profile"] == "balanced"

    with pytest.raises(ValueError):
        UnknownDeviceApproval.model_validate(
            {
                "name": "Spoofed",
                "access_profile": "balanced",
                "mac": "02:00:00:00:00:99",
                "ip": "192.168.1.99",
            }
        )


def test_device_access_profiles_map_to_real_dns_policy(tmp_path: Path) -> None:
    harness = _ParentalHarness(tmp_path)
    base = {
        "id": "phone",
        "name": "Phone",
        "ip": "192.168.1.55",
        "mac": "02:00:00:00:00:55",
        "enabled": True,
        "blocked_services": [],
    }

    balanced = dict(base, shield_profile="balanced")
    *_, balanced_profiles, _bindings = harness._build_parental_policy_documents(
        [balanced]
    )
    assert balanced_profiles[0]["filter_level"] == "standard"

    kids = dict(base, shield_profile="kids", parental=True, safesearch=True)
    *_, kids_profiles, _bindings = harness._build_parental_policy_documents([kids])
    assert kids_profiles[0]["filter_level"] == "strict"
    assert kids_profiles[0]["safe_search"] is True
    assert "__adult_heuristic__" in kids_profiles[0]["blacklist"]


def test_failed_device_approval_restores_policy_files(tmp_path: Path) -> None:
    harness = _FailingApprovalHarness(tmp_path)
    original = b'{"clients":[]}'
    (tmp_path / "clients.json").write_bytes(original)

    with pytest.raises(RuntimeError, match="sync failed"):
        asyncio.run(
            harness.approve_client_transactional(
                {
                    "name": "Phone",
                    "ip": "192.168.1.55",
                    "mac": "02:00:00:00:00:55",
                }
            )
        )

    assert (tmp_path / "clients.json").read_bytes() == original
    for name in ("devices.json", "profiles.json", "bindings.json"):
        assert not (tmp_path / name).exists()
    assert harness.actions == ["hold-admission"]


def test_existing_mac_approval_preserves_restrictions_under_admission_hold(
    tmp_path: Path,
) -> None:
    harness = _ParentalHarness(tmp_path)
    (tmp_path / "clients.json").write_text(
        '{"clients":[{"id":"phone-id","name":"Phone",'
        '"ip":"192.168.1.55","ids":["192.168.1.55"],'
        '"mac":"02:00:00:00:00:55","shield_profile":"kids",'
        '"blocked_services":["tor"],'
        '"custom_blocked_domains":["blocked.example"],'
        '"custom_allowed_domains":["allowed.example"],'
        '"bypass_mode":"quarantine","parental_enabled":true,'
        '"safesearch_enabled":true,"safebrowsing_enabled":false,'
        '"filtering_enabled":false,"use_global_settings":true}]}',
        encoding="utf-8",
    )

    result = asyncio.run(
        harness.approve_client_transactional(
            {
                "name": "Phone",
                "ip": "192.168.1.77",
                "ids": ["192.168.1.77"],
                "mac": "02:00:00:00:00:55",
                "shield_profile": "balanced",
                # Defaults used for a brand-new device. They must not weaken an
                # already managed device during a DHCP address update.
                "blocked_services": [],
                "custom_blocked_domains": [],
                "custom_allowed_domains": [],
                "bypass_mode": "warn",
                "parental_enabled": False,
                "safesearch_enabled": False,
                "safebrowsing_enabled": True,
            }
        )
    )

    persisted = json.loads(
        (tmp_path / "clients.json").read_text(encoding="utf-8")
    )["clients"]
    assert len(persisted) == 1
    assert persisted[0]["id"] == "phone-id"
    assert persisted[0]["ip"] == "192.168.1.77"
    assert persisted[0]["shield_profile"] == "balanced"
    assert persisted[0]["blocked_services"] == ["tor"]
    assert persisted[0]["custom_blocked_domains"] == ["blocked.example"]
    assert persisted[0]["custom_allowed_domains"] == ["allowed.example"]
    assert persisted[0]["bypass_mode"] == "quarantine"
    assert persisted[0]["parental_enabled"] is True
    assert persisted[0]["safesearch_enabled"] is True
    assert persisted[0]["safebrowsing_enabled"] is False
    assert persisted[0]["filtering_enabled"] is False
    assert persisted[0]["use_global_settings"] is True
    assert result["updated_existing"] is True
    assert harness.actions == ["hold-admission", "release-admission"]


def test_new_device_alerts_are_rate_limited_and_summarized(tmp_path: Path) -> None:
    async def scenario() -> list[dict]:
        monitor = ProactiveMonitor(tmp_path)
        emitted: list[dict] = []
        monitor._emit = lambda **record: emitted.append(record)  # type: ignore[method-assign]
        for index in range(8):
            monitor._queue_new_device_alert(
                {
                    "id": f"device-{index}",
                    "ip": f"192.168.1.{index + 10}",
                    "mac": f"02:00:00:00:00:{index:02x}",
                }
            )
        assert len(emitted) == 5
        assert monitor._suppressed_device_alerts == 3
        assert monitor._device_summary_task is not None
        monitor._device_summary_task.cancel()
        try:
            await monitor._device_summary_task
        except asyncio.CancelledError:
            pass
        await monitor._emit_suppressed_device_summary(0)
        return emitted

    emitted = asyncio.run(scenario())
    assert len(emitted) == 6
    assert emitted[-1]["title"] == "More new devices detected"
    assert "3 additional" in emitted[-1]["message"]


def test_telegram_watchdog_content_is_html_escaped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import app.services.push_notification_service as push_module
    import app.services.telegram_alert_service as telegram_module

    sent: list[str] = []

    class _Push:
        is_configured = False

        @staticmethod
        def get_subscription_count() -> int:
            return 0

    class _Telegram:
        is_configured = True

        async def send(self, text: str) -> dict:
            sent.append(text)
            return {"ok": True}

    monkeypatch.setattr(push_module, "get_push_service", lambda: _Push())
    monkeypatch.setattr(telegram_module, "get_telegram_alerts", lambda: _Telegram())

    monitor = ProactiveMonitor(tmp_path)
    asyncio.run(
        monitor._dispatch_alert(
            {
                "title": '<a href="https://evil.invalid">Phone</a>',
                "message": "<b>spoofed</b>",
                "severity": "warning",
                "event_id": "test",
            }
        )
    )
    assert len(sent) == 1
    assert '<a href="https://evil.invalid">' not in sent[0]
    assert "&lt;a href=&quot;https://evil.invalid&quot;&gt;" in sent[0]
    assert "&lt;b&gt;spoofed&lt;/b&gt;" in sent[0]


def test_mobile_tunnel_address_belongs_to_exactly_one_managed_device(
    tmp_path: Path,
) -> None:
    harness = _ParentalHarness(tmp_path)
    (tmp_path / "clients.json").write_text(
        '{"clients":[{"id":"phone-a","name":"Phone A","ip":"10.77.0.3",'
        '"ids":["10.77.0.3"],"mac":"02:00:00:00:00:0a"}]}',
        encoding="utf-8",
    )
    original = (tmp_path / "clients.json").read_bytes()

    with pytest.raises(ValueError, match="already belongs to another"):
        asyncio.run(
            harness.approve_client_transactional(
                ParentalMixin.managed_client_record(
                    "Phone B", "10.77.0.3", "02:00:00:00:00:0b", "balanced"
                )
            )
        )
    assert (tmp_path / "clients.json").read_bytes() == original
    # The refusal happens before any root-owned hold is created.
    assert harness.actions == []

    # The owning phone itself, and LAN addresses, are unaffected.
    asyncio.run(
        harness.approve_client_transactional(
            {"ip": "10.77.0.3", "ids": ["10.77.0.3"], "mac": "02:00:00:00:00:0a"}
        )
    )
    assert harness.actions == ["hold-admission", "release-admission"]


def _admission_firewall_rules(tmp_path: Path, registry: str | None) -> list[str]:
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash is unavailable")
    script = Path("scripts/settings/setup_vpn_blocking.sh").read_text(encoding="utf-8")

    def function(name: str) -> str:
        # A function ends where the next top-level function begins; embedded
        # Python heredocs contain closing braces of their own.
        start = script.index(f"\n{name}() {{") + 1
        following = re.search(r"\n[a-z_]+\(\) \{\n", script[start:])
        assert following is not None
        return script[start : start + following.start() + 1]

    data_dir = tmp_path / "netprotection"
    runtime_dir = tmp_path / "run"
    data_dir.mkdir()
    runtime_dir.mkdir()
    if registry is not None:
        (data_dir / "mobile-home-tunnel-peers.json").write_text(registry, encoding="utf-8")
    phone = "eb4613c0-3146-47e9-878c-788c48a3713f"
    live_mac = UnknownDeviceAdmissionService.mobile_tunnel_mac(phone).lower()
    body = (
        function("is_valid_ipv4")
        + function("is_valid_mac")
        + function("sync_unknown_device_admission")
    ).replace("/opt/EasyPi/data/netprotection", data_dir.as_posix()).replace(
        "/usr/bin/python3", "python_shim"
    )
    log = tmp_path / "iptables.log"
    program = f"""
set -u -o pipefail
RUNTIME_DIR={shlex.quote(runtime_dir.as_posix())}
# Normalise Windows line endings of the test interpreter; Linux is unaffected.
python_shim() {{ {shlex.quote(Path(sys.executable).as_posix())} "$@" | tr -d '\\r'; }}
iptables() {{
    case "$1" in -C|-L) return 1;; esac
    printf '%s\n' "$*" >> {shlex.quote(log.as_posix())}
}}
chain_exists() {{ iptables -L "$1" -n >/dev/null 2>&1; }}
{body}
managed_macs=({live_mac} 02:00:00:00:00:0b 02:00:00:00:00:0c aa:bb:cc:dd:ee:01)
declare -A mac_ips=(
    [{live_mac}]=10.77.0.3
    [02:00:00:00:00:0b]=10.77.0.3
    [02:00:00:00:00:0c]=10.77.0.5
    [aa:bb:cc:dd:ee:01]=192.168.1.10
)
sync_unknown_device_admission
"""
    program_path = tmp_path / "admission.sh"
    program_path.write_text(program, encoding="utf-8", newline="\n")
    result = subprocess.run(
        [bash, program_path.as_posix()], capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    return log.read_text(encoding="utf-8").splitlines()


def test_tunnel_admission_follows_the_live_peer_registry(tmp_path: Path) -> None:
    registry = (
        '{"version":1,"devices":[{"id":"eb4613c0-3146-47e9-878c-788c48a3713f",'
        '"address":"10.77.0.3"}]}'
    )
    rules = _admission_firewall_rules(tmp_path, registry)
    tunnel = [rule for rule in rules if "easypi-mobile0" in rule]
    # Only the phone the registry assigns to 10.77.0.3 is admitted. A stale
    # approval for the same address, and one for an unassigned address, are not.
    assert tunnel == [
        "-A EASYPI_ADMISSION_NEXT -i easypi-mobile0 -s 10.77.0.3 -j RETURN"
    ]
    assert (
        "-A EASYPI_ADMISSION_NEXT -s 192.168.1.10 -m mac --mac-source "
        "aa:bb:cc:dd:ee:01 -j RETURN"
    ) in rules
    assert "-A EASYPI_ADMISSION_NEXT -j REJECT --reject-with icmp-admin-prohibited" in rules


@pytest.mark.parametrize("registry", [None, "{not json", '{"version":1,"devices":[{"id":"x"}]}'])
def test_unreadable_peer_registry_admits_no_tunnel_peer(
    tmp_path: Path, registry: str | None
) -> None:
    rules = _admission_firewall_rules(tmp_path, registry)
    assert not [rule for rule in rules if "easypi-mobile0" in rule]
    assert any("192.168.1.10" in rule for rule in rules)


def test_tunnel_holds_emit_no_mac_rule() -> None:
    script = Path("scripts/settings/setup_vpn_blocking.sh").read_text(encoding="utf-8")
    holds = script[script.index("sync_admission_holds() {") :]
    holds = holds[: holds.index("\n}\n")]
    assert holds.index('[[ "$hold_ip" == 10.77.0.* ]] && continue') < holds.index(
        "--mac-source"
    )


def test_tunnel_phone_dns_redirect_and_bypass_chain_use_the_tunnel_address(
    tmp_path: Path,
) -> None:
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash is unavailable")
    script = Path("scripts/settings/setup_vpn_blocking.sh").read_text(encoding="utf-8")

    def function(name: str) -> str:
        start = script.index(f"\n{name}() {{") + 1
        following = re.search(r"\n[a-z_]+\(\) \{\n", script[start:])
        assert following is not None
        return script[start : start + following.start() + 1]

    log = tmp_path / "iptables.log"
    program = (
        "set -u\n"
        'MOBILE_TUNNEL_IFACE="easypi-mobile0"\n'
        'DNS_REDIRECT_COMMENT="easypi-dns-redirect"\n'
        "iptables() {\n"
        '    for arg in "$@"; do [[ "$arg" == "-C" ]] && return 1; done\n'
        f'    printf "%s\n" "$*" >> {shlex.quote(log.as_posix())}\n'
        "}\n"
        + function("is_valid_ipv4")
        + function("is_valid_mac")
        + function("is_mobile_tunnel_ip")
        + function("add_dns_redirect")
        + "add_dns_redirect 10.77.0.3 02:00:00:00:02:03\n"
        + "add_dns_redirect 192.168.1.20 aa:bb:cc:dd:ee:20\n"
        + "is_mobile_tunnel_ip 10.77.0.1 && echo gateway-misclassified >&2 || true\n"
    )
    program_path = tmp_path / "redirect.sh"
    program_path.write_text(program, encoding="utf-8", newline="\n")
    result = subprocess.run([bash, program_path.as_posix()], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "gateway-misclassified" not in result.stderr
    rules = log.read_text(encoding="utf-8").splitlines()
    assert (
        "-t nat -A PREROUTING -i easypi-mobile0 -s 10.77.0.3 -p udp --dport 53 "
        "-m comment --comment easypi-dns-redirect -j REDIRECT --to-ports 53"
    ) in rules
    assert not any("10.77.0.3" in rule and "--mac-source" in rule for rule in rules)
    assert any("--mac-source aa:bb:cc:dd:ee:20" in rule for rule in rules)

    hook = script[script.index("    remove_chain_references \"$chain_name\"\n    if is_mobile_tunnel_ip") :]
    assert hook.index('-i "$MOBILE_TUNNEL_IFACE" -s "$client_ip" -j "$chain_name"') < hook.index(
        '-m mac --mac-source "$client_mac" -j "$chain_name"'
    )
    reconcile = script[script.index("local -a desired_dns_redirects=()") :]
    assert 'desired_dns_redirects+=("ip:${mac_ips[$desired_mac]}")' in reconcile[:600]
