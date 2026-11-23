from __future__ import annotations

import hashlib
import io
import re
import socket
import tarfile
from pathlib import Path

import pytest

from scripts.maintenance.update_url_guard import (
    UrlGuardError,
    redirect_target,
    resolve_public_https_url,
)
from scripts.release.validate_release_archive import (
    ReleaseValidationError,
    validate_release_archive,
)


ROOT = Path(__file__).resolve().parents[2]


def test_stealth_status_checks_do_not_trip_pipefail_with_early_grep_exit() -> None:
    script = (ROOT / "scripts/settings/stealth_vpn.sh").read_text(encoding="utf-8")
    assert re.search(r"\|\s*grep\s+-[^\n]*q", script) is None


def _resolver(*addresses: str):
    def resolve(host: str, port: int, *, type: int):
        assert host == "releases.example"
        assert port == 443
        assert type == socket.SOCK_STREAM
        return [
            (socket.AF_INET6 if ":" in address else socket.AF_INET, type, 6, "", (address, port))
            for address in addresses
        ]

    return resolve


def _release_archive(
    tmp_path: Path,
    *,
    tamper_manifest: bool = False,
    extra_build_info_line: bytes = b"",
) -> Path:
    payload = tmp_path / "payload"
    payload.mkdir()
    files = {
        "VERSION": b"1.1.0\n",
        "BUILD_INFO": (
            b"EasyPi full binary release\n"
            b"Architecture: aarch64\n"
            b"Build distro codename: trixie\n"
            b"Build glibc: 2.36\n"
            + extra_build_info_line
            + b"Source commit: 0123456789abcdef0123456789abcdef01234567\n"
        ),
        "install.sh": b"#!/bin/sh\nexit 0\n",
        "update.sh": b"#!/bin/sh\nexit 0\n",
        "uninstall.sh": b"#!/bin/sh\nexit 0\n",
    }
    required_files = {
        "backend/bin/easypi-backend",
        "backend/main.py",
        "backend/app/core/openvpn_config.py",
        "backend/requirements.lock",
        "frontend/dist/index.html",
        "templates/nginx/easypi.conf",
        "templates/nginx/easypi-mobile-link.conf",
        "templates/systemd/easypi-backend-binary.service",
        "templates/systemd/easypi-dhcp-observer.service",
        "templates/systemd/easypi-installer@.service",
        "templates/systemd/easypi-netprotection.service",
        "templates/systemd/easypi-mobile-link-agent.service",
        "templates/systemd/easypi-mobile-home-tunnel-agent.service",
        "templates/systemd/easypi-mobile-home-tunnel.service",
        "templates/systemd/easypi-stealth-guard.service",
        "templates/systemd/easypi-stealth-dns.service",
        "templates/systemd/easypi-stealth-resume.service",
        "templates/systemd/easypi-telegram-bot.service",
        "templates/systemd/easypi-taildrop-import.service",
        "config/netprotection.toml",
        "easypi_netprotection/__main__.py",
        "easypi_netprotection/stealth_dns.py",
        "easypi_netprotection/stealth_dns_policy.py",
        "prism_dpi/__init__.py",
        "docs/PRISM_TLS_ENDPOINT_BRIDGE.md",
        "prism_tls_bridge/__init__.py",
        "prism_tls_bridge/bridge.py",
        "prism_tls_bridge/capture.py",
        "prism_tls_bridge/channel.py",
        "prism_tls_bridge/entrypoint.py",
        "prism_tls_bridge/models.py",
        "prism_tls_bridge/pcap_live.py",
        "prism_tls_bridge/qpack_guard.py",
        "prism_tls_bridge/quic.py",
        "prism_tls_bridge/resource_guard.py",
        "prism_tls_bridge/shadow.py",
        "prism_tls_bridge/shadow_agent.py",
        "prism_tls_bridge/shadow_child.py",
        "prism_tls_bridge/tls.py",
        "prism_tls_bridge/transport.py",
        "prism_tls_bridge/worker.py",
        "templates/systemd/easypi-prism-endpoint-bridge.socket",
        "templates/systemd/easypi-prism-endpoint-bridge@.service",

        "scripts/runner",
        "scripts/services/picloud_taildrop_import.py",
        "scripts/services/chameleon_mobile_link_relay.sh",
        "scripts/services/tailscale_peer_relay.sh",
        "scripts/sudoers.d/easypi",
        "scripts/settings/network_firewall.sh",
        "scripts/settings/mobile_link_agent.sh",
        "scripts/settings/mobile_link_relay_secrets.sh",
        "scripts/settings/stealth_vpn.sh",
        "scripts/settings/tailscale_relay_secrets.sh",
        "scripts/setup/setup_unbound.sh",
        "scripts/security/verify_trusted_install_path.sh",
        "scripts/security/verify_chameleon_install_inputs.sh",
        "scripts/maintenance/apply_update.sh",
        "scripts/maintenance/verify_runtime_health.py",
        "scripts/maintenance/update_url_guard.py",
        "scripts/maintenance/update_signing_key.pub",
        "scripts/maintenance/easypi-update-recovery.service",
        "scripts/utils/postgres_backup.py",
        "scripts/release/validate_release_archive.py",
        "chameleon/build.sh",
        "chameleon/ensure-go.sh",
        "chameleon/go.mod",
        "chameleon/go.sum",
        "chameleon/mobilelink/protocol.go",
        "chameleon/cmd/chameleon-mobile-link-agent/main.go",
        "chameleon/cmd/chameleon-mobile-link-relay/main.go",
        "chameleon/tools/prepare_http2_modfile.sh",
    }
    files.update({name: b"release fixture\n" for name in required_files})
    for name, value in files.items():
        destination = payload / name
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(value)
    manifest_lines = [
        f"{hashlib.sha256(value).hexdigest()}  ./{name}"
        for name, value in sorted(files.items())
    ]
    if tamper_manifest:
        manifest_lines = [
            f"{'0' * 64}  ./uninstall.sh" if line.endswith("  ./uninstall.sh") else line
            for line in manifest_lines
        ]
    (payload / "RELEASE_MANIFEST.sha256").write_text(
        "\n".join(manifest_lines) + "\n", encoding="utf-8"
    )
    archive_path = tmp_path / "easypi-full-aarch64-trixie.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        for path in sorted(payload.rglob("*")):
            if path.is_file():
                archive.add(path, arcname=path.relative_to(payload).as_posix(), recursive=False)
    return archive_path


def test_url_guard_pins_a_public_https_address() -> None:
    hop = resolve_public_https_url(
        "https://Releases.Example/download?id=1",
        resolver=_resolver("93.184.216.34"),
    )
    assert hop.url == "https://releases.example/download?id=1"
    assert hop.host == "releases.example"
    assert hop.port == 443
    assert hop.address == "93.184.216.34"


@pytest.mark.parametrize(
    "url",
    [
        "http://releases.example/file",
        "https://user@releases.example/file",
        "https://releases.example/file#fragment",
        "https://releases.example/file name",
        "https://releases.example\\@127.0.0.1/file",
    ],
)
def test_url_guard_rejects_unsafe_urls(url: str) -> None:
    with pytest.raises(UrlGuardError):
        resolve_public_https_url(url, resolver=_resolver("93.184.216.34"))


def test_url_guard_rejects_mixed_public_and_private_dns_answers() -> None:
    with pytest.raises(UrlGuardError, match="non-public"):
        resolve_public_https_url(
            "https://releases.example/file",
            resolver=_resolver("93.184.216.34", "127.0.0.1"),
        )


def test_redirect_guard_accepts_one_relative_https_target() -> None:
    headers = b"HTTP/1.1 302 Found\r\nLocation: ../asset.tar.gz\r\n\r\n"
    assert redirect_target(
        "https://releases.example/v1/current", headers
    ) == "https://releases.example/asset.tar.gz"


@pytest.mark.parametrize(
    "headers",
    [
        b"HTTP/1.1 302 Found\r\nLocation: http://example.com/file\r\n\r\n",
        b"HTTP/1.1 302 Found\r\nLocation: /a\r\nLocation: /b\r\n\r\n",
        b"HTTP/1.1 302 Found\r\nLocation: /a\r\n folded\r\n\r\n",
        b"HTTP/1.1 302 Found\r\nLocation: /unsafe path\r\n\r\n",
    ],
)
def test_redirect_guard_rejects_unsafe_locations(headers: bytes) -> None:
    with pytest.raises(UrlGuardError):
        redirect_target("https://releases.example/current", headers)


def test_release_validator_accepts_complete_manifest(tmp_path: Path) -> None:
    archive = _release_archive(tmp_path)
    assert validate_release_archive(archive) == "1.1.0"


def test_release_validator_rejects_manifest_tampering(tmp_path: Path) -> None:
    archive = _release_archive(tmp_path, tamper_manifest=True)
    with pytest.raises(ReleaseValidationError, match="hash mismatch"):
        validate_release_archive(archive)


def test_release_validator_rejects_unlabeled_build_metadata(tmp_path: Path) -> None:
    archive = _release_archive(tmp_path, extra_build_info_line=b"unknown\n")
    with pytest.raises(ReleaseValidationError, match="unlabeled"):
        validate_release_archive(archive)


def test_release_validator_rejects_incomplete_product_payload(tmp_path: Path) -> None:
    archive = _release_archive(tmp_path)
    incomplete = tmp_path / "incomplete.tar.gz"
    with tarfile.open(archive, "r:gz") as source, tarfile.open(incomplete, "w:gz") as target:
        for member in source.getmembers():
            if member.name == "frontend/dist/index.html":
                continue
            stream = source.extractfile(member) if member.isfile() else None
            target.addfile(member, stream)

    with pytest.raises(ReleaseValidationError, match="release archive is missing"):
        validate_release_archive(incomplete)


@pytest.mark.parametrize(
    "name",
    [
        "data/db/easypi.db",
        "data/backups/config.epibak",
        "data/notification_prefs.json",
        "backend/data/users.db",
        "prism_dpi/captures/phone.pcap",
        "easypi_netprotection/proxy/session.json",
        "backend/app/.env.production",
    ],
)
def test_release_validator_rejects_runtime_and_user_state(
    tmp_path: Path,
    name: str,
) -> None:
    archive = _release_archive(tmp_path)
    poisoned = tmp_path / "poisoned.tar.gz"
    with tarfile.open(archive, "r:gz") as source, tarfile.open(poisoned, "w:gz") as target:
        for member in source.getmembers():
            stream = source.extractfile(member) if member.isfile() else None
            target.addfile(member, stream)
        payload = b"private runtime state"
        member = tarfile.TarInfo(name)
        member.size = len(payload)
        target.addfile(member, io.BytesIO(payload))

    with pytest.raises(ReleaseValidationError, match="runtime|database|backup|environment"):
        validate_release_archive(poisoned)


def test_release_scripts_enforce_lifecycle_and_signature_contract() -> None:
    installer = (ROOT / "install.sh").read_text(encoding="utf-8")
    packager = (ROOT / "backend/packaging/build_binary.sh").read_text(
        encoding="utf-8"
    )
    updater = (ROOT / "scripts/maintenance/apply_update.sh").read_text(
        encoding="utf-8"
    )
    bootstrap = (ROOT / "scripts/maintenance/install_signed_release.sh").read_text(
        encoding="utf-8"
    )
    public_bundle = (ROOT / "scripts/release/prepare_public_repo.sh").read_text(
        encoding="utf-8"
    )
    upload = (ROOT / "distribution/releases/UPLOAD.md").read_text(encoding="utf-8")

    assert 'build_info_file="${BASE_DIR}/BUILD_INFO"' in installer
    assert "for lifecycle_script in install.sh update.sh uninstall.sh" in installer
    assert "for lifecycle_script in install.sh update.sh uninstall.sh" in packager
    assert 'chmod 755 "${RELEASE_DIR}/update.sh"' in packager
    assert 'validate_release_archive.py" \\' in packager
    assert '|| error "Release archive validation failed"' in packager
    assert 'git -C "${SOURCE_PROJECT_ROOT}" archive' in packager
    assert 'Source commit: ${SOURCE_COMMIT}' in packager
    assert '"${SOURCE_PROJECT_ROOT}/scripts/release/stage_chameleon_source.sh"' in packager
    assert '"${SOURCE_PROJECT_ROOT}/chameleon" "${RELEASE_DIR}/chameleon"' in packager
    assert "URL_GUARD=" in updater
    assert "ARCHIVE_VALIDATOR=" in updater
    assert "--noproxy '*'" in updater
    assert "curl --disable" in updater
    assert 'python3 "${ARCHIVE_VALIDATOR}" "${ARCHIVE}"' in updater
    assert "301|302|303|307|308" in updater
    assert '[[ -n "${SIG_IN}" ]]' in updater
    assert "trusted_snapshot_dir" in updater
    assert 'APPLY_EXCLUDES=("${RSYNC_EXCLUDES[@]}" --exclude "certs/")' in updater
    assert 'RSYNC_ARGS=(-a --chown=root:easypi --chmod=go-w "${APPLY_EXCLUDES[@]}")' in updater
    assert 'PAYLOAD_CHAMELEON_DIGEST="$(chameleon_source_digest "${PAYLOAD}/chameleon")"' in updater
    assert 'INSTALLED_CHAMELEON_DIGEST="$(chameleon_source_digest "${TARGET_DIR}/chameleon")"' in updater
    assert 'if [[ "${PAYLOAD_CHAMELEON_DIGEST}" != "${INSTALLED_CHAMELEON_DIGEST}" ]]' in updater
    assert "RUN_INSTALL=1" in updater
    assert "--exclude=.build" in updater
    assert 'rsync -a --delete "${snap}/db/" "${TARGET_DIR}/data/db/"' in updater
    assert 'systemctl stop easypi-backend.service' in updater
    assert "Database snapshot failed (nothing applied)" in updater
    assert "the update marker was retained for recovery" in updater
    assert "trusted_root_file" in bootstrap
    assert "--noproxy '*'" in bootstrap
    assert "curl --disable" in bootstrap
    assert 'test -L "${TARGET_DIR}"' in bootstrap
    assert 'run_privileged mkdir -- "${TARGET_DIR}"' in bootstrap
    assert 'run_privileged install -d' not in bootstrap
    assert "easypi-install-root.XXXXXX" in bootstrap
    assert 'run_privileged openssl dgst -sha256 -verify "${TRUSTED_KEY}"' in bootstrap
    assert 'run_privileged python3 "${ARCHIVE_VALIDATOR}" "${ROOT_ARCHIVE_FILE}"' in bootstrap
    assert '--file "${ROOT_ARCHIVE_FILE}"' in bootstrap
    assert 'rm -rf "${OUT_DIR' not in public_bundle
    assert "Refusing to overwrite a non-empty output directory" in public_bundle
    assert "shell-safe direct HTTPS URL" in public_bundle
    assert ".tar.gz.sig" in upload
    assert "checksum-only" not in upload.lower()


def test_updates_restore_only_an_enabled_mobile_link_agent() -> None:
    installer = (ROOT / "install.sh").read_text(encoding="utf-8")
    updater = (ROOT / "scripts/maintenance/apply_update.sh").read_text(
        encoding="utf-8"
    )
    agent_unit = (ROOT / "templates/systemd/easypi-mobile-link-agent.service").read_text(
        encoding="utf-8"
    )

    for script in (installer, updater):
        assert "systemctl is-enabled --quiet easypi-mobile-link-agent.service" in script
        assert "systemctl restart easypi-mobile-link-agent.service" in script
    assert "refresh_mobile_link_units" in updater
    assert "easypi-mobile-home-tunnel.service" in updater
    assert "easypi-mobile-home-tunnel-agent.service" in updater
    # Updated tunnel binaries must replace the running processes.
    restore = updater[updater.index("restart_enabled_mobile_link_agent() {") :]
    assert restore.index('ensure-home >/dev/null') < restore.index(
        "restart_enabled_mobile_home_tunnel\n"
    )
    home = updater[updater.index("restart_enabled_mobile_home_tunnel() {") :]
    home = home[: home.index("\n}\n")]
    assert 'systemctl is-enabled --quiet "${svc}"' in home
    assert 'systemctl restart "${svc}"' in home
    assert "easypi-mobile-home-tunnel.service easypi-mobile-home-tunnel-agent.service" in home
    agent_script = (ROOT / "scripts/settings/mobile_link_agent.sh").read_text(encoding="utf-8")
    assert "systemctl restart" not in agent_script[agent_script.index("ensure_home_server() {") :].split("\n}\n")[0]
    assert 'mobile_link_agent.sh" ensure-endpoint' in updater
    assert 'mobile_link_agent.sh" ensure-endpoint' in installer
    assert "Wants=network-online.target nginx.service easypi-backend.service" in agent_unit
    assert "Requires=nginx.service easypi-backend.service" not in agent_unit
    unit_section, service_section = agent_unit.split("[Service]", maxsplit=1)
    assert "StartLimitIntervalSec=300" in unit_section
    assert "StartLimitBurst=10" in unit_section
    assert "StartLimitIntervalSec" not in service_section
    assert "StartLimitBurst" not in service_section


def test_archive_update_uses_unprivileged_inbox_and_root_owned_staging() -> None:
    installer = (ROOT / "install.sh").read_text(encoding="utf-8")
    dispatcher = (ROOT / "scripts/services/installer_dispatch.sh").read_text(
        encoding="utf-8"
    )

    assert 'update_inbox="${EASYPI_PREFIX}/data/updates"' in installer
    assert 'trusted_update_dir="/var/lib/easypi/updates"' in installer
    assert 'install -d -o "${EASYPI_USER}" -g "${EASYPI_GROUP}" -m 0750 "${update_inbox}"' in installer
    assert 'install -d -o root -g "${EASYPI_GROUP}" -m 0750 "${trusted_update_dir}"' in installer
    assert "setup_update_staging" in installer

    assert 'TRUSTED_UPDATE_DIR="/var/lib/easypi/updates"' in dispatcher
    assert 'incoming = easypi_root / "data" / "updates"' in dispatcher
    assert 'stage = trusted_update_dir / f".staged-{job_id}"' in dispatcher
    assert 'getattr(os, "O_NOFOLLOW", 0)' in dispatcher
    assert "before.st_mtime_ns != after.st_mtime_ns" in dispatcher
    assert 'trap cleanup_update_stage EXIT' in dispatcher
