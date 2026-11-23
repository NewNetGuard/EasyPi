#!/usr/bin/env python3
"""Validate an EasyPi release archive before it is signed or installed."""

from __future__ import annotations

import argparse
import hashlib
import re
import tarfile
from pathlib import Path, PurePosixPath

MAX_MEMBERS = 200_000
MAX_MEMBER_SIZE = 2 * 1024 * 1024 * 1024
MAX_TOTAL_SIZE = 8 * 1024 * 1024 * 1024
READ_CHUNK = 1024 * 1024
REQUIRED_FILES = {
    "VERSION",
    "BUILD_INFO",
    "RELEASE_MANIFEST.sha256",
    "install.sh",
    "update.sh",
    "uninstall.sh",
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
SHA256_LINE = re.compile(r"^([0-9a-f]{64})  (.+)$")
SEMVER = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
SOURCE_COMMIT = re.compile(r"^[0-9a-f]{40}(?:[0-9a-f]{24})?$")
FORBIDDEN_RUNTIME_PREFIXES = (
    "data/db/",
    "data/backups/",
    "data/uploads/",
    "data/operations/",
    "data/recordings/",
    "data/rollback/",
    "data/user/",
    "data/security/",
    "prism_dpi/captures/",
    "easypi_netprotection/proxy/",
)
FORBIDDEN_RUNTIME_NAMES = {
    "data/notification_prefs.json",
    "data/.setup_token",
}
FORBIDDEN_SUFFIXES = (".db", ".db-shm", ".db-wal", ".sqlite", ".sqlite3", ".epibak")


class ReleaseValidationError(ValueError):
    """The archive violates the signed-release contract."""


def _safe_name(raw_name: str) -> str:
    if (
        not raw_name
        or "\\" in raw_name
        or any(ord(character) < 0x20 or ord(character) == 0x7F for character in raw_name)
    ):
        raise ReleaseValidationError(f"unsafe archive path: {raw_name!r}")
    path = PurePosixPath(raw_name)
    if path.is_absolute() or ".." in path.parts:
        raise ReleaseValidationError(f"unsafe archive path: {raw_name!r}")
    parts = [part for part in path.parts if part not in {"", "."}]
    if not parts:
        return "."
    return "/".join(parts)


def _read_small(archive: tarfile.TarFile, member: tarfile.TarInfo) -> bytes:
    if member.size > 1024 * 1024:
        raise ReleaseValidationError(f"metadata file is unexpectedly large: {member.name}")
    stream = archive.extractfile(member)
    if stream is None:
        raise ReleaseValidationError(f"cannot read archive member: {member.name}")
    return stream.read()


def _reject_runtime_state(name: str) -> None:
    lowered = name.lower()
    basename = PurePosixPath(lowered).name
    forbidden_roots = tuple(prefix.rstrip("/") for prefix in FORBIDDEN_RUNTIME_PREFIXES)
    if (
        lowered in FORBIDDEN_RUNTIME_NAMES
        or lowered in forbidden_roots
        or lowered.startswith(FORBIDDEN_RUNTIME_PREFIXES)
    ):
        raise ReleaseValidationError(f"release contains runtime state: {name}")
    if lowered.startswith("backend/data/") and lowered != "backend/data/services.json":
        raise ReleaseValidationError(f"release contains backend runtime data: {name}")
    if basename == ".env" or (basename.startswith(".env.") and basename != ".env.example"):
        raise ReleaseValidationError(f"release contains environment state: {name}")
    if basename.endswith(".key") or basename in {"vapid_private.pem", "private_key.pem"}:
        raise ReleaseValidationError(f"release contains private key state: {name}")
    if lowered.endswith(FORBIDDEN_SUFFIXES):
        raise ReleaseValidationError(f"release contains database or backup state: {name}")


def _build_info(payload: bytes) -> dict[str, str]:
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ReleaseValidationError("BUILD_INFO is not UTF-8") from exc
    lines = text.splitlines()
    if not lines or lines[0] != "EasyPi full binary release":
        raise ReleaseValidationError("BUILD_INFO has an invalid product header")
    fields: dict[str, str] = {}
    for line in lines[1:]:
        if not line:
            continue
        key, separator, value = line.partition(":")
        if not separator:
            raise ReleaseValidationError("BUILD_INFO contains an unlabeled value")
        normalized_key = key.strip()
        if normalized_key in fields:
            raise ReleaseValidationError(
                f"BUILD_INFO contains a duplicate field: {normalized_key}"
            )
        fields[normalized_key] = value.strip()
    return fields


def validate_release_archive(
    archive_path: Path,
    *,
    expected_arch: str = "aarch64",
    expected_codename: str = "trixie",
) -> str:
    if not archive_path.is_file() or archive_path.is_symlink():
        raise ReleaseValidationError("release archive must be a regular file")

    try:
        archive = tarfile.open(archive_path, mode="r:gz")
    except (OSError, tarfile.TarError) as exc:
        raise ReleaseValidationError(f"release is not a readable gzip tar archive: {exc}") from exc

    with archive:
        members = archive.getmembers()
        if not members or len(members) > MAX_MEMBERS:
            raise ReleaseValidationError("release archive has an invalid member count")

        indexed: dict[str, tarfile.TarInfo] = {}
        total_size = 0
        for member in members:
            name = _safe_name(member.name)
            _reject_runtime_state(name)
            if name in indexed:
                raise ReleaseValidationError(f"duplicate archive path: {name}")
            indexed[name] = member
            if member.issym() or member.islnk() or member.isdev() or member.isfifo():
                raise ReleaseValidationError(f"unsupported archive member type: {name}")
            if not (member.isfile() or member.isdir()):
                raise ReleaseValidationError(f"unsupported archive member type: {name}")
            if member.size < 0 or member.size > MAX_MEMBER_SIZE:
                raise ReleaseValidationError(f"archive member is too large: {name}")
            total_size += member.size
            if total_size > MAX_TOTAL_SIZE:
                raise ReleaseValidationError("release archive expands beyond the size limit")

        # A regular file may never be an ancestor of another member. GNU tar's
        # handling of such type conflicts is order-dependent, which makes the
        # extracted tree differ between tools even when every individual name
        # is traversal-safe.
        for name in indexed:
            for parent in PurePosixPath(name).parents:
                parent_name = _safe_name(str(parent))
                if parent_name == ".":
                    break
                parent_member = indexed.get(parent_name)
                if parent_member is not None and not parent_member.isdir():
                    raise ReleaseValidationError(
                        f"archive path has a non-directory ancestor: {name}"
                    )

        missing = sorted(REQUIRED_FILES - indexed.keys())
        if missing:
            raise ReleaseValidationError(f"release archive is missing: {', '.join(missing)}")
        for required in REQUIRED_FILES:
            if not indexed[required].isfile():
                raise ReleaseValidationError(f"required release path is not a file: {required}")
            if indexed[required].size <= 0:
                raise ReleaseValidationError(f"required release file is empty: {required}")

        version_bytes = _read_small(archive, indexed["VERSION"])
        try:
            version = version_bytes.decode("ascii").strip()
        except UnicodeDecodeError as exc:
            raise ReleaseValidationError("VERSION is not ASCII") from exc
        if not SEMVER.fullmatch(version):
            raise ReleaseValidationError("VERSION is not a valid semantic version")

        fields = _build_info(_read_small(archive, indexed["BUILD_INFO"]))
        arch = fields.get("Architecture", "").lower()
        codename = fields.get("Build distro codename", "").lower()
        glibc = fields.get("Build glibc", "")
        source_commit = fields.get("Source commit", "").lower()
        if arch not in {expected_arch.lower(), "arm64" if expected_arch == "aarch64" else expected_arch.lower()}:
            raise ReleaseValidationError(
                f"release architecture mismatch: expected {expected_arch}, got {arch or 'missing'}"
            )
        if codename != expected_codename.lower():
            raise ReleaseValidationError(
                f"release codename mismatch: expected {expected_codename}, got {codename or 'missing'}"
            )
        if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)+", glibc):
            raise ReleaseValidationError(
                "BUILD_INFO must contain the numeric glibc version used for the build"
            )
        if not SOURCE_COMMIT.fullmatch(source_commit):
            raise ReleaseValidationError(
                "BUILD_INFO must contain the exact Git source commit"
            )

        manifest_bytes = _read_small(archive, indexed["RELEASE_MANIFEST.sha256"])
        try:
            manifest_text = manifest_bytes.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise ReleaseValidationError("release manifest is not UTF-8") from exc

        expected_hashes: dict[str, str] = {}
        for line in manifest_text.splitlines():
            match = SHA256_LINE.fullmatch(line)
            if not match:
                raise ReleaseValidationError("release manifest contains an invalid line")
            name = _safe_name(match.group(2))
            if name == "RELEASE_MANIFEST.sha256" or name in expected_hashes:
                raise ReleaseValidationError(f"release manifest contains an invalid path: {name}")
            expected_hashes[name] = match.group(1)

        regular_files = {
            name for name, member in indexed.items()
            if member.isfile() and name != "RELEASE_MANIFEST.sha256"
        }
        if set(expected_hashes) != regular_files:
            missing_manifest = sorted(regular_files - expected_hashes.keys())
            extra_manifest = sorted(expected_hashes.keys() - regular_files)
            raise ReleaseValidationError(
                "release manifest file set mismatch"
                f" (missing={missing_manifest[:5]}, extra={extra_manifest[:5]})"
            )

        for name in sorted(regular_files):
            stream = archive.extractfile(indexed[name])
            if stream is None:
                raise ReleaseValidationError(f"cannot read archive member: {name}")
            digest = hashlib.sha256()
            while chunk := stream.read(READ_CHUNK):
                digest.update(chunk)
            if digest.hexdigest() != expected_hashes[name]:
                raise ReleaseValidationError(f"release manifest hash mismatch: {name}")

    return version


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("archive", type=Path)
    parser.add_argument("--expected-arch", default="aarch64")
    parser.add_argument("--expected-codename", default="trixie")
    args = parser.parse_args()
    try:
        version = validate_release_archive(
            args.archive,
            expected_arch=args.expected_arch,
            expected_codename=args.expected_codename,
        )
    except (OSError, ReleaseValidationError) as exc:
        parser.exit(1, f"[ERROR] {exc}\n")
    print(f"RELEASE_VALIDATION=OK VERSION={version}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
