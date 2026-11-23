from __future__ import annotations

import asyncio
import io
import json
import tarfile
import time
from pathlib import Path

import dns.message
import dns.rdatatype
import dns.rrset

from easypi_netprotection.server import NetProtectionServer
from easypi_netprotection.stealth_dns_policy import (
    INDETERMINATE,
    NEED_MAC,
    ORDINARY,
    PROTECTED,
    StealthDNSPolicy,
)
from scripts.utils.backup_snapshot import validate_stealth_snapshot
from scripts.utils.secure_restore import validate_archive_contents


ROOT = Path(__file__).resolve().parents[2]


def test_missing_policy_is_disabled(tmp_path: Path) -> None:
    policy = StealthDNSPolicy(tmp_path / "missing" / "dns-policy.json")

    assert policy.active_for("192.168.1.20") is False
    assert policy.may_need_mac("192.168.1.20") is False


def test_invalid_existing_policy_fails_closed(tmp_path: Path) -> None:
    path = tmp_path / "dns-policy.json"
    path.write_text("not-json", encoding="utf-8")
    policy = StealthDNSPolicy(path)

    assert policy.active_for("192.168.1.20") is True
    assert policy.active_for("127.0.0.1") is False

    path.write_text(
        '{"version":1,"enabled":0,"scope":"all","ips":[],"macs":[]}',
        encoding="utf-8",
    )
    assert policy.active_for("192.168.1.20") is True


def test_selected_policy_uses_ip_or_mac() -> None:
    policy = StealthDNSPolicy()
    policy._load = lambda: {  # type: ignore[method-assign]
        "enabled": True,
        "scope": "selected",
        "ips": ["192.168.1.20"],
        "macs": ["02:00:00:00:00:20"],
    }

    assert policy.active_for("192.168.1.20") is True
    assert policy.may_need_mac("192.168.1.20") is False
    assert policy.may_need_mac("192.168.1.21") is True
    assert policy.active_for("192.168.1.21", "02:00:00:00:00:20") is True
    assert policy.active_for("192.168.1.21", "02:00:00:00:00:21") is False
    assert policy.classify("192.168.1.21") == NEED_MAC
    assert (
        policy.classify("192.168.1.21", None, mac_lookup_complete=True) == INDETERMINATE
    )
    assert (
        policy.classify(
            "192.168.1.21",
            "02:00:00:00:00:21",
            mac_lookup_complete=True,
        )
        == ORDINARY
    )


def test_protected_query_has_no_ordinary_fallback() -> None:
    server = object.__new__(NetProtectionServer)

    class ProtectedPolicy:
        @staticmethod
        def classify(
            _client_ip: str,
            _client_mac: str | None = None,
            *,
            mac_lookup_complete: bool = False,
        ) -> str:
            return PROTECTED

    server._stealth_dns_policy = ProtectedPolicy()
    server.upstream = None
    calls: list[str] = []

    async def protected(_data: bytes) -> bytes:
        calls.append("protected")
        return b"protected"

    async def ordinary(_data: bytes) -> bytes:
        calls.append("ordinary")
        return b"ordinary"

    server._query_stealth_dns_proxy = protected
    server._query_ordinary_udp_fallback = ordinary

    result = asyncio.run(server._direct_upstream_query(b"query", "192.168.1.20"))

    assert result == b"protected"
    assert calls == ["protected"]


def test_unknown_selected_device_identity_has_no_direct_dns_fallback() -> None:
    server = object.__new__(NetProtectionServer)

    class UnknownPolicy:
        @staticmethod
        def classify(
            _client_ip: str,
            _client_mac: str | None = None,
            *,
            mac_lookup_complete: bool = False,
        ) -> str:
            return INDETERMINATE if mac_lookup_complete else NEED_MAC

    server._stealth_dns_policy = UnknownPolicy()
    server.upstream = None
    calls: list[str] = []

    async def no_mac(_client_ip: str, *, fresh: bool = False) -> None:
        assert fresh is True
        return None

    async def ordinary(_data: bytes) -> bytes:
        calls.append("ordinary")
        return b"ordinary"

    async def protected(_data: bytes) -> bytes:
        calls.append("protected")
        return b"protected"

    server._resolve_client_mac = no_mac
    server._query_ordinary_udp_fallback = ordinary
    server._query_stealth_dns_proxy = protected

    result = asyncio.run(server._direct_upstream_query(b"query", "192.168.1.21"))

    assert result is None
    assert calls == []


def test_dns_routing_ignores_stale_positive_mac_cache() -> None:
    server = object.__new__(NetProtectionServer)
    client_ip = "192.168.1.21"
    old_unprotected_mac = "02:00:00:00:00:21"
    current_protected_mac = "02:00:00:00:00:20"
    server._client_mac_cache = {
        client_ip: (old_unprotected_mac, time.monotonic()),
    }
    server._mac_cache_ttl_sec = 120.0
    server._mac_negative_cache_ttl_sec = 2.0
    server._lookup_mac_from_arp = lambda _ip: current_protected_mac

    async def no_neighbor_mac(_client_ip: str) -> None:
        raise AssertionError("ARP lookup already returned the current MAC")

    class SelectedPolicy:
        @staticmethod
        def classify(
            _client_ip: str,
            client_mac: str | None = None,
            *,
            mac_lookup_complete: bool = False,
        ) -> str:
            if not mac_lookup_complete:
                return NEED_MAC
            return PROTECTED if client_mac == current_protected_mac else ORDINARY

    calls: list[str] = []

    async def protected(_data: bytes) -> bytes:
        calls.append("protected")
        return b"protected"

    async def ordinary(_data: bytes) -> bytes:
        calls.append("ordinary")
        return b"ordinary"

    server._lookup_mac_from_neigh = no_neighbor_mac
    server._stealth_dns_policy = SelectedPolicy()
    server._query_stealth_dns_proxy = protected
    server._query_ordinary_udp_fallback = ordinary
    server.upstream = None

    result = asyncio.run(server._direct_upstream_query(b"query", client_ip))

    assert result == b"protected"
    assert calls == ["protected"]
    assert server._client_mac_cache[client_ip][0] == current_protected_mac


def test_safe_search_resolution_keeps_the_client_dns_path() -> None:
    server = object.__new__(NetProtectionServer)
    calls: list[str] = []

    async def routed_query(data: bytes, client_ip: str) -> bytes:
        calls.append(client_ip)
        query = dns.message.from_wire(data)
        reply = dns.message.make_response(query)
        reply.answer.append(
            dns.rrset.from_text(query.question[0].name, 60, "IN", "A", "1.2.3.4")
        )
        return reply.to_wire()

    server._direct_upstream_query = routed_query
    original = dns.message.make_query("www.example.test", "A")
    response = dns.message.make_response(original)

    asyncio.run(
        server._append_resolved(
            response,
            "safe.example.test.",
            "A",
            dns.rdatatype.A,
            "192.168.1.20",
        )
    )

    assert calls == ["192.168.1.20"]
    assert str(response.answer[0][0]) == "1.2.3.4"


def test_installer_orders_strict_restore_before_netprotection() -> None:
    installer = (ROOT / "install.sh").read_text(encoding="utf-8")
    call_region = installer[installer.index("verify_ipv6_policy_invariant\n") :]
    assert call_region.index("setup_stealth_strict_services\n") < call_region.index(
        "setup_netprotection\n"
    )

    unit = (ROOT / "templates/systemd/easypi-netprotection.service").read_text(
        encoding="utf-8"
    )
    requires = next(line for line in unit.splitlines() if line.startswith("Requires="))
    assert "easypi-ipv6-policy-guard.service" in requires
    assert "easypi-stealth-guard.service" in requires
    assert "easypi-stealth-resume.service" in requires
    assert "easypi-stealth-dns.service" in requires
    assert "RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK" in unit

    dns_unit = (ROOT / "templates/systemd/easypi-stealth-dns.service").read_text(
        encoding="utf-8"
    )
    assert (
        "ExecStart=/usr/bin/python3 /opt/EasyPi/easypi_netprotection/stealth_dns.py"
        in dns_unit
    )
    assert "backend/.venv" not in dns_unit
    assert "CapabilityBoundingSet=\n" in dns_unit
    assert "SystemCallFilter=@system-service" in dns_unit

    guard_unit = (ROOT / "templates/systemd/easypi-stealth-guard.service").read_text(
        encoding="utf-8"
    )
    assert "DefaultDependencies=no" in guard_unit
    assert (
        "Before=network-pre.target network.target network-online.target" in guard_unit
    )
    assert "settings/stealth_vpn.sh guard" in guard_unit

    for backup_name in ("create_config_backup.sh", "create_full_backup.sh"):
        backup = (ROOT / "scripts/backup" / backup_name).read_text(encoding="utf-8")
        assert "/var/lib/easypi/stealth-policy" in backup
        # The guard unit is installer-owned: a backup must not carry a unit
        # file that a restore could replace the fail-closed guard with.
        assert "easypi-stealth-guard.service" not in backup
    config_backup = (ROOT / "scripts/backup/create_config_backup.sh").read_text(
        encoding="utf-8"
    )
    assert "/opt/EasyPi/data/netprotection/stealth_meta.json" in config_backup
    assert "/opt/EasyPi/data/netprotection/stealth_client.conf" in config_backup
    assert ".stealth-state-v1" in config_backup
    assert "--validate-stealth" in config_backup
    restore = (ROOT / "scripts/backup/restore_config_backup.sh").read_text(
        encoding="utf-8"
    )
    assert "/var/lib/easypi/stealth-policy" in restore
    assert "contains Chameleon policy without its matching metadata" in restore


def test_backup_rejects_inconsistent_chameleon_state(tmp_path: Path) -> None:
    state_dir = tmp_path / "opt/EasyPi/data/netprotection"
    policy_dir = tmp_path / "var/lib/easypi/stealth-policy"
    state_dir.mkdir(parents=True)
    policy_dir.mkdir(parents=True)
    (state_dir / "stealth_meta.json").write_text(
        '{"enabled":true,"scope":"all"}', encoding="utf-8"
    )
    (policy_dir / "dns-policy.json").write_text(
        '{"version":1,"enabled":false,"scope":"all","macs":[]}', encoding="utf-8"
    )

    try:
        validate_stealth_snapshot(tmp_path)
    except ValueError as exc:
        assert "different states" in str(exc)
    else:
        raise AssertionError("inconsistent Chameleon snapshot was accepted")


def test_backup_accepts_matching_chameleon_state(tmp_path: Path) -> None:
    state_dir = tmp_path / "opt/EasyPi/data/netprotection"
    policy_dir = tmp_path / "var/lib/easypi/stealth-policy"
    state_dir.mkdir(parents=True)
    policy_dir.mkdir(parents=True)
    meta = {
        "enabled": True,
        "scope": "selected",
        "devices": [{"mac": "02:00:00:00:00:20"}],
        "block_quic": True,
        "server_address": "203.0.113.20:443",
        "psk_key": "a" * 64,
        "reality_public": "public-key",
    }
    config = {
        "server_address": meta["server_address"],
        "psk_key": meta["psk_key"],
        "reality_server_public_key": meta["reality_public"],
        "doh_domain": "",
        "buffer_size": 1000,
        "reconnect_interval": 5,
        "fingerprint_mode": "auto",
        "protocol": "http2",
        "verify_server_certificate": True,
        "tun_name": "cham0",
        "mtu": 1420,
    }
    policy = {
        "version": 1,
        "enabled": True,
        "scope": "selected",
        "ips": ["192.168.1.20"],
        "macs": ["02:00:00:00:00:20"],
        "block_quic": True,
    }
    (state_dir / "stealth_meta.json").write_text(json.dumps(meta), encoding="utf-8")
    (state_dir / "stealth_client.conf").write_text(json.dumps(config), encoding="utf-8")
    (policy_dir / "dns-policy.json").write_text(json.dumps(policy), encoding="utf-8")

    validate_stealth_snapshot(tmp_path)


def test_strict_policy_storage_is_separate_from_client_writable_profile() -> None:
    script = (ROOT / "scripts/settings/stealth_vpn.sh").read_text(encoding="utf-8")
    assert 'POLICY_DIR="/var/lib/easypi/stealth-policy"' in script
    assert 'PROFILE_DIR="/var/lib/easypi/stealth"' in script
    assert 'install -d -o root -g easypi -m 0750 "$POLICY_DIR"' in script
    assert (
        'ip route replace blackhole default metric 42760 table "$DNS_RT_TABLE"'
        in script
    )
    assert 'DNS_EGRESS_CHAIN="EASYPI_STEALTH_DNS_EGRESS"' in script
    assert 'DNS_PROXY_STAGING_PREF="5093"' in script
    activation_body = script[
        script.index("activate_strict_dns_policy() {") :
        script.index("clear_strict_dns_routing() {")
    ]
    assert activation_body.index("install_strict_dns_routing_rules") < (
        activation_body.index("write_dns_policy true")
    ) < activation_body.index('systemctl start "$DNS_PROXY_SERVICE"')
    migration_body = script[
        script.index("migrate_running_policy_if_needed() {") :
        script.index("ensure_dns_proxy_identity() {")
    ]
    assert '[[ -f "$SOURCE_CONF" && ! -L "$SOURCE_CONF" ]] || return 0' in migration_body
    assert 'realpath -e -- "$SOURCE_CONF"' in migration_body
    assert (
        'activate_strict_dns_policy "$scope" "$ips" "$macs" "$block_quic"'
        in migration_body
    )
    up_body = script[script.index("do_up() {") : script.index("# ── reconcile")]
    assert 'activate_strict_dns_policy "$scope" "$ips" "$macs" "$block_quic"' in up_body
    assert 'install_prestart_guard "$scope" "$ips" "$macs" "$wan"' in script
    assert "ensure_strict_service_units || return 1" in script
    assert "migrate_running_policy_if_needed || return 1" in script
    assert '${EASYPI_LIFECYCLE_MODE:-runtime}' in script
    assert 'err()  { json' in script and 'exit 1; }' in script
    assert '[[ ! -e "$UPDATE_MARKER" ]]' in script
    assert 'UPDATE_LOCK_FILE="/run/lock/easypi-update.lock"' in script
    assert "update_lock_is_held" in script
    assert 'err "signed update is awaiting rollback or recovery"' in script
    assert 'err "signed update is still in progress"' in script


def test_restore_rejects_policy_file_without_protected_directory(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "policy-without-directory.tar.gz"
    payload = b'{"version":1,"enabled":false,"scope":"all","ips":[],"macs":[]}'
    with tarfile.open(archive_path, "w:gz") as archive:
        member = tarfile.TarInfo("var/lib/easypi/stealth-policy/dns-policy.json")
        member.size = len(payload)
        archive.addfile(member, io.BytesIO(payload))

    try:
        validate_archive_contents(archive_path)
    except SystemExit as exc:
        assert "without its protected directory" in str(exc)
    else:
        raise AssertionError("unsafe Chameleon policy archive was accepted")
