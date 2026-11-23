from __future__ import annotations

import io
import os
import tarfile
from pathlib import Path

import pytest

from scripts.utils import secure_restore


def make_archive(path, names):
    with tarfile.open(path, "w:gz") as archive:
        for name, content in names:
            member = tarfile.TarInfo(name)
            member.size = len(content)
            archive.addfile(member, io.BytesIO(content))


@pytest.mark.parametrize("name", sorted(secure_restore.SKIPPED_LEGACY_FILES))
def test_host_files_are_not_restore_targets(name):
    member = tarfile.TarInfo(name)
    with pytest.raises(SystemExit, match="outside the restore allowlist"):
        secure_restore.validate_member(member)
    assert secure_restore.validate_member(member, allow_legacy_skip=True) is None
    for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.DIRTYPE):
        member.type = kind
        with pytest.raises(SystemExit):
            secure_restore.validate_member(member, allow_legacy_skip=True)


def test_legacy_archive_validates_data_and_reports_skipped_host_files(tmp_path, capsys):
    archive = tmp_path / "legacy.tar.gz"
    make_archive(archive, [
        ("opt/EasyPi/config/settings.json", b'{"test":true}'),
        ("./etc/systemd/system/easypi-backend.service", b"[Service]\nExecStart=/tmp/payload"),
        ("etc/ssh/sshd_config", b"AuthorizedKeysCommand /tmp/payload"),
    ])
    secure_restore.validate_archive_contents(archive)
    warning = capsys.readouterr().err
    assert "skipping etc/systemd/system/easypi-backend.service" in warning
    assert "skipping etc/ssh/sshd_config" in warning
    assert "/tmp/payload" not in warning


def test_only_host_identity_files_remain_restorable_outside_easypi():
    assert {name for name in secure_restore.ALLOWED_FILES if name.startswith("etc/")} == {
        "etc/hostname",
        "etc/hosts",
    }
    assert not secure_restore.ALLOWED_FILES & secure_restore.SKIPPED_LEGACY_FILES
    assert all(prefix.startswith("opt/EasyPi/") for prefix in secure_restore.ALLOWED_PREFIXES)


def test_root_interpreted_configuration_is_skipped_not_restored(tmp_path, capsys):
    archive = tmp_path / "legacy.tar.gz"
    payloads = [
        ("etc/sysctl.conf", b"kernel.core_pattern=|/opt/EasyPi/data/payload"),
        ("etc/sysctl.d/99-easypi-gateway.conf", b"kernel.modprobe=/opt/EasyPi/data/payload"),
        ("etc/nginx/sites-available/easypi", b"access_log /etc/cron.d/payload;"),
        ("etc/unbound/unbound.conf.d/easypi.conf", b"server:\n  username: \"\""),
    ]
    make_archive(archive, [("opt/EasyPi/config/settings.json", b"{}"), *payloads])
    secure_restore.validate_archive_contents(archive)
    warning = capsys.readouterr().err
    for name, content in payloads:
        assert f"skipping {name}" in warning
        assert content.decode() not in warning
        with pytest.raises(SystemExit, match="outside the restore allowlist"):
            secure_restore.validate_member(tarfile.TarInfo(name))


@pytest.mark.parametrize("name", [
    "etc/systemd/system/evil.service",
    "etc/ssh/sshd_config.d/evil.conf",
    "etc/ssh/../ssh/sshd_config",
    "etc/sysctl.d/99-evil.conf",
    "etc/nginx/sites-available/evil",
    "etc/nginx/nginx.conf",
    "etc/unbound/unbound.conf",
])
def test_legacy_compatibility_does_not_widen_archive_allowlist(tmp_path, name):
    archive = tmp_path / "invalid.tar.gz"
    make_archive(archive, [("opt/EasyPi/config/settings.json", b"{}"), (name, b"bad")])
    with pytest.raises(SystemExit):
        secure_restore.validate_archive_contents(archive)


def test_legacy_files_still_count_toward_limits_and_duplicate_checks(tmp_path, monkeypatch):
    archive = tmp_path / "invalid.tar.gz"
    name = "etc/ssh/sshd_config"
    make_archive(archive, [("opt/EasyPi/config/settings.json", b"{}"), (name, b"large")])
    monkeypatch.setattr(secure_restore, "MAX_TOTAL_SIZE", 4)
    with pytest.raises(SystemExit, match="size limit"):
        secure_restore.validate_archive_contents(archive)
    monkeypatch.setattr(secure_restore, "MAX_TOTAL_SIZE", 100)
    make_archive(archive, [(name, b"a"), ("./" + name, b"b")])
    with pytest.raises(SystemExit, match="duplicate"):
        secure_restore.validate_archive_contents(archive)


def test_new_snapshots_and_rollback_do_not_touch_protected_host_files():
    root = Path(__file__).resolve().parents[2]
    for name in ("create_config_backup.sh", "create_full_backup.sh", "restore_config_backup.sh"):
        script = (root / "scripts/backup" / name).read_text()
        for protected in secure_restore.SKIPPED_LEGACY_FILES:
            assert f"/{protected}" not in script


@pytest.mark.skipif(os.name != "posix", reason="restore uses Linux directory file descriptors")
def test_restore_writes_data_but_never_opens_legacy_host_targets(tmp_path, monkeypatch):
    archive = tmp_path / "legacy.tar.gz"
    data_name = "opt/EasyPi/config/settings.json"
    members = [(data_name, b'{"restored":true}')]
    members += [(name, b"untrusted host configuration") for name in secure_restore.SKIPPED_LEGACY_FILES]
    make_archive(archive, members)
    destination = tmp_path / "root"
    destination.mkdir()
    for name in secure_restore.SKIPPED_LEGACY_FILES:
        path = destination / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(b"trusted installed file")
    real_open = os.open
    opened = []

    def confined_open(path, flags, *args, **kwargs):
        if path == "/":
            path = str(destination)
        opened.append(str(path))
        return real_open(path, flags, *args, **kwargs)

    monkeypatch.setattr(secure_restore.os, "open", confined_open)
    monkeypatch.setattr(secure_restore, "owner_for", lambda _rel: (os.getuid(), os.getgid()))
    secure_restore.restore(archive)
    assert (destination / data_name).read_bytes() == b'{"restored":true}'
    for name in secure_restore.SKIPPED_LEGACY_FILES:
        assert (destination / name).read_bytes() == b"trusted installed file"
        assert Path(name).name not in opened
