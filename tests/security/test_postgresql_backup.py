from __future__ import annotations

import io
import tarfile
from pathlib import Path

import pytest

from scripts.utils import postgres_backup
from scripts.utils.postgres_backup import (
    POSTGRES_DUMP_MEMBER,
    archive_info,
    database_kind,
    dump_database,
    load_database_url,
    restore_database,
)
from scripts.utils.secure_restore import mode_for, owner_for

ROOT = Path(__file__).resolve().parents[2]
DATABASE_URL = "postgresql+psycopg://backup_user:p%40ssword@db.example:5433/easypi"


def _install_fake_postgres_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> list[tuple[list[str], dict[str, str]]]:
    calls: list[tuple[list[str], dict[str, str]]] = []
    monkeypatch.setattr(postgres_backup.os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(postgres_backup, "_trusted_program", lambda name: name)
    monkeypatch.setattr(postgres_backup, "_validate_private_input", lambda path: path)

    def run(command: list[str], environment: dict[str, str], _timeout: int) -> None:
        calls.append((command, environment))
        if command[0] == "pg_dump":
            destination = Path(command[command.index("--file") + 1])
            destination.write_bytes(b"PGDMP\x01safe-test-dump")

    monkeypatch.setattr(postgres_backup, "_run_private", run)
    return calls


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("", "missing"),
        ("sqlite:////opt/EasyPi/data/db/easypi.db", "sqlite"),
        (DATABASE_URL, "postgresql"),
        ("postgres://user@db/easypi", "postgresql"),
        ("mysql://user@db/easypi", "unsupported"),
    ],
)
def test_database_kind_is_explicit(url: str, expected: str) -> None:
    assert database_kind(url) == expected


def test_database_selection_uses_the_archived_env_not_inherited_input(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text("DATABASE_URL=sqlite:///trusted.db\n", encoding="utf-8")
    monkeypatch.setenv("DATABASE_URL", "postgresql://attacker@other/database")
    monkeypatch.setattr(postgres_backup.os, "geteuid", lambda: 1000, raising=False)

    assert load_database_url(env_file) == "sqlite:///trusted.db"


def test_database_url_expands_only_values_from_the_same_env_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "POSTGRES_PASSWORD=p%40ssword\n"
        "DATABASE_URL=postgresql://user:${POSTGRES_PASSWORD}@db/easypi\n",
        encoding="utf-8",
    )
    monkeypatch.setenv("POSTGRES_PASSWORD", "attacker-value")
    monkeypatch.setattr(postgres_backup.os, "geteuid", lambda: 1000, raising=False)

    assert load_database_url(env_file) == (
        "postgresql://user:p%40ssword@db/easypi"
    )


def test_dump_and_restore_keep_password_out_of_argv(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = _install_fake_postgres_tools(monkeypatch)
    dump = tmp_path / "database.dump"

    dump_database(dump, DATABASE_URL)
    restore_database(dump, DATABASE_URL)

    assert dump.read_bytes().startswith(b"PGDMP")
    assert all("p@ssword" not in " ".join(command) for command, _ in calls)
    assert all(environment.get("PGPASSWORD") == "p@ssword" for command, environment in calls if command[0] != "pg_restore" or "--list" not in command)
    restore = next(command for command, _ in calls if "--single-transaction" in command)
    assert "--clean" in restore
    assert "--if-exists" in restore
    assert "--no-owner" in restore
    assert "--no-privileges" in restore
    assert "--exit-on-error" in restore
    assert restore[restore.index("--dbname") + 1] == "easypi"


def _add_bytes(archive: tarfile.TarFile, name: str, payload: bytes) -> None:
    member = tarfile.TarInfo(name)
    member.size = len(payload)
    member.mode = 0o600
    archive.addfile(member, io.BytesIO(payload))


def test_archive_metadata_detects_postgresql_dump(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _install_fake_postgres_tools(monkeypatch)
    archive_path = tmp_path / "backup.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        _add_bytes(archive, "opt/EasyPi/.env", f"DATABASE_URL={DATABASE_URL}\n".encode())
        _add_bytes(archive, POSTGRES_DUMP_MEMBER, b"PGDMP\x01archive-dump")

    assert archive_info(archive_path) == ("postgresql", True)


def test_archive_metadata_exposes_incomplete_legacy_postgresql_backup(
    tmp_path: Path,
) -> None:
    archive_path = tmp_path / "legacy.tar.gz"
    with tarfile.open(archive_path, "w:gz") as archive:
        _add_bytes(archive, "opt/EasyPi/.env", f"DATABASE_URL={DATABASE_URL}\n".encode())

    assert archive_info(archive_path) == ("postgresql", False)


def test_postgresql_dump_is_restored_root_only() -> None:
    assert owner_for(Path(POSTGRES_DUMP_MEMBER)) == (0, 0)
    assert mode_for(Path(POSTGRES_DUMP_MEMBER), False) == 0o600


def test_backup_and_restore_scripts_enforce_postgresql_contract() -> None:
    config_backup = (ROOT / "scripts/backup/create_config_backup.sh").read_text()
    full_backup = (ROOT / "scripts/backup/create_full_backup.sh").read_text()
    restore = (ROOT / "scripts/backup/restore_config_backup.sh").read_text()
    installer = (ROOT / "install.sh").read_text(encoding="utf-8")

    for source in (config_backup, full_backup):
        assert '"$POSTGRES_HELPER" dump' in source
        assert "configured database type cannot be backed up safely" in source
        assert "POSTGRES_DUMP_REL" in source
    assert "validate_database_archive_contract" in restore
    assert "PostgreSQL backup is incomplete" in restore
    assert 'restore_extracted_database "$ARCHIVE_DB_KIND"' in restore
    assert 'restore_extracted_database "$rollback_kind"' in restore
    assert '"$SNAPSHOT_HELPER"' in restore
    assert 'PRE_SNAPSHOT_ARGS+=(--exclude "$POSTGRES_DUMP")' in restore
    assert 'tar -C "$PRE_SNAPSHOT_DIR" -czf -' in restore
    assert '--exclude="$POSTGRES_DUMP_REL"' not in restore
    assert "postgresql-client" in installer


def test_root_updater_delegates_to_the_hardened_health_gated_engine() -> None:
    wrapper = (ROOT / "update.sh").read_text()
    hardened = (ROOT / "scripts/maintenance/apply_update.sh").read_text()

    assert 'UPDATER="${TARGET_DIR}/scripts/maintenance/apply_update.sh"' in wrapper
    assert 'exec "${COMMAND[@]}"' in wrapper
    assert "wait_for_http" not in wrapper
    assert "rsync -a" not in wrapper
    assert "health_ok" in hardened
    assert "rollback_from" in hardened
    assert "EasyPi runtime did not become healthy after the update" in hardened
    assert 'dump "${SNAP}/postgresql.dump"' in hardened
    assert 'restore "${snap}/postgresql.dump"' in hardened
    assert "services remain stopped" in hardened
    assert 'chown root:root "${SNAP}" "${SNAP}/tree" "${SNAP}/db"' in hardened
    assert 'chown -R root:root "${SNAP}/db"' in hardened
    assert "secure_sqlite_runtime" in hardened
