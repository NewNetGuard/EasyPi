from __future__ import annotations

import sqlite3
from pathlib import Path

from scripts.utils.backup_snapshot import _snapshot_destination, build_snapshot


def test_backup_snapshot_uses_sqlite_online_backup_and_omits_sidecars(
    tmp_path: Path,
) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    database = source_root / "state.sqlite3"
    connection = sqlite3.connect(database)
    connection.execute("PRAGMA journal_mode=WAL")
    connection.execute("CREATE TABLE values_table (value TEXT NOT NULL)")
    connection.execute("INSERT INTO values_table VALUES ('committed')")
    connection.commit()
    connection.execute("INSERT INTO values_table VALUES ('uncommitted')")

    snapshot_root = tmp_path / "snapshot"
    snapshot_root.mkdir()
    build_snapshot(snapshot_root, [source_root], [])
    copied = _snapshot_destination(snapshot_root, database)

    with sqlite3.connect(copied) as copied_connection:
        assert copied_connection.execute("PRAGMA integrity_check").fetchone() == ("ok",)
        assert copied_connection.execute("SELECT value FROM values_table").fetchall() == [
            ("committed",)
        ]
    assert not Path(f"{copied}-wal").exists()
    assert not Path(f"{copied}-shm").exists()
    connection.rollback()
    connection.close()


def test_backup_snapshot_rejects_symlink(tmp_path: Path) -> None:
    source_root = tmp_path / "source"
    source_root.mkdir()
    target = tmp_path / "target.txt"
    target.write_text("secret", encoding="utf-8")
    link = source_root / "link"
    try:
        link.symlink_to(target)
    except OSError:
        return
    snapshot_root = tmp_path / "snapshot"
    snapshot_root.mkdir()

    try:
        build_snapshot(snapshot_root, [source_root], [])
    except ValueError as exc:
        assert "symlink" in str(exc)
    else:
        raise AssertionError("snapshot accepted a symlink")
