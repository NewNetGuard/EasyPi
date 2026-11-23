from __future__ import annotations

from pathlib import Path

from easypi_netprotection.rewrites import RewriteManager, RewriteType


def test_rewrite_manager_observes_atomic_changes_from_another_process(tmp_path) -> None:
    writer = RewriteManager(tmp_path)
    reader = RewriteManager(tmp_path)

    rule = writer.add("cross-process.invalid", "203.0.113.77", RewriteType.A)
    match = reader.lookup("cross-process.invalid")
    assert match is not None
    assert match.rewritten_answer == "203.0.113.77"

    writer.update(rule.id, answer="203.0.113.78")
    reader._last_external_change_check = 0.0
    match = reader.lookup("cross-process.invalid")
    assert match is not None
    assert match.rewritten_answer == "203.0.113.78"

    assert writer.delete(rule.id) is True
    reader._last_external_change_check = 0.0
    assert reader.lookup("cross-process.invalid") is None


def test_relative_rewrite_data_dir_does_not_depend_on_working_directory(
    tmp_path, monkeypatch
) -> None:
    monkeypatch.chdir(tmp_path)
    manager = RewriteManager("data/netprotection")
    expected_root = Path(__file__).resolve().parents[2]
    assert manager._data_dir == expected_root / "data/netprotection"
