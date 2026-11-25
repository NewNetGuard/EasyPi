from __future__ import annotations

import importlib.util
import io
import json
import os
import stat
import subprocess
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]
IMPORTER_PATH = ROOT / "scripts/services/picloud_taildrop_import.py"
UNIT_PATH = ROOT / "templates/systemd/easypi-taildrop-import.service"

spec = importlib.util.spec_from_file_location("picloud_taildrop_import", IMPORTER_PATH)
assert spec and spec.loader
taildrop = importlib.util.module_from_spec(spec)
spec.loader.exec_module(taildrop)


@pytest.fixture(autouse=True)
def _trust_test_file_owner(monkeypatch: pytest.MonkeyPatch) -> None:
    # The importer runs as root and trusts only root-owned state. Fixtures are
    # created by the user running the tests, so trust that uid instead.
    if hasattr(os, "geteuid"):
        monkeypatch.setattr(taildrop, "ROOT_UID", os.geteuid())


def test_importer_trusts_only_root_owned_state_by_default() -> None:
    source = IMPORTER_PATH.read_text(encoding="utf-8")
    assert "\nROOT_UID = 0\n" in source


class FakeStream(io.BytesIO):
    def __init__(self, content: bytes, declared_size: int | None = None) -> None:
        super().__init__(content)
        self.size = len(content) if declared_size is None else declared_size


class FakeAPI:
    def __init__(
        self,
        content: bytes,
        declared_size: int | None = None,
        delete_failures: int = 0,
    ) -> None:
        self.content = content
        self.declared_size = declared_size
        self.delete_failures = delete_failures
        self.deleted: list[str] = []
        self.opened: list[str] = []

    def open_file(self, name: str) -> FakeStream:
        self.opened.append(name)
        return FakeStream(self.content, self.declared_size)

    def delete_file(self, name: str) -> None:
        self.deleted.append(name)
        if self.delete_failures:
            self.delete_failures -= 1
            raise RuntimeError("simulated Taildrop DELETE failure")


def open_test_directories(tmp_path: Path) -> tuple[Path, Path, int, int]:
    state = tmp_path / "state"
    destination = tmp_path / "picloud/Taildrop"
    state.mkdir(parents=True)
    destination.mkdir(parents=True)
    state.chmod(0o700)
    destination.chmod(0o700)
    return (
        state,
        destination,
        taildrop.open_directory_no_symlinks(state),
        taildrop.open_directory_no_symlinks(destination),
    )


def test_taildrop_filename_is_never_treated_as_a_path_or_too_long() -> None:
    assert taildrop.sanitize_filename("../../etc/passwd") == "passwd"
    assert taildrop.sanitize_filename("..\\..\\photo.jpg") == "photo.jpg"
    assert taildrop.sanitize_filename("\x00\r\n") == "upload.bin"
    assert len(taildrop.sanitize_filename("é" * 400 + ".pdf").encode()) <= 255


@pytest.mark.parametrize(
    ("filename", "folder"),
    [
        ("photo.jpg", "Photos"),
        ("movie.MKV", "Videos"),
        ("report.pdf", "Documents"),
        ("recording.opus", "Music"),
        ("secret.epec", "Encrypted"),
        ("application.apk", "Files"),
        ("archive.zip", "Files"),
    ],
)
def test_taildrop_uses_picloud_type_folders(filename: str, folder: str) -> None:
    assert taildrop.sort_folder_for_filename(filename) == folder


@pytest.mark.skipif(os.name != "posix", reason="secure directory FDs require Linux")
def test_taildrop_transport_does_not_create_a_taildrop_library_folder(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    picloud = tmp_path / "picloud"
    state.mkdir()
    picloud.mkdir()
    state.chmod(0o700)
    picloud.chmod(0o700)
    for folder in taildrop.SORT_FOLDERS:
        (picloud / folder).mkdir(mode=0o700)

    state_fd = taildrop.open_directory_no_symlinks(state)
    picloud_fd = taildrop.open_directory_no_symlinks(picloud)
    api = FakeAPI(b"ok")

    def resolver(filename: str) -> int:
        return taildrop.open_sort_directory(
            picloud_fd,
            filename,
            owner_uid=os.getuid(),
        )

    try:
        published, deferred = taildrop.process_waiting_files(
            api,
            [
                {"Name": "photo.jpg", "Size": 2},
                {"Name": "report.pdf", "Size": 2},
                {"Name": "movie.mp4", "Size": 2},
                {"Name": "package.apk", "Size": 2},
            ],
            state_fd,
            picloud_fd,
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
            maximum_bytes=1024,
            destination_resolver=resolver,
        )
    finally:
        os.close(state_fd)
        os.close(picloud_fd)

    assert deferred == 0
    assert published == [
        "Photos/photo.jpg",
        "Documents/report.pdf",
        "Videos/movie.mp4",
        "Files/package.apk",
    ]
    assert (picloud / "Photos/photo.jpg").read_bytes() == b"ok"
    assert (picloud / "Documents/report.pdf").read_bytes() == b"ok"
    assert (picloud / "Videos/movie.mp4").read_bytes() == b"ok"
    assert (picloud / "Files/package.apk").read_bytes() == b"ok"
    assert not (picloud / "Taildrop").exists()


def test_capacity_warning_repeats_after_interval(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    moments = iter((0.0, 100.0, 299.0, 300.0, 303.0))
    monkeypatch.setattr(taildrop, "_capacity_warning_last", None)
    monkeypatch.setattr(taildrop.time, "monotonic", lambda: next(moments))
    with caplog.at_level("WARNING", logger="easypi-taildrop"):
        for _ in range(5):
            taildrop._log_deferred_capacity("large.bin", 20)

    messages = [
        record.message
        for record in caplog.records
        if record.name == "easypi-taildrop" and "large.bin" in record.message
    ]
    assert len(messages) == 2


def test_taildrop_has_no_fixed_size_limit_by_default(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("EASYPI_MAX_UPLOAD_BYTES", raising=False)
    assert taildrop.max_upload_bytes() == 0


def test_taildrop_reads_only_the_upload_limit_from_the_settings_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    settings = tmp_path / ".env"
    settings.write_text(
        "LD_PRELOAD=/opt/EasyPi/data/payload.so\n"
        "PYTHONPATH=/opt/EasyPi/data\n"
        "EASYPI_MAX_UPLOAD_BYTES=10\n"
        "OTHER_EASYPI_MAX_UPLOAD_BYTES=99\n"
        'EASYPI_MAX_UPLOAD_BYTES = "4096"  # last assignment wins\n',
        encoding="utf-8",
    )
    # The file is authoritative when the unit names it; the process
    # environment is neither consulted nor changed.
    monkeypatch.setenv("EASYPI_MAX_UPLOAD_BYTES", "7")
    monkeypatch.delenv("LD_PRELOAD", raising=False)
    monkeypatch.delenv("PYTHONPATH", raising=False)
    assert taildrop.max_upload_bytes(settings) == 4096
    assert "LD_PRELOAD" not in os.environ
    assert "PYTHONPATH" not in os.environ


@pytest.mark.parametrize("content", ["", "EASYPI_MAX_UPLOAD_BYTES=many\n", "EASYPI_MAX_UPLOAD_BYTES=-5\n"])
def test_taildrop_settings_file_falls_back_to_no_fixed_limit(
    tmp_path: Path, content: str
) -> None:
    settings = tmp_path / ".env"
    settings.write_text(content, encoding="utf-8")
    assert taildrop.max_upload_bytes(settings) == 0
    assert taildrop.max_upload_bytes(tmp_path / "missing.env") == 0


def test_taildrop_root_service_does_not_load_the_restorable_settings_file() -> None:
    unit = UNIT_PATH.read_text(encoding="utf-8")
    assert "EnvironmentFile" not in unit
    assert "--settings-file /opt/EasyPi/.env" in unit


@pytest.mark.skipif(os.name != "posix", reason="secure status writes require Linux")
def test_taildrop_status_reports_capacity_without_rewriting_unchanged_file(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state"
    state.mkdir()
    state.chmod(0o750)
    state_fd = taildrop.open_directory_no_symlinks(state)
    try:
        taildrop._write_status(
            state_fd,
            owner_gid=os.getgid(),
            error="Not enough disk space",
            free_bytes=123,
            deferred=2,
        )
        first_mtime = (state / taildrop.STATUS_FILENAME).stat().st_mtime_ns
        taildrop._write_status(
            state_fd,
            owner_gid=os.getgid(),
            error="Not enough disk space",
            free_bytes=123,
            deferred=2,
        )
    finally:
        os.close(state_fd)

    payload = json.loads((state / taildrop.STATUS_FILENAME).read_text())
    assert payload["error"] == "Not enough disk space"
    assert payload["free_bytes"] == 123
    assert payload["reserve_bytes"] == taildrop.FREE_SPACE_RESERVE
    assert payload["deferred_files"] == 2
    assert (state / taildrop.STATUS_FILENAME).stat().st_mtime_ns == first_mtime


def test_large_capacity_queue_cannot_churn_warning_limiter(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    now = [0.0]
    monkeypatch.setattr(taildrop, "_capacity_warning_last", None)
    monkeypatch.setattr(taildrop.time, "monotonic", lambda: now[0])
    with caplog.at_level("WARNING", logger="easypi-taildrop"):
        for _ in range(3):
            for index in range(1025):
                taildrop._log_deferred_capacity(f"large-{index}.bin", 20)
        now[0] = 300.0
        taildrop._log_deferred_capacity("large-0.bin", 20)

    messages = [
        record.message
        for record in caplog.records
        if record.name == "easypi-taildrop" and "capacity warnings" in record.message
    ]
    assert len(messages) == 2


@pytest.mark.skipif(os.name != "posix", reason="openat ownership checks require Linux")
def test_completed_taildrop_is_atomic_and_never_overwrites(tmp_path: Path) -> None:
    _, destination, state_fd, destination_fd = open_test_directories(tmp_path)
    (destination / "report.pdf").write_bytes(b"existing")
    api = FakeAPI(b"first")
    try:
        imported = taildrop.process_waiting_file(
            api,
            {"Name": "report.pdf", "Size": 5},
            state_fd,
            destination_fd,
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
            maximum_bytes=1024,
        )
    finally:
        os.close(state_fd)
        os.close(destination_fd)

    assert imported == "report_1.pdf"
    assert (destination / "report.pdf").read_bytes() == b"existing"
    assert (destination / "report_1.pdf").read_bytes() == b"first"
    assert stat.S_IMODE((destination / "report_1.pdf").stat().st_mode) == 0o640
    assert api.deleted == ["report.pdf"]


@pytest.mark.skipif(os.name != "posix", reason="openat ownership checks require Linux")
def test_incomplete_taildrop_is_never_published_or_deleted(tmp_path: Path) -> None:
    state, destination, state_fd, destination_fd = open_test_directories(tmp_path)
    api = FakeAPI(b"half", declared_size=8)
    try:
        with pytest.raises(OSError, match="incomplete Taildrop stream"):
            taildrop.process_waiting_file(
                api,
                {"Name": "video.mp4", "Size": 8},
                state_fd,
                destination_fd,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
                maximum_bytes=1024,
            )
    finally:
        os.close(state_fd)
        os.close(destination_fd)

    assert not list(destination.iterdir())
    assert not list(state.iterdir())
    assert api.deleted == []


@pytest.mark.skipif(os.name != "posix", reason="openat ownership checks require Linux")
def test_oversized_taildrop_is_deleted_without_copy_or_rejected_file(
    tmp_path: Path,
) -> None:
    _, destination, state_fd, destination_fd = open_test_directories(tmp_path)
    api = FakeAPI(b"12345")
    try:
        result = taildrop.process_waiting_file(
            api,
            {"Name": "large.bin", "Size": 5},
            state_fd,
            destination_fd,
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
            maximum_bytes=4,
        )
    finally:
        os.close(state_fd)
        os.close(destination_fd)

    assert result is None
    assert api.opened == []
    assert api.deleted == ["large.bin"]
    assert not list(destination.iterdir())


@pytest.mark.skipif(os.name != "posix", reason="transaction checks require Linux")
def test_delete_failure_never_publishes_or_duplicates(tmp_path: Path) -> None:
    state, destination, state_fd, destination_fd = open_test_directories(tmp_path)
    api = FakeAPI(b"content", delete_failures=1)
    item = {"Name": "same.bin", "Size": 7}
    try:
        with pytest.raises(RuntimeError, match="DELETE failure"):
            taildrop.process_waiting_file(
                api,
                item,
                state_fd,
                destination_fd,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
                maximum_bytes=1024,
            )
        assert not list(destination.iterdir())

        imported = taildrop.process_waiting_file(
            api,
            item,
            state_fd,
            destination_fd,
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
            maximum_bytes=1024,
        )
    finally:
        os.close(state_fd)
        os.close(destination_fd)

    assert imported == "same.bin"
    assert [path.name for path in destination.iterdir()] == ["same.bin"]
    assert (destination / "same.bin").read_bytes() == b"content"
    assert not list(state.iterdir())
    assert api.opened == ["same.bin", "same.bin"]
    assert api.deleted == ["same.bin", "same.bin"]


@pytest.mark.skipif(os.name != "posix", reason="transaction checks require Linux")
@pytest.mark.parametrize("replacement", [b"BBBBBBB", b"BBBBBBBB"])
def test_new_file_reusing_pending_name_is_never_deleted_as_the_old_file(
    tmp_path: Path, replacement: bytes
) -> None:
    state, destination, state_fd, destination_fd = open_test_directories(tmp_path)
    api = FakeAPI(b"AAAAAAA", delete_failures=1)
    try:
        with pytest.raises(RuntimeError, match="DELETE failure"):
            taildrop.process_waiting_file(
                api,
                {"Name": "same.bin", "Size": 7},
                state_fd,
                destination_fd,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
                maximum_bytes=1024,
            )
        api.content = replacement
        imported = taildrop.process_waiting_file(
            api,
            {"Name": "same.bin", "Size": len(replacement)},
            state_fd,
            destination_fd,
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
            maximum_bytes=1024,
        )
    finally:
        os.close(state_fd)
        os.close(destination_fd)

    assert imported == "same_1.bin"
    assert (destination / "same.bin").read_bytes() == b"AAAAAAA"
    assert (destination / "same_1.bin").read_bytes() == replacement
    assert api.opened == ["same.bin", "same.bin"]
    assert api.deleted == ["same.bin", "same.bin"]
    assert not list(state.iterdir())


@pytest.mark.skipif(os.name != "posix", reason="capacity checks require Linux")
def test_new_import_requires_space_for_staging_and_atomic_publication(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state, destination, state_fd, destination_fd = open_test_directories(tmp_path)
    api = FakeAPI(b"content")
    monkeypatch.setattr(taildrop, "FREE_SPACE_RESERVE", 10)
    monkeypatch.setattr(taildrop, "_free_bytes", lambda directory_fd: 20)
    try:
        with pytest.raises(RuntimeError, match="24 bytes required"):
            taildrop.process_waiting_file(
                api,
                {"Name": "file.bin", "Size": 7},
                state_fd,
                destination_fd,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
                maximum_bytes=1024,
            )
    finally:
        os.close(state_fd)
        os.close(destination_fd)

    assert api.opened == []
    assert api.deleted == []
    assert not list(state.iterdir())
    assert not list(destination.iterdir())


@pytest.mark.skipif(os.name != "posix", reason="capacity checks require Linux")
def test_critically_low_space_never_deletes_waiting_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state, destination, state_fd, destination_fd = open_test_directories(tmp_path)
    api = FakeAPI(b"important")
    monkeypatch.setattr(taildrop, "FREE_SPACE_RESERVE", 10)
    monkeypatch.setattr(taildrop, "_free_bytes", lambda directory_fd: 5)
    try:
        with pytest.raises(RuntimeError, match="28 bytes required"):
            taildrop.process_waiting_file(
                api,
                {"Name": "important.bin", "Size": 9},
                state_fd,
                destination_fd,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
                maximum_bytes=1024,
            )
    finally:
        os.close(state_fd)
        os.close(destination_fd)

    assert api.opened == []
    assert api.deleted == []
    assert not list(state.iterdir())
    assert not list(destination.iterdir())


@pytest.mark.skipif(os.name != "posix", reason="capacity checks require Linux")
def test_large_deferred_file_does_not_starve_smaller_waiting_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state, destination, state_fd, destination_fd = open_test_directories(tmp_path)
    api = FakeAPI(b"ok")
    monkeypatch.setattr(taildrop, "FREE_SPACE_RESERVE", 10)
    monkeypatch.setattr(taildrop, "_free_bytes", lambda directory_fd: 20)
    try:
        published, deferred = taildrop.process_waiting_files(
            api,
            [
                {"Name": "large.bin", "Size": 20},
                {"Name": "small.bin", "Size": 2},
            ],
            state_fd,
            destination_fd,
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
            maximum_bytes=1024,
        )
    finally:
        os.close(state_fd)
        os.close(destination_fd)

    assert published == ["small.bin"]
    assert deferred == 1
    assert api.opened == ["small.bin"]
    assert api.deleted == ["small.bin"]
    assert (destination / "small.bin").read_bytes() == b"ok"
    assert not list(state.iterdir())


@pytest.mark.skipif(os.name != "posix", reason="capacity checks require Linux")
def test_pending_replacement_does_not_fill_disk_before_old_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state, destination, state_fd, destination_fd = open_test_directories(tmp_path)
    api = FakeAPI(b"AAAAAAA", delete_failures=1)
    try:
        with pytest.raises(RuntimeError, match="DELETE failure"):
            taildrop.process_waiting_file(
                api,
                {"Name": "same.bin", "Size": 7},
                state_fd,
                destination_fd,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
                maximum_bytes=1024,
            )
        api.content = b"BBBBBBB"
        monkeypatch.setattr(taildrop, "FREE_SPACE_RESERVE", 10)
        monkeypatch.setattr(taildrop, "_free_bytes", lambda directory_fd: 20)
        with pytest.raises(RuntimeError, match="24 bytes required"):
            taildrop.process_waiting_file(
                api,
                {"Name": "same.bin", "Size": 7},
                state_fd,
                destination_fd,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
                maximum_bytes=1024,
            )
    finally:
        os.close(state_fd)
        os.close(destination_fd)

    assert api.opened == ["same.bin"]
    assert api.deleted == ["same.bin"]
    assert len(list(state.iterdir())) == 2
    assert not list(destination.iterdir())


@pytest.mark.skipif(os.name != "posix", reason="transaction checks require Linux")
def test_deleted_file_is_recovered_after_interrupted_publish(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    state, destination, state_fd, destination_fd = open_test_directories(tmp_path)
    api = FakeAPI(b"recover")
    real_publish = taildrop._publish_receipt
    monkeypatch.setattr(
        taildrop,
        "_publish_receipt",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            RuntimeError("interrupted publish")
        ),
    )
    try:
        with pytest.raises(RuntimeError, match="interrupted publish"):
            taildrop.process_waiting_file(
                api,
                {"Name": "recover.bin", "Size": 7},
                state_fd,
                destination_fd,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
                maximum_bytes=1024,
            )
        assert not list(destination.iterdir())
        receipt_path = next(state.glob("receipt-*.json"))
        receipt = taildrop._read_receipt(state_fd, receipt_path.name)
        temporary = destination / str(receipt["temporary_name"])
        temporary.write_bytes(b"recover")
        temporary.chmod(0o600)
        os.link(temporary, destination / str(receipt["published_name"]))
        monkeypatch.setattr(taildrop, "_publish_receipt", real_publish)
        taildrop.recover_receipts(
            state_fd,
            destination_fd,
            {"recover.bin"},
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
        )
    finally:
        os.close(state_fd)
        os.close(destination_fd)

    assert (destination / "recover.bin").read_bytes() == b"recover"
    assert [path.name for path in destination.iterdir()] == ["recover.bin"]
    assert not list(state.iterdir())


@pytest.mark.skipif(os.name != "posix", reason="transaction checks require Linux")
def test_recovery_uses_capacity_limiter_and_reports_deferred_work(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    state, destination, state_fd, destination_fd = open_test_directories(tmp_path)
    api = FakeAPI(b"recover")
    real_publish = taildrop._publish_receipt
    monkeypatch.setattr(
        taildrop,
        "_publish_receipt",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            RuntimeError("interrupted publish")
        ),
    )
    try:
        with pytest.raises(RuntimeError, match="interrupted publish"):
            taildrop.process_waiting_file(
                api,
                {"Name": "recover.bin", "Size": 7},
                state_fd,
                destination_fd,
                owner_uid=os.getuid(),
                owner_gid=os.getgid(),
                maximum_bytes=1024,
            )
        monkeypatch.setattr(taildrop, "_publish_receipt", real_publish)
        monkeypatch.setattr(taildrop, "FREE_SPACE_RESERVE", 10)
        monkeypatch.setattr(taildrop, "_free_bytes", lambda directory_fd: 0)
        monkeypatch.setattr(taildrop, "_capacity_warning_last", None)
        moments = iter((0.0, 100.0, 303.0))
        monkeypatch.setattr(taildrop.time, "monotonic", lambda: next(moments))
        with caplog.at_level("WARNING", logger="easypi-taildrop"):
            deferred = [
                taildrop.recover_receipts(
                    state_fd,
                    destination_fd,
                    set(),
                    owner_uid=os.getuid(),
                    owner_gid=os.getgid(),
                )
                for _ in range(3)
            ]
    finally:
        os.close(state_fd)
        os.close(destination_fd)

    messages = [
        record.message
        for record in caplog.records
        if record.name == "easypi-taildrop" and "recover.bin" in record.message
    ]
    assert deferred == [1, 1, 1]
    assert len(messages) == 2
    assert not list(destination.iterdir())
    assert len(list(state.iterdir())) == 2


@pytest.mark.skipif(os.name != "posix", reason="transaction checks require Linux")
def test_orphaned_transaction_payload_is_removed(tmp_path: Path) -> None:
    state, destination, state_fd, destination_fd = open_test_directories(tmp_path)
    (state / "payload-orphan").write_bytes(b"unfinished")
    (state / "payload-orphan").chmod(0o600)
    try:
        taildrop.recover_receipts(
            state_fd,
            destination_fd,
            set(),
            owner_uid=os.getuid(),
            owner_gid=os.getgid(),
        )
    finally:
        os.close(state_fd)
        os.close(destination_fd)

    assert not list(state.iterdir())
    assert not list(destination.iterdir())


@pytest.mark.skipif(os.name != "posix", reason="NAME_MAX check requires Linux")
def test_valid_maximum_utf8_name_can_be_renamed_on_collision(tmp_path: Path) -> None:
    destination = tmp_path / "Taildrop"
    destination.mkdir()
    destination.chmod(0o700)
    original = "é" * 125 + ".txt"
    assert len(original.encode()) == 254
    (destination / original).write_bytes(b"old")
    destination_fd = taildrop.open_directory_no_symlinks(destination)
    try:
        candidate = taildrop.unique_name(destination_fd, original)
    finally:
        os.close(destination_fd)

    assert candidate != original
    assert len(candidate.encode()) <= 255


@pytest.mark.skipif(os.name != "posix", reason="secure cleanup requires Linux")
def test_legacy_partial_files_are_deleted_and_never_imported(tmp_path: Path) -> None:
    state = tmp_path / "state"
    incoming = state / "incoming"
    rejected = state / "rejected"
    incoming.mkdir(parents=True)
    rejected.mkdir()
    for directory in (state, incoming, rejected):
        directory.chmod(0o700)
    (incoming / "partial.apk").write_bytes(b"partial")
    (rejected / "large.iso").write_bytes(b"large")

    taildrop.purge_legacy_staging(state)

    assert not incoming.exists()
    assert not rejected.exists()


@pytest.mark.skipif(os.name != "posix", reason="spool quota guard requires Linux")
def test_partial_spool_quota_aborts_and_removes_transfer(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    files_root = tmp_path / "tailscale/files"
    profile = files_root / "profile"
    profile.mkdir(parents=True)
    files_root.chmod(0o700)
    profile.chmod(0o700)
    partial = profile / "movie.node.partial"
    partial.write_bytes(b"12345")
    commands: list[list[str]] = []
    monkeypatch.setattr(
        taildrop,
        "trusted_root_file",
        lambda *args, **kwargs: Path("/bin/true"),
    )
    monkeypatch.setattr(
        taildrop.subprocess,
        "run",
        lambda command, **kwargs: commands.append(command),
    )

    assert taildrop.enforce_partial_spool_quota(files_root, maximum_bytes=4) is True
    assert not partial.exists()
    assert commands == [
        ["/bin/true", "stop", "tailscaled.service"],
        ["/bin/true", "start", "tailscaled.service"],
    ]


@pytest.mark.skipif(os.name != "posix", reason="spool quota guard requires Linux")
def test_unlimited_taildrop_uses_disk_reserve_instead_of_file_size(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    files_root = tmp_path / "tailscale/files"
    profile = files_root / "profile"
    profile.mkdir(parents=True)
    files_root.chmod(0o700)
    profile.chmod(0o700)
    partial = profile / "movie.node.partial"
    partial.write_bytes(b"12345")
    monkeypatch.setattr(taildrop, "FREE_SPACE_RESERVE", 4)

    assert taildrop.enforce_partial_spool_quota(files_root, maximum_bytes=0) is False
    assert partial.exists()


@pytest.mark.skipif(os.name != "posix", reason="spool quota guard requires Linux")
def test_partial_spool_quota_restarts_tailscale_after_stop_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    files_root = tmp_path / "tailscale/files"
    profile = files_root / "profile"
    profile.mkdir(parents=True)
    files_root.chmod(0o700)
    profile.chmod(0o700)
    (profile / "movie.node.partial").write_bytes(b"12345")
    commands: list[list[str]] = []
    monkeypatch.setattr(
        taildrop, "trusted_root_file", lambda *args, **kwargs: Path("/bin/true")
    )

    def run(command: list[str], **kwargs: object) -> None:
        commands.append(command)
        if command[1] == "stop":
            raise subprocess.TimeoutExpired(command, 30)

    monkeypatch.setattr(taildrop.subprocess, "run", run)
    with pytest.raises(subprocess.TimeoutExpired):
        taildrop.enforce_partial_spool_quota(files_root, maximum_bytes=4)

    assert commands == [
        ["/bin/true", "stop", "tailscaled.service"],
        ["/bin/true", "start", "tailscaled.service"],
    ]


def test_taildrop_service_keeps_root_receiver_confined() -> None:
    unit = UNIT_PATH.read_text(encoding="utf-8")
    importer = IMPORTER_PATH.read_text(encoding="utf-8")
    assert "User=root" in unit
    assert "NoNewPrivileges=yes" in unit
    assert "ProtectSystem=strict" in unit
    assert "RestrictAddressFamilies=AF_UNIX" in unit
    assert "CapabilityBoundingSet=CAP_CHOWN CAP_DAC_OVERRIDE CAP_FOWNER" in unit
    assert "ReadWritePaths=/var/lib/easypi/taildrop -/var/lib/tailscale/files" in unit
    assert "--destination /opt/EasyPi/backend/data/picloud " in unit
    for folder in taildrop.SORT_FOLDERS:
        assert f"/opt/EasyPi/backend/data/picloud/{folder}" in unit
    assert "/localapi/v0/files/" in importer
    assert "tailscale file get" not in importer
    assert "Wants=tailscaled.service" not in unit
    assert "After=local-fs.target tailscaled.service" not in unit


def test_missing_optional_tailscale_is_not_started(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    commands: list[list[str]] = []

    def trusted_file(candidates: tuple[Path, ...], **_kwargs: object) -> Path | None:
        if candidates == taildrop.TAILSCALED_CANDIDATES:
            return None
        return Path("/bin/true")

    monkeypatch.setattr(taildrop, "trusted_root_file", trusted_file)
    monkeypatch.setattr(
        taildrop.subprocess,
        "run",
        lambda command, **_kwargs: commands.append(command),
    )

    assert taildrop.tailscaled_installed() is False
    assert taildrop.start_tailscaled() is False
    assert commands == []


def test_release_and_uninstall_include_taildrop_components() -> None:
    installer = (ROOT / "install.sh").read_text(encoding="utf-8")
    uninstaller = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
    updater = (ROOT / "scripts/maintenance/apply_update.sh").read_text(
        encoding="utf-8"
    )
    restart_helper = (ROOT / "scripts/maintenance/restart_services.sh").read_text(
        encoding="utf-8"
    )
    validator = (ROOT / "scripts/release/validate_release_archive.py").read_text(
        encoding="utf-8"
    )
    context = (ROOT / "backend/app/services/picloud_components/context.py").read_text(
        encoding="utf-8"
    )
    assert "easypi-taildrop-import.service" in installer
    assert "easypi-taildrop-import.service" in uninstaller
    assert "systemctl restart easypi-taildrop-import.service" in installer
    assert "easypi-taildrop-import" in updater
    assert "easypi-taildrop-import" in restart_helper
    assert "scripts/services/picloud_taildrop_import.py" in validator
    assert '"Taildrop"' in context
    assert 'picloud_root="${EASYPI_PREFIX}/backend/data/picloud"' in installer
    assert (
        'install -d -o "${EASYPI_USER}" -g "${EASYPI_GROUP}" -m 0750 \\\n'
        '    "${picloud_root}"'
    ) in installer
    assert 'for picloud_folder in "${picloud_folders[@]}"; do' in installer
    for folder in (".thumbnails", ".meta", ".trash", *taildrop.SORT_FOLDERS):
        assert f"    {folder}" in installer
    assert "Refusing symlinked PiCloud path" in installer
    assert "PiCloud storage ownership invariant failed" in installer
