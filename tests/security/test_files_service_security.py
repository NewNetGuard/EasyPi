from __future__ import annotations

import asyncio
import multiprocessing
import os
import stat
from pathlib import Path

import pytest
from fastapi import HTTPException

from app.services import files_service as files_module
from app.services.files_service import FilesService


class _Upload:
    filename = "upload.bin"

    def __init__(self, chunks: list[bytes | Exception]) -> None:
        self._chunks = iter(chunks)

    async def read(self, _size: int) -> bytes:
        value = next(self._chunks, b"")
        if isinstance(value, Exception):
            raise value
        return value


def _read_fifo(service: FilesService, path: str, result: multiprocessing.Queue) -> None:
    try:
        service.read_file(path)
    except HTTPException as exc:
        result.put(exc.status_code)
    except Exception as exc:  # pragma: no cover - diagnostic result from child
        result.put(type(exc).__name__)
    else:
        result.put("accepted")


def test_legacy_secret_locations_are_protected() -> None:
    assert "/opt/EasyPi/backend/.env" in files_module.BLACKLISTED_PATHS
    assert "/opt/EasyPi/backend/data/db" in files_module.BLACKLISTED_PATHS
    assert FilesService.resolve_safe_path("/opt/EasyPi/backend/.env") is None
    assert FilesService.resolve_safe_path("/opt/EasyPi/backend/data/db/easypi.db") is None


@pytest.mark.skipif(os.name != "posix", reason="dirfd security requires Linux")
class TestLinuxFilesSecurity:
    @staticmethod
    def _scope(monkeypatch: pytest.MonkeyPatch, root: Path, blocked: Path) -> FilesService:
        monkeypatch.setattr(files_module, "ALLOWED_ROOTS", [str(root)])
        monkeypatch.setattr(files_module, "BLACKLISTED_PATHS", [str(blocked)])
        monkeypatch.setattr(files_module, "FILES_FREE_SPACE_RESERVE", 0)
        return FilesService()

    def test_parent_of_protected_database_cannot_be_deleted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = tmp_path / "EasyPi"
        database = root / "data" / "db" / "easypi.db"
        database.parent.mkdir(parents=True)
        database.write_bytes(b"database")
        service = self._scope(monkeypatch, root, database.parent)

        with pytest.raises(HTTPException) as exc_info:
            service.delete(str(root / "data"))

        assert exc_info.value.status_code == 403
        assert database.read_bytes() == b"database"

    def test_unprotected_directory_can_still_be_deleted(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = tmp_path / "EasyPi"
        disposable = root / "data" / "disposable"
        disposable.mkdir(parents=True)
        (disposable / "file.txt").write_text("content", encoding="utf-8")
        service = self._scope(monkeypatch, root, root / "data" / "db")

        result = service.delete(str(disposable))

        assert result["status"] == "success"
        assert not disposable.exists()

    def test_oversized_upload_preserves_existing_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = tmp_path / "EasyPi"
        root.mkdir()
        target = root / "existing.bin"
        target.write_bytes(b"original")
        service = self._scope(monkeypatch, root, root / "protected")
        monkeypatch.setenv("EASYPI_MAX_UPLOAD_BYTES", "4")

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(service.upload_file(_Upload([b"replacement"]), str(target)))

        assert exc_info.value.status_code == 413
        assert target.read_bytes() == b"original"
        assert not list(root.glob(".easypi-files-*.tmp"))

    def test_interrupted_upload_preserves_existing_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = tmp_path / "EasyPi"
        root.mkdir()
        target = root / "existing.bin"
        target.write_bytes(b"original")
        service = self._scope(monkeypatch, root, root / "protected")

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(
                service.upload_file(
                    _Upload([b"partial", OSError("connection lost")]), str(target)
                )
            )

        assert exc_info.value.status_code == 500
        assert target.read_bytes() == b"original"
        assert not list(root.glob(".easypi-files-*.tmp"))

    def test_successful_upload_replaces_file_only_after_receive(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = tmp_path / "EasyPi"
        root.mkdir()
        target = root / "existing.bin"
        target.write_bytes(b"original")
        service = self._scope(monkeypatch, root, root / "protected")

        result = asyncio.run(
            service.upload_file(_Upload([b"complete", b" payload"]), str(target))
        )

        assert result["size"] == len(b"complete payload")
        assert target.read_bytes() == b"complete payload"
        assert not list(root.glob(".easypi-files-*.tmp"))

    def test_new_files_keep_service_private_mode(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = tmp_path / "EasyPi"
        root.mkdir()
        service = self._scope(monkeypatch, root, root / "protected")
        written = root / "written.txt"
        uploaded = root / "uploaded.bin"
        created = root / "created.txt"
        previous_umask = os.umask(0o027)
        try:
            service.write_file(str(written), "content")
            asyncio.run(service.upload_file(_Upload([b"payload"]), str(uploaded)))
            service.create_file(str(created))
        finally:
            os.umask(previous_umask)

        assert stat.S_IMODE(written.stat().st_mode) == 0o640
        assert stat.S_IMODE(uploaded.stat().st_mode) == 0o640
        assert stat.S_IMODE(created.stat().st_mode) == 0o640

    def test_fifo_read_is_rejected_without_blocking(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = tmp_path / "EasyPi"
        root.mkdir()
        fifo = root / "blocked.fifo"
        os.mkfifo(fifo, 0o640)
        service = self._scope(monkeypatch, root, root / "protected")
        context = multiprocessing.get_context("fork")
        result = context.Queue()
        process = context.Process(target=_read_fifo, args=(service, str(fifo), result))

        process.start()
        process.join(timeout=1.0)
        if process.is_alive():
            process.terminate()
            process.join(timeout=1.0)
            pytest.fail("FIFO read blocked a backend worker")

        assert process.exitcode == 0
        assert result.get(timeout=1.0) == 400

    def test_parent_symlink_swap_cannot_redirect_upload(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = tmp_path / "EasyPi"
        user_directory = root / "user"
        protected_directory = root / "protected"
        user_directory.mkdir(parents=True)
        protected_directory.mkdir()
        protected_file = protected_directory / "secret.bin"
        protected_file.write_bytes(b"secret")
        service = self._scope(monkeypatch, root, protected_directory)
        original_allowed_root_for = FilesService._allowed_root_for
        swapped = False

        def swap_after_validation(cls: type[FilesService], path: str) -> str:
            nonlocal swapped
            result = original_allowed_root_for(path)
            if not swapped and path == str(user_directory):
                swapped = True
                user_directory.rename(root / "user-original")
                user_directory.symlink_to(protected_directory, target_is_directory=True)
            return result

        monkeypatch.setattr(
            FilesService, "_allowed_root_for", classmethod(swap_after_validation)
        )

        with pytest.raises(HTTPException) as exc_info:
            asyncio.run(
                service.upload_file(_Upload([b"replacement"]), str(user_directory / "secret.bin"))
            )

        assert exc_info.value.status_code == 403
        assert protected_file.read_bytes() == b"secret"

    def test_parent_symlink_swap_cannot_redirect_read(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = tmp_path / "EasyPi"
        user_directory = root / "user"
        protected_directory = root / "protected"
        user_directory.mkdir(parents=True)
        protected_directory.mkdir()
        (user_directory / "document.txt").write_text("public", encoding="utf-8")
        protected_file = protected_directory / "document.txt"
        protected_file.write_text("secret", encoding="utf-8")
        service = self._scope(monkeypatch, root, protected_directory)
        original_allowed_root_for = FilesService._allowed_root_for
        swapped = False

        def swap_after_validation(cls: type[FilesService], path: str) -> str:
            nonlocal swapped
            result = original_allowed_root_for(path)
            if not swapped and path == str(user_directory):
                swapped = True
                user_directory.rename(root / "user-original")
                user_directory.symlink_to(protected_directory, target_is_directory=True)
            return result

        monkeypatch.setattr(
            FilesService, "_allowed_root_for", classmethod(swap_after_validation)
        )

        with pytest.raises(HTTPException) as exc_info:
            service.read_file(str(user_directory / "document.txt"))

        assert exc_info.value.status_code == 403
        assert protected_file.read_text(encoding="utf-8") == "secret"

    def test_files_and_picloud_preserve_system_disk_reserve(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        root = tmp_path / "EasyPi"
        cloud = root / "data" / "picloud" / "Files"
        cloud.mkdir(parents=True)
        target = cloud / "movie.bin"
        target.write_bytes(b"original")
        notes = cloud / "notes.txt"
        notes.write_text("original", encoding="utf-8")
        service = self._scope(monkeypatch, root, root / "protected")
        monkeypatch.setattr(files_module, "FILES_FREE_SPACE_RESERVE", 1 << 80)

        with pytest.raises(HTTPException) as upload_error:
            asyncio.run(service.upload_file(_Upload([b"replacement"]), str(target)))
        with pytest.raises(HTTPException) as write_error:
            service.write_file(str(notes), "new content")

        assert upload_error.value.status_code == 507
        assert write_error.value.status_code == 507
        assert target.read_bytes() == b"original"
        assert notes.read_text(encoding="utf-8") == "original"
        assert not list(cloud.glob(".easypi-files-*.tmp"))
