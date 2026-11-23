from __future__ import annotations

import asyncio
import json
import os
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest
from app.api.v1.endpoints import picloud
from app.services.picloud_components import files as cloud_files_module
from app.services.picloud_components import context as cloud_context_module
from app.services.picloud_components import metadata as cloud_metadata_module
from app.services.picloud_components import telegram as cloud_telegram_module
from app.services.picloud_components.files import CloudFilesMixin
from app.services.picloud_components.metadata import CloudMetadataMixin
from app.services.picloud_components.telegram import CloudTelegramMixin
from app.services import picloud_service as picloud_service_module
from app.services.picloud_service import PiCloudService
from fastapi import HTTPException


class CloudHarness(CloudFilesMixin, CloudMetadataMixin, CloudTelegramMixin):
    pass


@pytest.fixture
def cloud_harness(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[CloudHarness, SimpleNamespace]:
    meta = tmp_path / ".meta"
    meta.mkdir()
    runtime = SimpleNamespace(
        STORAGE_ROOT=tmp_path,
        PROTECTED_ROOT_FOLDERS={"Photos", "Videos", "Music", "Documents", "Files"},
        UPLOAD_CHUNK_BYTES=1024,
        SHARE_FILE=meta / "shares.json",
        SHARES_DB_FILE=meta / "shares_db.json",
        TELEGRAM_CONFIG_FILE=meta / "telegram_config.json",
        TELEGRAM_STATE_FILE=meta / "telegram_state.json",
    )
    runtime.SHARE_FILE.write_text("{}", encoding="utf-8")
    for module in (
        cloud_files_module,
        cloud_metadata_module,
        cloud_telegram_module,
    ):
        monkeypatch.setattr(module, "cloud_runtime", lambda: runtime)
    service = CloudHarness()
    service._share_lock = threading.RLock()
    service.share_tokens = service._load_shares()
    service._telegram_state_cache = {}
    service._telegram_fs_error = None
    return service, runtime


@pytest.fixture
def cloud_files(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> tuple[CloudFilesMixin, Path]:
    runtime = SimpleNamespace(
        STORAGE_ROOT=tmp_path,
        PROTECTED_ROOT_FOLDERS={"Photos", "Videos", "Music", "Documents", "Files"},
        UPLOAD_CHUNK_BYTES=1024,
    )
    monkeypatch.setattr(cloud_files_module, "cloud_runtime", lambda: runtime)
    return CloudFilesMixin(), tmp_path


def test_cloud_applies_photo_limit_without_reducing_other_file_limit(
    cloud_harness: tuple[CloudHarness, SimpleNamespace],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, runtime = cloud_harness
    root = runtime.STORAGE_ROOT
    monkeypatch.setenv("EASYPI_MAX_PHOTO_UPLOAD_BYTES", "4")
    monkeypatch.setenv("EASYPI_MAX_UPLOAD_BYTES", "10")

    class Upload:
        size = 5

        def __init__(self, filename: str) -> None:
            self.filename = filename
            self.sent = False

        async def read(self, _size: int) -> bytes:
            if self.sent:
                return b""
            self.sent = True
            return b"12345"

    with pytest.raises(HTTPException, match="250 MiB photo limit") as photo_error:
        asyncio.run(service.upload_files([Upload("photo.jpg")], "/", auto_sort=True))
    assert photo_error.value.status_code == 413
    assert not (root / "Photos" / "photo.jpg").exists()

    result = asyncio.run(service.upload_files([Upload("archive.bin")], "/", auto_sort=True))
    assert result.uploaded[0].id == "archive.bin"
    assert (root / "archive.bin").read_bytes() == b"12345"


def test_copy_file_uses_an_exact_non_overwriting_destination(
    cloud_files: tuple[CloudFilesMixin, Path],
) -> None:
    service, root = cloud_files
    source = root / "Documents" / "report.txt"
    source.parent.mkdir()
    source.write_text("release data", encoding="utf-8")

    copied = service.copy_file("Documents/report.txt", "Documents/report copy.txt")

    assert source.read_text(encoding="utf-8") == "release data"
    assert (root / "Documents" / "report copy.txt").read_text(encoding="utf-8") == "release data"
    assert copied.id == "Documents/report copy.txt"
    assert copied.type == "file"

    with pytest.raises(FileExistsError):
        service.copy_file("Documents/report.txt", "Documents/report copy.txt")


def test_copy_file_rejects_recursive_directory_copy(
    cloud_files: tuple[CloudFilesMixin, Path],
) -> None:
    service, root = cloud_files
    (root / "source").mkdir()

    with pytest.raises(ValueError, match="into itself"):
        service.copy_file("source", "source/nested/copy")

    assert not (root / "source" / "nested").exists()


def test_move_rejects_protected_root_and_existing_destination(
    cloud_files: tuple[CloudFilesMixin, Path],
) -> None:
    service, root = cloud_files
    (root / "Photos").mkdir()
    (root / "one.txt").write_text("one", encoding="utf-8")
    (root / "two.txt").write_text("two", encoding="utf-8")

    with pytest.raises(ValueError, match="System folders"):
        service.rename_or_move("Photos", "Pictures")
    with pytest.raises(FileExistsError):
        service.rename_or_move("one.txt", "two.txt")

    assert (root / "Photos").is_dir()
    assert (root / "one.txt").read_text(encoding="utf-8") == "one"
    assert (root / "two.txt").read_text(encoding="utf-8") == "two"


def test_picloud_router_exposes_the_copy_contract() -> None:
    matching = [
        route
        for route in picloud.router.routes
        if route.path == "/copy/{file_id:path}" and "POST" in route.methods
    ]
    assert len(matching) == 1


@pytest.mark.parametrize(
    ("filename", "mime", "folder"),
    [
        ("photo.jpg", "image/jpeg", "Photos"),
        ("movie.mp4", "video/mp4", "Videos"),
        ("report.pdf", "application/pdf", "Documents"),
        ("song.mp3", "audio/mpeg", "Music"),
        ("backup.epec", "application/octet-stream", "Encrypted"),
        ("application.apk", "application/vnd.android.package-archive", "Files"),
    ],
)
def test_telegram_uploads_use_picloud_type_folders(
    tmp_path: Path,
    filename: str,
    mime: str,
    folder: str,
) -> None:
    class TelegramHarness(CloudTelegramMixin):
        def _safe_path(self, rel_path: str, allow_root: bool = True) -> Path:
            del allow_root
            return tmp_path / rel_path

    target = TelegramHarness()._telegram_upload_directory(filename, mime)

    assert target == tmp_path / folder
    assert target.is_dir()


def test_legacy_taildrop_files_are_sorted_without_overwriting(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    legacy = tmp_path / "Taildrop"
    legacy.mkdir()
    documents = tmp_path / "Documents"
    documents.mkdir()
    (documents / "report.pdf").write_bytes(b"existing")
    (legacy / "report.pdf").write_bytes(b"new")
    (legacy / "movie.mp4").write_bytes(b"video")
    monkeypatch.setattr(picloud_service_module, "STORAGE_ROOT", tmp_path)

    service = object.__new__(PiCloudService)
    service._migrate_taildrop_folder()

    assert (documents / "report.pdf").read_bytes() == b"existing"
    assert (documents / "report_1.pdf").read_bytes() == b"new"
    assert (tmp_path / "Videos/movie.mp4").read_bytes() == b"video"
    assert not legacy.exists()


@pytest.mark.parametrize(
    ("error", "status_code", "detail"),
    [
        (FileNotFoundError(), 404, "Source file not found"),
        (FileExistsError(), 409, "Destination already exists"),
        (ValueError(), 400, "Invalid path"),
    ],
)
def test_copy_endpoint_maps_expected_storage_errors(
    monkeypatch: pytest.MonkeyPatch,
    error: Exception,
    status_code: int,
    detail: str,
) -> None:
    def fail(_file_id: str, _new_path: str) -> None:
        raise error

    monkeypatch.setattr(picloud.pi_cloud_service, "copy_file", fail)
    monkeypatch.setattr(picloud, "_record_cloud_event", lambda **_kwargs: None)

    with pytest.raises(HTTPException) as raised:
        picloud.copy_file("source.txt", "copy.txt")

    assert raised.value.status_code == status_code
    assert raised.value.detail == detail


def test_deleted_share_is_revoked_in_memory_and_on_reload(
    cloud_harness: tuple[CloudHarness, SimpleNamespace],
) -> None:
    service, runtime = cloud_harness
    target = runtime.STORAGE_ROOT / "report.pdf"
    target.write_bytes(b"private report")
    share = service.create_share("report.pdf")

    reloaded = CloudHarness()
    reloaded._share_lock = threading.RLock()
    reloaded.share_tokens = reloaded._load_shares()
    assert reloaded.resolve_share(share.id) == target
    reloaded.delete_share(share.id)
    assert reloaded.resolve_share(share.id) is None

    restarted = CloudHarness()
    restarted._share_lock = threading.RLock()
    restarted.share_tokens = restarted._load_shares()
    assert restarted.resolve_share(share.id) is None


def test_share_does_not_follow_a_replacement_at_the_same_path(
    cloud_harness: tuple[CloudHarness, SimpleNamespace],
) -> None:
    service, runtime = cloud_harness
    target = runtime.STORAGE_ROOT / "same-name.txt"
    target.write_bytes(b"old private data")
    share = service.create_share("same-name.txt")

    target.unlink()
    target.write_bytes(b"new private data")

    assert service.resolve_share(share.id) is None
    assert share.id not in service.share_tokens


def test_parallel_share_create_cannot_restore_a_revoked_token(
    cloud_harness: tuple[CloudHarness, SimpleNamespace],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, runtime = cloud_harness
    (runtime.STORAGE_ROOT / "first.txt").write_bytes(b"first")
    (runtime.STORAGE_ROOT / "second.txt").write_bytes(b"second")
    revoked = service.create_share("first.txt")
    original_replace = cloud_files_module.os.replace
    creator_waiting = threading.Event()
    release_creator = threading.Event()
    deleter_started = threading.Event()
    deleter_finished = threading.Event()
    errors: list[BaseException] = []

    def delayed_replace(source, destination) -> None:
        if threading.current_thread().name == "share-creator":
            creator_waiting.set()
            if not release_creator.wait(timeout=5):
                raise TimeoutError("share persistence test timed out")
        original_replace(source, destination)

    monkeypatch.setattr(cloud_files_module.os, "replace", delayed_replace)

    def create() -> None:
        try:
            service.create_share("second.txt")
        except BaseException as exc:
            errors.append(exc)

    def revoke() -> None:
        deleter_started.set()
        try:
            service.delete_share(revoked.id)
        except BaseException as exc:
            errors.append(exc)
        finally:
            deleter_finished.set()

    creator = threading.Thread(target=create, name="share-creator")
    deleter = threading.Thread(target=revoke, name="share-deleter")
    creator.start()
    assert creator_waiting.wait(timeout=5)
    deleter.start()
    assert deleter_started.wait(timeout=5)
    deleter_finished.wait(timeout=0.2)
    release_creator.set()
    creator.join(timeout=5)
    deleter.join(timeout=5)

    assert not creator.is_alive()
    assert not deleter.is_alive()
    assert not errors
    persisted = service._load_shares()
    assert revoked.id not in persisted
    assert len(persisted) == 1


def test_legacy_path_only_share_is_revoked_during_load(
    cloud_harness: tuple[CloudHarness, SimpleNamespace],
) -> None:
    service, runtime = cloud_harness
    runtime.SHARE_FILE.write_text(
        json.dumps(
            {
                "legacy": {
                    "file_id": "same-name.txt",
                    "expires": None,
                    "password_hash": None,
                }
            }
        ),
        encoding="utf-8",
    )

    assert service._load_shares() == {}
    assert json.loads(runtime.SHARE_FILE.read_text(encoding="utf-8")) == {}


def test_removing_telegram_user_revokes_running_authorization(
    cloud_harness: tuple[CloudHarness, SimpleNamespace],
) -> None:
    service, runtime = cloud_harness
    runtime.TELEGRAM_CONFIG_FILE.write_text(
        json.dumps({"token": "test", "allowed_user_ids": [123, 456]}),
        encoding="utf-8",
    )

    assert service._telegram_user_is_authorized(123) is True
    service.remove_telegram_user(123)
    assert service._telegram_user_is_authorized(123) is False
    assert service._telegram_user_is_authorized(456) is True


def test_all_cloud_ingress_paths_preserve_the_disk_reserve(
    cloud_harness: tuple[CloudHarness, SimpleNamespace],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, runtime = cloud_harness
    monkeypatch.setattr(cloud_context_module, "PICLOUD_FREE_SPACE_RESERVE", 100)
    monkeypatch.setattr(
        cloud_context_module.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(total=200, used=95, free=105),
    )

    class BrowserUpload:
        filename = "browser.bin"
        size = 10

        async def read(self, _size: int) -> bytes:
            return b"payload"

    with pytest.raises(HTTPException) as upload_error:
        asyncio.run(service.upload_files([BrowserUpload()], "/", auto_sort=False))
    assert upload_error.value.status_code == 507
    assert not (runtime.STORAGE_ROOT / "browser.bin").exists()

    source = runtime.STORAGE_ROOT / "source.bin"
    source.write_bytes(b"0123456789")
    with pytest.raises(HTTPException) as copy_error:
        service.copy_file("source.bin", "copy.bin")
    assert copy_error.value.status_code == 507
    assert not (runtime.STORAGE_ROOT / "copy.bin").exists()

    class TelegramFile:
        called = False

        async def download_as_bytearray(self) -> bytearray:
            self.called = True
            return bytearray(b"0123456789")

    telegram_file = TelegramFile()
    telegram_target = runtime.STORAGE_ROOT / "telegram.bin"
    with pytest.raises(HTTPException) as telegram_error:
        asyncio.run(
            service._download_telegram_file(telegram_file, telegram_target, 10)
        )
    assert telegram_error.value.status_code == 507
    assert telegram_file.called is False
    assert not telegram_target.exists()


def test_telegram_rechecks_capacity_after_network_download(
    cloud_harness: tuple[CloudHarness, SimpleNamespace],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service, runtime = cloud_harness
    monkeypatch.setattr(cloud_context_module, "PICLOUD_FREE_SPACE_RESERVE", 100)
    free_values = iter((200, 200, 200, 95))
    monkeypatch.setattr(
        cloud_context_module.shutil,
        "disk_usage",
        lambda _path: SimpleNamespace(total=300, used=100, free=next(free_values)),
    )

    class TelegramFile:
        async def download_as_bytearray(self) -> bytearray:
            return bytearray(b"0123456789")

    target = runtime.STORAGE_ROOT / "telegram-race.bin"
    with pytest.raises(HTTPException) as raised:
        asyncio.run(service._download_telegram_file(TelegramFile(), target, 10))

    assert raised.value.status_code == 507
    assert not target.exists()
    assert not list(runtime.STORAGE_ROOT.glob("*.part"))


def test_telegram_publish_never_overwrites_or_deletes_a_concurrent_file(
    cloud_harness: tuple[CloudHarness, SimpleNamespace],
) -> None:
    service, runtime = cloud_harness
    requested = runtime.STORAGE_ROOT / "same-name.bin"

    class SuccessfulTelegramFile:
        async def download_as_bytearray(self) -> bytearray:
            requested.write_bytes(b"browser upload")
            return bytearray(b"telegram upload")

    published = asyncio.run(
        service._download_telegram_file(SuccessfulTelegramFile(), requested, 15)
    )

    assert requested.read_bytes() == b"browser upload"
    assert published != requested
    assert published.read_bytes() == b"telegram upload"

    failed_target = runtime.STORAGE_ROOT / "failed-name.bin"

    class FailedTelegramFile:
        async def download_as_bytearray(self) -> bytearray:
            failed_target.write_bytes(b"browser upload survives")
            raise RuntimeError("network interrupted")

    with pytest.raises(RuntimeError, match="network interrupted"):
        asyncio.run(
            service._download_telegram_file(FailedTelegramFile(), failed_target, 10)
        )

    assert failed_target.read_bytes() == b"browser upload survives"
    assert not list(runtime.STORAGE_ROOT.glob(".tg-*.part"))


@pytest.mark.skipif(os.name != "posix", reason="Linux NAME_MAX contract")
def test_telegram_temporary_name_is_independent_of_long_destination(
    cloud_harness: tuple[CloudHarness, SimpleNamespace],
) -> None:
    service, runtime = cloud_harness
    requested = runtime.STORAGE_ROOT / ("a" * 216 + ".bin")

    class TelegramFile:
        async def download_as_bytearray(self) -> bytearray:
            return bytearray(b"payload")

    published = asyncio.run(
        service._download_telegram_file(TelegramFile(), requested, 7)
    )

    assert published == requested
    assert published.read_bytes() == b"payload"
    assert not list(runtime.STORAGE_ROOT.glob(".tg-*.part"))
