from __future__ import annotations

from pathlib import Path

import pytest

from scripts.utils.backup_crypto import (
    create_recovery_package,
    decrypt_file_with_keys,
    encrypt_file,
    import_recovery_package,
    key_fingerprint,
    load_decryption_keys,
    open_recovery_package,
    write_recovery_package,
)

PASSPHRASE = "correct horse battery staple"


def test_recovery_key_package_roundtrip_and_tamper_rejection() -> None:
    key = bytes(range(32))
    package = create_recovery_package(key, PASSPHRASE)
    assert open_recovery_package(package, PASSPHRASE) == key

    with pytest.raises(ValueError, match="authentication failed"):
        open_recovery_package(package, "wrong recovery passphrase")

    tampered = bytearray(package)
    tampered[-1] ^= 1
    with pytest.raises(ValueError, match="authentication failed"):
        open_recovery_package(bytes(tampered), PASSPHRASE)


def test_imported_recovery_key_decrypts_an_old_host_backup(tmp_path: Path) -> None:
    old_key = bytes(range(32))
    primary_path = tmp_path / "primary" / "backup.key"
    imported_directory = tmp_path / "primary" / "imported-keys"
    package_path = tmp_path / "old-host.epikey"
    write_recovery_package(package_path, old_key, PASSPHRASE)

    fingerprint, imported = import_recovery_package(
        package_path,
        PASSPHRASE,
        primary_path=primary_path,
        imported_directory=imported_directory,
    )
    assert imported is True
    assert fingerprint == key_fingerprint(old_key)

    _, imported_again = import_recovery_package(
        package_path,
        PASSPHRASE,
        primary_path=primary_path,
        imported_directory=imported_directory,
    )
    assert imported_again is False

    plain = tmp_path / "legacy.tar.gz"
    encrypted = tmp_path / "legacy.epibak"
    restored = tmp_path / "restored.tar.gz"
    plain.write_bytes(b"legacy backup payload")
    plain.chmod(0o600)
    encrypt_file(plain, encrypted, old_key)

    used_fingerprint = decrypt_file_with_keys(
        encrypted,
        restored,
        load_decryption_keys(primary_path, imported_directory),
    )
    assert used_fingerprint == fingerprint
    assert restored.read_bytes() == plain.read_bytes()
