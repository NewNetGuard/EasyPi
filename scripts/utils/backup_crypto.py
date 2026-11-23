#!/opt/EasyPi/backend/.venv/bin/python
"""Authenticated streaming encryption for EasyPi backup archives."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import sys
import tarfile
import tempfile
from pathlib import Path

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"EASYPIBK1"
NONCE_SIZE = 12
TAG_SIZE = 16
CHUNK_SIZE = 1024 * 1024
DEFAULT_KEY_FILE = Path("/var/lib/easypi/backup/backup.key")
IMPORTED_KEY_DIR = DEFAULT_KEY_FILE.parent / "imported-keys"
RECOVERY_MAGIC = b"EASYPIKEY1"
RECOVERY_SALT_SIZE = 16
RECOVERY_KDF_ITERATIONS = 600_000
MAX_IMPORTED_KEYS = 8
MAX_RECOVERY_PACKAGE_SIZE = 4096


def _write_all(fd: int, payload: bytes) -> None:
    view = memoryview(payload)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write while storing backup key")
        view = view[written:]


def _regular_root_file(path: Path, *, writable: bool = False) -> os.stat_result:
    details = path.lstat()
    if not stat.S_ISREG(details.st_mode):
        raise ValueError(f"{path} must be a regular file")
    # Privileged production commands execute as root, so requiring ownership by
    # the current effective UID is root ownership there while still allowing
    # unprivileged pure-function tests to exercise the format safely.
    if os.name == "posix":
        if details.st_uid != os.geteuid():
            raise ValueError(f"{path} must be owned by the current process user")
        if details.st_mode & 0o022:
            raise ValueError(f"{path} must not be writable by group or others")
        if writable and details.st_mode & 0o077:
            raise ValueError(f"{path} must be private to root")
    return details


def load_or_create_key(path: Path = DEFAULT_KEY_FILE) -> bytes:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path.parent, 0o700)
    if not path.exists():
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(path, flags, 0o600)
        try:
            _write_all(fd, os.urandom(32))
            os.fsync(fd)
        finally:
            os.close(fd)
    _regular_root_file(path, writable=True)
    key = path.read_bytes()
    if len(key) != 32:
        raise ValueError("backup key must contain exactly 32 bytes")
    return key


def key_fingerprint(key: bytes) -> str:
    if len(key) != 32:
        raise ValueError("backup key must contain exactly 32 bytes")
    return hashlib.sha256(key).hexdigest()


def _private_key_directory(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if path.is_symlink() or not path.is_dir():
        raise ValueError(f"{path} must be a real directory")
    if os.name == "posix":
        details = path.stat()
        if details.st_uid != os.geteuid() or details.st_mode & 0o077:
            raise ValueError(f"{path} must be private to the current process user")
        os.chmod(path, 0o700)


def load_imported_keys(directory: Path = IMPORTED_KEY_DIR) -> list[bytes]:
    if not directory.exists():
        return []
    _private_key_directory(directory)
    paths = sorted(directory.glob("*.key"))
    if len(paths) > MAX_IMPORTED_KEYS:
        raise ValueError("too many imported backup keys")
    keys: list[bytes] = []
    for path in paths:
        _regular_root_file(path, writable=True)
        key = path.read_bytes()
        fingerprint = key_fingerprint(key)
        if path.name != f"{fingerprint}.key":
            raise ValueError(f"imported backup key has an invalid name: {path.name}")
        keys.append(key)
    return keys


def load_decryption_keys(
    primary_path: Path = DEFAULT_KEY_FILE,
    imported_directory: Path = IMPORTED_KEY_DIR,
) -> list[bytes]:
    primary = load_or_create_key(primary_path)
    result = [primary]
    for key in load_imported_keys(imported_directory):
        if key not in result:
            result.append(key)
    return result


def _derive_recovery_key(passphrase: str, salt: bytes) -> bytes:
    if len(passphrase) < 12 or len(passphrase) > 1024:
        raise ValueError("recovery passphrase must contain 12 to 1024 characters")
    return PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=RECOVERY_KDF_ITERATIONS,
    ).derive(passphrase.encode("utf-8"))


def create_recovery_package(key: bytes, passphrase: str) -> bytes:
    key_fingerprint(key)
    salt = os.urandom(RECOVERY_SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    wrapping_key = _derive_recovery_key(passphrase, salt)
    ciphertext = AESGCM(wrapping_key).encrypt(nonce, key, RECOVERY_MAGIC)
    return RECOVERY_MAGIC + salt + nonce + ciphertext


def open_recovery_package(payload: bytes, passphrase: str) -> bytes:
    expected_size = len(RECOVERY_MAGIC) + RECOVERY_SALT_SIZE + NONCE_SIZE + 32 + TAG_SIZE
    if len(payload) != expected_size or not payload.startswith(RECOVERY_MAGIC):
        raise ValueError("not an EasyPi recovery-key package")
    offset = len(RECOVERY_MAGIC)
    salt = payload[offset : offset + RECOVERY_SALT_SIZE]
    offset += RECOVERY_SALT_SIZE
    nonce = payload[offset : offset + NONCE_SIZE]
    ciphertext = payload[offset + NONCE_SIZE :]
    wrapping_key = _derive_recovery_key(passphrase, salt)
    try:
        key = AESGCM(wrapping_key).decrypt(nonce, ciphertext, RECOVERY_MAGIC)
    except InvalidTag as exc:
        raise ValueError("recovery-key package authentication failed") from exc
    key_fingerprint(key)
    return key


def write_recovery_package(
    destination: Path,
    key: bytes,
    passphrase: str,
) -> str:
    payload = create_recovery_package(key, passphrase)
    fd, temporary = _temporary_output(destination)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
        if os.name == "posix":
            os.chmod(destination, 0o600)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise
    return key_fingerprint(key)


def import_recovery_package(
    source: Path,
    passphrase: str,
    *,
    primary_path: Path = DEFAULT_KEY_FILE,
    imported_directory: Path = IMPORTED_KEY_DIR,
) -> tuple[str, bool]:
    details = _regular_root_file(source)
    if details.st_size > MAX_RECOVERY_PACKAGE_SIZE:
        raise ValueError("recovery-key package is too large")
    key = open_recovery_package(source.read_bytes(), passphrase)
    fingerprint = key_fingerprint(key)
    primary = load_or_create_key(primary_path)
    if key == primary:
        return fingerprint, False

    _private_key_directory(imported_directory)
    existing = load_imported_keys(imported_directory)
    if key in existing:
        return fingerprint, False
    if len(existing) >= MAX_IMPORTED_KEYS:
        raise ValueError("imported backup key limit reached")

    destination = imported_directory / f"{fingerprint}.key"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(destination, flags, 0o600)
    try:
        _write_all(fd, key)
        os.fsync(fd)
    finally:
        os.close(fd)
    if os.name == "posix":
        os.chmod(destination, 0o600)
    return fingerprint, True


def _temporary_output(destination: Path) -> tuple[int, Path]:
    destination.parent.mkdir(parents=True, exist_ok=True)
    fd, raw_path = tempfile.mkstemp(
        prefix=f".{destination.name}.", dir=destination.parent
    )
    os.chmod(raw_path, 0o600)
    return fd, Path(raw_path)


def encrypt_stream(source, destination: Path, key: bytes) -> None:
    nonce = os.urandom(NONCE_SIZE)
    encryptor = Cipher(algorithms.AES(key), modes.GCM(nonce)).encryptor()
    encryptor.authenticate_additional_data(MAGIC)
    fd, temporary = _temporary_output(destination)
    try:
        with os.fdopen(fd, "wb") as dst:
            dst.write(MAGIC)
            dst.write(nonce)
            while chunk := source.read(CHUNK_SIZE):
                dst.write(encryptor.update(chunk))
            dst.write(encryptor.finalize())
            dst.write(encryptor.tag)
            dst.flush()
            os.fsync(dst.fileno())
        os.replace(temporary, destination)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def encrypt_file(source: Path, destination: Path, key: bytes) -> None:
    _regular_root_file(source)
    with source.open("rb") as stream:
        encrypt_stream(stream, destination, key)


def decrypt_file(source: Path, destination: Path, key: bytes) -> None:
    details = _regular_root_file(source)
    minimum = len(MAGIC) + NONCE_SIZE + TAG_SIZE
    if details.st_size < minimum:
        raise ValueError("encrypted backup is truncated")
    with source.open("rb") as src:
        if src.read(len(MAGIC)) != MAGIC:
            raise ValueError("not an EasyPi encrypted backup")
        nonce = src.read(NONCE_SIZE)
        ciphertext_size = details.st_size - len(MAGIC) - NONCE_SIZE - TAG_SIZE
        src.seek(-TAG_SIZE, os.SEEK_END)
        tag = src.read(TAG_SIZE)
        src.seek(len(MAGIC) + NONCE_SIZE)

        decryptor = Cipher(algorithms.AES(key), modes.GCM(nonce, tag)).decryptor()
        decryptor.authenticate_additional_data(MAGIC)
        fd, temporary = _temporary_output(destination)
        try:
            with os.fdopen(fd, "wb") as dst:
                remaining = ciphertext_size
                while remaining:
                    chunk = src.read(min(CHUNK_SIZE, remaining))
                    if not chunk:
                        raise ValueError("encrypted backup is truncated")
                    remaining -= len(chunk)
                    dst.write(decryptor.update(chunk))
                dst.write(decryptor.finalize())
                dst.flush()
                os.fsync(dst.fileno())
            os.replace(temporary, destination)
        except InvalidTag as exc:
            temporary.unlink(missing_ok=True)
            raise ValueError("backup authentication failed") from exc
        except Exception:
            temporary.unlink(missing_ok=True)
            raise


def decrypt_file_with_keys(
    source: Path,
    destination: Path,
    keys: list[bytes],
) -> str:
    if not keys:
        raise ValueError("no backup decryption keys are available")
    for key in keys:
        try:
            decrypt_file(source, destination, key)
            return key_fingerprint(key)
        except ValueError as exc:
            if str(exc) != "backup authentication failed":
                raise
    raise ValueError("backup authentication failed for all available keys")


def validate_tar_archive(source: Path) -> None:
    """Fully read a backup tarball and reject unsafe archive structure."""

    with tarfile.open(source, "r:*") as archive:
        members = archive.getmembers()
        if not members:
            raise ValueError("backup archive contains no members")
        if len(members) > 100_000:
            raise ValueError("backup archive contains too many members")
        for member in members:
            member_path = Path(member.name.replace("\\", "/"))
            if member_path.is_absolute() or ".." in member_path.parts:
                raise ValueError(f"unsafe archive member path: {member.name}")
            if member.isdev() or member.isfifo():
                raise ValueError(f"unsafe special archive member: {member.name}")
            if member.issym() or member.islnk():
                link_path = Path(member.linkname.replace("\\", "/"))
                if link_path.is_absolute() or ".." in link_path.parts:
                    raise ValueError(
                        f"unsafe archive link target: {member.linkname}"
                    )
            if member.isfile():
                extracted = archive.extractfile(member)
                if extracted is None:
                    raise ValueError(
                        f"archive member payload is unreadable: {member.name}"
                    )
                while extracted.read(CHUNK_SIZE):
                    pass


def verify_encrypted_backup(
    source: Path,
    key: bytes,
    *,
    work_dir: Path,
) -> None:
    """Authenticate, decrypt privately, and validate an EasyPi backup."""

    work_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        os.chmod(work_dir, 0o700)
    with tempfile.TemporaryDirectory(prefix=".verify.", dir=work_dir) as raw_dir:
        restored = Path(raw_dir) / "archive.tar.gz"
        decrypt_file(source, restored, key)
        validate_tar_archive(restored)


def verify_encrypted_backup_with_keys(
    source: Path,
    keys: list[bytes],
    *,
    work_dir: Path,
) -> str:
    work_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        os.chmod(work_dir, 0o700)
    with tempfile.TemporaryDirectory(prefix=".verify.", dir=work_dir) as raw_dir:
        restored = Path(raw_dir) / "archive.tar.gz"
        fingerprint = decrypt_file_with_keys(source, restored, keys)
        validate_tar_archive(restored)
        return fingerprint


def _passphrase_from_stdin() -> str:
    # A valid 1,024-character passphrase can occupy 4,096 UTF-8 bytes, plus
    # the single newline written by the backend's stdin protocol.
    payload = sys.stdin.buffer.read(4098)
    if payload.endswith(b"\n"):
        payload = payload[:-1]
    if len(payload) > 4096:
        raise ValueError("recovery passphrase input is too large")
    if b"\n" in payload or b"\r" in payload or b"\x00" in payload:
        raise ValueError("recovery passphrase contains an unsupported character")
    try:
        return payload.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError("recovery passphrase is not UTF-8") from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "operation",
        choices=(
            "encrypt",
            "encrypt-stdin",
            "decrypt",
            "verify",
            "export-recovery",
            "import-recovery",
        ),
    )
    parser.add_argument("source", type=Path)
    parser.add_argument("destination", type=Path, nargs="?")
    args = parser.parse_args()

    if args.operation == "encrypt-stdin":
        key = load_or_create_key()
        encrypt_stream(sys.stdin.buffer, args.source, key)
    elif args.operation == "encrypt":
        if args.destination is None:
            parser.error("encrypt requires source and destination")
        key = load_or_create_key()
        encrypt_file(args.source, args.destination, key)
    elif args.operation == "decrypt":
        if args.destination is None:
            parser.error("decrypt requires source and destination")
        fingerprint = decrypt_file_with_keys(
            args.source,
            args.destination,
            load_decryption_keys(),
        )
        print(f"BACKUP_KEY_FINGERPRINT={fingerprint}")
    elif args.operation == "verify":
        if args.destination is not None:
            parser.error("verify accepts only the encrypted backup path")
        fingerprint = verify_encrypted_backup_with_keys(
            args.source,
            load_decryption_keys(),
            work_dir=DEFAULT_KEY_FILE.parent,
        )
        print("BACKUP_INTEGRITY=OK")
        print(f"BACKUP_KEY_FINGERPRINT={fingerprint}")
    elif args.operation == "export-recovery":
        if args.destination is not None:
            parser.error("export-recovery accepts only the destination path")
        fingerprint = write_recovery_package(
            args.source,
            load_or_create_key(),
            _passphrase_from_stdin(),
        )
        print(f"RECOVERY_KEY_FINGERPRINT={fingerprint}")
    else:
        if args.destination is not None:
            parser.error("import-recovery accepts only the package path")
        fingerprint, imported = import_recovery_package(
            args.source,
            _passphrase_from_stdin(),
        )
        print(f"RECOVERY_KEY_FINGERPRINT={fingerprint}")
        print(f"RECOVERY_KEY_IMPORTED={'YES' if imported else 'ALREADY_PRESENT'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
