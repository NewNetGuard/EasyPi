#!/usr/bin/env python3
"""
Decrypt EasyPi Cloud encrypted files.

Format:
  MAGIC "EPEC" (4 bytes) + VERSION (1) + SALT (16) + IV (12) + CIPHERTEXT
Key derivation:
  PBKDF2-HMAC-SHA256, 100000 iterations, 32 bytes
Cipher:
  AES-256-GCM
"""

from __future__ import annotations

import argparse
import getpass
from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

MAGIC = b"EPEC"
VERSION = 1
SALT_LENGTH = 16
IV_LENGTH = 12
HEADER_LENGTH = len(MAGIC) + 1 + SALT_LENGTH + IV_LENGTH
PBKDF2_ITERATIONS = 100000


def _derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def decrypt_file(input_path: Path, output_path: Path, password: str) -> None:
    data = input_path.read_bytes()
    if len(data) < HEADER_LENGTH:
        raise ValueError("File is too small to be a valid EasyPi encrypted file")
    if data[: len(MAGIC)] != MAGIC:
        raise ValueError("Missing EPEC magic header")
    version = data[len(MAGIC)]
    if version != VERSION:
        raise ValueError(f"Unsupported encryption version: {version}")

    salt_start = len(MAGIC) + 1
    salt_end = salt_start + SALT_LENGTH
    iv_end = salt_end + IV_LENGTH

    salt = data[salt_start:salt_end]
    iv = data[salt_end:iv_end]
    ciphertext = data[iv_end:]

    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(iv, ciphertext, None)

    output_path.write_bytes(plaintext)


def _default_output_path(input_path: Path) -> Path:
    if input_path.name.endswith(".encrypted"):
        return input_path.with_name(input_path.name[:-10])
    return input_path.with_name(f"{input_path.name}.decrypted")


def main() -> int:
    parser = argparse.ArgumentParser(description="Decrypt EasyPi Cloud encrypted files")
    parser.add_argument("input", help="Path to .encrypted file")
    parser.add_argument(
        "-o",
        "--output",
        help="Output file path (default: remove .encrypted or add .decrypted)",
    )
    parser.add_argument("-p", "--password", help="Password (if omitted, prompt)")
    args = parser.parse_args()

    input_path = Path(args.input).expanduser()
    if not input_path.exists():
        raise SystemExit(f"Input file not found: {input_path}")

    output_path = Path(args.output).expanduser() if args.output else _default_output_path(input_path)
    password = args.password or getpass.getpass("Password: ")

    decrypt_file(input_path, output_path, password)
    print(f"Decrypted file written to: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
