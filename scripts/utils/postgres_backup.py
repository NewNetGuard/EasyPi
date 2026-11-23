#!/usr/bin/env python3
"""Create and restore private PostgreSQL dumps for EasyPi backups."""

from __future__ import annotations

import argparse
import os
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path, PurePosixPath
from urllib.parse import parse_qsl, unquote, urlsplit

ENV_FILE = Path("/opt/EasyPi/.env")
POSTGRES_DUMP_MEMBER = "opt/EasyPi/data/db/easypi-postgresql.dump"
TRUSTED_SEARCH_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
MAX_ENV_BYTES = 1024 * 1024
ENV_REFERENCE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
POSTGRES_QUERY_ENV = {
    "application_name": "PGAPPNAME",
    "connect_timeout": "PGCONNECT_TIMEOUT",
    "gssencmode": "PGGSSENCMODE",
    "krbsrvname": "PGKRBSRVNAME",
    "options": "PGOPTIONS",
    "sslcert": "PGSSLCERT",
    "sslcrl": "PGSSLCRL",
    "sslkey": "PGSSLKEY",
    "sslmode": "PGSSLMODE",
    "sslrootcert": "PGSSLROOTCERT",
    "target_session_attrs": "PGTARGETSESSIONATTRS",
}
POSTGRES_ENV_KEYS = {
    "PGAPPNAME",
    "PGCONNECT_TIMEOUT",
    "PGDATABASE",
    "PGGSSENCMODE",
    "PGHOST",
    "PGKRBSRVNAME",
    "PGOPTIONS",
    "PGPASSFILE",
    "PGPASSWORD",
    "PGPORT",
    "PGSERVICE",
    "PGSERVICEFILE",
    "PGSSLCERT",
    "PGSSLCRL",
    "PGSSLKEY",
    "PGSSLMODE",
    "PGSSLROOTCERT",
    "PGTARGETSESSIONATTRS",
    "PGUSER",
}


class PostgresBackupError(RuntimeError):
    """A privacy-safe PostgreSQL backup failure."""


def _parse_env_text(text: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if not key.replace("_", "").isalnum():
            continue
        value = value.strip()
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        values[key] = value
    return values


def _database_url_from_values(values: dict[str, str]) -> str:
    value = values.get("DATABASE_URL", "").strip()
    for _ in range(10):
        references = ENV_REFERENCE.findall(value)
        if not references:
            return value
        missing = [name for name in references if name not in values]
        if missing:
            raise PostgresBackupError("DATABASE_URL contains an unresolved variable")
        expanded = ENV_REFERENCE.sub(lambda match: values[match.group(1)], value)
        if expanded == value:
            break
        value = expanded
    if ENV_REFERENCE.search(value):
        raise PostgresBackupError("DATABASE_URL variable expansion is cyclic")
    return value


def load_database_url(env_file: Path = ENV_FILE) -> str:
    # Backups must describe the configuration that is actually included in the
    # archive. Do not let a caller-controlled inherited environment silently
    # select a different database from the root-owned EasyPi .env file.
    try:
        details = env_file.stat(follow_symlinks=False)
        if not stat.S_ISREG(details.st_mode) or env_file.is_symlink():
            raise PostgresBackupError("EasyPi environment file is unsafe")
        if os.name == "posix":
            if details.st_mode & 0o022:
                raise PostgresBackupError("EasyPi environment file permissions are unsafe")
            if os.geteuid() == 0 and details.st_uid != 0:
                raise PostgresBackupError("EasyPi environment file is not root-owned")
        if details.st_size > MAX_ENV_BYTES:
            raise PostgresBackupError("EasyPi environment file is too large")
        text = env_file.read_text(encoding="utf-8")
    except FileNotFoundError:
        return ""
    except (OSError, UnicodeError) as exc:
        raise PostgresBackupError("EasyPi database configuration is unreadable") from exc
    return _database_url_from_values(_parse_env_text(text))


def database_kind(database_url: str) -> str:
    if not database_url:
        return "missing"
    scheme = database_url.split(":", 1)[0].lower().split("+", 1)[0]
    if scheme == "sqlite":
        return "sqlite"
    if scheme in {"postgres", "postgresql"}:
        return "postgresql"
    return "unsupported"


def _postgres_environment(database_url: str) -> tuple[dict[str, str], str]:
    if database_kind(database_url) != "postgresql":
        raise PostgresBackupError("EasyPi is not configured for PostgreSQL")
    _, remainder = database_url.split(":", 1)
    try:
        parsed = urlsplit("postgresql:" + remainder)
        port = parsed.port
    except ValueError as exc:
        raise PostgresBackupError("PostgreSQL connection settings are invalid") from exc
    database = unquote(parsed.path.lstrip("/"))
    if not database or "\x00" in database:
        raise PostgresBackupError("PostgreSQL database name is invalid")

    environment = {key: value for key, value in os.environ.items() if key not in POSTGRES_ENV_KEYS}
    environment["PATH"] = TRUSTED_SEARCH_PATH
    environment["PGDATABASE"] = database
    environment["PGCONNECT_TIMEOUT"] = "15"
    if parsed.hostname:
        environment["PGHOST"] = parsed.hostname
    if port:
        environment["PGPORT"] = str(port)
    if parsed.username:
        environment["PGUSER"] = unquote(parsed.username)
    if parsed.password:
        environment["PGPASSWORD"] = unquote(parsed.password)
    for key, value in parse_qsl(parsed.query, keep_blank_values=False):
        target = POSTGRES_QUERY_ENV.get(key.lower())
        if target:
            environment[target] = value
    return environment, database


def _trusted_program(name: str) -> str:
    candidate = shutil.which(name, path=TRUSTED_SEARCH_PATH)
    if not candidate:
        raise PostgresBackupError(f"required PostgreSQL tool is unavailable: {name}")
    path = Path(candidate)
    try:
        resolved = path.resolve(strict=True)
        entries = {path, resolved}
        entries.update(path.parents)
        entries.update(resolved.parents)
        for entry in entries:
            details = entry.stat()
            if details.st_mode & 0o022:
                raise PostgresBackupError(f"PostgreSQL tool path is writable outside root: {name}")
            if os.geteuid() == 0 and details.st_uid != 0:
                raise PostgresBackupError(f"PostgreSQL tool path is not root-owned: {name}")
        if not stat.S_ISREG(resolved.stat().st_mode):
            raise PostgresBackupError(f"PostgreSQL tool is not a regular file: {name}")
    except OSError as exc:
        raise PostgresBackupError(f"PostgreSQL tool cannot be inspected: {name}") from exc
    return str(path)


def _run_private(command: list[str], environment: dict[str, str], timeout: int) -> None:
    try:
        result = subprocess.run(
            command,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise PostgresBackupError("PostgreSQL backup command could not complete") from exc
    if result.returncode != 0:
        raise PostgresBackupError(
            f"PostgreSQL backup command failed with status {result.returncode}"
        )


def _validate_private_input(path: Path) -> Path:
    try:
        details = path.stat(follow_symlinks=False)
    except OSError as exc:
        raise PostgresBackupError("PostgreSQL dump is unavailable") from exc
    if path.is_symlink() or not stat.S_ISREG(details.st_mode):
        raise PostgresBackupError("PostgreSQL dump is not a regular file")
    if details.st_mode & 0o077:
        raise PostgresBackupError("PostgreSQL dump permissions are unsafe")
    if os.geteuid() == 0 and details.st_uid != 0:
        raise PostgresBackupError("PostgreSQL dump is not root-owned")
    return path


def validate_dump(path: Path) -> None:
    environment = {
        key: value for key, value in os.environ.items() if key not in POSTGRES_ENV_KEYS
    }
    environment["PATH"] = TRUSTED_SEARCH_PATH
    _run_private(
        [_trusted_program("pg_restore"), "--list", str(_validate_private_input(path))],
        environment,
        900,
    )


def dump_database(path: Path, database_url: str) -> None:
    environment, _ = _postgres_environment(database_url)
    parent = path.parent
    parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    if parent.is_symlink() or path.exists() or path.is_symlink():
        raise PostgresBackupError("PostgreSQL dump destination is unsafe")
    descriptor, temporary_name = tempfile.mkstemp(prefix=".postgresql-", dir=parent)
    os.close(descriptor)
    temporary = Path(temporary_name)
    try:
        temporary.unlink()
        _run_private(
            [
                _trusted_program("pg_dump"),
                "--format=custom",
                "--no-owner",
                "--no-privileges",
                "--file",
                str(temporary),
            ],
            environment,
            3600,
        )
        os.chmod(temporary, 0o600)
        validate_dump(temporary)
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def restore_database(path: Path, database_url: str) -> None:
    path = _validate_private_input(path)
    validate_dump(path)
    environment, database = _postgres_environment(database_url)
    _run_private(
        [
            _trusted_program("pg_restore"),
            "--clean",
            "--if-exists",
            "--no-owner",
            "--no-privileges",
            "--single-transaction",
            "--exit-on-error",
            "--dbname",
            database,
            str(path),
        ],
        environment,
        3600,
    )


def archive_info(path: Path) -> tuple[str, bool]:
    env_members: list[tarfile.TarInfo] = []
    dump_members: list[tarfile.TarInfo] = []
    try:
        with tarfile.open(path, "r:gz") as archive:
            for member in archive:
                raw = member.name
                while raw.startswith("./"):
                    raw = raw[2:]
                normalized = PurePosixPath(raw).as_posix()
                if normalized == "opt/EasyPi/.env":
                    env_members.append(member)
                elif normalized == POSTGRES_DUMP_MEMBER:
                    dump_members.append(member)
            if len(env_members) > 1 or len(dump_members) > 1:
                raise PostgresBackupError("backup contains duplicate database metadata")
            kind = "missing"
            if env_members:
                member = env_members[0]
                if not member.isfile() or member.size > MAX_ENV_BYTES:
                    raise PostgresBackupError("backup database configuration is unsafe")
                source = archive.extractfile(member)
                if source is None:
                    raise PostgresBackupError("backup database configuration is unreadable")
                with source:
                    text = source.read(MAX_ENV_BYTES + 1).decode("utf-8")
                kind = database_kind(_database_url_from_values(_parse_env_text(text)))
            if dump_members:
                dump_member = dump_members[0]
                if not dump_member.isfile() or dump_member.size <= 0:
                    raise PostgresBackupError("backup PostgreSQL dump is invalid")
                source = archive.extractfile(dump_member)
                if source is None:
                    raise PostgresBackupError("backup PostgreSQL dump is unreadable")
                descriptor, temporary_name = tempfile.mkstemp(
                    prefix=".postgres-check.", dir=path.parent
                )
                temporary = Path(temporary_name)
                try:
                    with os.fdopen(descriptor, "wb") as target, source:
                        shutil.copyfileobj(source, target, length=1024 * 1024)
                        target.flush()
                        os.fsync(target.fileno())
                    os.chmod(temporary, 0o600)
                    validate_dump(temporary)
                finally:
                    temporary.unlink(missing_ok=True)
            return kind, bool(dump_members)
    except (OSError, EOFError, UnicodeError, tarfile.TarError) as exc:
        raise PostgresBackupError("backup database metadata is unreadable") from exc


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("kind", "dump", "restore", "validate", "archive-info"))
    parser.add_argument("path", nargs="?", type=Path)
    args = parser.parse_args()
    try:
        if args.action == "archive-info":
            if args.path is None:
                raise PostgresBackupError("archive path is required")
            kind, has_dump = archive_info(args.path)
            print(f"{kind} {'yes' if has_dump else 'no'}")
            return 0

        if args.action == "validate":
            if args.path is None:
                raise PostgresBackupError("dump path is required")
            validate_dump(args.path)
            return 0

        database_url = load_database_url()
        if args.action == "kind":
            print(database_kind(database_url))
        elif args.path is None:
            raise PostgresBackupError("dump path is required")
        elif args.action == "dump":
            dump_database(args.path, database_url)
        elif args.action == "restore":
            restore_database(args.path, database_url)
        else:
            raise PostgresBackupError("unsupported PostgreSQL backup action")
    except PostgresBackupError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
