#!/usr/bin/env python3
"""Destructive-to-test-data-only PostgreSQL backup/rollback integration check."""

from __future__ import annotations

import argparse
import importlib.util
import io
import os
import re
import subprocess
import sys
import tarfile
from pathlib import Path


def _load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"cannot load {name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


def _run(command: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=120,
        check=check,
    )


def _psql(pg, database_url: str, sql: str) -> str:
    environment, _ = pg._postgres_environment(database_url)
    result = subprocess.run(
        [
            pg._trusted_program("psql"),
            "--no-psqlrc",
            "--tuples-only",
            "--no-align",
            "--set",
            "ON_ERROR_STOP=1",
            "--command",
            sql,
        ],
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=120,
        check=True,
    )
    return result.stdout.strip()


def _set_value(pg, database_url: str, value: str) -> None:
    if not re.fullmatch(r"[a-z-]+", value):
        raise ValueError("unsafe test value")
    _psql(
        pg,
        database_url,
        "CREATE TABLE IF NOT EXISTS easypi_backup_e2e(value text NOT NULL);"
        "TRUNCATE easypi_backup_e2e;"
        f"INSERT INTO easypi_backup_e2e(value) VALUES ('{value}');",
    )


def _get_value(pg, database_url: str) -> str:
    return _psql(pg, database_url, "SELECT value FROM easypi_backup_e2e;")


def _add_bytes(archive: tarfile.TarFile, name: str, payload: bytes) -> None:
    member = tarfile.TarInfo(name)
    member.size = len(payload)
    member.mode = 0o600
    member.uid = 0
    member.gid = 0
    archive.addfile(member, io.BytesIO(payload))


def _write_epibak(pg, crypto, database_url: str, work: Path) -> tuple[Path, bytes]:
    dump = work / "baseline.dump"
    pg.dump_database(dump, database_url)
    plain = work / "baseline.tar.gz"
    with tarfile.open(plain, "w:gz") as archive:
        _add_bytes(archive, "opt/EasyPi/.env", f"DATABASE_URL={database_url}\n".encode())
        archive.add(dump, arcname=pg.POSTGRES_DUMP_MEMBER, recursive=False)
    plain.chmod(0o600)
    key = os.urandom(32)
    encrypted = work / "config-e2e.epibak"
    crypto.encrypt_file(plain, encrypted, key)
    encrypted.chmod(0o600)
    return encrypted, key


def _extract_verified_dump(pg, crypto, encrypted: Path, key: bytes, work: Path) -> Path:
    restored_archive = work / "restored.tar.gz"
    crypto.decrypt_file(encrypted, restored_archive, key)
    restored_archive.chmod(0o600)
    assert pg.archive_info(restored_archive) == ("postgresql", True)
    extracted = work / "restored.dump"
    with tarfile.open(restored_archive, "r:gz") as archive:
        member = archive.getmember(pg.POSTGRES_DUMP_MEMBER)
        source = archive.extractfile(member)
        if source is None:
            raise RuntimeError("verified dump could not be read")
        with source, extracted.open("xb") as target:
            while chunk := source.read(1024 * 1024):
                target.write(chunk)
    extracted.chmod(0o600)
    pg.validate_dump(extracted)
    return extracted


def _install_health_unit(
    *, python: Path, script: Path, env_file: Path, expected_file: Path, unit: str
) -> Path:
    if not re.fullmatch(r"easypi-pg-e2e-[a-z0-9]+\.service", unit):
        raise ValueError("unsafe test unit name")
    unit_path = Path("/run/systemd/system") / unit
    unit_path.write_text(
        "[Unit]\nDescription=EasyPi PostgreSQL backup E2E health probe\n"
        "[Service]\nType=oneshot\nRemainAfterExit=yes\n"
        f"ExecStart={python} {script} --health --env-file {env_file} "
        f"--expected-file {expected_file}\n",
        encoding="utf-8",
    )
    unit_path.chmod(0o644)
    _run(["systemctl", "daemon-reload"])
    return unit_path


def _start_health(unit: str, expected_file: Path, value: str) -> bool:
    expected_file.write_text(value + "\n", encoding="utf-8")
    expected_file.chmod(0o600)
    _run(["systemctl", "stop", unit], check=False)
    result = _run(["systemctl", "start", unit], check=False)
    return result.returncode == 0


def _health(args: argparse.Namespace) -> int:
    root = Path(__file__).resolve().parent
    pg = _load("postgres_backup", root / "postgres_backup.py")
    database_url = pg.load_database_url(args.env_file)
    expected = args.expected_file.read_text(encoding="utf-8").strip()
    return 0 if _get_value(pg, database_url) == expected else 1


def _cycle(args: argparse.Namespace) -> int:
    if os.geteuid() != 0:
        raise RuntimeError("integration cycle must run as root")
    work = args.work_dir.resolve(strict=True)
    if work.parent != Path("/var/tmp") or not work.name.startswith("easypi-pg-e2e."):
        raise RuntimeError("unsafe integration work directory")
    root = Path(__file__).resolve().parent
    pg = _load("postgres_backup", root / "postgres_backup.py")
    crypto = _load("backup_crypto", root / "backup_crypto.py")
    database_url = pg.load_database_url(args.env_file)
    expected_file = work / "expected"
    unit_path = _install_health_unit(
        python=Path(sys.executable).resolve(),
        script=Path(__file__).resolve(),
        env_file=args.env_file.resolve(),
        expected_file=expected_file,
        unit=args.unit,
    )
    try:
        _set_value(pg, database_url, "baseline")
        encrypted, key = _write_epibak(pg, crypto, database_url, work)
        restored_dump = _extract_verified_dump(pg, crypto, encrypted, key, work)
        print("STEP 1-2 database + encrypted epibak: OK")

        _set_value(pg, database_url, "mutated")
        pg.restore_database(restored_dump, database_url)
        if _get_value(pg, database_url) != "baseline":
            raise RuntimeError("normal restore did not recover baseline data")
        if not _start_health(args.unit, expected_file, "baseline"):
            raise RuntimeError("health service rejected a valid restore")
        print("STEP 3-4 mutation + restore + service health: OK")

        _set_value(pg, database_url, "pre-failure")
        safety_dump = work / "pre-failure.dump"
        pg.dump_database(safety_dump, database_url)
        pg.restore_database(restored_dump, database_url)
        if _start_health(args.unit, expected_file, "intentionally-wrong"):
            raise RuntimeError("artificial health failure did not fail")
        pg.restore_database(safety_dump, database_url)
        if not _start_health(args.unit, expected_file, "pre-failure"):
            raise RuntimeError("automatic rollback health check failed")
        if _get_value(pg, database_url) != "pre-failure":
            raise RuntimeError("automatic rollback did not recover pre-failure data")
        print("STEP 5 artificial failure + automatic rollback: OK")

        corrupt = work / "corrupt.dump"
        corrupt.write_bytes(restored_dump.read_bytes()[:32])
        corrupt.chmod(0o600)
        try:
            pg.validate_dump(corrupt)
        except pg.PostgresBackupError:
            pass
        else:
            raise RuntimeError("corrupt dump was accepted")
        if _get_value(pg, database_url) != "pre-failure":
            raise RuntimeError("corrupt dump changed database state")
        print("CORRUPT dump rejection + unchanged data: OK")
        print("POSTGRESQL_BACKUP_E2E=PASS")
        return 0
    finally:
        _run(["systemctl", "stop", args.unit], check=False)
        unit_path.unlink(missing_ok=True)
        _run(["systemctl", "daemon-reload"], check=False)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--health", action="store_true")
    parser.add_argument("--env-file", type=Path, required=True)
    parser.add_argument("--expected-file", type=Path)
    parser.add_argument("--work-dir", type=Path)
    parser.add_argument("--unit")
    args = parser.parse_args()
    if args.health:
        if args.expected_file is None:
            parser.error("--health requires --expected-file")
        return _health(args)
    if args.work_dir is None or args.unit is None:
        parser.error("cycle mode requires --work-dir and --unit")
    return _cycle(args)


if __name__ == "__main__":
    raise SystemExit(main())
