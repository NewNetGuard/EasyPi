#!/usr/bin/python3
from __future__ import annotations

import os
import re
import stat
import sys
import tarfile
from pathlib import Path, PurePosixPath

BACKUP_DIR = Path("/opt/EasyPi/backups")
NAME_RE = re.compile(
    r"^(?:config|full|pre-restore)-[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{2}-[0-9]{2}(?:-[0-9]{2})?\.tar\.gz$"
)
STAGED_NAME_RE = re.compile(r"^\.restore\.[A-Za-z0-9]{6}\.tar\.gz$")
MAX_MEMBERS = 200_000
MAX_TOTAL_SIZE = 20 * 1024 * 1024 * 1024
POSTGRES_DUMP_MEMBER = "opt/EasyPi/data/db/easypi-postgresql.dump"

ALLOWED_FILES = {
    "etc/hostname",
    "etc/hosts",
    "opt/EasyPi/.env",
    "var/lib/easypi/stealth-policy",
    "var/lib/easypi/stealth-policy/dns-policy.json",
}
ALLOWED_PREFIXES = ("opt/EasyPi/config/", "opt/EasyPi/data/")

# Earlier releases included these executable/security-sensitive host files.
# Recognize only their exact names for compatibility, but NEVER restore them.
# Units, SSH policy, kernel parameters and the nginx/unbound configuration are
# all interpreted by root: a kernel parameter can name a root-run helper and a
# web-server configuration can create root-owned files. They are maintained by
# the trusted installer/updater and the validating settings scripts only.
SKIPPED_LEGACY_FILES = frozenset({
    "etc/sysctl.conf",
    "etc/sysctl.d/99-easypi-gateway.conf",
    "etc/sysctl.d/99-easypi-forwarding.conf",
    "etc/sysctl.d/99-easypi-ip-forward.conf",
    "etc/sysctl.d/99-easypi-netprotection.conf",
    "etc/sysctl.d/99-easypi-tailscale-exit-node.conf",
    "etc/nginx/sites-available/easypi",
    "etc/unbound/unbound.conf.d/easypi.conf",
    "etc/unbound/unbound.conf.d/easypi-recursive.conf",
    "etc/ssh/sshd_config",
    "etc/ssh/sshd_config.d/easypi-hardening.conf",
    "etc/systemd/system/easypi-backend.service",
    "etc/systemd/system/easypi-netprotection.service",
    "etc/systemd/system/easypi-stealth-guard.service",
    "etc/systemd/system/easypi-stealth-dns.service",
    "etc/systemd/system/easypi-stealth-resume.service",
    "etc/systemd/system/easypi-gateway-fix.service",
    "etc/systemd/system/easypi-gateway-fix.timer",
})


def fail(message: str) -> None:
    raise SystemExit(f"ERROR: {message}")


def validate_archive(path_text: str) -> Path:
    path = Path(path_text)
    try:
        parent = path.parent.resolve(strict=True)
        details = path.lstat()
    except OSError as exc:
        fail(f"cannot inspect backup: {exc}")
    generated_name = NAME_RE.fullmatch(path.name) is not None
    staged_name = STAGED_NAME_RE.fullmatch(path.name) is not None
    if parent != BACKUP_DIR or not (generated_name or staged_name):
        fail("backup must be a generated archive directly under /opt/EasyPi/backups")
    if not stat.S_ISREG(details.st_mode) or details.st_uid != 0:
        fail("backup must be a root-owned regular file")
    if details.st_mode & 0o022:
        fail("backup must not be writable by group or others")
    if staged_name and details.st_mode & 0o077:
        fail("decrypted restore staging archive must be private to root")
    return path


def validate_member(
    member: tarfile.TarInfo, *, allow_legacy_skip: bool = False
) -> PurePosixPath | None:
    raw = member.name
    while raw.startswith("./"):
        raw = raw[2:]
    rel = PurePosixPath(raw)
    if (
        not raw
        or member.name.startswith("/")
        or ".." in rel.parts
        or member.issym()
        or member.islnk()
        or member.isdev()
        or not (member.isdir() or member.isfile())
    ):
        fail(f"unsafe archive member: {member.name}")
    normalized = rel.as_posix().rstrip("/")
    if allow_legacy_skip and normalized in SKIPPED_LEGACY_FILES and member.isfile():
        return None
    allowed = normalized in ALLOWED_FILES or any(
        normalized == prefix.rstrip("/") or normalized.startswith(prefix)
        for prefix in ALLOWED_PREFIXES
    )
    if not allowed:
        fail(f"archive member is outside the restore allowlist: {member.name}")
    return rel


def open_parent(root_fd: int, parts: tuple[str, ...]) -> int:
    current_fd = os.dup(root_fd)
    try:
        for part in parts:
            try:
                next_fd = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=current_fd,
                )
            except FileNotFoundError:
                os.mkdir(part, 0o750, dir_fd=current_fd)
                next_fd = os.open(
                    part,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=current_fd,
                )
            os.close(current_fd)
            current_fd = next_fd
        return current_fd
    except Exception:
        os.close(current_fd)
        raise


def owner_for(rel: PurePosixPath) -> tuple[int, int]:
    path = rel.as_posix()
    if path == POSTGRES_DUMP_MEMBER:
        return 0, 0

    # POSIX account modules are imported only for the write phase so the pure
    # archive validator remains testable on release workstations as well.
    import grp
    import pwd

    easypi_gid = grp.getgrnam("easypi").gr_gid
    if path == "opt/EasyPi/.env":
        return 0, easypi_gid
    if path == "var/lib/easypi/stealth-policy" or path.startswith(
        "var/lib/easypi/stealth-policy/"
    ):
        return 0, easypi_gid
    if path.startswith(("opt/EasyPi/config/", "opt/EasyPi/data/")) or path in {
        "opt/EasyPi/config",
        "opt/EasyPi/data",
    }:
        return pwd.getpwnam("easypi").pw_uid, easypi_gid
    return 0, 0


def mode_for(rel: PurePosixPath, is_dir: bool) -> int:
    path = rel.as_posix()
    if is_dir:
        return 0o750
    if path == POSTGRES_DUMP_MEMBER:
        return 0o600
    if path == "var/lib/easypi/stealth-policy" or path.startswith(
        "var/lib/easypi/stealth-policy/"
    ):
        return 0o750 if is_dir else 0o640
    if path == "opt/EasyPi/.env" or path.startswith(
        ("opt/EasyPi/config/", "opt/EasyPi/data/")
    ):
        return 0o640
    return 0o644


def validate_archive_contents(path: Path) -> None:
    """Prove the complete archive is safe and readable before any writes."""

    total_size = 0
    member_count = 0
    restorable_files = 0
    names: set[str] = set()
    try:
        with tarfile.open(path, "r:gz") as archive:
            for member in archive:
                member_count += 1
                if member_count > MAX_MEMBERS:
                    fail("archive has too many members")
                rel = validate_member(member, allow_legacy_skip=True)
                normalized = PurePosixPath(member.name).as_posix().rstrip("/")
                if rel is None:
                    print(f"WARNING: preserving installed host configuration; skipping {normalized}", file=sys.stderr)
                elif member.isfile():
                    restorable_files += 1
                if normalized in names:
                    fail(f"archive contains a duplicate member: {member.name}")
                names.add(normalized)
                total_size += max(0, member.size)
                if total_size > MAX_TOTAL_SIZE:
                    fail("archive expands beyond the restore size limit")
                if not member.isfile():
                    continue
                source = archive.extractfile(member)
                if source is None:
                    fail(f"cannot read archive member: {member.name}")
                with source:
                    while source.read(1024 * 1024):
                        pass
    except (OSError, EOFError, tarfile.TarError) as exc:
        fail(f"backup archive is unreadable: {exc}")

    if member_count == 0:
        fail("backup archive is empty")
    if restorable_files == 0:
        fail("backup contains no restorable files")
    policy_file = "var/lib/easypi/stealth-policy/dns-policy.json"
    policy_dir = "var/lib/easypi/stealth-policy"
    if policy_file in names and policy_dir not in names:
        fail("backup contains a Chameleon policy without its protected directory")


def restore(path: Path) -> None:
    # Validation is a separate full pass by design. A truncated/corrupt payload
    # or disallowed late member must be discovered before the first target file
    # is opened or truncated.
    validate_archive_contents(path)
    with tarfile.open(path, "r:gz") as archive:
        root_fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
        try:
            for member in archive:
                rel = validate_member(member, allow_legacy_skip=True)
                if rel is None:
                    continue
                uid, gid = owner_for(rel)
                if member.isdir():
                    parent_fd = open_parent(root_fd, tuple(rel.parts[:-1]))
                    try:
                        try:
                            os.mkdir(rel.name, 0o750, dir_fd=parent_fd)
                        except FileExistsError:
                            pass
                        dir_fd = os.open(
                            rel.name,
                            os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                            dir_fd=parent_fd,
                        )
                        try:
                            os.fchmod(dir_fd, mode_for(rel, True))
                            os.fchown(dir_fd, uid, gid)
                        finally:
                            os.close(dir_fd)
                    finally:
                        os.close(parent_fd)
                    continue

                source = archive.extractfile(member)
                if source is None:
                    fail(f"cannot read archive member: {member.name}")
                parent_fd = open_parent(root_fd, tuple(rel.parts[:-1]))
                try:
                    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW
                    file_fd = os.open(rel.name, flags, 0o600, dir_fd=parent_fd)
                    try:
                        with os.fdopen(file_fd, "wb", closefd=False) as target:
                            while True:
                                chunk = source.read(1024 * 1024)
                                if not chunk:
                                    break
                                target.write(chunk)
                            target.flush()
                            os.fsync(target.fileno())
                        os.fchmod(file_fd, mode_for(rel, False))
                        os.fchown(file_fd, uid, gid)
                    finally:
                        os.close(file_fd)
                        source.close()
                finally:
                    os.close(parent_fd)
        finally:
            os.close(root_fd)


def main() -> None:
    validate_only = len(sys.argv) == 3 and sys.argv[1] == "--validate-only"
    if not validate_only and len(sys.argv) != 2:
        fail("usage: secure_restore.py [--validate-only] <backup_file>")
    path = validate_archive(sys.argv[-1])
    if validate_only:
        validate_archive_contents(path)
        print("RESTORE_ARCHIVE=VALID")
        return
    restore(path)


if __name__ == "__main__":
    main()
