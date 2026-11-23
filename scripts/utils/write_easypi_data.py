#!/usr/bin/env python3
"""Atomically publish generated data after permanently dropping root privileges."""

from __future__ import annotations

import os
import pwd
import secrets
import stat
import sys
from pathlib import Path

MAX_SOURCE_SIZE = 512 * 1024 * 1024


def fail(message: str) -> None:
    print(f"write_easypi_data: {message}", file=sys.stderr)
    raise SystemExit(1)


def main() -> None:
    if len(sys.argv) != 3:
        fail("usage: write_easypi_data.py <source> <destination>")

    source = Path(sys.argv[1])
    destination = Path(sys.argv[2])
    if not source.is_absolute() or not destination.is_absolute() or not destination.name:
        fail("source and destination must be absolute file paths")

    flags = os.O_RDONLY | getattr(os, "O_CLOEXEC", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        source_fd = os.open(source, flags)
    except OSError as exc:
        fail(f"cannot open source: {exc}")

    try:
        source_stat = os.fstat(source_fd)
        if not stat.S_ISREG(source_stat.st_mode):
            fail("source is not a regular file")
        if source_stat.st_size > MAX_SOURCE_SIZE:
            fail("source exceeds the size limit")

        account = pwd.getpwnam("easypi")
        if os.geteuid() == 0:
            os.setgroups([])
            os.setgid(account.pw_gid)
            os.setuid(account.pw_uid)
        if os.geteuid() != account.pw_uid or os.getegid() != account.pw_gid:
            fail("failed to drop privileges to easypi")

        dir_flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
        directory_fd = os.open(destination.parent, dir_flags)
        temp_name = f".{destination.name}.{secrets.token_hex(12)}.tmp"
        temp_fd = -1
        try:
            temp_flags = (
                os.O_WRONLY
                | os.O_CREAT
                | os.O_EXCL
                | getattr(os, "O_CLOEXEC", 0)
                | getattr(os, "O_NOFOLLOW", 0)
            )
            temp_fd = os.open(temp_name, temp_flags, 0o644, dir_fd=directory_fd)
            while True:
                chunk = os.read(source_fd, 1024 * 1024)
                if not chunk:
                    break
                view = memoryview(chunk)
                while view:
                    written = os.write(temp_fd, view)
                    view = view[written:]
            os.fchmod(temp_fd, 0o644)
            os.fsync(temp_fd)
            os.close(temp_fd)
            temp_fd = -1
            os.replace(
                temp_name,
                destination.name,
                src_dir_fd=directory_fd,
                dst_dir_fd=directory_fd,
            )
            os.fsync(directory_fd)
        finally:
            if temp_fd >= 0:
                os.close(temp_fd)
            try:
                os.unlink(temp_name, dir_fd=directory_fd)
            except FileNotFoundError:
                pass
            os.close(directory_fd)
    finally:
        os.close(source_fd)


if __name__ == "__main__":
    main()
