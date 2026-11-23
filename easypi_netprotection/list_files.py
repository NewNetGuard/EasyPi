"""Shared, crash-safe access to the user's list files.

The backend (edits from the UI) and the DNS engine (hit counters) both
rewrite the files in data/netprotection: allowlist.txt, user_blocklist.txt and
their *_meta.json. Both services run as the same user. Each holds
LOCK_FILE_NAME while it reads, changes and writes one of these files, and every
write replaces the file in one step. Neither process can then read a
half-written file or overwrite a change the other has just made.
"""

from __future__ import annotations

import os
import stat
import tempfile
import threading
from contextlib import contextmanager, suppress
from pathlib import Path
from typing import Iterator

try:
    import fcntl
except ImportError:  # Windows development machines: in-process lock only.
    fcntl = None  # type: ignore[assignment]

LOCK_FILE_NAME = ".lists.lock"

_THREAD_LOCK = threading.RLock()


@contextmanager
def lists_lock(data_dir: Path | str) -> Iterator[None]:
    """Hold the list-files lock shared by the backend and the engine."""
    with _THREAD_LOCK:
        if fcntl is None:
            yield
            return
        flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(Path(data_dir) / LOCK_FILE_NAME, flags, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)  # closing the descriptor releases the lock


def write_text_atomic(path: Path | str, text: str, *, durable: bool = True) -> None:
    """Replace a file in one step, keeping its permissions.

    The content is written to a temporary file in the same directory and
    renamed over the target, so a reader always sees either the old or the new
    file. With durable=True the data is also flushed to disk first, so a power
    loss never leaves the file empty or cut short. Hit counters, written on the
    DNS path, pass durable=False: losing the last few counts is harmless,
    stalling DNS answers on a slow SD card is not.
    """
    path = Path(path)
    mode = None
    with suppress(FileNotFoundError):
        mode = stat.S_IMODE(path.stat().st_mode)
    fd, temporary = tempfile.mkstemp(
        prefix=f".{path.name}.", suffix=".tmp", dir=path.parent
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(text)
            if durable:
                handle.flush()
                os.fsync(handle.fileno())
        if mode is not None:
            os.chmod(temporary, mode)
        os.replace(temporary, path)
    except BaseException:
        with suppress(FileNotFoundError):
            os.unlink(temporary)
        raise
