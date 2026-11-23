"""
Newly-Registered Domain (NRD) filter.

Loads a downloaded NRD feed (domains registered within the configured age window)
into a frozenset and answers ``is_nrd(domain)`` in O(1). Blocking freshly-registered
domains catches phishing/scam before it reaches conventional blocklists.

The feed file (``nrd_domains.txt`` in the NetProtection data dir) is refreshed by
``scripts/settings/update_nrd_list.sh``. If the file is missing/empty this filter
matches nothing, so the feature is always fail-open until a feed is present.
"""

from __future__ import annotations

import logging
import threading
from pathlib import Path

from ..config import get_settings

logger = logging.getLogger(__name__)

NRD_FILE = "nrd_domains.txt"


class NRDFilter:
    def __init__(self, data_dir: str | Path | None = None) -> None:
        if data_dir is None:
            data_dir = get_settings().NETPROTECTION_DATA_DIR
        self._path = Path(data_dir) / NRD_FILE
        self._domains: frozenset[str] = frozenset()
        self._mtime: float | None = None
        self._lock = threading.Lock()

    def _ensure_loaded(self) -> None:
        try:
            mtime = self._path.stat().st_mtime
        except OSError:
            if self._domains:
                with self._lock:
                    self._domains = frozenset()
                    self._mtime = None
            return
        if self._mtime == mtime:
            return
        with self._lock:
            if self._mtime == mtime:
                return
            domains: set[str] = set()
            try:
                with open(self._path, "r", encoding="utf-8", errors="ignore") as fh:
                    for raw in fh:
                        line = raw.strip().lower()
                        if not line or line[0] in "#!":
                            continue
                        dom = line.split()[-1].strip().rstrip(".")
                        if dom and "." in dom:
                            domains.add(dom)
            except OSError:
                pass
            self._domains = frozenset(domains)
            self._mtime = mtime
            logger.info(f"NRD feed loaded: {len(self._domains)} domains")

    @property
    def size(self) -> int:
        self._ensure_loaded()
        return len(self._domains)

    def is_nrd(self, domain: str) -> bool:
        """True if the domain (or its registrable base) is in the NRD feed."""
        self._ensure_loaded()
        if not self._domains:
            return False
        d = (domain or "").lower().strip().rstrip(".")
        if not d:
            return False
        if d in self._domains:
            return True
        labels = d.split(".")
        # Match the registrable base and one level up (covers www./login. subdomains).
        for n in (2, 3):
            if len(labels) >= n:
                candidate = ".".join(labels[-n:])
                if candidate in self._domains:
                    return True
        return False


_instance: NRDFilter | None = None
_ilock = threading.Lock()


def get_nrd_filter(data_dir: str | Path | None = None) -> NRDFilter:
    global _instance
    if _instance is None:
        with _ilock:
            if _instance is None:
                _instance = NRDFilter(data_dir)
    return _instance
