#!/usr/bin/env python3
"""Fetch the IEEE OUI (MAC-vendor) database for the EasyPi network scanner.

Best-effort by design. Downloads the public IEEE OUI registry, converts it to the
compact ``AABBCC<TAB>Vendor`` gzip format the scanner loads (native_scanner.OUIDatabase),
and writes it atomically to argv[1] (default ``/opt/EasyPi/data/network/oui.txt.gz``).

This must NEVER hard-break an install/update:
  * if a fresh file already exists, it is kept (no download);
  * if the download or parse fails but an old file exists, the old one is kept;
  * only when there is no data AND no existing file does it exit non-zero — and the
    caller (install.sh) treats that as a warning, because the scanner falls back to its
    built-in vendor list anyway.
"""
from __future__ import annotations

import gzip
import os
import re
import sys
import tempfile
import time
import urllib.request

DEFAULT_DEST = "/opt/EasyPi/data/network/oui.txt.gz"
URLS = [
    "https://standards-oui.ieee.org/oui/oui.txt",
    "http://standards-oui.ieee.org/oui/oui.txt",
]
MIN_ENTRIES = 10000        # a valid IEEE dump has ~40k; anything less is a bad fetch
FRESH_SECONDS = 30 * 86400  # skip the download if the local copy is younger than this
_LINE = re.compile(r"^\s*([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})-([0-9A-Fa-f]{2})\s+\(hex\)\s+(.+?)\s*$")


def _existing_ok(dest: str) -> bool:
    try:
        return os.path.getsize(dest) > 50_000
    except OSError:
        return False


def _fetch() -> str | None:
    for url in URLS:
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "EasyPi-OUI/1"})
            with urllib.request.urlopen(req, timeout=45) as resp:
                return resp.read().decode("utf-8", "ignore")
        except Exception as exc:  # noqa: BLE001 - best effort, any failure is tolerable
            sys.stderr.write(f"oui: fetch failed for {url}: {exc}\n")
    return None


def main() -> int:
    dest = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_DEST

    # Already have a recent copy — nothing to do.
    try:
        if _existing_ok(dest) and (time.time() - os.path.getmtime(dest)) < FRESH_SECONDS:
            print(f"oui: up-to-date, keeping {dest}")
            return 0
    except OSError:
        pass

    raw = _fetch()
    if not raw:
        if _existing_ok(dest):
            print("oui: download failed — keeping existing database")
            return 0
        sys.stderr.write("oui: no data and no existing database (scanner uses built-in list)\n")
        return 1

    vendors: dict[str, str] = {}
    for line in raw.splitlines():
        m = _LINE.match(line)
        if m:
            vendors[(m.group(1) + m.group(2) + m.group(3)).upper()] = m.group(4).strip()

    if len(vendors) < MIN_ENTRIES:
        sys.stderr.write(f"oui: parsed only {len(vendors)} entries — treating as bad fetch\n")
        return 0 if _existing_ok(dest) else 1

    body = "".join(f"{oui}\t{vendors[oui]}\n" for oui in sorted(vendors))
    dest_dir = os.path.dirname(dest) or "."
    try:
        os.makedirs(dest_dir, exist_ok=True)
    except OSError as exc:
        sys.stderr.write(f"oui: cannot create {dest_dir}: {exc}\n")
        return 1

    fd, tmp = tempfile.mkstemp(prefix=".oui.", dir=dest_dir)
    os.close(fd)
    try:
        with gzip.open(tmp, "wt", encoding="utf-8") as fh:
            fh.write(body)
        os.replace(tmp, dest)
        try:
            os.chmod(dest, 0o644)
        except OSError:
            pass
        print(f"oui: wrote {len(vendors)} vendors -> {dest}")
        return 0
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"oui: write failed: {exc}\n")
        return 0 if _existing_ok(dest) else 1
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as exc:  # noqa: BLE001 - never propagate; install must survive
        sys.stderr.write(f"oui: unexpected error: {exc}\n")
        sys.exit(1)
