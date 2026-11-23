"""Opt-in read-only Linux filter observer; never changes rules or service state."""

import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import time


def snapshot():
    rules = subprocess.check_output(["iptables-save"], text=True, timeout=3)
    rules = "\n".join(
        re.sub(r"\[\d+:\d+\]", "[counter]", line)
        for line in rules.splitlines()
        if not line.startswith("#")
    )
    text = subprocess.check_output(["ipset", "list", "-terse"], text=True, timeout=3)
    sets = {}
    name = None
    for line in text.splitlines():
        if line.startswith("Name: "):
            name = line[6:]
            sets[name] = []
        elif name and line.startswith(("Type:", "Revision:", "Header:")):
            sets[name].append(line)
    config = dict(firewall=rules, ipset_headers=sets)
    encoded = json.dumps(config, sort_keys=True).encode()
    return hashlib.sha256(encoded).hexdigest(), config


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--seconds", type=int, default=21600)
    args = parser.parse_args()
    if os.geteuid() != 0 or not 1 <= args.seconds <= 21600:
        parser.error("bounded root read-only observer required")
    parent = args.output.parent.resolve()
    if parent.parent != Path("/tmp") or not parent.name.startswith("prism-"):
        parser.error("private experiment directory required")
    if parent.stat().st_mode & 0o077:
        parser.error("experiment directory must be owner-private")
    fd = os.open(
        args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
    )
    samples = records = size = 0
    previous = None
    deadline = time.monotonic() + args.seconds
    with os.fdopen(fd, "w", encoding="utf-8") as output:
        while time.monotonic() < deadline and records < 128 and size < 2 * 1024 * 1024:
            samples += 1
            try:
                digest, config = snapshot()
                if digest != previous:
                    event = dict(
                        type="filter_snapshot",
                        observed_utc=datetime.datetime.now(
                            datetime.timezone.utc
                        ).isoformat(),
                        sha256=digest,
                        config=config,
                    )
                    line = json.dumps(event, sort_keys=True) + "\n"
                    output.write(line)
                    output.flush()
                    size += len(line.encode())
                    records += 1
                    previous = digest
            except (OSError, subprocess.SubprocessError):
                # No raw command output or configuration is emitted to journal.
                pass
            time.sleep(1)
    print(
        json.dumps(dict(samples=samples, snapshots=records, bytes=size, read_only=True))
    )


if __name__ == "__main__":
    main()
