#!/usr/bin/env python3
"""Upload and run the isolated PostgreSQL backup cycle over strict SSH."""

from __future__ import annotations

import argparse
import getpass
import select
import shlex
import sys
import uuid
from pathlib import Path

import paramiko


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", required=True)
    parser.add_argument("--user", required=True)
    args = parser.parse_args()

    root = Path(__file__).resolve().parents[2]
    inputs = {
        "postgresql_backup_cycle.py": Path(__file__).with_name(
            "postgresql_backup_cycle.py"
        ),
        "run_postgresql_backup_cycle.sh": Path(__file__).with_name(
            "run_postgresql_backup_cycle.sh"
        ),
        "postgres_backup.py": root / "scripts/utils/postgres_backup.py",
        "backup_crypto.py": root / "scripts/utils/backup_crypto.py",
    }
    for path in inputs.values():
        if not path.is_file():
            raise SystemExit(f"missing integration input: {path}")

    password = getpass.getpass("SSH/sudo password: ")
    client = paramiko.SSHClient()
    client.load_host_keys(str(Path.home() / ".ssh" / "known_hosts"))
    client.set_missing_host_key_policy(paramiko.RejectPolicy())
    client.connect(
        args.host,
        username=args.user,
        password=password,
        look_for_keys=False,
        allow_agent=False,
        timeout=15,
        auth_timeout=15,
    )

    upload = f"/tmp/easypi-pg-upload-{uuid.uuid4().hex}"
    try:
        sftp = client.open_sftp()
        sftp.mkdir(upload, mode=0o700)
        for remote_name, local_path in inputs.items():
            destination = f"{upload}/{remote_name}"
            sftp.put(str(local_path), destination)
            sftp.chmod(destination, 0o600)
        sftp.close()

        remote_script = f"{upload}/run_postgresql_backup_cycle.sh"
        command = (
            "sudo -S -p '' /bin/bash "
            f"{shlex.quote(remote_script)} {shlex.quote(upload)}"
        )
        transport = client.get_transport()
        if transport is None:
            raise RuntimeError("SSH transport is unavailable")
        channel = transport.open_session(timeout=15)
        channel.get_pty(term="dumb", width=160, height=40)
        channel.exec_command(command)
        channel.sendall((password + "\n").encode())
        channel.shutdown_write()

        while True:
            readable, _, _ = select.select([channel], [], [], 1.0)
            if readable and channel.recv_ready():
                sys.stdout.buffer.write(channel.recv(65536))
                sys.stdout.buffer.flush()
            if channel.exit_status_ready() and not channel.recv_ready():
                break
        return channel.recv_exit_status()
    finally:
        client.close()


if __name__ == "__main__":
    raise SystemExit(main())
