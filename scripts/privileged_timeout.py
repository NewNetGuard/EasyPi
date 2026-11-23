#!/usr/bin/env python3
"""Run one trusted privileged command in a bounded process group."""

from __future__ import annotations

import argparse
import os
import signal
import subprocess
import sys
import time


TIMEOUT_EXIT_CODE = 124
TERMINATED_EXIT_CODE = 128 + signal.SIGTERM
FORCED_KILL_WAIT_SECONDS = 1.0


def _parse_args() -> tuple[float, float, int | None, list[str]]:
    parser = argparse.ArgumentParser(add_help=False)
    parser.add_argument("--timeout", type=float, required=True)
    parser.add_argument("--kill-after", type=float, required=True)
    parser.add_argument("--deadline-monotonic-ns", type=int)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = list(args.command)
    if command[:1] == ["--"]:
        command = command[1:]
    if not command:
        parser.error("a command is required")
    if not 0.1 <= args.timeout <= 3600 or not 0.1 <= args.kill_after <= 60:
        parser.error("timeout is outside the permitted range")
    if args.deadline_monotonic_ns is not None and args.deadline_monotonic_ns <= 0:
        parser.error("deadline must be positive")
    return args.timeout, args.kill_after, args.deadline_monotonic_ns, command


def _signal_group(process_group: int, sig: signal.Signals) -> None:
    try:
        os.killpg(process_group, sig)
    except ProcessLookupError:
        pass


def _group_exists(process_group: int) -> bool:
    try:
        os.killpg(process_group, 0)
        return True
    except ProcessLookupError:
        return False


def _wait_for_group_exit(
    process: subprocess.Popen[bytes], process_group: int, timeout: float
) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        process.poll()  # reap the group leader so a zombie cannot extend the deadline
        if not _group_exists(process_group):
            return True
        time.sleep(0.02)
    process.poll()
    return not _group_exists(process_group)


def _terminate_group(
    process: subprocess.Popen[bytes], process_group: int, kill_after: float
) -> None:
    _signal_group(process_group, signal.SIGTERM)
    if not _wait_for_group_exit(process, process_group, kill_after):
        _signal_group(process_group, signal.SIGKILL)
        _wait_for_group_exit(process, process_group, FORCED_KILL_WAIT_SECONDS)
    process.poll()


def main() -> int:
    if os.name != "posix" or os.geteuid() != 0:
        print("privileged timeout supervisor requires root on Linux", file=sys.stderr)
        return 126

    timeout, kill_after, requested_deadline_ns, command = _parse_args()
    deadline = time.monotonic() + timeout
    if requested_deadline_ns is not None:
        deadline = min(deadline, requested_deadline_ns / 1_000_000_000)
    if time.monotonic() >= deadline:
        return TIMEOUT_EXIT_CODE

    process = subprocess.Popen(command, start_new_session=True)
    process_group = process.pid
    termination_requested = False

    def request_termination(_signum: int, _frame: object) -> None:
        nonlocal termination_requested
        termination_requested = True

    # An outer sudo/client timeout must wake this root supervisor instead of
    # killing only its unprivileged parent and abandoning privileged children.
    signal.signal(signal.SIGTERM, request_termination)
    signal.signal(signal.SIGHUP, request_termination)

    while True:
        return_code = process.poll()
        if return_code is not None:
            # A trusted operation must not leave direct background descendants.
            # systemd services are launched by PID 1 and do not remain here.
            if _group_exists(process_group):
                _terminate_group(process, process_group, kill_after)
            return return_code
        if termination_requested:
            _terminate_group(process, process_group, kill_after)
            return TERMINATED_EXIT_CODE
        if time.monotonic() >= deadline:
            _terminate_group(process, process_group, kill_after)
            return TIMEOUT_EXIT_CODE
        time.sleep(0.02)


if __name__ == "__main__":
    raise SystemExit(main())
