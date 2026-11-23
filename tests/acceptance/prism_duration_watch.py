"""Read-only Windows duration-test observer, invoked independently by Task Scheduler.

No test imports, network calls, process termination or test restart are permitted.
The private config binds each PID to its Windows process creation FILETIME.
"""

import argparse
import ctypes
from ctypes import wintypes
import datetime
import hashlib
import json
import os
from pathlib import Path
import time


def utc_now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def process_identity(pid):
    """Return an immutable birth token; distinguish access failure from absence."""
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
    kernel.GetProcessTimes.restype = wintypes.BOOL
    kernel.GetExitCodeProcess.argtypes = [wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD)]
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    handle = kernel.OpenProcess(0x1000, False, pid)
    if not handle:
        error = ctypes.get_last_error()
        return {"state": "missing" if error == 87 else "unavailable", "winerror": error}
    try:
        times = [wintypes.FILETIME() for _ in range(4)]
        code = wintypes.DWORD()
        if not kernel.GetProcessTimes(handle, *[ctypes.byref(t) for t in times]):
            return {"state": "unavailable", "winerror": ctypes.get_last_error()}
        if not kernel.GetExitCodeProcess(handle, ctypes.byref(code)):
            return {"state": "unavailable", "winerror": ctypes.get_last_error()}
        born = str((times[0].dwHighDateTime << 32) | times[0].dwLowDateTime)
        return {"state": "alive" if code.value == 259 else "exited", "birth": born}
    finally:
        kernel.CloseHandle(handle)


def read_report(path):
    # Hash the exact parsed bytes, without exporting report contents or secrets.
    with path.open("rb") as source:
        encoded = source.read(16 * 1024 * 1024 + 1)
        stat = os.fstat(source.fileno())
    if len(encoded) > 16 * 1024 * 1024:
        raise ValueError("report size bound")
    value = json.loads(encoded.decode("utf-8-sig"))
    if not isinstance(value, dict):
        raise ValueError("report object required")
    return value, hashlib.sha256(encoded).hexdigest(), stat.st_mtime


def evaluate(target, report, identity, age):
    """Completion and availability are separate; never infer a six-hour pass."""
    if target["kind"] == "launcher" and report.get("finished_utc"):
        if report.get("phase") != "finished" or report.get("timeout") or report.get("child_exit_code") != 0:
            return "launcher_failed"
        return "launcher_finished_review_required"
    if target["kind"] == "duration" and report.get("finished_utc"):
        if report.get("status") in {"completed", "failed"}:
            if report.get("requested_hours") == 6 and report.get("elapsed_seconds", 0) >= 21600:
                return "duration_finished_review_required"
        return "ended_without_full_duration"
    if target["kind"] == "controller" and report.get("phase") == "followup_failed":
        return "controller_failed"
    if target["kind"] == "controller" and report.get("phase") in {
        "repeat_duration_finished", "operator_stopped"
    }:
        return "controller_terminal_review_required"
    if identity["state"] in {"missing", "exited"}:
        return "interrupted_without_final_report"
    if identity["state"] != "alive":
        return "process_unavailable"
    if not target.get("birth"):
        return "unbound_process_identity"
    if target["birth"] != identity.get("birth"):
        return "pid_reused"
    # Old controllers have no waiting heartbeat. Do not pretend to detect hangs.
    if target["kind"] == "controller":
        return "controller_alive_progress_unverified"
    if age > target.get("stale_after_seconds", 240):
        return "progress_stale"
    return "process_alive_progress_recent"


def observe(config, probe=process_identity, now=None):
    now = time.time() if now is None else now
    results = []
    for target in config["targets"]:
        item = {"name": target["name"], "pid": target["pid"]}
        try:
            value, digest, modified = read_report(Path(target["report"]))
            identity = probe(target["pid"])
            age = max(0, now - modified)
            item.update(
                state=evaluate(target, value, identity, age),
                source_sha256=digest,
                source_age_seconds=round(age, 3),
                process=identity,
            )
            if item["state"] == "process_alive_progress_recent" and target.get("progress_report"):
                try:
                    _, progress_hash, progress_modified = read_report(Path(target["progress_report"]))
                    progress_age = max(0, now - progress_modified)
                    item.update(progress_sha256=progress_hash, progress_age_seconds=round(progress_age, 3))
                    if progress_age > 240:
                        item["state"] = "child_progress_stale"
                except (OSError, ValueError, TypeError):
                    if value.get("elapsed_seconds", 0) > 240:
                        item["state"] = "child_progress_unavailable"
        except (OSError, ValueError, TypeError):
            # No exception strings: malformed/private report content stays private.
            item["state"] = "observation_unavailable"
        results.append(item)
    return results


def validate(config):
    targets = config.get("targets", [])
    if not 1 <= len(targets) <= 8:
        raise ValueError("one to eight targets required")
    output = Path(config["output"]).resolve()
    for target in targets:
        if target["kind"] not in {"duration", "controller", "launcher"}:
            raise ValueError("unknown target kind")
        if not isinstance(target["pid"], int) or not 1 <= target["pid"] <= 0xFFFFFFFF:
            raise ValueError("invalid PID")
        if not isinstance(target["name"], str) or len(target["name"]) > 64:
            raise ValueError("bounded name required")
        if Path(target["report"]).resolve().parent == output:
            raise ValueError("monitor output must be separate from evidence")
        if not 30 <= target.get("stale_after_seconds", 240) <= 3600:
            raise ValueError("bounded staleness required")
    return output


def sample(config):
    output = validate(config)
    output.mkdir(mode=0o700, parents=True, exist_ok=True)
    destination = output / "health.json"
    previous = {}
    if destination.exists():
        try:
            previous = json.loads(destination.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
    results = observe(config)
    # Keep the first incident even after recovery; bounded by target count.
    incidents = previous.get("incidents", {})
    healthy = {
        "process_alive_progress_recent", "controller_alive_progress_unverified",
        "duration_finished_review_required", "controller_terminal_review_required",
        "launcher_finished_review_required",
    }
    for item in results:
        if item["state"] not in healthy:
            incidents.setdefault(item["name"], {"first_observed_utc": utc_now(), **item})
    state = dict(
        observed_utc=utc_now(), observer_pid=os.getpid(), observer_parent_pid=os.getppid(),
        samples=previous.get("samples", 0) + 1,
        read_only=True, automatic_test_restart=False,
        targets=results, incidents=incidents,
    )
    temp = destination.with_suffix(".new")
    temp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    temp.replace(destination)
    return state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, required=True)
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding="utf-8-sig"))
    output = validate(config)
    if args.config.resolve().parent == output:
        parser.error("config must be separate from monitor output")
    sample(config)


if __name__ == "__main__":
    main()
