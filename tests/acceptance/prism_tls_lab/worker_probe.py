import os
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from prism_tls_target_support import ServiceProbe, remote


class WorkerProbe:
    def __init__(
        self,
        ssh,
        directory,
        python,
        session,
        transport,
        host,
        port,
        log,
        runtime,
        fault="none",
        capture_scope=None,
    ):
        self.baseline = os.environ.get("PRISM_TEST_BASELINE") == "1"
        if self.baseline:
            self.events = []
            self.probe = None
            return
        scope = capture_scope or {}
        address = remote(
            "import os; print(os.environ['SSH_CONNECTION'].split()[2])"
        ).stdout.strip()
        self.probe = ServiceProbe(
            transport,
            dict(address=address, port=scope["client_port"]),
            dict(address=scope["target_address"], port=port),
            fault=fault,
        )
        if not self.probe.ready.wait(25):
            report = self.probe.close()
            raise RuntimeError("target service did not become ready: " + str(report))
        self.events = self.probe.events

    def send_key(self, line):
        if self.probe:
            self.probe.key(line)

    def decoded(self, path):
        return [
            dict(protocol=e.get("protocol"), diagnostic_id=index, flow=e.get("flow"))
            for index, e in enumerate(list(self.events))
            if e.get("type") == "headers"
        ]

    def close(self):
        if self.baseline:
            return dict(baseline=True, ready=False, headers=0)
        report = self.probe.close()
        report["fault"] = self.probe.fault
        report["unit"] = self.probe.unit
        report["visibility_reasons"] = [
            e
            for e in self.events
            if e.get("type")
            in ("visibility", "disabled", "capture_loss", "shadow_stopped")
        ]
        health = [e for e in self.events if e.get("type") == "health"]
        report["peak_decoder_rss"] = max((e["rss"] for e in health), default=None)
        report["last_decoder_cpu"] = health[-1]["cpu"] if health else None
        report["invalid_secret_rejections"] = max(
            (e.get("invalid_secret", 0) for e in health), default=0
        )
        report["key_store_full"] = max(
            (e.get("key_store_full", 0) for e in health), default=0
        )
        captures = [e for e in self.events if e.get("type") == "capture_health"]
        report["capture_health"] = captures[-1] if captures else None
        report["observed_capture_loss"] = sum(
            e.get("count", 0) for e in self.events if e.get("type") == "capture_loss"
        )
        report["queue_drops"] = max(
            (e.get("queue_drops", 0) for e in health), default=0
        )
        return report


def validate_worker_report(report, fault):
    if report.get("baseline"):
        return True
    if not report.get("ready") or report.get("tls_secret_leak_detected") is not False:
        return False
    capture = report.get("capture_health") or {}
    capture_ok = (
        capture.get("submitted_packets", 0) > 0
        and not capture.get("failed")
        and capture.get("dropped", 0) == 0
        and capture.get("interface_dropped", 0) == 0
    )
    if fault == "none":
        return report.get("headers") == 4 and capture_ok
    if report.get("headers") != 0:
        return False
    reasons = {e.get("reason") for e in report.get("visibility_reasons", [])}
    if fault in ("no-keys", "wrong-keys"):
        if not capture_ok:
            return False
        history = [
            e
            for e in report.get("visibility_reasons", [])
            if e.get("type") == "visibility"
        ]
        last = history[-1] if history else {}
        if last.get("reason") not in {
            "awaiting_matching_keys",
            "matching_keys_timeout",
            "transport_closed",
            "invalid_secret",
        }:
            return False
        if fault == "no-keys":
            return (
                report.get("key_frames_suppressed", 0) > 0
                and report.get("key_frames_submitted", 0) == 0
                and last.get("diagnostic") in {"missing_key", "matching_keys_timeout"}
            )
        if (
            report.get("key_frames_corrupted", 0) <= 0
            or report.get("key_frames_submitted", 0) <= 0
        ):
            return False
        if report.get("transport") == "tcp":
            return last.get("state") == "Unknown" and (
                last.get("diagnostic") == "invalid_secret"
                or report.get("invalid_secret_rejections", 0) > 0
            )
        return (
            last.get("state") == "Unknown"
            and last.get("reason") == "matching_keys_timeout"
        )
    if not report.get("fault_injected"):
        return False
    if fault == "exit":
        return "process_exited" in reasons
    if fault == "hang":
        return "heartbeat_timeout" in reasons
    if fault == "overflow":
        return "input_overflow" in reasons
    if fault == "memory":
        return report.get("service_result", {}).get("Result") == "oom-kill"
    if fault == "drop":
        return "capture_incomplete" in reasons
    return False
