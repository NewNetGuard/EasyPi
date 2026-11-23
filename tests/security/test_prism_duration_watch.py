"""Infrastructure observer regressions; never launch network acceptance tests."""

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

SOURCE = Path(__file__).resolve().parents[1] / "acceptance/prism_duration_watch.py"
spec = importlib.util.spec_from_file_location("duration_watch", SOURCE)
watch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(watch)


class DurationWatchTests(unittest.TestCase):
    def setUp(self):
        self.target = dict(name="duration", kind="duration", pid=123, birth="42")
        self.alive = dict(state="alive", birth="42")

    def test_missing_process_does_not_trust_running(self):
        self.assertEqual(watch.evaluate(self.target, {"status": "running"}, {"state": "missing"}, 0), "interrupted_without_final_report")

    def test_pid_reuse_and_unbound_identity(self):
        self.assertEqual(watch.evaluate(self.target, {}, dict(state="alive", birth="43"), 0), "pid_reused")
        self.target.pop("birth")
        self.assertEqual(watch.evaluate(self.target, {}, self.alive, 0), "unbound_process_identity")

    def test_recent_and_stale_progress(self):
        self.assertEqual(watch.evaluate(self.target, {}, self.alive, 10), "process_alive_progress_recent")
        self.assertEqual(watch.evaluate(self.target, {}, self.alive, 241), "progress_stale")

    def test_access_denial_is_not_process_death(self):
        self.assertEqual(watch.evaluate(self.target, {}, {"state": "unavailable"}, 0), "process_unavailable")

    def test_waiting_controller_does_not_claim_progress(self):
        self.target["kind"] = "controller"
        self.assertEqual(watch.evaluate(self.target, {}, self.alive, 9999), "controller_alive_progress_unverified")

    def test_full_duration_is_not_automatic_pass(self):
        value = dict(status="failed", finished_utc="recorded", elapsed_seconds=21600, requested_hours=6)
        self.assertEqual(watch.evaluate(self.target, value, {"state": "missing"}, 0), "duration_finished_review_required")
        value["elapsed_seconds"] = 13772
        self.assertEqual(watch.evaluate(self.target, value, {"state": "missing"}, 0), "ended_without_full_duration")

    def test_source_immutable_and_private_content_not_exported(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            report = root / "source.json"
            report.write_text(json.dumps(dict(status="running", private_marker="must_remain_in_source")))
            before = report.read_bytes(), report.stat().st_mtime_ns
            config = dict(output=str(root / "observer"), targets=[dict(self.target, report=str(report))])
            result = watch.observe(config, probe=lambda _: {"state": "missing"})
            self.assertEqual(result[0]["state"], "interrupted_without_final_report")
            self.assertNotIn("must_remain_in_source", json.dumps(result))
            self.assertEqual(before, (report.read_bytes(), report.stat().st_mtime_ns))
            report.write_text("{")
            self.assertEqual(watch.observe(config)[0]["state"], "observation_unavailable")

    def test_output_cannot_share_evidence_directory(self):
        with tempfile.TemporaryDirectory() as directory:
            config = dict(output=directory, targets=[dict(self.target, report=str(Path(directory) / "health.json"))])
            with self.assertRaises(ValueError):
                watch.validate(config)

    def test_first_incident_survives_recovery_and_monitor_restart(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            config = dict(output=str(root / "observer"), targets=[dict(self.target, report=str(root / "source.json"))])
            failure = dict(name="duration", pid=123, state="interrupted_without_final_report")
            with patch.object(watch, "observe", return_value=[failure]):
                first = watch.sample(config)
            with patch.object(watch, "observe", return_value=[dict(failure, state="process_alive_progress_recent")]):
                second = watch.sample(config)
            self.assertEqual(second["samples"], 2)
            self.assertEqual(first["incidents"], second["incidents"])
            self.assertFalse(second["automatic_test_restart"])

    @unittest.skipUnless(os.name == "nt", "Windows process API")
    def test_real_canary_exit_is_detected(self):
        process = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(20)"], creationflags=subprocess.CREATE_NO_WINDOW)
        try:
            identity = watch.process_identity(process.pid)
            self.assertEqual(identity["state"], "alive")
            self.target.update(pid=process.pid, birth=identity["birth"])
            process.terminate()  # Only this test's harmless canary.
            process.wait(timeout=5)
            self.assertIn(watch.process_identity(process.pid)["state"], {"missing", "exited"})
        finally:
            if process.poll() is None:
                process.kill()
                process.wait(timeout=5)


if __name__ == "__main__":
    unittest.main()
