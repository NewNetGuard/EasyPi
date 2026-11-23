"""Acceptance-driver safety gates tested without SSH or target configuration."""

import importlib.util
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import Mock
import pytest

ROOT = Path(__file__).resolve().parents[2]


@pytest.fixture
def driver(tmp_path, monkeypatch):
    support = SimpleNamespace(
        META={"test_network_confirmed": True, "ssh": "test-target"},
        RUNTIME=tmp_path,
        remote=Mock(),
    )
    monkeypatch.setitem(sys.modules, "prism_tls_target_support", support)
    spec = importlib.util.spec_from_file_location(
        "isolated_prism_target_suite",
        ROOT / "tests/acceptance/prism_tls_target_suite.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module, support


def test_coverage_never_claims_success_without_known_requests(driver):
    module, _ = driver
    assert module.ratio(4, 4) == 100
    assert module.ratio(0, 4) == 0
    assert module.ratio(3, 4) == 75
    for decoded, eligible in ((0, 0), (5, 4), (-1, 4), (True, 4), (4, -1)):
        assert module.ratio(decoded, eligible) is None


def test_missing_memory_controller_blocks_unattended_stress(driver, monkeypatch):
    module, support = driver
    monkeypatch.setattr(sys, "argv", ["suite", "--hours", "6"])
    module.os = SimpleNamespace(name="posix", replace=__import__("os").replace)
    support.remote.return_value = SimpleNamespace(
        stdout=json.dumps({"memory_controller": False})
    )
    with pytest.raises(SystemExit, match="memory cgroup"):
        module.main()
    state = json.loads((support.RUNTIME / "long-run-status.json").read_text())
    assert state["status"] == "blocked_memory_controller"
    assert state["cases"] == []
    assert all(
        call.kwargs.get("root") is not True for call in support.remote.call_args_list
    )


def test_network_gap_requires_confirmed_recovery_timer(driver):
    module, support = driver
    support.remote.side_effect = subprocess.CalledProcessError(
        1, ["mock"], output="restoration was not scheduled"
    )
    with pytest.raises(RuntimeError, match="not scheduled"):
        module.network_gap()
    assert support.remote.call_count == 1


def test_reboot_does_not_pass_until_boot_identity_changes(driver):
    module, support = driver
    reads = []
    healthy = {
        name: "active"
        for name in (
            "easypi-backend.service",
            "easypi-prism-shadow.service",
            "easypi-prism-flowgraph.service",
        )
    }

    def remote(code, **kwargs):
        if "boot_id" in code:
            reads.append(1)
            return SimpleNamespace(stdout="old" if len(reads) < 3 else "new")
        if "reboot" in code:
            return SimpleNamespace(stdout="")
        return SimpleNamespace(stdout=json.dumps(healthy))

    support.remote.side_effect = remote
    module.time = SimpleNamespace(monotonic=lambda: 0, sleep=lambda unused: None)
    assert module.reboot() == healthy
    assert len(reads) == 3


@pytest.fixture
def worker_validator(monkeypatch):
    monkeypatch.setitem(
        sys.modules,
        "prism_tls_target_support",
        SimpleNamespace(ServiceProbe=Mock(), remote=Mock()),
    )
    spec = importlib.util.spec_from_file_location(
        "isolated_worker_validation",
        ROOT / "tests/acceptance/prism_tls_lab/worker_probe.py",
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.validate_worker_report


def test_capture_loss_does_not_prove_queue_overflow(worker_validator):
    report = dict(
        ready=True,
        headers=0,
        fault_injected=True,
        tls_secret_leak_detected=False,
        visibility_reasons=[dict(reason="capture_incomplete")],
    )
    assert worker_validator(report, "overflow") is False
    report["visibility_reasons"] = [dict(reason="input_overflow")]
    assert worker_validator(report, "overflow") is True


def test_memory_limit_declaration_does_not_prove_oom(worker_validator):
    report = dict(
        ready=True,
        headers=0,
        fault_injected=True,
        tls_secret_leak_detected=False,
        service_result=dict(Result="success"),
    )
    assert worker_validator(report, "memory") is False
    report["service_result"]["Result"] = "oom-kill"
    assert worker_validator(report, "memory") is True


def test_normal_decode_requires_exact_count_and_audited_diagnostics(worker_validator):
    report = dict(
        ready=True,
        headers=4,
        tls_secret_leak_detected=False,
        capture_health=dict(
            submitted_packets=1, failed=False, dropped=0, interface_dropped=0
        ),
    )
    assert worker_validator(report, "none") is True
    for count in (0, 3, 5):
        assert worker_validator(dict(report, headers=count), "none") is False
    assert (
        worker_validator(dict(report, tls_secret_leak_detected=None), "none") is False
    )


def test_duration_run_requires_all_core_services_active(driver):
    module, _ = driver
    names = (
        "easypi-backend.service",
        "easypi-prism-shadow.service",
        "easypi-prism-flowgraph.service",
    )
    healthy = dict.fromkeys(names, "active")
    module.require_core_services(healthy)
    for name in names:
        with pytest.raises(RuntimeError, match="core service unavailable"):
            module.require_core_services(dict(healthy, **{name: "inactive"}))


def test_filter_mismatch_preserves_the_observed_inputs_before_cleanup(
    driver, monkeypatch
):
    module, support = driver
    monkeypatch.setattr(sys, "argv", ["suite", "--hours", "0.01", "--max-cases", "1"])
    module.os = SimpleNamespace(name="posix", replace=__import__("os").replace)
    initial = dict.fromkeys(
        (
            "easypi-backend.service",
            "easypi-prism-shadow.service",
            "easypi-prism-flowgraph.service",
        ),
        "active",
    )
    initial.update(
        memory_controller=True,
        firewall="baseline",
        ipsets="baseline",
        filter_fingerprint_inputs={
            "firewall": "baseline input",
            "ipsets": "baseline input",
        },
    )
    changed = dict(
        initial,
        ipsets="changed",
        filter_fingerprint_inputs={
            "firewall": "baseline input",
            "ipsets": "observed transient input",
        },
    )
    snapshots = iter((initial, changed))

    def remote(code, **kwargs):
        if code == module.SNAPSHOT:
            return SimpleNamespace(stdout=json.dumps(next(snapshots)))
        assert code == module.CLEANUP
        return SimpleNamespace(stdout=json.dumps(dict(observer_stopped=True)))

    support.remote.side_effect = remote
    module.run_case = Mock(
        side_effect=AssertionError("a changed policy must prevent the next case")
    )
    with pytest.raises(SystemExit):
        module.main()
    state = json.loads((support.RUNTIME / "long-run-status.json").read_text())
    assert state["status"] == "failed"
    assert state["filtering_mismatch"]["changed"] == ["ipsets"]
    assert (
        state["filtering_mismatch"]["snapshot"]["filter_fingerprint_inputs"]["ipsets"]
        == "observed transient input"
    )
    assert state["cleanup"]["observer_stopped"] is True
    module.run_case.assert_not_called()


def test_new_negative_policy_checks_actual_suppression_and_capture(worker_validator):
    report = dict(
        ready=True,
        headers=0,
        tls_secret_leak_detected=False,
        capture_health=dict(submitted_packets=1, failed=False, dropped=0),
        key_frames_suppressed=4,
        key_frames_submitted=0,
        visibility_reasons=[
            dict(
                type="visibility",
                state="Metadata only",
                reason="transport_closed",
                diagnostic="missing_key",
            )
        ],
    )
    assert worker_validator(report, "no-keys") is True
    assert worker_validator(dict(report, key_frames_suppressed=0), "no-keys") is False
    assert (
        worker_validator(
            dict(report, capture_health=dict(submitted_packets=0)), "no-keys"
        )
        is False
    )


def test_invalid_value_control_requires_specific_authentication_evidence(
    worker_validator,
):
    report = dict(
        ready=True,
        headers=0,
        tls_secret_leak_detected=False,
        transport="tcp",
        capture_health=dict(submitted_packets=1, failed=False, dropped=0),
        key_frames_corrupted=4,
        key_frames_submitted=4,
        visibility_reasons=[
            dict(
                type="visibility",
                state="Unknown",
                reason="matching_keys_timeout",
                diagnostic="invalid_secret",
            )
        ],
    )
    assert worker_validator(report, "wrong-keys") is True
    generic = dict(
        report,
        visibility_reasons=[
            dict(type="visibility", state="Unknown", reason="decoder_error")
        ],
    )
    assert worker_validator(generic, "wrong-keys") is False
    assert worker_validator(dict(report, key_frames_corrupted=0), "wrong-keys") is False
