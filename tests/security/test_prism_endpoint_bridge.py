"""Integration contracts for the optional embedded observation-only runtime."""

import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from unittest.mock import patch
import pytest

from prism_tls_bridge.entrypoint import dispatch
from prism_tls_bridge.shadow import ShadowSupervisor

ROOT = Path(__file__).resolve().parents[2]


def test_normal_binary_dispatch_does_not_start_shadow():
    with patch("subprocess.Popen", side_effect=AssertionError("must stay disabled")):
        assert dispatch([]) is None
        assert dispatch(["--ordinary-option"]) is None


def test_embedded_check_skips_backend_initialization():
    environment = os.environ.copy()
    environment["PYTHONPATH"] = (
        str(ROOT) + os.pathsep + environment.get("PYTHONPATH", "")
    )
    result = subprocess.run(
        [
            sys.executable,
            "-B",
            str(ROOT / "backend/packaging/run_backend.py"),
            "--prism-tls-check",
        ],
        cwd=ROOT,
        env=environment,
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads(result.stdout)
    assert report["component"] == "prism_tls_endpoint_bridge"
    assert report["default_enabled"] is False
    assert report["mode"] == "shadow_only"
    assert len(report["protocols"]) == 2


def test_unknown_binary_mode_is_rejected_without_backend():
    with pytest.raises(SystemExit, match="unknown Prism TLS mode"):
        dispatch(["--prism-tls-unrecognized"])


def test_frozen_spawn_reexecutes_binary_and_resets_bootloader_environment():
    class Process:
        pid = 123

    supervisor = ShadowSupervisor()
    with (
        patch.object(sys, "frozen", True, create=True),
        patch("subprocess.Popen", return_value=Process()) as spawn,
        patch("threading.Thread.start"),
    ):
        assert supervisor.start()
        args, kwargs = spawn.call_args
        assert args[0][0:2] == [sys.executable, "--prism-tls-child"]
        assert "-m" not in args[0] and "--memory" in args[0]
        assert kwargs["env"]["PYINSTALLER_RESET_ENVIRONMENT"] == "1"
        assert kwargs["start_new_session"] is (os.name == "posix")


@pytest.mark.skipif(
    os.name != "posix", reason="POSIX bootloader/child process-group cleanup"
)
@pytest.mark.parametrize("parent_exited", [False, True])
def test_disabling_shadow_kills_child_process_group(parent_exited):
    code = "import subprocess,sys,time; p=subprocess.Popen([sys.executable,'-c','import time; time.sleep(60)']); print(p.pid,flush=True); time.sleep(60)"
    process = subprocess.Popen(
        [sys.executable, "-c", code],
        start_new_session=True,
        stdout=subprocess.PIPE,
        text=True,
    )
    pid = int(process.stdout.readline())
    supervisor = ShadowSupervisor()
    supervisor.process = process
    supervisor.enabled = True
    try:
        if parent_exited:
            process.kill()
            process.wait(timeout=3)
        supervisor.disable()
        process.wait(timeout=3)
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            status = Path("/proc") / str(pid) / "status"
            if not status.exists() or "State:\tZ" in status.read_text():
                break
            time.sleep(0.02)
        else:
            raise AssertionError("descendant survived group shutdown")
        assert supervisor.status("any")["state"] == "Unknown"
    finally:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        supervisor.close()


def test_service_is_separate_private_opt_in_and_bounds_entire_tree():
    service = (
        ROOT / "templates/systemd/easypi-prism-endpoint-bridge@.service"
    ).read_text()
    socket = (
        ROOT / "templates/systemd/easypi-prism-endpoint-bridge.socket"
    ).read_text()
    assert "User=easypi-prism-tls" in service and "User=root" not in service
    assert "--prism-tls-shadow" in service and "StandardInput=socket" in service
    for value in (
        "CPUQuota=25%",
        "MemoryMax=512M",
        "MemorySwapMax=0",
        "KillMode=control-group",
        "Restart=no",
        "NoNewPrivileges=yes",
        "CapabilityBoundingSet=CAP_NET_RAW",
    ):
        assert value in service
    assert "CAP_NET_ADMIN" not in service
    assert "SocketMode=0600" in socket and "ListenStream=/run/" in socket
    assert "MaxConnections=1" in socket
    assert "\n[Install]" not in service and "\n[Install]" not in socket
    assert "WantedBy=" not in socket


def test_install_keeps_feature_disabled_and_uninstall_removes_instances():
    install = (ROOT / "install.sh").read_text(encoding="utf-8")
    start = install.index("setup_prism_endpoint_bridge() {")
    section = install[start : install.index("retire_prism_experiments() {", start)]
    assert "useradd --system" in section and "/usr/sbin/nologin" in section
    assert "systemctl start" not in section and "systemctl enable" not in section
    assert "iptables" not in section and "setcap" not in section
    assert 'cp -rf "${BASE_DIR}/prism_tls_bridge"' in install
    uninstall = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
    assert "easypi-prism-endpoint-bridge.socket" in uninstall
    assert "list-units 'easypi-prism-endpoint-bridge@*.service'" in uninstall


def test_build_embeds_and_checks_all_native_decoder_modules():
    spec = (ROOT / "backend/packaging/easypi-backend.spec").read_text()
    for name in ("prism_tls_bridge", "aioquic", "pylsqpack", "hpack"):
        assert "collect_submodules('" + name + "')" in spec
    build = (ROOT / "backend/packaging/build_binary.sh").read_text()
    assert "--prism-tls-check" in build
    assert 'prism_tls_bridge/"*.py' in build
    assert "/prism_tls_bridge/tests" not in build


@pytest.mark.skipif(
    os.name != "posix" or not os.environ.get("EASYPI_PRISM_TLS_SMOKE_BINARY"),
    reason="requires an explicitly supplied Linux one-file build",
)
def test_real_frozen_binary_crash_and_restart():
    binary = Path(os.environ["EASYPI_PRISM_TLS_SMOKE_BINARY"]).resolve()
    report = subprocess.run(
        [str(binary), "--prism-tls-check"], capture_output=True, text=True, timeout=30
    )
    assert report.returncode == 0, report.stderr
    assert json.loads(report.stdout)["default_enabled"] is False
    supervisor = ShadowSupervisor()

    def start():
        with (
            patch.object(sys, "frozen", True, create=True),
            patch.object(sys, "executable", str(binary)),
        ):
            assert supervisor.start()
        deadline = time.monotonic() + 25
        while (
            supervisor.os_limits is None
            and supervisor.enabled
            and time.monotonic() < deadline
        ):
            time.sleep(0.02)
        assert supervisor.os_limits == "rlimit_as_cpu", supervisor.reason

    try:
        start()
        pid = supervisor.process.pid
        child_file = Path("/proc") / str(pid) / "task" / str(pid) / "children"
        children = [int(n) for n in child_file.read_text().split()]
        assert children, "one-file bootloader did not spawn its worker"
        supervisor.process.kill()
        supervisor.process.wait(timeout=3)
        deadline = time.monotonic() + 5
        while supervisor.enabled and time.monotonic() < deadline:
            time.sleep(0.02)
        assert not supervisor.enabled
        for child in children:
            status = Path("/proc") / str(child) / "status"
            deadline = time.monotonic() + 3
            while (
                status.exists()
                and "State:\tZ" not in status.read_text()
                and time.monotonic() < deadline
            ):
                time.sleep(0.02)
            assert not status.exists() or "State:\tZ" in status.read_text(), (
                "orphan frozen decoder"
            )
        assert supervisor.status("previous")["state"] == "Unknown"
        start()
        assert supervisor.generation == 2
        assert not supervisor.flows
    finally:
        supervisor.close()


def test_cold_child_ready_starts_a_fresh_running_heartbeat_budget():
    supervisor = ShadowSupervisor()
    supervisor.enabled = True
    supervisor.generation = 1
    supervisor.last_heartbeat = time.monotonic() - 10

    class Output:
        calls = 0

        def readline(self, limit):
            self.calls += 1
            if self.calls == 1:
                return b'{"type":"ready","os_limits":"rlimit_as_cpu"}\n'
            assert time.monotonic() - supervisor.last_heartbeat < 1
            return b""

    class Process:
        stdout = Output()

    import threading

    with patch.object(supervisor, "disable"):
        supervisor._read(1, Process(), None, threading.Event())
    assert supervisor.os_limits == "rlimit_as_cpu"
