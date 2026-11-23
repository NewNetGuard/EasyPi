from __future__ import annotations

import asyncio
import signal
from typing import Any

import pytest

from app.services.stealth_service import StealthService
from app.services.stealth_components import client as client_module


def _runtime_meta() -> dict[str, Any]:
    return {
        "server_address": "203.0.113.10:443",
        "psk_key": "a" * 64,
        "scope": "selected",
        "devices": [{"mac": "02:00:00:00:00:01", "name": "test"}],
        "block_quic": True,
        "enabled": False,
        "ssh": {"ip_shield_deployed": True},
    }


def _prepare_runtime_service(
    service: StealthService,
    meta: dict[str, Any],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(service, "_meta", lambda: meta)
    monkeypatch.setattr(service, "_save_meta", lambda updated: meta.update(updated))
    monkeypatch.setattr(service, "_write_client_conf", lambda _meta: None)
    monkeypatch.setattr(service, "_resolve_ips", lambda _meta: ["192.0.2.20"])
    monkeypatch.setattr(service, "_resolve_macs", lambda _meta: ["02:00:00:00:00:01"])


def test_watchdog_waits_for_manual_enable_before_reconciling(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        service = StealthService()
        meta = _runtime_meta()
        _prepare_runtime_service(service, meta, monkeypatch)

        first_up_started = asyncio.Event()
        release_first_up = asyncio.Event()
        actions: list[str] = []

        async def fake_run(action: str, *_args: str, **_kwargs: Any) -> dict[str, Any]:
            actions.append(action)
            if action == "up":
                first_up_started.set()
                await release_first_up.wait()
                return {
                    "success": True,
                    "running": True,
                    "connected": True,
                    "killswitch": True,
                }
            if action == "status":
                return {"success": True, "running": True, "connected": True}
            raise AssertionError(f"unexpected action: {action}")

        async def fake_status() -> dict[str, Any]:
            return {
                "success": True,
                "enabled": True,
                "running": True,
                "connected": True,
            }

        monkeypatch.setattr(service, "_run", fake_run)
        monkeypatch.setattr(service, "status", fake_status)

        enable_task = asyncio.create_task(service.enable(confirm_routing_conflict=True))
        await asyncio.wait_for(first_up_started.wait(), timeout=1)
        reconcile_task = asyncio.create_task(service.reconcile_if_needed())
        await asyncio.sleep(0)

        # The watchdog is blocked on the lifecycle lock and cannot issue a
        # second privileged `up` while the manual start is publishing config.
        assert actions == ["up"]

        release_first_up.set()
        await asyncio.wait_for(asyncio.gather(enable_task, reconcile_task), timeout=1)
        assert actions == ["up", "status"]

    asyncio.run(scenario())


def test_disable_returns_complete_authoritative_status(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        service = StealthService()
        meta = _runtime_meta()
        meta["enabled"] = True
        _prepare_runtime_service(service, meta, monkeypatch)

        async def fake_run(action: str, *_args: str, **_kwargs: Any) -> dict[str, Any]:
            assert action == "down"
            return {"success": True, "running": False, "connected": False}

        async def fake_status() -> dict[str, Any]:
            return {
                "success": True,
                "enabled": meta["enabled"],
                "running": False,
                "connected": False,
                "configured": True,
            }

        monkeypatch.setattr(service, "_run", fake_run)
        monkeypatch.setattr(service, "status", fake_status)

        result = await service.disable()

        assert meta["enabled"] is False
        assert result == {
            "success": True,
            "enabled": False,
            "running": False,
            "connected": False,
            "configured": True,
        }

    asyncio.run(scenario())


def test_privileged_timeout_stops_process_group_before_returning(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def scenario() -> None:
        runner = tmp_path / "scripts" / "runner"
        runner.parent.mkdir(parents=True)
        runner.touch()
        process = FakeProcess()
        signals: list[int] = []
        create_options: dict[str, Any] = {}
        created_command: list[str] = []

        async def fake_create(*command: str, **kwargs: Any) -> FakeProcess:
            created_command.extend(command)
            create_options.update(kwargs)
            return process

        def fake_killpg(pid: int, sent_signal: int) -> None:
            assert pid == process.pid
            signals.append(sent_signal)

        monkeypatch.setattr(client_module, "get_easypi_root", lambda: tmp_path)
        monkeypatch.setattr(
            client_module.asyncio, "create_subprocess_exec", fake_create
        )
        monkeypatch.setattr(client_module.os, "killpg", fake_killpg, raising=False)

        result = await StealthService()._run("down", timeout=0.01)

        assert result == {"success": False, "error": "timeout running 'down'"}
        assert create_options["start_new_session"] is True
        deadline_index = created_command.index("--deadline-monotonic-ns")
        assert int(created_command[deadline_index + 1]) > 0
        assert created_command[deadline_index + 2 :] == [
            "settings/stealth_vpn.sh",
            "down",
        ]
        assert signals == [signal.SIGTERM]
        assert process.communicate_calls == 2
        assert process.returncode == -signal.SIGTERM

    class FakeProcess:
        pid = 4242

        def __init__(self) -> None:
            self.returncode: int | None = None
            self.communicate_calls = 0

        async def communicate(self) -> tuple[bytes, bytes]:
            self.communicate_calls += 1
            if self.communicate_calls == 1:
                await asyncio.Event().wait()
            self.returncode = -signal.SIGTERM
            return b"", b""

        def terminate(self) -> None:
            raise AssertionError("timeout cleanup did not target the process group")

        def kill(self) -> None:
            raise AssertionError("SIGTERM should have stopped the process group")

    asyncio.run(scenario())


def test_status_timeout_preserves_requested_protection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        service = StealthService()
        meta = _runtime_meta()
        meta["enabled"] = True
        _prepare_runtime_service(service, meta, monkeypatch)

        async def fake_run(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
            return {"success": False, "error": "timeout running 'status'"}

        monkeypatch.setattr(service, "_run", fake_run)
        monkeypatch.setattr(service, "client_state", lambda: {"enabled": meta["enabled"]})
        monkeypatch.setattr(service, "server_state", lambda: {})
        monkeypatch.setattr(service, "_online_ips", lambda _meta: [])
        monkeypatch.setattr(service, "_devices_with_live_ips", lambda _meta: [])
        monkeypatch.setattr(service, "_log_tail", lambda: "")

        result = await service.status()

        assert meta["enabled"] is True
        assert result["enabled"] is True
        assert result["error"] == "timeout running 'status'"

    asyncio.run(scenario())


def test_missing_runtime_guard_does_not_clear_requested_protection(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    async def scenario() -> None:
        service = StealthService()
        meta = _runtime_meta()
        meta["enabled"] = True
        _prepare_runtime_service(service, meta, monkeypatch)

        async def fake_run(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
            return {"success": True, "running": False, "killswitch": False}

        monkeypatch.setattr(service, "_run", fake_run)
        monkeypatch.setattr(service, "client_state", lambda: {"enabled": meta["enabled"]})
        monkeypatch.setattr(service, "server_state", lambda: {})
        monkeypatch.setattr(service, "_online_ips", lambda _meta: [])
        monkeypatch.setattr(service, "_devices_with_live_ips", lambda _meta: [])
        monkeypatch.setattr(service, "_log_tail", lambda: "")

        result = await service.status()

        assert meta["enabled"] is True
        assert result["enabled"] is True

    asyncio.run(scenario())
