from __future__ import annotations

from types import SimpleNamespace

import pytest

from app.services.mobile_link_agent_service import MobileLinkAgentError, MobileLinkAgentService


def test_agent_service_uses_fixed_runner_without_shell(monkeypatch) -> None:
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        captured["kwargs"] = kwargs
        return SimpleNamespace(
            returncode=0,
            stdout='{"configured":false,"enabled":false,"active":false}',
            stderr="",
        )

    monkeypatch.setattr("app.services.mobile_link_agent_service.subprocess.run", fake_run)
    status = MobileLinkAgentService().run("status")

    assert status["configured"] is False
    assert captured["command"][-2:] == ["settings/mobile_link_agent.sh", "status"]
    assert "shell" not in captured["kwargs"]
    assert captured["kwargs"]["timeout"] == 30


def test_endpoint_install_uses_fixed_runner_action(monkeypatch) -> None:
    captured = {}

    def fake_run(command, **kwargs):
        captured["command"] = command
        return SimpleNamespace(returncode=0, stdout='{"configured":true}', stderr="")

    monkeypatch.setattr("app.services.mobile_link_agent_service.subprocess.run", fake_run)
    MobileLinkAgentService().run("ensure-endpoint")

    assert captured["command"][-2:] == ["settings/mobile_link_agent.sh", "ensure-endpoint"]


def test_agent_service_does_not_expose_privileged_stderr(monkeypatch) -> None:
    def fake_run(_command, **_kwargs):
        return SimpleNamespace(returncode=1, stdout="", stderr="secret diagnostic")

    monkeypatch.setattr("app.services.mobile_link_agent_service.subprocess.run", fake_run)
    with pytest.raises(MobileLinkAgentError) as error:
        MobileLinkAgentService().run("enable")
    assert "secret diagnostic" not in str(error.value)


def test_agent_registration_rejects_malformed_privileged_output(monkeypatch) -> None:
    monkeypatch.setattr(
        MobileLinkAgentService,
        "run",
        lambda _self, _action: {"installation_id": "z" * 32, "secret": "x" * 64},
    )
    with pytest.raises(MobileLinkAgentError):
        MobileLinkAgentService().registration()
