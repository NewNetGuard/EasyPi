from __future__ import annotations

import asyncio
import json
import os
import stat
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from app.api.v1.endpoints.notifications import (
    NotificationPreferencesRequest,
    PushNotificationRequest,
    PushSubscriptionRequest,
    SMTPConfigRequest,
    TestEmailRequest as EmailTestRequest,
)
from app.api.websocket import terminal as terminal_module
from app.core import terminal_security as terminal_security_module
from app.services.email_service import (
    EmailMessage,
    EmailNotificationService,
    EmailPriority,
    EmailTemplates,
    SMTPConfig,
)
from app.services.jobs_service import JobsService
from app.services.push_notification_service import PushNotificationService
from app.services.audit_log_service import AuditLogService


class _NoRowsQuery:
    def order_by(self, *_args):
        return self

    def limit(self, *_args):
        return self

    def all(self):
        return []


class _NoRowsDB:
    def query(self, *_args):
        return _NoRowsQuery()


def test_terminal_session_limit_is_reserved_atomically() -> None:
    manager = terminal_security_module.TerminalSecurityManager()

    assert manager.try_register_session(7, "one")[0] is True
    assert manager.try_register_session(7, "two")[0] is True
    allowed, reason = manager.try_register_session(7, "three")

    assert allowed is False
    assert "Maximum" in reason
    assert manager.get_active_session_count(7) == 2


def test_terminal_input_is_bounded_before_pty_write(monkeypatch: pytest.MonkeyPatch) -> None:
    terminal = terminal_module.PTYTerminal(SimpleNamespace(), 1, "admin", None)
    terminal.master_fd = 9
    terminal.running = True
    writes: list[bytes] = []
    monkeypatch.setattr(terminal, "_input_echo_enabled", lambda: True)
    monkeypatch.setattr(terminal_module.os, "write", lambda _fd, data: writes.append(data))

    asyncio.run(terminal.write_to_pty("x" * (terminal_module.MAX_TERMINAL_INPUT_CHARS + 1)))
    assert writes == []

    asyncio.run(
        terminal.write_to_pty(
            "x" * (terminal_module.MAX_TERMINAL_COMMAND_BUFFER_CHARS * 2)
        )
    )
    assert len(terminal.command_buffer) == terminal_module.MAX_TERMINAL_COMMAND_BUFFER_CHARS


def test_terminal_hidden_input_is_never_added_to_command_audit(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    terminal = terminal_module.PTYTerminal(SimpleNamespace(), 1, "admin", 9)
    terminal.master_fd = 10
    terminal.running = True
    terminal.command_buffer = "previous-visible-text"
    writes: list[bytes] = []
    audited: list[str] = []

    async def capture_audit(command: str) -> None:
        audited.append(command)

    monkeypatch.setattr(terminal, "_input_echo_enabled", lambda: False)
    monkeypatch.setattr(terminal, "log_command", capture_audit)
    monkeypatch.setattr(terminal_module.os, "write", lambda _fd, data: writes.append(data))

    asyncio.run(terminal.write_to_pty("synthetic-password\r"))

    assert writes == [b"synthetic-password\r"]
    assert terminal.command_buffer == ""
    assert audited == []


def test_terminal_reads_kernel_echo_state() -> None:
    if os.name == "nt":
        pytest.skip("PTY echo state is verified on Linux")
    import termios

    master_fd, slave_fd = os.openpty()
    try:
        terminal = terminal_module.PTYTerminal(SimpleNamespace(), 1, "admin", None)
        terminal.master_fd = master_fd
        attributes = termios.tcgetattr(slave_fd)
        attributes[3] &= ~termios.ECHO
        termios.tcsetattr(slave_fd, termios.TCSANOW, attributes)

        assert terminal._input_echo_enabled() is False

        attributes[3] |= termios.ECHO
        termios.tcsetattr(slave_fd, termios.TCSANOW, attributes)
        assert terminal._input_echo_enabled() is True
    finally:
        os.close(master_fd)
        os.close(slave_fd)


def test_terminal_rejects_token_from_revoked_login_session(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from app.db import session as db_session_module

    user = SimpleNamespace(id=7, is_active=True, role="admin")

    class Result:
        def __init__(self, value):
            self.value = value

        def scalar_one_or_none(self):
            return self.value

    class RevokedSessionDB:
        def __init__(self):
            self.results = iter((Result(user), Result(None)))

        def execute(self, _statement):
            return next(self.results)

        def close(self):
            pass

    def revoked_db():
        yield RevokedSessionDB()

    class WebSocket:
        headers = {
            "user-agent": "audit-browser",
            "sec-websocket-protocol": "easypi-terminal.one-shot-token",
        }
        client = ("192.168.1.20", 50000)

        def __init__(self):
            self.accepted = False
            self.close_codes: list[int] = []

        async def accept(self, **_kwargs):
            self.accepted = True

        async def close(self, code: int):
            self.close_codes.append(code)

    token = SimpleNamespace(
        user_id=7,
        username="admin",
        session_fingerprint="terminal-session",
        session_jti="revoked-session-jti",
    )
    websocket = WebSocket()
    monkeypatch.setattr(terminal_module, "_get_ws_client_ip", lambda _ws: "192.168.1.20")
    monkeypatch.setattr(
        terminal_module.terminal_security, "is_ip_allowed", lambda _ip: (True, "Allowed")
    )
    monkeypatch.setattr(
        terminal_module.terminal_security,
        "verify_and_consume_token",
        lambda *_args: (token, "Valid"),
    )
    monkeypatch.setattr(db_session_module, "get_db", revoked_db)

    asyncio.run(terminal_module.terminal_websocket_handler(websocket))

    assert websocket.accepted is False
    assert websocket.close_codes == [terminal_module.status.WS_1008_POLICY_VIOLATION]

    active_session = SimpleNamespace(
        revoked_at=None,
        expires_at=terminal_module.utc_now() + timedelta(minutes=5),
    )

    class ActiveSessionDB(RevokedSessionDB):
        def __init__(self):
            self.results = iter((Result(user), Result(active_session)))

    assert terminal_module._authorized_terminal_user(
        ActiveSessionDB(), 7, "active-session-jti"
    ) is user


def test_terminal_stop_kills_children_after_shell_exits(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    if os.name == "nt":
        pytest.skip("PTY process-group behavior is verified on Linux")

    async def scenario() -> None:
        started = tmp_path / "child-started"
        late = tmp_path / "late-child-mutation"
        shell = tmp_path / "terminal-child.py"
        shell.write_text(
            "#!/usr/bin/python3\n"
            "import os, signal, time\n"
            "from pathlib import Path\n"
            "if os.fork():\n"
            "    os._exit(0)\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            f"Path({str(started)!r}).write_text('started')\n"
            "time.sleep(2)\n"
            f"Path({str(late)!r}).write_text('late')\n",
            encoding="utf-8",
        )
        shell.chmod(shell.stat().st_mode | stat.S_IXUSR)

        terminal = terminal_module.PTYTerminal(SimpleNamespace(), 1, "admin", None)
        await terminal.start(shell=str(shell))
        assert terminal.process is not None
        await terminal.process.wait()
        for _ in range(100):
            if started.exists():
                break
            await asyncio.sleep(0.01)
        assert started.exists()

        await terminal.stop()
        await asyncio.sleep(2.1)

        assert not late.exists()

    monkeypatch.setattr(terminal_module, "HAS_PTY", True)
    asyncio.run(scenario())


def test_terminal_start_closes_both_pty_descriptors_when_spawn_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    terminal = terminal_module.PTYTerminal(SimpleNamespace(), 1, "admin", None)
    closed: list[int] = []

    async def fail_spawn(*_args, **_kwargs):
        raise OSError("synthetic spawn failure")

    monkeypatch.setattr(terminal_module, "HAS_PTY", True)
    monkeypatch.setattr(terminal_module.os, "openpty", lambda: (101, 102), raising=False)
    monkeypatch.setattr(terminal_module.os, "setsid", lambda: None, raising=False)
    monkeypatch.setattr(terminal_module.os, "close", closed.append)
    monkeypatch.setattr(terminal_module.asyncio, "create_subprocess_exec", fail_spawn)

    with pytest.raises(OSError, match="synthetic spawn failure"):
        asyncio.run(terminal.start())

    assert sorted(closed) == [101, 102]
    assert terminal.master_fd is None
    assert terminal.process is None


def test_terminal_token_is_sent_as_websocket_subprotocol() -> None:
    frontend = Path("frontend/src/components/terminal/TerminalEmulator.tsx").read_text(
        encoding="utf-8"
    )
    assert "/ws/terminal?ws_token=" not in frontend
    assert "easypi-terminal.${wsToken}" in frontend


def test_jobs_response_never_exposes_installer_arguments_or_logs(tmp_path: Path) -> None:
    installer_dir = tmp_path / "installer"
    logs_dir = tmp_path / "logs"
    installer_dir.mkdir()
    logs_dir.mkdir()
    job_id = "a" * 32
    (installer_dir / f"{job_id}.json").write_text(
        json.dumps(
            {
                "script": "maintenance/apply_update.sh",
                "args": ["--url", "https://updates.example/release?token=SECRET"],
                "created_at_epoch": 1_800_000_000,
            }
        ),
        encoding="utf-8",
    )
    (logs_dir / f"installer-{job_id}.log").write_text(
        "authorization=SECRET\nInstaller job finished (exit=0)\n",
        encoding="utf-8",
    )
    service = JobsService(installer_dir=installer_dir, logs_dir=logs_dir)
    service.rollback_service.list_snapshots = lambda limit: SimpleNamespace(snapshots=[])
    service.operation_event_service.list_events = lambda limit: []

    payload = service.list_jobs(_NoRowsDB(), limit=10).model_dump(mode="json")
    serialized = json.dumps(payload)

    assert payload["jobs"][0]["status"] == "success"
    assert payload["jobs"][0]["message"] == "Job finished successfully"
    assert "SECRET" not in serialized
    assert "args" not in payload["jobs"][0]
    assert "log_tail" not in payload["jobs"][0]
    assert "script" not in payload["jobs"][0]


def test_jobs_ignore_symlinked_payload(tmp_path: Path) -> None:
    installer_dir = tmp_path / "installer"
    installer_dir.mkdir()
    target = tmp_path / "outside.json"
    target.write_text(
        json.dumps({"script": "services/ai.sh", "args": ["install"]}),
        encoding="utf-8",
    )
    link = installer_dir / f"{'b' * 32}.json"
    try:
        link.symlink_to(target)
    except OSError:
        pytest.skip("Symlinks are unavailable on this platform")

    service = JobsService(installer_dir=installer_dir, logs_dir=tmp_path / "logs")
    assert service._collect_installer_jobs(limit=10) == []


def test_jobs_do_not_return_raw_operation_event_messages(tmp_path: Path) -> None:
    service = JobsService(installer_dir=tmp_path / "installer", logs_dir=tmp_path / "logs")
    service.operation_event_service.list_events = lambda limit: [
        SimpleNamespace(
            event_id="op-secret",
            status="failed",
            title="Failed operation",
            subtitle="Test",
            route="/settings",
            started_at="2026-09-07T00:00:00+00:00",
            updated_at="2026-09-07T00:00:01+00:00",
            message="password=SUPER_SECRET",
        )
    ]

    records = service._collect_operation_jobs(limit=10)

    assert len(records) == 1
    assert records[0].record.message == "Operation failed; open the related section for details"
    assert "SUPER_SECRET" not in records[0].record.model_dump_json()


def test_email_html_templates_escape_all_dynamic_values() -> None:
    _, security_html = EmailTemplates.security_alert(
        alert_type="custom<script>",
        title="Title <img src=x>",
        description="Description & more",
        details={"<key>": "<svg onload=alert(1)>"},
        priority=EmailPriority.HIGH,
        timestamp=terminal_module.utc_now(),
    )
    _, system_html = EmailTemplates.system_notification(
        "<title>", "<message>", {"<key>": "<value>"}
    )
    _, digest_html = EmailTemplates.digest_email(
        [{"priority": "normal", "title": "<title>", "message": "<message>"}],
        "24 hours",
        terminal_module.utc_now(),
    )

    for rendered in (security_html, system_html, digest_html):
        assert "<script>" not in rendered
        assert "<img src=x>" not in rendered
        assert "<svg onload=alert(1)>" not in rendered
    assert "&lt;svg onload=alert(1)&gt;" in security_html


def test_email_headers_reject_control_characters() -> None:
    service = EmailNotificationService(
        SMTPConfig(
            username="sender@example.test",
            password="password",
            from_email="sender@example.test",
        )
    )
    with pytest.raises(ValueError):
        service._create_mime_message(
            EmailMessage(
                to=["recipient@example.test"],
                subject="Safe\r\nBcc: victim@example.test",
                body_text="body",
            )
        )


@pytest.mark.parametrize(
    "factory",
    [
        lambda: SMTPConfigRequest(
            host="smtp.example.test",
            username="user",
            password="password",
            use_tls=True,
            use_ssl=True,
        ),
        lambda: EmailTestRequest(
            to_email="recipient@example.test",
            subject="safe\nBcc: victim@example.test",
        ),
        lambda: NotificationPreferencesRequest(
            alert_types=["not_a_real_alert"]
        ),
        lambda: PushSubscriptionRequest(
            endpoint="https://fcm.googleapis.com/push/token",
            keys={"p256dh": "short", "auth": "short"},
        ),
        lambda: PushNotificationRequest(
            title="Title", body="Body", icon="https://tracker.example/pixel.png"
        ),
    ],
)
def test_notification_models_reject_unsafe_or_ambiguous_input(factory) -> None:
    with pytest.raises(ValueError):
        factory()


def test_push_subscription_state_rolls_back_when_persistence_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    service = PushNotificationService()
    endpoint = "https://fcm.googleapis.com/fcm/send/token"
    monkeypatch.setattr(
        service,
        "_save_subscriptions",
        lambda: (_ for _ in ()).throw(RuntimeError("disk full")),
    )

    with pytest.raises(RuntimeError):
        service.add_subscription(
            endpoint,
            {"p256dh": "p256dh_test_value_123", "auth": "auth_test_value_123"},
            user_id=3,
        )

    assert service.get_subscriptions() == []


def test_push_service_worker_renews_with_key_and_csrf() -> None:
    worker = Path("frontend/public/sw.js").read_text(encoding="utf-8")

    assert "oldSubscription?.options?.applicationServerKey" in worker
    assert "'/api/v1/auth/csrf'" in worker
    assert "'X-CSRF-Token': csrfPayload.csrf_token" in worker
    assert "self.applicationServerKey" not in worker
    assert "version: STATIC_CACHE" in worker


def test_full_email_settings_are_reachable_from_settings_page() -> None:
    settings = Path("frontend/src/components/settings/Settings.tsx").read_text(
        encoding="utf-8"
    )
    advanced = Path("frontend/src/components/security/AdvancedSettings.tsx").read_text(
        encoding="utf-8"
    )

    assert "<EmailNotificationSettings />" in settings
    assert 'to="/settings?tab=notifications"' in advanced
    assert "api.put('/notifications/preferences'" not in advanced


def test_audit_log_does_not_expose_sudo_arguments() -> None:
    record = AuditLogService()._parse_auth_log_line(
        "Sep  7 12:00:00 host sudo: admin : TTY=pts/0 ; COMMAND=/bin/tool --token SUPER_SECRET"
    )

    assert record is not None
    assert record.details == "User: admin | Command arguments hidden"
    assert "SUPER_SECRET" not in record.details
