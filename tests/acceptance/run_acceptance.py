#!/usr/bin/env python3
"""Run repeatable EasyPi acceptance gates and write machine-readable evidence."""

from __future__ import annotations

import argparse
import ast
import io
import json
import os
import re
import shlex
import shutil
import ssl
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
ROOT = Path(__file__).resolve().parents[2]
MANIFEST_PATH = Path(__file__).with_name("acceptance_manifest.json")
DEFAULT_REPORT_ROOT = ROOT / ".build" / "acceptance"


@dataclass
class CheckResult:
    name: str
    status: str
    duration_seconds: float
    detail: str
    command: list[str] | None = None


def _python() -> str:
    candidates = [
        ROOT / ".venv" / "Scripts" / "python.exe",
        ROOT / ".venv" / "bin" / "python",
    ]
    return str(next((path for path in candidates if path.exists()), Path(sys.executable)))


def _tail(value: str, lines: int = 35) -> str:
    clean = value.replace("\x00", "")
    for name, secret in os.environ.items():
        if len(secret) >= 8 and any(marker in name.upper() for marker in ("KEY", "PASSWORD", "SECRET", "TOKEN")):
            clean = clean.replace(secret, "[REDACTED]")
    return "\n".join(clean.splitlines()[-lines:])


def _run_command(
    name: str,
    command: list[str],
    cwd: Path = ROOT,
    extra_environment: dict[str, str] | None = None,
) -> CheckResult:
    started = time.monotonic()
    test_environment = {
        **os.environ,
        "PYTHONPATH": f"{ROOT / 'backend'}{os.pathsep}{ROOT}",
        "DATABASE_URL": "sqlite:///./.build/acceptance/acceptance.db",
        "SECRET_KEY": "acceptance-only-secret-key-never-used-in-production",
        "ENV": "testing",
        "LOG_TO_FILE": "false",
    }
    test_environment.update(extra_environment or {})
    try:
        process = subprocess.run(
            command,
            cwd=cwd,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=1800,
            env=test_environment,
            check=False,
        )
        output = "\n".join(part for part in (process.stdout, process.stderr) if part).strip()
        return CheckResult(
            name=name,
            status="pass" if process.returncode == 0 else "fail",
            duration_seconds=round(time.monotonic() - started, 3),
            detail=_tail(output) or f"exit code {process.returncode}",
            command=command,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CheckResult(
            name=name,
            status="fail",
            duration_seconds=round(time.monotonic() - started, 3),
            detail=f"{type(exc).__name__}: {exc}",
            command=command,
        )


def _api_inventory() -> list[dict[str, str]]:
    methods = {"get", "post", "put", "patch", "delete", "websocket"}
    rows: list[dict[str, str]] = []
    for path in sorted((ROOT / "backend" / "app" / "api").rglob("*.py")):
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (OSError, SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                call = decorator if isinstance(decorator, ast.Call) else None
                function = call.func if call else decorator
                if not isinstance(function, ast.Attribute) or function.attr not in methods:
                    continue
                route = "<dynamic>"
                if call and call.args and isinstance(call.args[0], ast.Constant):
                    route = str(call.args[0].value)
                rows.append(
                    {
                        "method": function.attr.upper(),
                        "declared_path": route,
                        "handler": node.name,
                        "source": path.relative_to(ROOT).as_posix(),
                    }
                )
    return rows


def _ui_inventory() -> list[dict[str, str]]:
    source = (ROOT / "frontend" / "src" / "App.tsx").read_text(encoding="utf-8")
    rows = []
    for match in re.finditer(r'<Route\s+(?:index\s+|path="([^"]+)")', source):
        path = match.group(1) or "<index>"
        rows.append({"path": path if path.startswith("/") else f"/{path}"})
    return rows


def _inventory_result(report_dir: Path) -> CheckResult:
    started = time.monotonic()
    api = _api_inventory()
    ui = _ui_inventory()
    inventory = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "api_declarations": api,
        "ui_routes": ui,
        "counts": {"api_declarations": len(api), "ui_routes": len(ui)},
    }
    (report_dir / "inventory.json").write_text(
        json.dumps(inventory, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    return CheckResult(
        name="inventory",
        status="pass",
        duration_seconds=round(time.monotonic() - started, 3),
        detail=f"{len(api)} API declarations and {len(ui)} UI routes catalogued",
    )


def _http_get(base_url: str, path: str, insecure: bool) -> tuple[int, bytes, dict[str, str]]:
    context = ssl._create_unverified_context() if insecure else ssl.create_default_context()
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}{path}", headers={"User-Agent": "EasyPi-Acceptance/1.0"}
    )
    try:
        with urllib.request.urlopen(request, timeout=12, context=context) as response:
            return response.status, response.read(512_000), dict(response.headers.items())
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read(512_000), dict(exc.headers.items())


def _live_http(base_url: str, insecure: bool) -> CheckResult:
    started = time.monotonic()
    failures: list[str] = []
    evidence: list[str] = []
    probes = [("/health", {200}), ("/api/v1/healthz_v1", {200}), ("/api/v1/auth/me", {401, 403})]
    for path, expected in probes:
        try:
            status, body, headers = _http_get(base_url, path, insecure)
        except (OSError, ssl.SSLError, urllib.error.URLError) as exc:
            failures.append(f"{path}: {type(exc).__name__}: {exc}")
            continue
        evidence.append(f"{path}: HTTP {status}")
        if status not in expected:
            failures.append(f"{path}: expected {sorted(expected)}, got {status}")
        if path == "/health" and status == 200:
            try:
                if json.loads(body)["status"] != "ok":
                    failures.append("/health: JSON status is not ok")
            except (KeyError, TypeError, ValueError):
                failures.append("/health: invalid health JSON")
        lowered = {key.lower(): value for key, value in headers.items()}
        if status == 200 and lowered.get("x-content-type-options", "").lower() != "nosniff":
            failures.append(f"{path}: missing X-Content-Type-Options: nosniff")
    return CheckResult(
        name="live-http",
        status="fail" if failures else "pass",
        duration_seconds=round(time.monotonic() - started, 3),
        detail="; ".join(failures or evidence),
    )


def _remote_services(ssh_target: str) -> CheckResult:
    command = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
        ssh_target,
        "systemctl is-active easypi-backend easypi-netprotection easypi-prism-flowgraph easypi-chameleon-client nginx",
    ]
    result = _run_command("remote-services", command)
    if result.status == "pass":
        states = [line.strip() for line in result.detail.splitlines() if line.strip()]
        if len(states) < 5 or any(state != "active" for state in states[-5:]):
            result.status = "fail"
            result.detail = f"unexpected service states: {states}"
    return result


def _remote_script(name: str, ssh_target: str, script_name: str) -> CheckResult:
    script_path = Path(__file__).with_name(script_name)
    command = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
        ssh_target,
        "sudo",
        "bash",
        "-s",
    ]
    started = time.monotonic()
    try:
        process = subprocess.run(
            command,
            input=script_path.read_text(encoding="utf-8").replace("\r", "").encode("utf-8"),
            capture_output=True,
            timeout=120,
            check=False,
        )
        output = "\n".join(
            part.decode("utf-8", errors="replace")
            for part in (process.stdout, process.stderr)
            if part
        ).strip()
        return CheckResult(
            name=name,
            status="pass" if process.returncode == 0 else "fail",
            duration_seconds=round(time.monotonic() - started, 3),
            detail=_tail(output) or f"exit code {process.returncode}",
            command=command,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CheckResult(
            name=name,
            status="fail",
            duration_seconds=round(time.monotonic() - started, 3),
            detail=f"{type(exc).__name__}: {exc}",
            command=command,
        )


def _remote_wireguard_lifecycle(ssh_target: str) -> CheckResult:
    """Run the local WireGuard source against isolated Linux command doubles."""
    bundle = io.BytesIO()
    with tarfile.open(fileobj=bundle, mode="w:gz") as archive:
        archive.add(ROOT / "scripts/services/wireguard.sh", arcname="wireguard.sh")
        archive.add(
            Path(__file__).with_name("wireguard_script_live.sh"),
            arcname="wireguard_script_live.sh",
        )
    remote_script = (
        "set -euo pipefail; "
        "test_dir=$(mktemp -d /tmp/easypi-wireguard-bundle.XXXXXX); "
        "trap 'rm -rf -- \"$test_dir\"' EXIT; "
        "tar -xzf - -C \"$test_dir\"; "
        "bash \"$test_dir/wireguard_script_live.sh\" \"$test_dir/wireguard.sh\""
    )
    command = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "ConnectTimeout=10",
        ssh_target,
        f"sudo bash -c {shlex.quote(remote_script)}",
    ]
    started = time.monotonic()
    try:
        process = subprocess.run(
            command,
            input=bundle.getvalue(),
            capture_output=True,
            timeout=120,
            check=False,
        )
        output = "\n".join(
            part.decode("utf-8", errors="replace")
            for part in (process.stdout, process.stderr)
            if part
        ).strip()
        return CheckResult(
            name="wireguard-lifecycle",
            status="pass" if process.returncode == 0 else "fail",
            duration_seconds=round(time.monotonic() - started, 3),
            detail=_tail(output) or f"exit code {process.returncode}",
            command=command,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return CheckResult(
            name="wireguard-lifecycle",
            status="fail",
            duration_seconds=round(time.monotonic() - started, 3),
            detail=f"{type(exc).__name__}: {exc}",
            command=command,
        )


def _commands() -> dict[str, tuple[list[str] | None, Path]]:
    python = _python()
    npm = shutil.which("npm.cmd" if os.name == "nt" else "npm")
    bash = shutil.which("bash.exe" if os.name == "nt" else "bash")
    ruff = [python, "-m", "ruff"]
    return {
        "ruff": (ruff + ["check", "backend", "easypi_netprotection", "prism_dpi", "scripts", "tests"], ROOT),
        "acceptance-tests": ([python, "-m", "pytest", "-q", "tests/acceptance/test_acceptance_harness.py"], ROOT),
        "security-tests": ([python, "-m", "pytest", "-q", "tests/security"], ROOT),
        "agent-tests": ([python, "-m", "pytest", "-q", "tests/agent"], ROOT),
        "camera-security-tests": (
            [
                python,
                "-m",
                "pytest",
                "-q",
                "tests/security/test_camera_recording_contract.py",
                "tests/security/test_go2rtc_proxy_security.py",
            ],
            ROOT,
        ),
        "operations-security-tests": (
            [
                python,
                "-m",
                "pytest",
                "-q",
                "tests/security/test_terminal_jobs_notifications_security.py",
                "tests/security/test_confirmed_audit_fixes.py",
            ],
            ROOT,
        ),
        "marketplace-help-security-tests": (
            [python, "-m", "pytest", "-q", "tests/security/test_marketplace_help_security.py"],
            ROOT,
        ),
        "frontend-lint": ([npm, "run", "lint"] if npm else None, ROOT / "frontend"),
        "frontend-types": ([npm, "run", "type-check"] if npm else None, ROOT / "frontend"),
        "browser-test-list": (
            [npm, "run", "test:e2e", "--", "--list"] if npm else None,
            ROOT / "frontend",
        ),
        "frontend-build": ([npm, "run", "build"] if npm else None, ROOT / "frontend"),
        "chameleon-tests": (
            [bash, "test.sh"] if bash else None,
            ROOT / "chameleon",
        ),
        "browser-public": (
            [npm, "run", "test:e2e", "--", "--project=public"] if npm else None,
            ROOT / "frontend",
        ),
        "browser-authenticated": (
            [npm, "run", "test:e2e", "--", "--project=authenticated"] if npm else None,
            ROOT / "frontend",
        ),
        "browser-safe-interactions": (
            [npm, "run", "test:e2e", "--", "--project=safe-interactions"] if npm else None,
            ROOT / "frontend",
        ),
        "browser-user-lifecycle": (
            [npm, "run", "test:e2e", "--", "--project=data-lifecycle"] if npm else None,
            ROOT / "frontend",
        ),
        "browser-picloud-lifecycle": (
            [npm, "run", "test:e2e", "--", "--project=cloud-lifecycle"] if npm else None,
            ROOT / "frontend",
        ),
        "browser-files-lifecycle": (
            [npm, "run", "test:e2e", "--", "--project=files-lifecycle"] if npm else None,
            ROOT / "frontend",
        ),
        "browser-agent-live": (
            [npm, "run", "test:e2e", "--", "--project=agent-live"] if npm else None,
            ROOT / "frontend",
        ),
        "browser-network-observe": (
            [npm, "run", "test:e2e", "--", "--project=network-observe"] if npm else None,
            ROOT / "frontend",
        ),
        "browser-operations-live": (
            [npm, "run", "test:e2e", "--", "--project=operations-live"] if npm else None,
            ROOT / "frontend",
        ),
        "browser-marketplace-help": (
            [npm, "run", "test:e2e", "--", "--project=marketplace-help"] if npm else None,
            ROOT / "frontend",
        ),
        "browser-backup-live": (
            [npm, "run", "test:e2e", "--", "--project=backup-live"] if npm else None,
            ROOT / "frontend",
        ),
        "browser-dns-rewrite-live": (
            [npm, "run", "test:e2e", "--", "--project=dns-rewrite-live"] if npm else None,
            ROOT / "frontend",
        ),
    }


def _shell_syntax() -> CheckResult:
    bash = shutil.which("bash")
    if not bash:
        return CheckResult("shell-syntax", "skip", 0.0, "bash is not installed")
    git = shutil.which("git")
    if not git:
        return CheckResult("shell-syntax", "skip", 0.0, "git is not installed")
    discovered = subprocess.run(
        [git, "ls-files", "--cached", "--others", "--exclude-standard", "--", "*.sh"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
    )
    if discovered.returncode != 0:
        return CheckResult("shell-syntax", "fail", 0.0, _tail(discovered.stderr))
    files = sorted(line.strip() for line in discovered.stdout.splitlines() if line.strip())
    if not files:
        return CheckResult("shell-syntax", "skip", 0.0, "no shell files found")
    return _run_command("shell-syntax", [bash, "-n", *files])


def _write_report(report_dir: Path, profile: str, results: list[CheckResult]) -> Path:
    summary = {
        "pass": sum(result.status == "pass" for result in results),
        "fail": sum(result.status == "fail" for result in results),
        "skip": sum(result.status == "skip" for result in results),
    }
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "profile": profile,
        "summary": summary,
        "results": [asdict(result) for result in results],
    }
    json_path = report_dir / "report.json"
    json_path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    overall = "FAIL" if summary["fail"] else ("PASS WITH SKIPS" if summary["skip"] else "PASS")
    lines = [
        "# EasyPi acceptance report",
        "",
        f"Profile: `{profile}`",
        f"Result: **{overall}**",
        f"Passed: {summary['pass']}; failed: {summary['fail']}; skipped: {summary['skip']}",
        "",
        "| Check | Status | Seconds | Evidence |",
        "|---|---:|---:|---|",
    ]
    for result in results:
        detail = result.detail.replace("|", "\\|").replace("\n", "<br>")
        lines.append(f"| {result.name} | {result.status.upper()} | {result.duration_seconds:.3f} | {detail} |")
    (report_dir / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    return json_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--profile",
        choices=(
            "quick", "full", "live-readonly", "browser", "browser-data",
            "browser-agent", "browser-network", "browser-operations", "browser-marketplace-help", "browser-backup", "browser-dns",
            "guard-functional", "prism-functional", "release-security",
            "chameleon-recovery", "wireguard-functional", "camera-security",
            "operations-security", "marketplace-help-security",
        ),
        default="quick",
    )
    parser.add_argument("--base-url", help="EasyPi URL for the live-readonly profile")
    parser.add_argument("--ssh-target", help="SSH alias or user@host; key authentication only")
    parser.add_argument("--insecure", action="store_true", help="Allow a test appliance self-signed TLS certificate")
    parser.add_argument("--browser-channel", help="Playwright browser channel, for example chrome")
    parser.add_argument("--report-dir", type=Path)
    parser.add_argument("--inventory-only", action="store_true")
    parser.add_argument("--strict-tools", action="store_true", help="Treat unavailable tools as failures")
    args = parser.parse_args()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    report_dir = (args.report_dir or DEFAULT_REPORT_ROOT / stamp).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    manifest = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))

    results = [_inventory_result(report_dir)]
    if not args.inventory_only:
        checks = manifest["profiles"][args.profile]
        commands = _commands()
        for check in checks:
            if check == "inventory":
                continue
            if check == "shell-syntax":
                results.append(_shell_syntax())
            elif check == "live-http":
                if args.base_url:
                    results.append(_live_http(args.base_url, args.insecure))
                else:
                    results.append(CheckResult(check, "skip", 0.0, "--base-url was not provided"))
            elif check == "remote-services":
                if args.ssh_target:
                    results.append(_remote_services(args.ssh_target))
                else:
                    results.append(CheckResult(check, "skip", 0.0, "--ssh-target was not provided"))
            elif check == "wireguard-lifecycle":
                if args.ssh_target:
                    results.append(_remote_wireguard_lifecycle(args.ssh_target))
                else:
                    results.append(CheckResult(check, "skip", 0.0, "--ssh-target was not provided"))
            elif check in {
                "guard-dns-filter",
                "prism-flow-observe",
                "release-signature-reject",
                "chameleon-reconnect",
                "chameleon-network-recovery",
                "chameleon-runtime-connectivity",
                "camera-go2rtc-boundary",
            }:
                if args.ssh_target:
                    script_name = {
                        "guard-dns-filter": "guard_dns_filter_check.sh",
                        "prism-flow-observe": "prism_flow_observe_check.sh",
                        "release-signature-reject": "release_signature_reject_check.sh",
                        "chameleon-reconnect": "chameleon_reconnect_check.sh",
                        "chameleon-network-recovery": "chameleon_network_recovery_check.sh",
                        "chameleon-runtime-connectivity": "chameleon_runtime_connectivity_check.sh",
                        "camera-go2rtc-boundary": "camera_go2rtc_boundary_check.sh",
                    }[check]
                    results.append(_remote_script(check, args.ssh_target, script_name))
                else:
                    results.append(CheckResult(check, "skip", 0.0, "--ssh-target was not provided"))
            elif check in commands:
                command, cwd = commands[check]
                if command is None:
                    status = "fail" if args.strict_tools else "skip"
                    results.append(CheckResult(check, status, 0.0, "required executable is not installed"))
                else:
                    extra_environment: dict[str, str] = {}
                    if check in {
                        "browser-public",
                        "browser-authenticated",
                        "browser-safe-interactions",
                        "browser-user-lifecycle",
                        "browser-picloud-lifecycle",
                        "browser-files-lifecycle",
                        "browser-agent-live",
                        "browser-network-observe",
                        "browser-operations-live",
                        "browser-marketplace-help",
                        "browser-backup-live",
                        "browser-dns-rewrite-live",
                    }:
                        if not args.base_url:
                            results.append(CheckResult(check, "skip", 0.0, "--base-url was not provided"))
                            continue
                        if check in {
                            "browser-authenticated",
                            "browser-safe-interactions",
                            "browser-user-lifecycle",
                            "browser-picloud-lifecycle",
                            "browser-files-lifecycle",
                            "browser-agent-live",
                            "browser-network-observe",
                            "browser-operations-live",
                            "browser-marketplace-help",
                            "browser-backup-live",
                            "browser-dns-rewrite-live",
                        } and not (
                            os.environ.get("EASYPI_E2E_USERNAME")
                            and os.environ.get("EASYPI_E2E_PASSWORD")
                        ):
                            results.append(
                                CheckResult(
                                    check,
                                    "skip",
                                    0.0,
                                    "test administrator credentials were not supplied",
                                )
                            )
                            continue
                        extra_environment["EASYPI_BASE_URL"] = args.base_url
                        if args.insecure:
                            extra_environment["EASYPI_E2E_INSECURE"] = "1"
                        if args.browser_channel:
                            extra_environment["EASYPI_E2E_CHANNEL"] = args.browser_channel
                        if args.ssh_target:
                            extra_environment["EASYPI_E2E_SSH_TARGET"] = args.ssh_target
                    results.append(_run_command(check, command, cwd, extra_environment))
                    if check in {
                        "browser-authenticated",
                        "browser-safe-interactions",
                        "browser-user-lifecycle",
                        "browser-picloud-lifecycle",
                        "browser-files-lifecycle",
                        "browser-agent-live",
                        "browser-network-observe",
                        "browser-operations-live",
                        "browser-marketplace-help",
                        "browser-backup-live",
                        "browser-dns-rewrite-live",
                    }:
                        (ROOT / ".build" / "acceptance" / "playwright-auth.json").unlink(
                            missing_ok=True
                        )
            else:
                results.append(CheckResult(check, "fail", 0.0, "unknown check in manifest"))

    report_path = _write_report(report_dir, args.profile, results)
    failed = any(result.status == "fail" for result in results)
    skipped = any(result.status == "skip" for result in results)
    overall = "FAIL" if failed else ("PASS_WITH_SKIPS" if skipped else "PASS")
    print(f"ACCEPTANCE={overall}")
    print(f"REPORT={report_path}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
