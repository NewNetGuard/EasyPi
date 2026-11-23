from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess

import pytest


ROOT = Path(__file__).resolve().parents[2]
SCRIPT_PATH = ROOT / "backend/app/api/v1/endpoints/dns_deployment_scripts.py"
SPEC = importlib.util.spec_from_file_location("dns_deployment_scripts", SCRIPT_PATH)
assert SPEC is not None and SPEC.loader is not None
dns_deployment_scripts = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(dns_deployment_scripts)


def _certbot_helper(tmp_path: Path) -> str:
    deployment = dns_deployment_scripts.SECURE_DEPLOYMENT_SCRIPT
    start = deployment.index("run_certbot_with_optional_vps_guard() (")
    end = deployment.index("\n)\n\nif [", start) + len("\n)")
    helper = deployment[start:end]
    return (
        helper.replace(
            'guard="/usr/local/sbin/easypi-vps-guard"',
            f'guard="{tmp_path / "missing-vps-guard"}"',
        )
        .replace(
            'certbot_lock="/run/easypi-certbot.lock"',
            f'certbot_lock="{tmp_path / "certbot.lock"}"',
        )
        .replace("sleep 5", "sleep 0.01")
    )


def _fake_certbot(tmp_path: Path, body: str) -> Path:
    fake = tmp_path / "certbot"
    fake.write_text("#!/bin/sh\nset -eu\n" + body, encoding="utf-8")
    fake.chmod(0o700)
    return fake


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX shell and flock")
def test_personal_dns_retries_only_busy_certbot(tmp_path: Path) -> None:
    counter = tmp_path / "counter"
    fake = _fake_certbot(
        tmp_path,
        'count="$(cat "$COUNTER_FILE" 2>/dev/null || echo 0)"\n'
        'count=$((count + 1))\n'
        'printf "%s" "$count" > "$COUNTER_FILE"\n'
        'if [ "$count" -eq 1 ]; then\n'
        '  echo "Another instance of Certbot is already running." >&2\n'
        "  exit 1\n"
        "fi\n"
        'echo "certificate ready"\n',
    )
    command = _certbot_helper(tmp_path) + f'\nrun_certbot_with_optional_vps_guard "{fake}"\n'

    result = subprocess.run(
        ["bash", "-c", command],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "COUNTER_FILE": str(counter)},
    )

    assert result.returncode == 0, result.stderr
    assert counter.read_text(encoding="utf-8") == "2"
    assert "retrying in 5 seconds" in result.stderr
    assert "certificate ready" in result.stdout


@pytest.mark.skipif(os.name == "nt", reason="requires POSIX shell and flock")
def test_personal_dns_does_not_retry_other_certbot_failure(tmp_path: Path) -> None:
    counter = tmp_path / "counter"
    fake = _fake_certbot(
        tmp_path,
        'count="$(cat "$COUNTER_FILE" 2>/dev/null || echo 0)"\n'
        'count=$((count + 1))\n'
        'printf "%s" "$count" > "$COUNTER_FILE"\n'
        'echo "DNS validation failed" >&2\n'
        "exit 42\n",
    )
    command = _certbot_helper(tmp_path) + f'\nrun_certbot_with_optional_vps_guard "{fake}"\n'

    result = subprocess.run(
        ["bash", "-c", command],
        check=False,
        capture_output=True,
        text=True,
        env={**os.environ, "COUNTER_FILE": str(counter)},
    )

    assert result.returncode == 42
    assert counter.read_text(encoding="utf-8") == "1"
    assert "DNS validation failed" in result.stderr
    assert "retrying" not in result.stderr
