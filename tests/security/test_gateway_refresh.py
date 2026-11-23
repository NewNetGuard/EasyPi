"""Run the gateway timer function with command stubs, never the real firewall."""

import os
from pathlib import Path
import subprocess
import pytest

ROOT = Path(__file__).resolve().parents[2]
pytestmark = pytest.mark.skipif(
    os.name != "posix", reason="requires bash command stubs"
)


def run(tmp_path, present, fail=False):
    source = (ROOT / "scripts/setup/gateway_fix.sh").read_text()
    function = (
        "ensure_forwarding_rules() {"
        + source.split("ensure_forwarding_rules() {", 1)[1].split("\nsetup_nat() {", 1)[
            0
        ]
    )
    state = tmp_path / "present"
    log = tmp_path / "commands"
    if present:
        state.touch()
    harness = (
        """
log() { :; }
mock_iptables() {
 printf 'iptables %s\n' "$*" >> "$PROBE_LOG"
 if [[ "$*" == '-C ufw-user-forward -i test0 -o test0 -j ACCEPT' ]]; then [[ -f "$PROBE_STATE" ]]; return $?; fi
 return 1
}
ufw() {
 printf 'ufw %s\n' "$*" >> "$PROBE_LOG"
 if [[ "$1" == status ]]; then echo 'Status: active'; return 0; fi
 if [[ "$1" == route ]]; then
  [[ "$PROBE_FAIL" == 1 ]] && return 1
  touch "$PROBE_STATE"; return 0
 fi
 return 97
}
IPTABLES_CMD=mock_iptables
"""
        + function
        + "\nensure_forwarding_rules test0 || exit $?\nensure_forwarding_rules test0\n"
    )
    result = subprocess.run(
        ["bash", "-c", harness],
        env={
            **os.environ,
            "PROBE_LOG": str(log),
            "PROBE_STATE": str(state),
            "PROBE_FAIL": "1" if fail else "0",
        },
        capture_output=True,
        text=True,
        timeout=5,
    )
    return result, log.read_text().splitlines()


def test_healthy_repeated_ticks_never_reload_or_mutate(tmp_path):
    result, commands = run(tmp_path, True)
    assert result.returncode == 0
    assert not any(
        c.startswith(("ufw route", "ufw reload", "iptables -D")) for c in commands
    )


def test_missing_route_is_added_once_without_whole_firewall_reload(tmp_path):
    result, commands = run(tmp_path, False)
    assert result.returncode == 0
    assert commands.count("ufw route allow in on test0 out on test0") == 1
    assert "ufw reload" not in commands


def test_route_error_does_not_trigger_reload_or_broad_accept(tmp_path):
    result, commands = run(tmp_path, False, True)
    assert result.returncode != 0
    assert "ufw reload" not in commands
    assert not any(
        c.startswith("iptables -A") or c.startswith("iptables -I") for c in commands
    )
