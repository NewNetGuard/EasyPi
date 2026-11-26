"""Safe Update applies host configuration changes, and the home tunnel never
crash-loops while it is not configured.

Safe Update copies the release and restarts services; only install.sh writes
/etc (Unbound, sudoers, firewall, unit templates). A release that changes those
inputs must therefore run the installer, or the fix never reaches the host.
"""
from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
UPDATER = ROOT / "scripts/maintenance/apply_update.sh"
AGENT = ROOT / "scripts/settings/mobile_link_agent.sh"
UNITS = ROOT / "templates/systemd"

posix_only = pytest.mark.skipif(os.name != "posix", reason="runs the updater digest under Linux bash")


def _updater() -> str:
    return UPDATER.read_text(encoding="utf-8")


def _inputs() -> list[str]:
    block = _updater().split("HOST_SETUP_INPUTS=(", 1)[1].split(")", 1)[0]
    return block.split()


def test_host_setup_inputs_cover_everything_install_applies_to_the_host() -> None:
    inputs = set(_inputs())
    assert {"install.sh", "templates", "scripts/setup", "scripts/sudoers.d"} <= inputs
    for entry in inputs:
        assert (ROOT / entry).exists(), entry
    # Every setup script the installer calls from the scripts tree is covered.
    install = (ROOT / "install.sh").read_text(encoding="utf-8")
    for match in sorted(set(re.findall(r'\$\{SCRIPTS_DST\}/((?:setup|sudoers\.d|security/setup_firewall|services/install_netprotection|settings/setup_)[A-Za-z0-9_./-]*)', install))):
        assert any(match == entry.removeprefix("scripts/") or match.startswith(entry.removeprefix("scripts/") + "/")
                   for entry in inputs), match


def test_changed_host_setup_forces_the_installer_before_any_file_is_applied() -> None:
    script = _updater()
    trigger = script.index('if [[ "${RUN_INSTALL}" -eq 0 && "${PAYLOAD_HOST_DIGEST}" != "${INSTALLED_HOST_DIGEST}" ]]; then')
    assert "RUN_INSTALL=1" in script[trigger : trigger + 200]
    assert script.index('PAYLOAD_HOST_DIGEST="$(host_setup_digest "${PAYLOAD}")"') < trigger
    assert '|| die "Signed release contains unsafe host setup files"' in script
    # Decided before the dry run, the snapshot and the file copy.
    assert trigger < script.index("# --- Dry run: preview the file changes")
    assert trigger < script.index('rsync "${RSYNC_ARGS[@]}" "${PAYLOAD}/" "${TARGET_DIR}/"')
    # The installer that runs is the trusted extracted copy.
    assert '( cd "${PAYLOAD}" && bash "${PAYLOAD}/install.sh" --binary )' in script


def _digest(root: Path) -> str:
    script = _updater()
    start = script.index("HOST_SETUP_INPUTS=(")
    end = script.index("\n}\n", script.index("host_setup_digest() {")) + 3
    harness = f'set -euo pipefail\n{script[start:end]}\nhost_setup_digest "{root.as_posix()}"\n'
    result = subprocess.run(["bash", "-c", harness], capture_output=True, text=True, check=True)
    return result.stdout.strip()


def _tree(path: Path) -> Path:
    (path / "templates/systemd").mkdir(parents=True)
    (path / "scripts/setup").mkdir(parents=True)
    (path / "scripts/sudoers.d").mkdir(parents=True)
    (path / "backend").mkdir()
    (path / "install.sh").write_text("#!/bin/bash\n", encoding="utf-8")
    (path / "templates/systemd/a.service").write_text("[Unit]\n", encoding="utf-8")
    (path / "scripts/setup/setup_unbound.sh").write_text("harden-referral-path: no\n", encoding="utf-8")
    (path / "scripts/sudoers.d/easypi").write_text("# rules\n", encoding="utf-8")
    (path / "backend/app.py").write_text("print(1)\n", encoding="utf-8")
    return path


@posix_only
def test_digest_changes_only_with_host_setup_inputs(tmp_path: Path) -> None:
    installed, payload = _tree(tmp_path / "installed"), _tree(tmp_path / "payload")
    baseline = _digest(installed)
    assert re.fullmatch(r"[0-9a-f]{64}", baseline)
    assert _digest(payload) == baseline

    # Application-only change: Safe Update stays a plain copy.
    (payload / "backend/app.py").write_text("print(2)\n", encoding="utf-8")
    assert _digest(payload) == baseline

    (payload / "scripts/setup/setup_unbound.sh").write_text("harden-referral-path: yes\n", encoding="utf-8")
    assert _digest(payload) != baseline


@posix_only
def test_new_or_removed_host_files_change_the_digest(tmp_path: Path) -> None:
    installed, payload = _tree(tmp_path / "installed"), _tree(tmp_path / "payload")
    (payload / "templates/systemd/new.timer").write_text("[Timer]\n", encoding="utf-8")
    assert _digest(payload) != _digest(installed)
    (installed / "install.sh").unlink()
    assert _digest(installed) != _digest(_tree(tmp_path / "fresh"))


@posix_only
def test_symlinked_host_input_is_rejected(tmp_path: Path) -> None:
    payload = _tree(tmp_path / "payload")
    (payload / "templates/systemd/evil.service").symlink_to("/etc/shadow")
    assert _digest(payload) == "missing-or-unsafe"


def _unit(name: str) -> str:
    return (UNITS / name).read_text(encoding="utf-8")


def test_home_tunnel_units_are_skipped_until_the_home_server_is_configured() -> None:
    home = _unit("easypi-mobile-home-tunnel.service").split("[Service]", 1)[0]
    agent = _unit("easypi-mobile-home-tunnel-agent.service").split("[Service]", 1)[0]
    assert "ConditionFileNotEmpty=/etc/easypi-mobile-home/server_config.json" in home
    assert "ConditionFileNotEmpty=/etc/easypi-mobile-home/server_config.json" in agent
    assert "ConditionFileNotEmpty=/etc/easypi-mobile-link/tunnel-agent.json" in agent
    # The home server reads its configuration from the guarded directory.
    assert "WorkingDirectory=/etc/easypi-mobile-home" in _unit("easypi-mobile-home-tunnel.service")


def test_enabling_mobile_link_starts_the_tunnel_agent_only_with_a_home_server() -> None:
    script = AGENT.read_text(encoding="utf-8")
    enable = script.split("\n  enable)\n", 1)[1].split("\n    ;;\n", 1)[0]
    assert 'systemctl enable --now "$SERVICE" >/dev/null' in enable
    assert 'systemctl enable --now "$SERVICE" "$TUNNEL_SERVICE"' not in enable
    guarded = enable.split('if [[ -s "$TUNNEL_CONFIG_FILE" && -s "$HOME_CONFIG" ]]; then', 1)[1]
    assert 'systemctl enable --now "$TUNNEL_SERVICE"' in guarded.split("fi", 1)[0]
    assert "stop_unconfigured_home_tunnel" in guarded.split("\n    fi", 1)[0].split("else", 1)[1]
    # Every signed update calls ensure-endpoint, so a loop left by an earlier
    # release ends with the update (systemd does not re-check the unit's
    # Condition on automatic restarts).
    endpoint = script.split("\n  ensure-endpoint)\n", 1)[1].split("\n    ;;\n", 1)[0]
    assert endpoint.index("ensure_private_endpoint") < endpoint.index("stop_unconfigured_home_tunnel")
    stop = script.split("stop_unconfigured_home_tunnel() {", 1)[1].split("\n}\n", 1)[0]
    assert '[[ -s "$HOME_CONFIG" ]] && return 0' in stop
    assert 'systemctl disable --now "$TUNNEL_SERVICE" "$HOME_SERVICE"' in stop
    updater = _updater()
    assert '"${TARGET_DIR}/scripts/settings/mobile_link_agent.sh" ensure-endpoint' in updater
    # Disabling still stops both.
    disable = script.split("\n  disable)\n", 1)[1].split("\n    ;;\n", 1)[0]
    assert '"$SERVICE" "$TUNNEL_SERVICE"' in disable
