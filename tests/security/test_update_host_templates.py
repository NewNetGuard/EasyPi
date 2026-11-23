"""Ordinary signed updates keep root-interpreted host files in sync.

A normal update does not run the full installer, so the nginx site and the
root Taildrop importer unit would otherwise keep the configuration of the
release that was first installed, including any boundary a later release fixed.
"""
from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
UPDATER = ROOT / "scripts/maintenance/apply_update.sh"
NGINX_TEMPLATE = ROOT / "templates/nginx/easypi.conf"
TAILDROP_TEMPLATE = ROOT / "templates/systemd/easypi-taildrop-import.service"

posix_only = pytest.mark.skipif(os.name != "posix", reason="runs the updater functions under Linux bash")


def _function(name: str) -> str:
    script = UPDATER.read_text(encoding="utf-8")
    start = script.index(f"{name}() {{")
    return script[start : script.index("\n}\n", start) + 3]


def _run(function: str, tmp_path: Path, *, nginx_ok: bool = True) -> subprocess.CompletedProcess:
    """Run one updater function with only its host directories redirected."""
    body = (
        _function(function)
        .replace("/etc/nginx/sites-available", (tmp_path / "sites").as_posix())
        .replace("/etc/systemd/system", (tmp_path / "units").as_posix())
    )
    harness = f"""
set -euo pipefail
TARGET_DIR="{(tmp_path / 'release').as_posix()}"
warn() {{ echo "WARN: $1" >&2; }}
# The real function assigns root ownership; an unprivileged test cannot.
install() {{
  local args=()
  while (($#)); do
    case "$1" in -o|-g) shift 2;; *) args+=("$1"); shift;; esac
  done
  command install "${{args[@]}}"
}}
nginx() {{ echo called >> "{(tmp_path / 'nginx.calls').as_posix()}"; [[ "{int(nginx_ok)}" == 1 ]]; }}
{body}
{function}
"""
    return subprocess.run(["bash", "-c", harness], capture_output=True, text=True, check=False)


def _layout(tmp_path: Path) -> tuple[Path, Path, Path]:
    release, sites, units = tmp_path / "release", tmp_path / "sites", tmp_path / "units"
    (release / "templates/nginx").mkdir(parents=True)
    (release / "templates/systemd").mkdir(parents=True)
    sites.mkdir()
    units.mkdir()
    (release / "templates/nginx/easypi.conf").write_bytes(NGINX_TEMPLATE.read_bytes())
    (release / "templates/systemd/easypi-taildrop-import.service").write_bytes(
        TAILDROP_TEMPLATE.read_bytes()
    )
    return release, sites, units


def _leftovers(directory: Path) -> list[str]:
    return sorted(entry.name for entry in directory.iterdir() if entry.name.startswith("."))


def test_restart_cycle_refreshes_the_site_and_the_root_unit_before_restarting() -> None:
    restart = _function("restart_services")
    assert "refresh_nginx_site \\\n    || die " in restart
    assert "refresh_taildrop_unit\n" in restart
    loop = restart.index("for svc in")
    assert restart.index("refresh_nginx_site") < loop
    assert restart.index("refresh_taildrop_unit") < restart.index("systemctl daemon-reload") < loop
    assert "easypi-taildrop-import nginx" in restart[loop:]
    # A rollback restores the previous tree and then runs this same cycle, so
    # the host files follow the restored templates.
    assert "restart_services" in _function("rollback_from")


def test_staged_update_never_leaves_an_unloaded_site_configuration() -> None:
    script = UPDATER.read_text(encoding="utf-8")
    # The same condition also guards an earlier failure path; the staged-update
    # branch is the last one, after the restart and health gate.
    staged = script[script.rindex('elif [[ "${BACKEND_STOPPED_FOR_UPDATE}" -eq 1 ]]; then') :]
    staged = staged[: staged.index("\nfi\n")]
    assert "--skip-restart suppresses the broad service cycle" in staged
    assert "refresh_taildrop_unit" in staged
    assert "\n  refresh_nginx_site" not in staged


def test_site_refresh_checks_every_step_and_validates_before_keeping() -> None:
    site = _function("refresh_nginx_site")
    assert '[[ -f "${site}" && ! -L "${site}" ]] || return 0' in site
    assert "nginx -t" in site
    assert 'mv -f -- "${previous}" "${site}"' in site
    assert '[[ ! -s "${rendered}" ]]' in site
    unit = _function("refresh_taildrop_unit")
    assert '[[ -f "${unit}" && ! -L "${unit}" ]] || return 0' in unit
    assert "grep -q '^ExecStart=' \"${staged}\"" in unit


@posix_only
def test_site_is_replaced_by_the_release_template(tmp_path: Path) -> None:
    release, sites, _units = _layout(tmp_path)
    (sites / "easypi").write_text("server { listen 443 ssl; }\n", encoding="utf-8")
    result = _run("refresh_nginx_site", tmp_path)
    assert result.returncode == 0, result.stderr
    installed = (sites / "easypi").read_text(encoding="utf-8")
    assert "auth_request /_easypi_mobile_auth;" in installed
    assert "/opt/EasyPi" not in installed
    assert release.as_posix() in installed
    assert _leftovers(sites) == []


@posix_only
def test_rejected_site_keeps_the_previous_configuration(tmp_path: Path) -> None:
    _release, sites, _units = _layout(tmp_path)
    (sites / "easypi").write_text("server { listen 443 ssl; }\n", encoding="utf-8")
    result = _run("refresh_nginx_site", tmp_path, nginx_ok=False)
    assert result.returncode == 1
    assert "previous one was kept" in result.stderr
    assert (sites / "easypi").read_text(encoding="utf-8") == "server { listen 443 ssl; }\n"
    assert _leftovers(sites) == []


@posix_only
def test_unrendered_template_never_replaces_the_site(tmp_path: Path) -> None:
    release, sites, _units = _layout(tmp_path)
    (release / "templates/nginx/easypi.conf").write_bytes(b"")
    (sites / "easypi").write_text("server { listen 443 ssl; }\n", encoding="utf-8")
    result = _run("refresh_nginx_site", tmp_path)
    assert result.returncode == 1
    assert (sites / "easypi").read_text(encoding="utf-8") == "server { listen 443 ssl; }\n"
    assert not (tmp_path / "nginx.calls").exists()
    assert _leftovers(sites) == []


@posix_only
def test_site_is_not_created_followed_or_rewritten_needlessly(tmp_path: Path) -> None:
    _release, sites, _units = _layout(tmp_path)
    assert _run("refresh_nginx_site", tmp_path).returncode == 0
    assert list(sites.iterdir()) == []

    outside = tmp_path / "outside.conf"
    outside.write_text("unrelated\n", encoding="utf-8")
    (sites / "easypi").symlink_to(outside)
    assert _run("refresh_nginx_site", tmp_path).returncode == 0
    assert outside.read_text(encoding="utf-8") == "unrelated\n"
    assert (sites / "easypi").is_symlink()

    (sites / "easypi").unlink()
    (sites / "easypi").write_text("server {}\n", encoding="utf-8")
    assert _run("refresh_nginx_site", tmp_path).returncode == 0
    current = (sites / "easypi").read_bytes()
    (tmp_path / "nginx.calls").unlink()
    # Already current: nothing is rewritten and nginx is not consulted again.
    assert _run("refresh_nginx_site", tmp_path, nginx_ok=False).returncode == 0
    assert (sites / "easypi").read_bytes() == current
    assert not (tmp_path / "nginx.calls").exists()


@posix_only
def test_root_unit_stops_loading_the_settings_file_and_keeps_its_account(tmp_path: Path) -> None:
    _release, _sites, units = _layout(tmp_path)
    unit = units / "easypi-taildrop-import.service"
    unit.write_text(
        "[Service]\nUser=root\nEnvironmentFile=-/opt/EasyPi/.env\n"
        "ExecStart=/usr/bin/python3 /opt/EasyPi/scripts/services/picloud_taildrop_import.py"
        " --state /var/lib/easypi/taildrop --owner pi-cloud --group pi-data\n",
        encoding="utf-8",
    )
    result = _run("refresh_taildrop_unit", tmp_path)
    assert result.returncode == 0, result.stderr
    installed = unit.read_text(encoding="utf-8")
    assert "EnvironmentFile" not in installed
    assert "--owner pi-cloud --group pi-data --settings-file " in installed
    assert "/opt/EasyPi" not in installed
    assert _leftovers(units) == []


@posix_only
def test_root_unit_is_not_recreated_and_survives_a_broken_template(tmp_path: Path) -> None:
    release, _sites, units = _layout(tmp_path)
    assert _run("refresh_taildrop_unit", tmp_path).returncode == 0
    assert list(units.iterdir()) == []

    unit = units / "easypi-taildrop-import.service"
    unit.write_text("[Service]\nExecStart=/bin/true --owner easypi --group easypi\n", encoding="utf-8")
    (release / "templates/systemd/easypi-taildrop-import.service").write_bytes(b"")
    result = _run("refresh_taildrop_unit", tmp_path)
    assert result.returncode == 1
    assert "installed unit was kept" in result.stderr
    assert unit.read_text(encoding="utf-8").startswith("[Service]\nExecStart=/bin/true")
    assert _leftovers(units) == []
