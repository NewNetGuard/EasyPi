"""Unbound recursion settings and the IPv6 transport check.

A cold Unbound with do-ip6 on an IPv6-less host, or with the experimental
harden-referral-path, exceeds max-global-quota and answers SERVFAIL for valid,
signed domains (see scripts/maintenance/unbound_ipv6_transport.sh)."""
from __future__ import annotations

import re
import shlex
import shutil
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SETUP = ROOT / "scripts" / "setup" / "setup_unbound.sh"
TRANSPORT = "./scripts/maintenance/unbound_ipv6_transport.sh"

V4_ROOTS = "198.41.0.4 193.0.14.129 192.33.4.12"
V6_ROOTS = "2001:503:ba3e::2:30 2001:7fd::1 2001:500:2::c"


def _setup_config() -> str:
    text = SETUP.read_text(encoding="utf-8")
    return text.split("<< 'UNBOUND_CONFIG'", 1)[1].split("\nUNBOUND_CONFIG", 1)[0]


def test_unbound_config_keeps_dnssec_and_drops_referral_path_hardening() -> None:
    config = _setup_config()
    options = dict(
        re.findall(r"^\s*([a-z0-9-]+):\s*(\S+)", config, flags=re.MULTILINE)
    )
    assert options["harden-referral-path"] == "no"
    assert options["val-bogus-ttl"] == "10"
    # DNSSEC validation itself is untouched.
    assert options["harden-dnssec-stripped"] == "yes"
    assert options["harden-algo-downgrade"] == "yes"
    assert options["harden-below-nxdomain"] == "yes"
    assert "module-config" not in options
    assert "val-permissive-mode" not in options
    # The upstream budget is Unbound's own default, not raised to hide failures.
    assert "max-global-quota" not in options
    # IPv6 transport lives in the managed snippet, not in the static file.
    assert "do-ip6" not in options


def _host_path(path: Path) -> str:
    """Path as the bash in use sees it (Linux, WSL /mnt/c or MSYS /c)."""
    value = path.resolve().as_posix()
    if len(value) >= 3 and value[1:3] == ":/":
        bash = (shutil.which("bash") or "").lower()
        prefix = "/mnt/" if "system32" in bash or "windowsapps" in bash else "/"
        return f"{prefix}{value[0].lower()}{value[2:]}"
    return value


FAKES = {
    "dig": r"""#!/bin/bash
family=""; server=""
for arg in "$@"; do
  case "$arg" in -4|-6) family="${arg#-}" ;; @*) server="${arg#@}" ;; esac
done
up="$V4_UP"; [[ "$family" == 6 ]] && up="$V6_UP"
for address in $up; do
  if [[ "$address" == "$server" ]]; then
    echo ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 1"; exit 0
  fi
done
echo ";; communications error: network unreachable"; exit 9
""",
    "unbound-checkconf": '#!/bin/bash\necho "checkconf" >> "$CALLS"\nexit "${CHECKCONF_RC:-0}"\n',
    "unbound-control": '#!/bin/bash\necho "unbound-control $*" >> "$CALLS"\n',
    "systemctl": '#!/bin/bash\necho "systemctl $*" >> "$CALLS"\n',
}


def _run(
    tmp_path: Path,
    *,
    v4_up: str,
    v6_up: str,
    existing: str | None = None,
    args: str = "",
    checkconf_rc: int = 0,
) -> tuple[subprocess.CompletedProcess[str], str | None, list[str]]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    for name, text in FAKES.items():
        (bin_dir / name).write_text(text, encoding="utf-8", newline="\n")
    snippet = tmp_path / "easypi-transport.conf"
    if existing is not None:
        snippet.write_text(f"server:\n    do-ip6: {existing}\n", encoding="utf-8", newline="\n")
    calls = tmp_path / "calls"
    bash = shutil.which("bash")
    assert bash is not None
    # The script resets PATH when sourced; the fakes are put first afterwards.
    script = (
        f"chmod 700 {shlex.quote(_host_path(bin_dir))}/* && "
        f"export EASYPI_UNBOUND_TRANSPORT_FILE={shlex.quote(_host_path(snippet))} && "
        f"set -- {args} && source {TRANSPORT} && "
        f"export PATH={shlex.quote(_host_path(bin_dir))}:/usr/bin:/bin "
        f"CALLS={shlex.quote(_host_path(calls))} V4_UP={shlex.quote(v4_up)} "
        f"V6_UP={shlex.quote(v6_up)} CHECKCONF_RC={checkconf_rc} && main"
    )
    result = subprocess.run(
        [bash, "-c", script], cwd=ROOT, check=False, capture_output=True, text=True
    )
    content = snippet.read_text(encoding="utf-8") if snippet.exists() else None
    recorded = calls.read_text(encoding="utf-8").splitlines() if calls.exists() else []
    return result, content, recorded


def _setting(content: str | None) -> str | None:
    if content is None:
        return None
    match = re.search(r"^\s*do-ip6:\s*(yes|no)\s*$", content, flags=re.MULTILINE)
    return match.group(1) if match else None


def test_ipv6_less_host_gets_do_ip6_no_and_a_cache_keeping_reload(tmp_path: Path) -> None:
    result, content, calls = _run(tmp_path, v4_up=V4_ROOTS, v6_up="")
    assert result.returncode == 0, result.stderr
    assert _setting(content) == "no"
    assert content.startswith("# Managed by EasyPi")
    assert calls == [
        "checkconf",
        "systemctl is-active --quiet unbound",
        "unbound-control reload_keep_cache",
    ]


def test_working_ipv6_enables_the_transport(tmp_path: Path) -> None:
    result, content, _ = _run(tmp_path, v4_up=V4_ROOTS, v6_up=V6_ROOTS, existing="no")
    assert result.returncode == 0, result.stderr
    assert _setting(content) == "yes"


def test_offline_host_leaves_the_transport_unchanged(tmp_path: Path) -> None:
    result, content, calls = _run(tmp_path, v4_up="", v6_up="", existing="yes")
    assert result.returncode == 0, result.stderr
    assert _setting(content) == "yes"
    assert calls == []


def test_single_ipv6_answer_does_not_flap_an_existing_setting(tmp_path: Path) -> None:
    result, content, calls = _run(
        tmp_path, v4_up=V4_ROOTS, v6_up="2001:7fd::1", existing="yes"
    )
    assert result.returncode == 0, result.stderr
    assert _setting(content) == "yes"
    assert calls == []


def test_single_ipv6_answer_without_a_setting_chooses_ipv4_only(tmp_path: Path) -> None:
    result, content, _ = _run(tmp_path, v4_up=V4_ROOTS, v6_up="2001:7fd::1")
    assert result.returncode == 0, result.stderr
    assert _setting(content) == "no"


def test_unchanged_decision_does_not_reload(tmp_path: Path) -> None:
    result, content, calls = _run(tmp_path, v4_up=V4_ROOTS, v6_up="", existing="no")
    assert result.returncode == 0, result.stderr
    assert _setting(content) == "no"
    assert calls == []


def test_rejected_configuration_restores_the_previous_snippet(tmp_path: Path) -> None:
    result, content, calls = _run(
        tmp_path, v4_up=V4_ROOTS, v6_up="", existing="yes", checkconf_rc=1
    )
    assert result.returncode != 0
    assert _setting(content) == "yes"
    assert "unbound-control reload_keep_cache" not in calls


def test_dry_run_changes_nothing(tmp_path: Path) -> None:
    result, content, calls = _run(tmp_path, v4_up=V4_ROOTS, v6_up="", args="--dry-run")
    assert result.returncode == 0, result.stderr
    assert content is None
    assert calls == []


def test_no_reload_writes_but_leaves_reload_to_the_installer(tmp_path: Path) -> None:
    result, content, calls = _run(tmp_path, v4_up=V4_ROOTS, v6_up="", args="--no-reload")
    assert result.returncode == 0, result.stderr
    assert _setting(content) == "no"
    assert calls == ["checkconf"]
