from __future__ import annotations

import json
import os
import struct
import subprocess
from pathlib import Path

import pytest

from scripts.maintenance import verify_runtime_health as health


def completed(
    *command: str, rc: int = 0, stdout: str = ""
) -> subprocess.CompletedProcess[str]:
    return subprocess.CompletedProcess(command, rc, stdout=stdout, stderr="")


def bash_path(path: Path) -> str:
    value = path.resolve().as_posix()
    if os.name == "nt" and len(value) > 2 and value[1] == ":":
        return f"/mnt/{value[0].lower()}{value[2:]}"
    return value


def healthy_stealth_outputs(*, connected: bool = False) -> dict[tuple[str, ...], str]:
    pre4 = [
        f"-N {health.PRE_CHAIN}",
        f"-A {health.PRE_CHAIN} -o cham0 -j RETURN",
        f"-A {health.PRE_CHAIN} -o chtcp0 -j RETURN",
        *(
            f"-A {health.PRE_CHAIN} -d {network} -j RETURN"
            for network in (
                "10.0.0.0/8",
                "100.64.0.0/10",
                "172.16.0.0/12",
                "192.168.0.0/16",
                "169.254.0.0/16",
            )
        ),
        f"-A {health.PRE_CHAIN} -j DROP",
    ]
    dns_routes = ["blackhole default metric 42760"]
    if connected:
        dns_routes.insert(0, "default dev cham0 metric 10")
    return {
        ("id", "-u", "easypi-stealth-dns"): "991\n",
        ("ip", "rule", "show"): "5094: from all uidrange 991-991 lookup 51823\n",
        ("ip", "route", "show", "table", "51821"): (
            "default dev cham0\n" if connected else "blackhole default metric 42760\n"
        ),
        ("ip", "route", "show", "table", "51823"): "\n".join(dns_routes) + "\n",
        ("ip", "link", "show", "dev", "cham0"): "cham0: <UP,LOWER_UP>\n",
        ("iptables", "-S", "FORWARD"): (
            f"-P FORWARD DROP\n-A FORWARD -j {health.PRE_CHAIN}\n"
            "-A FORWARD -j ACCEPT\n"
        ),
        ("ip6tables", "-S", "FORWARD"): (
            f"-P FORWARD DROP\n-A FORWARD -j {health.PRE6_CHAIN}\n"
            "-A FORWARD -j ACCEPT\n"
        ),
        ("iptables", "-S", health.PRE_CHAIN): "\n".join(pre4) + "\n",
        ("ip6tables", "-S", health.PRE6_CHAIN): (
            f"-N {health.PRE6_CHAIN}\n-A {health.PRE6_CHAIN} -j DROP\n"
        ),
        ("iptables", "-S", "OUTPUT"): (
            f"-P OUTPUT ACCEPT\n-A OUTPUT -j {health.DNS_EGRESS_CHAIN}\n"
            "-A OUTPUT -j ACCEPT\n"
        ),
        ("iptables", "-S", health.DNS_EGRESS_CHAIN): (
            f"-N {health.DNS_EGRESS_CHAIN}\n"
            f"-A {health.DNS_EGRESS_CHAIN} -o cham0 -p tcp -m tcp --dport 53 "
            "-m owner --uid-owner 991 -j ACCEPT\n"
            f"-A {health.DNS_EGRESS_CHAIN} -o cham0 -p udp -m udp --dport 53 "
            "-m owner --uid-owner 991 -j ACCEPT\n"
            f"-A {health.DNS_EGRESS_CHAIN} -o lo -m owner --uid-owner 991 -j ACCEPT\n"
            f"-A {health.DNS_EGRESS_CHAIN} -m owner --uid-owner 991 "
            "-j REJECT --reject-with icmp-port-unreachable\n"
        ),
    }


def fake_run_from(outputs: dict[tuple[str, ...], str]):
    def fake_run(*command: str):
        return completed(*command, stdout=outputs.get(command, ""))

    return fake_run


def stealth_reader(*, connected: bool = False, config: bool = True):
    def fake_read(path: Path, **_kwargs):
        if path == health.STEALTH_POLICY:
            return {"version": 1, "enabled": True, "scope": "all", "macs": []}
        if path == health.STEALTH_CONFIG:
            return {"server_address": "203.0.113.10:443"} if config else None
        if path == health.STEALTH_META:
            return {"enabled": True}
        if path == health.STEALTH_STATUS:
            return {"connected": connected}
        return None

    return fake_read


def prepare_health(monkeypatch, *, connected: bool = False, config: bool = True) -> None:
    monkeypatch.setattr(health, "read_json", stealth_reader(connected=connected, config=config))
    monkeypatch.setattr(health, "service_active", lambda _name: True)
    monkeypatch.setattr(health, "dns_probe", lambda **_kwargs: (True, ""))
    monkeypatch.setattr(
        health,
        "run",
        fake_run_from(healthy_stealth_outputs(connected=connected)),
    )


def test_health_gate_accepts_healthy_core_without_optional_modes(monkeypatch) -> None:
    monkeypatch.setattr(health, "service_active", lambda _name: True)
    monkeypatch.setattr(health, "dns_probe", lambda **_kwargs: (True, ""))
    monkeypatch.setattr(health, "read_json", lambda _path, **_kwargs: None)

    assert health.verify() == []


def test_health_gate_rejects_enabled_stealth_without_config(monkeypatch) -> None:
    prepare_health(monkeypatch, connected=True, config=False)

    assert "strict Chameleon policy is enabled without a safe client config" in health.verify()


def test_health_gate_rejects_broken_gateway_forwarding_and_nat(
    monkeypatch, tmp_path: Path
) -> None:
    forwarding = tmp_path / "ip_forward"
    forwarding.write_text("0\n", encoding="ascii")

    def fake_read(path: Path, **_kwargs):
        if path == health.GATEWAY_STATE:
            return {"enabled": True, "wan_iface": "eth0"}
        return None

    def fake_run(*command: str):
        if command[:4] == ("iptables", "-t", "nat", "-C"):
            return completed(*command, rc=1)
        return completed(*command)

    monkeypatch.setattr(health, "IP_FORWARD_PATH", forwarding)
    monkeypatch.setattr(health, "read_json", fake_read)
    monkeypatch.setattr(health, "service_active", lambda _name: True)
    monkeypatch.setattr(health, "dns_probe", lambda **_kwargs: (True, ""))
    monkeypatch.setattr(health, "run", fake_run)

    failures = health.verify()

    assert "gateway mode is enabled but IPv4 forwarding is off" in failures
    assert "gateway NAT is missing on eth0" in failures


def test_disconnected_stealth_is_healthy_when_fail_closed(monkeypatch) -> None:
    prepare_health(monkeypatch)

    assert health.verify(require_connectivity=False) == []
    assert "Chameleon has not completed its server handshake" in health.verify(
        require_connectivity=True
    )


def test_health_gate_rejects_empty_forwarding_guard_chains(monkeypatch) -> None:
    outputs = healthy_stealth_outputs()
    outputs[("iptables", "-S", health.PRE_CHAIN)] = f"-N {health.PRE_CHAIN}\n"
    outputs[("ip6tables", "-S", health.PRE6_CHAIN)] = f"-N {health.PRE6_CHAIN}\n"
    prepare_health(monkeypatch)
    monkeypatch.setattr(health, "run", fake_run_from(outputs))

    failures = health.verify()

    assert "IPv4 Chameleon guard contents or order are unsafe" in failures
    assert "IPv6 Chameleon guard is not an unconditional DROP" in failures


def test_health_gate_rejects_guard_hook_after_accept(monkeypatch) -> None:
    outputs = healthy_stealth_outputs()
    outputs[("iptables", "-S", "FORWARD")] = (
        f"-A FORWARD -j ACCEPT\n-A FORWARD -j {health.PRE_CHAIN}\n"
    )
    prepare_health(monkeypatch)
    monkeypatch.setattr(health, "run", fake_run_from(outputs))

    assert "IPv4 Chameleon guards are not the first forwarding rules" in health.verify()


def test_health_gate_rejects_earlier_jump_to_another_chain(monkeypatch) -> None:
    outputs = healthy_stealth_outputs()
    outputs[("iptables", "-S", "FORWARD")] = (
        f"-A FORWARD -j EARLY_ALLOW\n-A FORWARD -j {health.PRE_CHAIN}\n"
    )
    prepare_health(monkeypatch)
    monkeypatch.setattr(health, "run", fake_run_from(outputs))

    assert "IPv4 Chameleon guards are not the first forwarding rules" in health.verify()


def test_selected_scope_requires_every_mac_hook(monkeypatch) -> None:
    outputs = healthy_stealth_outputs()
    outputs[("iptables", "-S", "FORWARD")] = (
        f"-A FORWARD -m mac --mac-source 02:00:00:00:00:20 -j {health.PRE_CHAIN}\n"
    )
    outputs[("ip6tables", "-S", "FORWARD")] = (
        f"-A FORWARD -m mac --mac-source 02:00:00:00:00:20 -j {health.PRE6_CHAIN}\n"
    )
    monkeypatch.setattr(health, "run", fake_run_from(outputs))
    failures: list[str] = []

    health.check_forwarding_guards(
        {
            "scope": "selected",
            "macs": ["02:00:00:00:00:20", "02:00:00:00:00:21"],
        },
        failures,
    )

    assert "IPv4 Chameleon guards are not the first forwarding rules" in failures
    assert "IPv6 Chameleon guards are not the first forwarding rules" in failures


def test_health_gate_rejects_missing_dns_uidrange_rule(monkeypatch) -> None:
    outputs = healthy_stealth_outputs()
    outputs[("ip", "rule", "show")] = ""
    prepare_health(monkeypatch)
    monkeypatch.setattr(health, "run", fake_run_from(outputs))

    assert "protected DNS uidrange policy rule is missing" in health.verify()


def test_health_gate_rejects_non_terminal_dns_reject(monkeypatch) -> None:
    outputs = healthy_stealth_outputs()
    key = ("iptables", "-S", health.DNS_EGRESS_CHAIN)
    outputs[key] += (
        f"-A {health.DNS_EGRESS_CHAIN} -m owner --uid-owner 991 -j ACCEPT\n"
    )
    prepare_health(monkeypatch)
    monkeypatch.setattr(health, "run", fake_run_from(outputs))

    assert "protected DNS OUTPUT chain is incomplete or too permissive" in health.verify()


def test_health_gate_rejects_early_return_in_dns_chain(monkeypatch) -> None:
    outputs = healthy_stealth_outputs()
    key = ("iptables", "-S", health.DNS_EGRESS_CHAIN)
    lines = outputs[key].splitlines()
    lines.insert(1, f"-A {health.DNS_EGRESS_CHAIN} -j RETURN")
    outputs[key] = "\n".join(lines) + "\n"
    prepare_health(monkeypatch)
    monkeypatch.setattr(health, "run", fake_run_from(outputs))

    assert "protected DNS OUTPUT chain is incomplete or too permissive" in health.verify()


def test_disabled_stealth_rejects_stale_guard(monkeypatch) -> None:
    def fake_read(path: Path, **_kwargs):
        if path == health.STEALTH_POLICY:
            return {"version": 1, "enabled": False, "scope": "all"}
        return None

    def fake_run(*command: str):
        if command == ("iptables", "-S", "FORWARD"):
            return completed(*command, stdout="-A FORWARD -j EASYPI_STEALTH_PRESTART\n")
        return completed(*command)

    monkeypatch.setattr(health, "read_json", fake_read)
    monkeypatch.setattr(health, "service_active", lambda _name: True)
    monkeypatch.setattr(health, "dns_probe", lambda **_kwargs: (True, ""))
    monkeypatch.setattr(health, "run", fake_run)

    assert "disabled Chameleon still has an IPv4 forwarding guard" in health.verify()


@pytest.mark.parametrize("rcode", [1, 2, 5])
def test_strict_dns_probe_rejects_error_responses(monkeypatch, rcode: int) -> None:
    class FakeSocket:
        packet = b""

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def settimeout(self, _timeout: float) -> None:
            pass

        def sendto(self, packet: bytes, _address) -> None:
            self.packet = packet

        def recvfrom(self, _size: int):
            transaction_id = struct.unpack("!H", self.packet[:2])[0]
            header = struct.pack("!HHHHHH", transaction_id, 0x8000 | rcode, 1, 0, 0, 0)
            return header + self.packet[12:], ("127.0.0.1", 53)

    monkeypatch.setattr(health.socket, "socket", lambda *_args: FakeSocket())

    ok, message = health.dns_probe(require_upstream=True)

    assert not ok
    assert f"RCODE {rcode}" in message


@pytest.mark.parametrize("rcode", [0, 3])
def test_strict_dns_probe_accepts_valid_noerror_or_nxdomain(monkeypatch, rcode: int) -> None:
    class FakeSocket:
        packet = b""

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

        def settimeout(self, _timeout: float) -> None:
            pass

        def sendto(self, packet: bytes, _address) -> None:
            self.packet = packet

        def recvfrom(self, _size: int):
            transaction_id = struct.unpack("!H", self.packet[:2])[0]
            header = struct.pack("!HHHHHH", transaction_id, 0x8000 | rcode, 1, 0, 0, 0)
            return header + self.packet[12:], ("127.0.0.1", 53)

    monkeypatch.setattr(health.socket, "socket", lambda *_args: FakeSocket())

    assert health.dns_probe(require_upstream=True) == (True, "")


def test_stale_runtime_state_cannot_enable_stealth_without_persistent_config(
    tmp_path: Path,
) -> None:
    state = tmp_path / "state.env"
    state.write_text("SCOPE=all\nIPS=\nMACS=\nBLOCK_QUIC=true\n", encoding="utf-8")
    policy = tmp_path / "dns-policy.json"
    missing_config = tmp_path / "missing-client.conf"
    script = bash_path(Path("scripts/settings/stealth_vpn.sh"))
    command = f"""
set -e
source '{script}'
STATE='{bash_path(state)}'
DNS_POLICY_FILE='{bash_path(policy)}'
SOURCE_CONF='{bash_path(missing_config)}'
migrate_running_policy_if_needed
test ! -e "$DNS_POLICY_FILE"
"""

    result = subprocess.run(["bash", "-c", command], capture_output=True, text=True)

    assert result.returncode == 0, result.stderr


def test_stealth_errors_have_a_nonzero_exit_status() -> None:
    script = bash_path(Path("scripts/settings/stealth_vpn.sh"))
    command = f"source '{script}'; err 'expected failure'"

    result = subprocess.run(["bash", "-c", command], capture_output=True, text=True)

    assert result.returncode == 1
    assert json.loads(result.stdout) == {"success": False, "error": "expected failure"}


def test_resume_does_not_hide_configuration_failure(tmp_path: Path) -> None:
    config = tmp_path / "stealth-client.conf"
    config.write_text("{}", encoding="utf-8")
    safe_config = tmp_path / "safe-client.conf"
    profile = tmp_path / "profile.json"
    status = tmp_path / "status.json"
    script = bash_path(Path("scripts/settings/stealth_vpn.sh"))
    command = f"""
source '{script}'
SOURCE_CONF='{bash_path(config)}'
SAFE_CONF='{bash_path(safe_config)}'
PROFILE_FILE='{bash_path(profile)}'
STATUS_FILE='{bash_path(status)}'
read_dns_policy() {{ printf 'true\nall\n\n\ntrue\n'; }}
wan_iface() {{ printf 'eth0\n'; }}
ensure_prestart_guard() {{ return 0; }}
install_strict_dns_routing() {{ return 0; }}
activate_strict_dns_policy() {{ return 0; }}
ensure_chameleon_identity() {{ return 0; }}
prestart_guard_matches_policy() {{ return 0; }}
strict_dns_guard_active() {{ return 0; }}
do_resume
"""

    result = subprocess.run(["bash", "-c", command], capture_output=True, text=True)

    assert result.returncode == 1
    assert "invalid stealth client configuration" in result.stdout
    assert "invalid tunnel key" in result.stderr


def test_resume_allows_only_typed_temporary_server_failure(tmp_path: Path) -> None:
    config = tmp_path / "stealth-client.conf"
    config.write_text("{}", encoding="utf-8")
    script = bash_path(Path("scripts/settings/stealth_vpn.sh"))
    command = f"""
source '{script}'
SOURCE_CONF='{bash_path(config)}'
read_dns_policy() {{ printf 'true\nall\n\n\ntrue\n'; }}
wan_iface() {{ printf 'eth0\n'; }}
ensure_prestart_guard() {{ return 0; }}
install_strict_dns_routing() {{ return 0; }}
do_up() {{ temporary_err 'server unavailable'; }}
prestart_guard_matches_policy() {{ return 0; }}
strict_dns_guard_active() {{ return 0; }}
do_resume
"""

    result = subprocess.run(["bash", "-c", command], capture_output=True, text=True)

    assert result.returncode == 0, result.stderr
    assert "server_unavailable" in result.stdout


def test_runtime_guard_rejects_an_earlier_chain_jump() -> None:
    script = bash_path(Path("scripts/settings/stealth_vpn.sh"))
    command = f"""
source '{script}'
read_dns_policy() {{ printf 'true\nall\n\n\ntrue\n'; }}
iptables() {{
  case "$*" in
    '-S EASYPI_STEALTH_PRESTART')
      printf '%s\n' \
        '-N EASYPI_STEALTH_PRESTART' \
        '-A EASYPI_STEALTH_PRESTART -o cham0 -j RETURN' \
        '-A EASYPI_STEALTH_PRESTART -o chtcp0 -j RETURN' \
        '-A EASYPI_STEALTH_PRESTART -d 10.0.0.0/8 -j RETURN' \
        '-A EASYPI_STEALTH_PRESTART -d 100.64.0.0/10 -j RETURN' \
        '-A EASYPI_STEALTH_PRESTART -d 172.16.0.0/12 -j RETURN' \
        '-A EASYPI_STEALTH_PRESTART -d 192.168.0.0/16 -j RETURN' \
        '-A EASYPI_STEALTH_PRESTART -d 169.254.0.0/16 -j RETURN' \
        '-A EASYPI_STEALTH_PRESTART -j DROP' ;;
    '-S FORWARD')
      printf '%s\n' '-A FORWARD -j EARLY_ALLOW' \
        '-A FORWARD -j EASYPI_STEALTH_PRESTART' ;;
  esac
}}
ip6tables() {{
  case "$*" in
    '-S EASYPI_STEALTH6_PRESTART')
      printf '%s\n' '-N EASYPI_STEALTH6_PRESTART' \
        '-A EASYPI_STEALTH6_PRESTART -j DROP' ;;
    '-S FORWARD') printf '%s\n' '-A FORWARD -j EASYPI_STEALTH6_PRESTART' ;;
  esac
}}
if prestart_guard_matches_policy all ''; then exit 1; fi
"""

    result = subprocess.run(["bash", "-c", command], capture_output=True, text=True)

    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(os.name == "nt", reason="requires Linux flock ownership semantics")
def test_resume_allows_only_an_actively_locked_update(tmp_path: Path) -> None:
    script = bash_path(Path("scripts/settings/stealth_vpn.sh"))
    lock = bash_path(tmp_path / "update.lock")
    marker = bash_path(tmp_path / "update.marker")
    command = f"""
set -euo pipefail
source '{script}'
UPDATE_LOCK_FILE='{lock}'
UPDATE_MARKER='{marker}'
touch "$UPDATE_LOCK_FILE" "$UPDATE_MARKER"
chmod 0600 "$UPDATE_LOCK_FILE" "$UPDATE_MARKER"
do_resume() {{ :; }}
if update_lock_is_held; then exit 10; fi
if (main resume >/dev/null 2>&1); then exit 11; fi
exec 9>"$UPDATE_LOCK_FILE"
flock -n 9
update_lock_is_held
main resume
flock -u 9
"""

    result = subprocess.run(["bash", "-c", command], capture_output=True, text=True)

    assert result.returncode == 0, result.stderr
