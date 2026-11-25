from __future__ import annotations

import json
import os
import re
import signal
import shutil
import stat
import subprocess
import time
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[2]


def test_ensure_go_accepts_the_exact_pinned_toolchain(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("executable-mode behavior is verified on Linux")
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash is unavailable")

    ensure_go = (ROOT / "chameleon/ensure-go.sh").read_text(encoding="utf-8")
    pinned = re.search(r"^PINNED_GO_VERSION=([0-9.]+)$", ensure_go, re.MULTILINE)
    assert pinned, "ensure-go.sh must declare PINNED_GO_VERSION"
    fake_go = tmp_path / "fake-go"
    fake_go.write_text(
        "#!/usr/bin/env bash\n"
        "[[ ${1:-} == version ]] || exit 2\n"
        f"printf '%s\\n' 'go version go{pinned.group(1)} linux/amd64'\n",
        encoding="utf-8",
    )
    fake_go.chmod(fake_go.stat().st_mode | stat.S_IXUSR)
    env = os.environ.copy()
    env["GO"] = str(fake_go)

    result = subprocess.run(
        [bash, str(ROOT / "chameleon/ensure-go.sh")],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    )
    assert result.stdout.strip() == env["GO"]


def test_stealth_client_runs_as_restricted_systemd_service() -> None:
    script = (ROOT / "scripts/settings/stealth_vpn.sh").read_text(encoding="utf-8")

    assert 'CHAM_USER="easypi-chameleon"' in script
    assert 'User=$CHAM_USER' in script
    assert 'Group=$CHAM_GROUP' in script
    assert "AmbientCapabilities=CAP_NET_ADMIN" in script
    assert "CapabilityBoundingSet=CAP_NET_ADMIN" in script
    assert "NoNewPrivileges=yes" in script
    assert "DeviceAllow=/dev/net/tun rw" in script
    assert "ProtectSystem=strict" in script
    assert "ProtectHome=yes" in script
    assert "RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK" in script
    assert 'systemctl start "$CHAM_SERVICE"' in script
    assert "ExecStartPost=+/bin/bash $STEALTH_SCRIPT restore-route" in script
    assert 'ip route replace default dev "$IF" metric 10 table "$RT_TABLE"' in script
    assert 'setsid "$CHAM_BIN"' not in script


def test_stealth_client_applies_best_effort_tcp_tuning_before_start() -> None:
    script = (ROOT / "scripts/settings/stealth_vpn.sh").read_text(encoding="utf-8")

    assert "net.core.rmem_max=67108864" in script
    assert "net.core.wmem_max=67108864" in script
    assert "'net.ipv4.tcp_rmem=4096 87380 67108864'" in script
    assert "'net.ipv4.tcp_wmem=4096 65536 67108864'" in script
    assert "if modprobe tcp_bbr >/dev/null 2>&1; then" in script
    assert "net.core.default_qdisc=fq" in script
    assert "net.ipv4.tcp_congestion_control=bbr" in script
    assert script.index("tune_tcp_transport\n") < script.index(
        'systemctl start "$CHAM_SERVICE"'
    )


def test_stealth_secrets_are_outside_the_client_writable_directory() -> None:
    script = (ROOT / "scripts/settings/stealth_vpn.sh").read_text(encoding="utf-8")

    assert 'SAFE_CONF="$RUNTIME_DIR/client.conf"' in script
    assert 'STATUS_DIR="$RUNTIME_DIR/status"' in script
    assert 'install -d -o root -g "$CHAM_GROUP" -m 0750 "$RUNTIME_DIR"' in script
    assert 'install -d -o "$CHAM_USER" -g "$CHAM_GROUP" -m 0700 "$STATUS_DIR"' in script
    assert 'install -d -o "$CHAM_USER" -g easypi -m 0750 "$PROFILE_DIR"' in script
    assert 'chown root:"$CHAM_GROUP" "$SAFE_CONF"' in script
    assert 'chmod 0640 "$SAFE_CONF"' in script
    assert "ReadWritePaths=$STATUS_DIR $PROFILE_DIR" in script
    assert 'STATUS_FILE="$STATUS_FILE" CHAM_GROUP="$CHAM_GROUP"' in script
    assert "os.fchown(handle.fileno(), 0, chameleon_gid)" in script
    assert "os.fchmod(handle.fileno(), 0o640)" in script
    assert script.index("os.fchown(handle.fileno(), 0, chameleon_gid)") < script.index(
        "os.replace(temp_name, destination)"
    )


def test_stealth_deploy_waits_for_the_bounded_server_operation() -> None:
    api = (ROOT / "frontend/src/api/stealth.ts").read_text(encoding="utf-8")
    start = api.index("export const deployStealthServer")
    end = api.index("export const configureStealthDomainTls", start)
    deploy = api[start:end]

    assert "timeout: 900_000" in deploy


def test_stealth_status_is_published_before_lifecycle_notifications() -> None:
    page = (ROOT / "frontend/src/pages/Stealth.tsx").read_text(encoding="utf-8")
    enable_start = page.index("const enable = useMutation")
    disable_start = page.index("const disable = useMutation", enable_start)
    delete_start = page.index("const del = useMutation", disable_start)
    enable = page[enable_start:disable_start]
    disable = page[disable_start:delete_start]

    assert enable.index("publishStatus(d)") < enable.index("toast.success")
    assert disable.index("publishStatus(d)") < disable.index("toast.success")


def test_stealth_clamps_tcp_mss_to_the_tunnel_path_mtu() -> None:
    script = (ROOT / "scripts/settings/stealth_vpn.sh").read_text(encoding="utf-8")

    assert 'mtu="$(cat "/sys/class/net/$IF/mtu" 2>/dev/null)"' in script
    assert "mss=$((mtu - 40))" in script
    assert script.count('-j TCPMSS --set-mss "$mss" || return 1') == 2
    assert 'iptables -t mangle -I FORWARD 1 -j "$MSS_CHAIN"' in script
    assert 'install_mss_clamp || return 1' in script
    assert 'iptables -t mangle -X "$MSS_CHAIN"' in script


def test_stealth_forwarding_allows_client_flows_but_not_new_vps_flows() -> None:
    script = (ROOT / "scripts/settings/stealth_vpn.sh").read_text(encoding="utf-8")

    assert 'iptables -A FORWARD -o "$IF" -j ACCEPT || return 1' in script
    assert (
        'iptables -A FORWARD -i "$IF" -m conntrack '
        '--ctstate RELATED,ESTABLISHED -j ACCEPT || return 1'
    ) in script
    assert 'iptables -I FORWARD 1 -o "$IF" -j ACCEPT' not in script
    assert 'iptables -I FORWARD 1 -i "$IF" -j ACCEPT' not in script
    assert (
        'iptables -I ufw-after-logging-forward 1 -o "$IF" -j RETURN'
        in script
    )
    assert (
        'iptables -I ufw-after-logging-forward 1 -i "$IF" -m conntrack'
        in script
    )
    assert 'clear_ufw_tunnel_log_exclusions' in script
    assert script.index("install_tunnel_forwarding || return 1") < script.index(
        'install_quic_guard "$scope" "$macs" "$block_quic" || return 1'
    )
    assert script.count('iptables -D FORWARD -o "$IF" -j ACCEPT') >= 2
    assert script.count(
        'iptables -D FORWARD -i "$IF" -m conntrack '
        '--ctstate RELATED,ESTABLISHED -j ACCEPT'
    ) >= 2


def test_stealth_drops_untranslated_invalid_packets_before_the_tunnel() -> None:
    # Packets of flows conntrack forgot when cham0 went away are INVALID, skip
    # MASQUERADE and would carry the LAN device address into the tunnel, where
    # the server rejects them and the upload stream stalls.
    script = (ROOT / "scripts/settings/stealth_vpn.sh").read_text(encoding="utf-8")
    drop = 'iptables -A FORWARD -o "$IF" -m conntrack --ctstate INVALID -j DROP || return 1'
    allow = 'iptables -A FORWARD -o "$IF" -j ACCEPT || return 1'

    assert drop in script
    assert script.index(drop) < script.index(allow)
    assert script.count(
        'iptables -D FORWARD -o "$IF" -m conntrack --ctstate INVALID -j DROP'
    ) >= 2


def test_active_routing_restores_prestart_as_the_first_policy_gate() -> None:
    script = (ROOT / "scripts/settings/stealth_vpn.sh").read_text(encoding="utf-8")
    routing_body = script[
        script.index("apply_manual_routing() {") : script.index("# ── up")
    ]

    assert routing_body.rindex(
        'ensure_prestart_guard "$scope" "$ips" "$macs" "$wan"'
    ) > routing_body.rindex('-j "$KILL_CHAIN"')


def test_root_runner_owns_stealth_operation_timeouts() -> None:
    runner = (ROOT / "scripts/runner").read_text(encoding="utf-8")
    start = runner.index(
        'elif [[ "$SCRIPT_RELATIVE" == "settings/stealth_vpn.sh" ]]'
    )
    end = runner.index(
        'elif [[ "$SCRIPT_RELATIVE" == "setup/install_ffmpeg.sh" ]]', start
    )
    block = runner[start:end]

    assert 'TIMEOUT_HELPER="$SCRIPTS_BASE/privileged_timeout.py"' in block
    assert 'TIMEOUT_HELPER_UID="$(stat -c' in block
    assert 'DEADLINE_ARGS=(--deadline-monotonic-ns "$OPERATION_DEADLINE_NS")' in block
    assert '--timeout 40 --kill-after 0.5 "${DEADLINE_ARGS[@]}"' in block
    assert '--timeout 25 --kill-after 0.5 "${DEADLINE_ARGS[@]}"' in block
    assert '--timeout 10 --kill-after 0.5 "${DEADLINE_ARGS[@]}"' in block
    assert block.index("up)") < block.index("down)") < block.index("reconcile)")


def test_privileged_timeout_kills_term_ignoring_descendants(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("privileged process-group behavior is verified on Linux")
    if os.geteuid() != 0:
        pytest.skip("root privileges are required")

    marker = tmp_path / "late-root-mutation"
    child = (
        "import pathlib,signal,time;"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN);"
        "time.sleep(2);"
        f"pathlib.Path({str(marker)!r}).write_text('late')"
    )
    parent = (
        "import subprocess,sys,time;"
        f"subprocess.Popen([sys.executable,'-c',{child!r}]);"
        "time.sleep(30)"
    )
    result = subprocess.run(
        [
            "python3",
            str(ROOT / "scripts/privileged_timeout.py"),
            "--timeout",
            "0.2",
            "--kill-after",
            "0.2",
            "--",
            "python3",
            "-c",
            parent,
        ],
        check=False,
        timeout=5,
    )
    time.sleep(2.1)

    assert result.returncode == 124
    assert not marker.exists()


def test_privileged_timeout_handles_outer_termination(tmp_path: Path) -> None:
    if os.name == "nt":
        pytest.skip("privileged process-group behavior is verified on Linux")
    if os.geteuid() != 0:
        pytest.skip("root privileges are required")

    marker = tmp_path / "late-root-mutation"
    child = (
        "import pathlib,signal,time;"
        "signal.signal(signal.SIGTERM, signal.SIG_IGN);"
        "time.sleep(2);"
        f"pathlib.Path({str(marker)!r}).write_text('late')"
    )
    parent = (
        "import subprocess,sys,time;"
        f"subprocess.Popen([sys.executable,'-c',{child!r}]);"
        "time.sleep(30)"
    )
    process = subprocess.Popen(
        [
            "python3",
            str(ROOT / "scripts/privileged_timeout.py"),
            "--timeout",
            "30",
            "--kill-after",
            "0.2",
            "--",
            "python3",
            "-c",
            parent,
        ]
    )
    time.sleep(0.2)
    process.terminate()
    assert process.wait(timeout=3) == 128 + signal.SIGTERM
    time.sleep(2.1)

    assert not marker.exists()


def test_chameleon_firewall_behavior_in_linux_namespaces() -> None:
    if os.name == "nt":
        pytest.skip("network-namespace behavior is verified on Linux")
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash is unavailable")

    command = [bash, str(ROOT / "tests/acceptance/chameleon_firewall_regression.sh")]
    if os.geteuid() != 0:
        sudo = shutil.which("sudo")
        if not sudo:
            pytest.skip("root network-namespace privileges are unavailable")
        privilege_check = subprocess.run(
            [sudo, "-n", "true"], capture_output=True, text=True, check=False
        )
        if privilege_check.returncode != 0:
            pytest.skip("passwordless root network-namespace privileges are unavailable")
        command = [sudo, "-n", *command]

    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode == 77:
        pytest.skip(result.stderr.strip() or "network-namespace prerequisites unavailable")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "CHAMELEON_FIREWALL_REGRESSION=PASS" in result.stdout


def test_chameleon_strict_dns_fails_closed_in_linux_namespaces() -> None:
    if os.name == "nt":
        pytest.skip("network-namespace behavior is verified on Linux")
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash is unavailable")

    command = [bash, str(ROOT / "tests/acceptance/chameleon_strict_dns_regression.sh")]
    if os.geteuid() != 0:
        sudo = shutil.which("sudo")
        if not sudo:
            pytest.skip("root network-namespace privileges are unavailable")
        privilege_check = subprocess.run(
            [sudo, "-n", "true"], capture_output=True, text=True, check=False
        )
        if privilege_check.returncode != 0:
            pytest.skip("passwordless root network-namespace privileges are unavailable")
        command = [sudo, "-n", *command]

    result = subprocess.run(command, capture_output=True, text=True, check=False)
    if result.returncode == 77:
        pytest.skip(result.stderr.strip() or "network-namespace prerequisites unavailable")
    assert result.returncode == 0, result.stdout + result.stderr
    assert "CHAMELEON_STRICT_DNS_REGRESSION=PASS" in result.stdout


def test_chameleon_example_enables_production_certificate_verification() -> None:
    path = ROOT / "chameleon/cmd/chameleon-client/config.example.json"
    config = json.loads(path.read_text(encoding="utf-8"))

    assert config["reality_shield_preset"] == "ip"
    assert config["verify_server_certificate"] is True


def test_stealth_deployment_does_not_persist_unused_x25519_private_key() -> None:
    context = (ROOT / "backend/app/services/stealth_components/context.py").read_text(
        encoding="utf-8"
    )
    client = (ROOT / "backend/app/services/stealth_components/client.py").read_text(
        encoding="utf-8"
    )
    deployment = (
        ROOT / "backend/app/services/stealth_components/deployment.py"
    ).read_text(encoding="utf-8")
    tls = (ROOT / "backend/app/services/stealth_components/tls.py").read_text(
        encoding="utf-8"
    )

    assert "def _gen_x25519_public() -> str:" in context
    assert 'meta.pop("reality_private", None)' in client
    assert 'meta["psk_key"] and meta["reality_public"]' in deployment
    assert '"reality_private_key":' not in tls


def _runtime_route_harness(up_after_checks: int) -> str:
    """Bash that runs the real route functions against a stub `ip` whose cham0
    link exists from the start but only reports UP from the given check on."""
    script = (ROOT / "scripts/settings/stealth_vpn.sh").read_text(encoding="utf-8")
    functions = []
    for name in ("install_runtime_routes", "restore_runtime_route"):
        start = script.index(f"{name}() {{")
        functions.append(script[start : script.index("\n}\n", start) + 3])
    # Counters live in files because `ip -o link show | grep` runs in a subshell.
    return (
        "IF=cham0; RT_TABLE=51821; DNS_RT_TABLE=51823\n"
        'state=$(mktemp -d); echo 0 > "$state/checks"; echo 0 > "$state/routes"\n'
        "ip() {\n"
        '  local checks; checks=$(<"$state/checks")\n'
        '  case "$1 $2" in\n'
        '    "-o link") checks=$((checks+1)); echo "$checks" > "$state/checks"\n'
        f"      if (( checks >= {up_after_checks} )); then\n"
        '        echo "5: cham0: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1380"\n'
        '      else echo "5: cham0: <POINTOPOINT,MULTICAST,NOARP> mtu 1380"; fi ;;\n'
        '    "route replace")\n'
        f"      if (( checks >= {up_after_checks} )); then\n"
        '        echo $(( $(<"$state/routes") + 1 )) > "$state/routes"; return 0; fi\n'
        '      echo "Error: Device for nexthop is not up." >&2; return 2 ;;\n'
        '    "rule show") return 0 ;;\n'
        "  esac\n"
        "}\n"
        "sleep() { :; }\n"
        + "".join(functions)
        + "restore_runtime_route; rc=$?\n"
        + 'echo "rc=$rc checks=$(<"$state/checks") routes=$(<"$state/routes")"; rm -rf "$state"\n'
    )


def test_stealth_route_restore_waits_for_the_tunnel_link_to_come_up() -> None:
    # The update installer once rolled back because ExecStartPost met cham0
    # after the client created it but before it was up.
    if os.name == "nt":
        pytest.skip("shell behavior is verified on Linux")
    bash = shutil.which("bash")
    if not bash:
        pytest.skip("bash is unavailable")

    ready = subprocess.run(
        [bash, "-c", _runtime_route_harness(up_after_checks=3)],
        check=True, capture_output=True, text=True, timeout=10,
    ).stdout.strip()
    assert ready == "rc=0 checks=3 routes=2"

    never = subprocess.run(
        [bash, "-c", _runtime_route_harness(up_after_checks=1000)],
        check=True, capture_output=True, text=True, timeout=10,
    ).stdout.strip()
    assert never == "rc=1 checks=30 routes=0"


def _stealth_function(script: str, name: str) -> str:
    start = script.index(f"{name}() {{")
    return script[start : script.index("\n}\n", start) + 3]


def test_stealth_prepares_tcp_streams_before_the_client_starts() -> None:
    script = (ROOT / "scripts/settings/stealth_vpn.sh").read_text(encoding="utf-8")
    up = _stealth_function(script, "do_up")

    prepare = 'if tcp_streams_in_host_ns install "$srv" >/dev/null 2>&1; then'
    unit = 'write_chameleon_unit "$tcp_streams"'
    socket = 'systemctl start "$TCP_STREAM_SOCKET"'
    client = 'systemctl start "$CHAM_SERVICE"'
    assert up.index(prepare) < up.index(unit) < up.index(socket) < up.index(client)
    # Any failure to prepare or start the listener leaves the client on the
    # packet tunnel instead of failing Stealth.
    assert "tcp_streams_in_host_ns clear >/dev/null 2>&1\n    write_chameleon_unit false" in up
    unit_body = _stealth_function(script, "write_chameleon_unit")
    assert 'stream_service="Sockets=$TCP_STREAM_SOCKET"' in unit_body
    assert "$stream_service" in unit_body


def test_stealth_builds_the_stream_namespace_where_systemd_can_see_it() -> None:
    # The backend calls the script inside its own mount namespace (PrivateTmp),
    # where an `ip netns add` mount is invisible to systemd and the listener's
    # NetworkNamespacePath= never resolved. Namespace work runs in a transient
    # unit in the host's mount namespace instead.
    script = (ROOT / "scripts/settings/stealth_vpn.sh").read_text(encoding="utf-8")
    helper = _stealth_function(script, "tcp_streams_in_host_ns")
    assert "systemd-run --quiet --wait --collect --pipe --service-type=oneshot" in helper
    assert "--setenv=EASYPI_STEALTH_HOST_NS=1" in helper
    assert '/bin/bash "$STEALTH_SCRIPT" tcp-streams "$@"' in helper
    internal = _stealth_function(script, "do_tcp_streams")
    assert '[[ "${EASYPI_STEALTH_HOST_NS:-}" == "1" ]] || err "internal subcommand"' in internal
    assert "validate_ip_csv" in internal
    up = _stealth_function(script, "do_up")
    down = _stealth_function(script, "do_down")
    assert "install_tcp_streams" not in up and "clear_tcp_streams" not in up
    assert "clear_tcp_streams" not in down
    assert 'if [[ "${1:-}" != "tcp-streams" ]]; then\n    initialize_runtime_paths' in script


def test_stealth_tcp_streams_keep_every_forward_policy_and_fall_back() -> None:
    script = (ROOT / "scripts/settings/stealth_vpn.sh").read_text(encoding="utf-8")
    install = _stealth_function(script, "install_tcp_streams")

    # Only covered devices' TCP, after the LAN-direct rule and before the
    # device rule, so an empty stream table falls through to cham0.
    assert 'MGMT_PREF="5090"' in script and 'DEVICE_PREF="5096"' in script
    assert 'TCP_STREAM_PREF="5092"' in script
    assert (
        'ip rule add pref "$TCP_STREAM_PREF" fwmark "$DEVICE_MARK/$DEVICE_MARK_MASK" '
        'ipproto tcp lookup "$TCP_STREAM_TABLE"' in install
    )
    assert (
        'ip rule add pref "$TCP_STREAM_VPS_PREF" fwmark "$DEVICE_MARK/$DEVICE_MARK_MASK" '
        'to "$srv/32" lookup "$RT_TABLE"' in install
    )
    # The script never routes into the stream table; the client does that only
    # while the server offers streams.
    assert "table $TCP_STREAM_TABLE" not in script
    assert 'route replace default via "$TCP_STREAM_NS_IP"' not in script
    assert '"tcp_stream_route": {' in script
    # Appended after EasyPi's FORWARD policies (admission, Prism, VPN
    # monitors, kill switch), never inserted ahead of them.
    forward = _stealth_function(script, "tcp_stream_forward_rules")
    assert "iptables -A FORWARD $rule" in forward
    assert "iptables -I FORWARD" not in forward
    assert '"-o $TCP_STREAM_IF -m conntrack --ctstate INVALID -j DROP"' in forward
    # TPROXY in the namespace needs reverse-path checks without the mark.
    assert "sysctl -qw net.ipv4.conf.all.src_valid_mark=0" in install
    assert "Transparent=yes" in install
    assert "NetworkNamespacePath=/run/netns/$TCP_STREAM_NS" in install
    # The prestart guard lets the stream veth pass, in builder and verifier.
    assert '"-A $PRE_CHAIN -o $TCP_STREAM_IF -j RETURN"' in script
    assert 'iptables -A "$next4" -o "$TCP_STREAM_IF" -j RETURN || return 1' in script


def test_stealth_down_stops_the_stream_listener_before_the_client() -> None:
    script = (ROOT / "scripts/settings/stealth_vpn.sh").read_text(encoding="utf-8")
    down = _stealth_function(script, "do_down")

    socket = 'systemctl stop "$TCP_STREAM_SOCKET"'
    client = 'systemctl stop "$CHAM_SERVICE"'
    assert down.index(socket) < down.index(client) < down.index("tcp_streams_in_host_ns clear")
    clear = _stealth_function(script, "clear_tcp_streams")
    for step in (
        'rm -f -- "$TCP_STREAM_SOCKET_UNIT"',
        'ip rule del pref "$TCP_STREAM_PREF"',
        'ip rule del pref "$TCP_STREAM_VPS_PREF"',
        'ip route flush table "$TCP_STREAM_TABLE"',
        "tcp_stream_forward_rules remove",
        'ip netns del "$TCP_STREAM_NS"',
    ):
        assert step in clear
    uninstall = (ROOT / "uninstall.sh").read_text(encoding="utf-8")
    assert "  easypi-chameleon-tcp.socket\n" in uninstall


def test_install_restores_the_stealth_guard_before_its_health_check() -> None:
    # NetProtection, PRISM and the backend insert FORWARD jumps at the top when
    # they start; an update with Stealth on then failed the guard-first check
    # and rolled back. The installer puts the guard back in front first.
    install = (ROOT / "install.sh").read_text(encoding="utf-8")
    reassert = '"${EASYPI_PREFIX}/scripts/runner" settings/stealth_vpn.sh guard'
    check = '/usr/bin/python3 "/opt/EasyPi/scripts/maintenance/verify_runtime_health.py"'
    assert install.index("systemctl restart easypi-backend.service") < install.index(reassert)
    assert install.index(reassert) < install.index(check)


def test_install_renders_the_mobile_link_endpoint_from_the_installed_copy() -> None:
    # mobile_link_agent.sh renders its nginx template with the EasyPi root it
    # runs from. Run from an update payload in a temporary directory, the
    # certificate paths pointed there, nginx -t failed on every update and a
    # fresh install outside /opt/EasyPi never installed the endpoint.
    install = (ROOT / "install.sh").read_text(encoding="utf-8")
    assert '"${SCRIPTS_DST}/settings/mobile_link_agent.sh" ensure-endpoint' in install
    assert '"${BASE_DIR}/scripts/settings/mobile_link_agent.sh"' not in install
    agent = (ROOT / "scripts/settings/mobile_link_agent.sh").read_text(encoding="utf-8")
    assert 'EASYPI_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"' in agent
    assert 'sed -i "s|/opt/EasyPi|${EASYPI_ROOT}|g" "$rendered"' in agent
