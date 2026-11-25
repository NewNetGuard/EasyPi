from __future__ import annotations

import shutil
import shlex
import subprocess
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
UNINSTALL = ROOT / "uninstall.sh"
UNINSTALL_SHELL_PATH = "./uninstall.sh"


def _bash(script: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["bash", "-c", script],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )


def test_uninstaller_help_is_safe_without_root() -> None:
    result = subprocess.run(
        ["bash", UNINSTALL_SHELL_PATH, "--help"],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0
    assert "--purge" in result.stdout
    assert "--yes" in result.stdout


def test_uninstaller_rejects_dangerous_prefixes_before_mutation() -> None:
    for candidate in ("/", "/opt", "relative/EasyPi", "/opt/../EasyPi", ""):
        quoted = candidate.replace("'", "'\\''")
        result = _bash(
            f"source '{UNINSTALL_SHELL_PATH}'; validate_prefix '{quoted}'"
        )
        assert result.returncode != 0, candidate


def test_uninstaller_accepts_only_canonical_easypi_named_prefix() -> None:
    result = _bash(
        f"source '{UNINSTALL_SHELL_PATH}'; validate_prefix '/opt/EasyPi'"
    )
    assert result.returncode == 0
    assert result.stdout.strip() == "/opt/EasyPi"


def test_uninstaller_requires_explicit_double_confirmation_for_purge() -> None:
    result = _bash(
        f"source '{UNINSTALL_SHELL_PATH}'; parse_args --prefix /opt/EasyPi --purge"
    )
    assert result.returncode != 0
    assert "requires both --purge and --yes" in result.stderr


def test_uninstaller_covers_every_locally_installed_easypi_unit() -> None:
    content = UNINSTALL.read_text(encoding="utf-8")
    expected = {
        "easypi-backend.service",
        "easypi-dhcp-observer.service",
        "easypi-netprotection.service",
        "easypi-netprotection-state-maintenance.timer",
        "easypi-netprotection-state-maintenance.service",
        "easypi-ipv6-policy-guard.service",
        "easypi-ipv6-policy-guard.timer",
        "easypi-prism-shadow.service",
        "easypi-prism-flowgraph.service",
        "easypi-prism-lineage.service",
        "easypi-prism-counterfactual.service",
        "easypi-telegram-bot.service",
        "easypi-taildrop-import.service",
        "easypi-tailscale-performance.service",
        "easypi-restore.service",
        "easypi-update-recovery.service",
        "easypi-gateway-fix.timer",
        "easypi-gateway-fix.service",
        "easypi-duckdns.timer",
        "easypi-duckdns.service",
        "easypi-installer@.service",
        "easypi-mobile-link-agent.service",
        "easypi-mobile-home-tunnel.service",
        "easypi-mobile-home-tunnel-agent.service",
    }
    assert not {unit for unit in expected if unit not in content}


def test_uninstaller_removes_installer_backups_and_drop_ins() -> None:
    content = UNINSTALL.read_text(encoding="utf-8")
    assert '"/etc/systemd/system/${unit}".bak-*' in content
    assert 'rm -rf -- "/etc/systemd/system/${unit}.d"' in content
    assert "/etc/nginx/sites-available/easypi.bak-*" in content
    assert "/etc/sudoers.d/easypi.bak-*" in content
    assert "/etc/easypi-mobile-home" in content


def _host_path(path: Path) -> str:
    value = path.resolve().as_posix()
    if len(value) >= 3 and value[1:3] == ":/":
        return f"/mnt/{value[0].lower()}{value[2:]}"
    return value


def _run_uninstall_function(
    tmp_path: Path, body: str, extra_fakes: dict[str, str] | None = None
) -> list[str]:
    """Source uninstall.sh (without running main) and call one function with
    fake iptables/ufw/ip commands that only record what they are asked.

    run_trusted_cleanup is replaced from a sourced file because shell code
    passed inline through ``bash -c`` is expanded early by the WSL launcher."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "calls"
    stub = tmp_path / "stub.sh"
    stub.write_text(
        'run_trusted_cleanup() { printf "cleanup %s\\n" "$*" >> "$CALLS"; }\n',
        encoding="utf-8",
        newline="\n",
    )
    fakes = {
        "iptables-save": r"""#!/bin/bash
case "$2" in
  nat) printf '%s\n' '-A POSTROUTING -s 10.77.0.0/24 -o eth0 -j MASQUERADE' \
         '-A POSTROUTING -o eth0 -j MASQUERADE' ;;
  filter) printf '%s\n' '-A FORWARD -i easypi-mobile0 -j ACCEPT' \
            '-A FORWARD -o easypi-mobile0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT' \
            '-A FORWARD -i easypi-mobile0 -m comment --comment "admin rule" -j ACCEPT' \
            '-A FORWARD -i easypi-mobile00 -j ACCEPT' \
            '-A ufw-user-forward -i easypi-mobile0 -o eth0 -j ACCEPT' ;;
  mangle) printf '%s\n' '-A FORWARD -i easypi-mobile0 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu' ;;
esac
""",
        "iptables": '#!/bin/bash\nprintf "iptables %s\\n" "$*" >> "$CALLS"\n',
        "ufw": '#!/bin/bash\nprintf "ufw %s\\n" "$*" >> "$CALLS"\n',
        "ip": r"""#!/bin/bash
if [[ "$*" == "-4 route show default" ]]; then echo "default via 192.0.2.1 dev eth0 proto static"; exit 0; fi
if [[ "$1 $2" == "link show" ]]; then exit 0; fi
printf 'ip %s\n' "$*" >> "$CALLS"
""",
    }
    fakes.update(extra_fakes or {})
    for name, text in fakes.items():
        (bin_dir / name).write_text(text, encoding="utf-8", newline="\n")
    bash = shutil.which("bash")
    assert bash is not None
    script = (
        f"chmod 700 {shlex.quote(_host_path(bin_dir))}/* && "
        f"source {UNINSTALL_SHELL_PATH} && "
        f"export PATH={shlex.quote(_host_path(bin_dir))}:/usr/bin:/bin "
        f"CALLS={shlex.quote(_host_path(calls))} && "
        f"source {shlex.quote(_host_path(stub))} && {body}"
    )
    result = subprocess.run(
        [bash, "-c", script], cwd=ROOT, check=False, capture_output=True, text=True
    )
    assert result.returncode == 0, result.stderr
    return calls.read_text(encoding="utf-8").splitlines() if calls.exists() else []


def test_uninstaller_removes_only_the_phone_tunnel_rules(tmp_path: Path) -> None:
    calls = _run_uninstall_function(tmp_path, "clear_mobile_tunnel_runtime")

    assert calls == [
        "iptables -t filter -D FORWARD -i easypi-mobile0 -j ACCEPT",
        "iptables -t filter -D FORWARD -o easypi-mobile0 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT",
        "iptables -t nat -D POSTROUTING -s 10.77.0.0/24 -o eth0 -j MASQUERADE",
        "iptables -t mangle -D FORWARD -i easypi-mobile0 -p tcp -m tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu",
        "ufw route delete allow in on easypi-mobile0 out on eth0",
        "ip link delete easypi-mobile0",
    ]


def test_uninstaller_undoes_exactly_the_recorded_gateway_mode(tmp_path: Path) -> None:
    network = tmp_path / "prefix" / "data" / "network"
    network.mkdir(parents=True)
    (network / "gateway_mode.json").write_text(
        '{"enabled": true, "interface": "eth0", "lan_iface": "wlan0", "wan_iface": "eth0"}',
        encoding="utf-8",
    )
    body = f"clear_gateway_runtime {shlex.quote(_host_path(tmp_path / 'prefix'))}"
    calls = _run_uninstall_function(tmp_path, body)

    prefix = _host_path(tmp_path / "prefix")
    assert calls[:2] == [
        f"cleanup {prefix} scripts/settings/network_firewall.sh gateway-disable eth0 wlan0",
        "ufw route delete allow in on wlan0 out on eth0",
    ]


def test_uninstaller_leaves_routing_alone_without_gateway_mode(tmp_path: Path) -> None:
    network = tmp_path / "prefix" / "data" / "network"
    network.mkdir(parents=True)
    (network / "gateway_mode.json").write_text('{"enabled": false}', encoding="utf-8")
    body = f"clear_gateway_runtime {shlex.quote(_host_path(tmp_path / 'prefix'))}"

    calls = _run_uninstall_function(tmp_path, body)

    assert not [call for call in calls if "gateway-disable" in call or "ufw route" in call]


ACCOUNT_FAKES = {
    # easypi-outline is an administrator's login with the same name (UID 1001)
    # and must survive; easypi-build does not exist.
    "id": r"""#!/bin/bash
case "$3" in
  easypi) echo 997 ;;
  easypi-chameleon|easypi-mobile-link|easypi-stealth-dns|easypi-prism-tls) echo 996 ;;
  easypi-outline) echo 1001 ;;
  *) exit 1 ;;
esac
""",
    "getent": r"""#!/bin/bash
case "$2" in
  easypi) echo "easypi:x:997:sb" ;;
  easypi-chameleon|easypi-mobile-link|easypi-stealth-dns|easypi-prism-tls) echo "$2:x:996:" ;;
  easypi-outline) echo "easypi-outline:x:1001:" ;;
  *) exit 2 ;;
esac
""",
    "userdel": '#!/bin/bash\nprintf "userdel %s\\n" "$*" >> "$CALLS"\n',
    "groupdel": '#!/bin/bash\nprintf "groupdel %s\\n" "$*" >> "$CALLS"\n',
}


def test_purge_removes_only_easypi_system_accounts(tmp_path: Path) -> None:
    calls = _run_uninstall_function(tmp_path, "remove_system_accounts", ACCOUNT_FAKES)

    removed = {call.split()[-1] for call in calls if call.startswith("userdel")}
    assert removed == {
        "easypi",
        "easypi-chameleon",
        "easypi-mobile-link",
        "easypi-stealth-dns",
        "easypi-prism-tls",
    }
    assert "easypi-outline" not in {call.split()[-1] for call in calls}
    assert "groupdel -- easypi" in calls


def test_accounts_are_removed_only_with_purge_and_timer_stamps_always() -> None:
    content = UNINSTALL.read_text(encoding="utf-8")
    main = content[content.index("main() {"):]
    assert 'purge_state "${EASYPI_PREFIX}"\n    remove_system_accounts' in main
    assert main.count("remove_system_accounts") == 1
    assert '"/var/lib/systemd/timers/stamp-${unit}"' in content
    assert "remove_system_account go2rtc" in content


def test_uninstaller_has_no_interactive_or_unvalidated_recursive_delete() -> None:
    content = UNINSTALL.read_text(encoding="utf-8")
    assert "read -r -p" not in content
    assert 'rm -rf -- "${prefix}"' in content
    assert "assert_safe_purge_target" in content
    assert "rm -rf $" not in content


def test_uninstaller_removes_current_unbound_integration_and_purges_owned_state() -> None:
    content = UNINSTALL.read_text(encoding="utf-8")
    assert "/etc/unbound/unbound.conf.d/easypi-recursive.conf" in content
    assert "/var/backups/easypi" in content
    assert "/var/log/easypi" in content


def test_uninstaller_removes_only_easypi_managed_go2rtc() -> None:
    content = UNINSTALL.read_text(encoding="utf-8")
    installer = (ROOT / "scripts/setup/install_go2rtc.sh").read_text(
        encoding="utf-8"
    )
    assert "easypi-managed-go2rtc-v1" in installer
    assert "easypi-managed-go2rtc-v1" in content
    assert "Unmanaged go2rtc installation was preserved" in content
    assert "systemctl disable --now go2rtc.service" in content
    assert 'rm -rf -- "${directory}"' in content


def test_uninstaller_clears_only_trusted_easypi_runtime_policies() -> None:
    content = UNINSTALL.read_text(encoding="utf-8")
    assert 'remove_systemd_units\n  run_runtime_cleanup "${EASYPI_PREFIX}"' in content
    assert "script_is_trusted" in content
    assert "scripts/settings/outbound_vpn.sh down" in content
    assert "scripts/settings/stealth_vpn.sh down" in content
    assert "scripts/settings/setup_app_blocking.sh clear-runtime" in content
    assert "scripts/settings/setup_vpn_blocking.sh clear-runtime" in content
    assert "scripts/settings/tailscale_performance.sh restore" in content
    assert "scripts/security/ipv6_policy_guard.sh --clear" in content
    assert "scripts/security/setup_firewall.sh clear-runtime" in content
    assert "scripts/settings/setup_prism_shadow.sh disable" in content
    assert "iptables -F FORWARD" not in content
    assert "ip6tables -F FORWARD" not in content
    assert '[[ -f "${script}" && ! -L "${script}" ]]' in content
    assert 'EASYPI_LIFECYCLE_MODE=uninstall /bin/bash -- "${script}" "$@"' in content


def test_uninstaller_removes_only_product_owned_sysctl_files() -> None:
    content = UNINSTALL.read_text(encoding="utf-8")
    assert "/etc/sysctl.d/99-easypi-ip-forward.conf" in content
    assert "/etc/sysctl.d/99-easypi-tailscale-exit-node.conf" in content
    assert "/etc/sysctl.d/99-ip-forward.conf" not in content


def test_setup_does_not_overwrite_global_iptables_persistence() -> None:
    tailscale = (ROOT / "scripts/setup/tailscale_exit_node.sh").read_text(
        encoding="utf-8"
    )
    gateway = (ROOT / "scripts/setup/gateway_fix.sh").read_text(encoding="utf-8")
    assert "iptables-save > /etc/iptables/rules.v4" not in tailscale
    assert "cat > /etc/network/if-pre-up.d/iptables" not in tailscale
    assert "persist_ipv4_rules" not in gateway


def test_ufw_rules_are_tagged_and_cleanup_preserves_global_policy() -> None:
    firewall = (ROOT / "scripts/security/setup_firewall.sh").read_text(
        encoding="utf-8"
    )
    uninstaller = UNINSTALL.read_text(encoding="utf-8")
    assert "# EasyPi([[:space:]]|$)" in firewall
    assert "comment 'EasyPi SSH'" in firewall
    assert 'comment "EasyPi DNS ${iface}"' in firewall
    assert 'ufw --force delete "$number"' in firewall
    assert "ufw --force reset" not in firewall
    assert "global UFW policies were preserved" in uninstaller
    assert "SSH firewall access was retained for remote recovery" in uninstaller


def test_ufw_cleanup_preserves_existing_ssh_access(tmp_path: Path) -> None:
    """A failed reinstall must not strand a remote administrator."""
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    calls = tmp_path / "ufw-calls"

    ufw = bin_dir / "ufw"
    ufw.write_text(
        r"""#!/bin/bash
set -eu
if [[ "${1:-}" == "status" && "${2:-}" == "numbered" ]]; then
  cat <<'EOF'
[ 1] 22/tcp ALLOW IN Anywhere # EasyPi SSH
[ 2] 80/tcp ALLOW IN Anywhere # EasyPi HTTP
[ 3] 443/tcp ALLOW IN Anywhere # EasyPi HTTPS
[ 4] 9000/tcp ALLOW IN Anywhere # administrator rule
[ 5] 53/udp ALLOW IN Anywhere # EasyPi DNS eth0
EOF
  exit 0
fi
printf '%s\n' "$*" >> "${UFW_TEST_CALLS:?}"
        """,
        encoding="utf-8",
        newline="\n",
    )
    ufw.chmod(0o755)

    sudo = bin_dir / "sudo"
    sudo.write_text(
        '#!/bin/bash\nset -eu\nexec "$@"\n', encoding="utf-8", newline="\n"
    )
    sudo.chmod(0o755)

    def bash_path(path: Path) -> str:
        value = path.resolve().as_posix()
        if len(value) >= 3 and value[1:3] == ":/":
            return f"/mnt/{value[0].lower()}{value[2:]}"
        return value

    bash = shutil.which("bash")
    assert bash is not None
    ufw_path = shlex.quote(bash_path(ufw))
    sudo_path = shlex.quote(bash_path(sudo))
    command = (
        f"chmod 700 {ufw_path} {sudo_path} && "
        f"PATH={shlex.quote(bash_path(bin_dir))}:/usr/bin:/bin "
        f"UFW_TEST_CALLS={shlex.quote(bash_path(calls))} "
        "bash ./scripts/security/setup_firewall.sh clear-runtime"
    )
    result = subprocess.run(
        [bash, "-c", command],
        cwd=ROOT,
        check=False,
        capture_output=True,
        text=True,
    )

    assert result.returncode == 0, result.stderr
    assert calls.read_text(encoding="utf-8").splitlines() == [
        "--force delete 5",
        "--force delete 3",
        "--force delete 2",
    ]


def test_backup_restore_uses_private_validator_accepted_staging() -> None:
    restore = (ROOT / "scripts/backup/restore_config_backup.sh").read_text(
        encoding="utf-8"
    )
    validator = (ROOT / "scripts/utils/secure_restore.py").read_text(encoding="utf-8")
    assert 'mktemp "${BACKUP_DIR}/.restore.XXXXXX.tar.gz"' in restore
    assert "STAGED_NAME_RE" in validator
    assert "decrypted restore staging archive must be private to root" in validator
    assert "/var/lib/easypi/backup/.restore." not in restore


def test_backup_restore_is_detached_quiesced_and_health_gated() -> None:
    restore = (ROOT / "scripts/backup/restore_config_backup.sh").read_text(
        encoding="utf-8"
    )
    assert "systemd-run --quiet --no-block --collect" in restore
    assert "EASYPI_RESTORE_DETACHED=1" in restore
    assert "record_and_stop_services" in restore
    assert "easypi-backend.service" in restore
    assert "RESTORE_STARTED=1" in restore
    assert "rollback_pre_restore" in restore
    assert "backend_health_ok" in restore
    assert "http://127.0.0.1:8000/health" in restore
    assert "remove_restore_changes_before_rollback" in restore
    assert 'PRE_CANDIDATES+=(/opt/EasyPi/data)' in restore
    first_validation = restore.index('--validate-only "$RESTORE_FILE"')
    restore_started = restore.index("RESTORE_STARTED=1")
    assert first_validation < restore_started
    rollback_validation = restore.index('--validate-only "$ROLLBACK_FILE"')
    rollback_delete = restore.index("remove_restore_changes_before_rollback")
    assert rollback_validation < rollback_delete


def test_backup_producers_publish_only_restore_validated_archives() -> None:
    for script_name in ("create_config_backup.sh", "create_full_backup.sh"):
        content = (ROOT / "scripts/backup" / script_name).read_text(encoding="utf-8")
        assert '"$RESTORE_VALIDATOR" --validate-only' in content
        assert "BACKUP_COMPLETE=0" in content
        assert 'rm -f -- "$BACKUP_FILE"' in content
        assert 'install -d -o root -g easypi -m 0750 "$BACKUP_DIR"' in content


def test_backup_mutations_share_a_nonblocking_operation_lock() -> None:
    scripts = [
        ROOT / "scripts/backup/create_config_backup.sh",
        ROOT / "scripts/backup/create_full_backup.sh",
        ROOT / "scripts/backup/restore_config_backup.sh",
    ]
    for script in scripts:
        content = script.read_text(encoding="utf-8")
        assert "exec 9>/run/easypi-backup.lock" in content
        assert "flock -n 9" in content


def test_uninstaller_refuses_to_race_update_backup_or_restore() -> None:
    content = UNINSTALL.read_text(encoding="utf-8")
    assert 'UPDATE_LOCK_FILE="/run/lock/easypi-update.lock"' in content
    assert 'BACKUP_LOCK_FILE="/run/easypi-backup.lock"' in content
    assert 'PACKAGE_LOCK_FILE="/run/lock/easypi-package-manager.lock"' in content
    assert "acquire_operation_locks" in content
    assert "flock -n 7" in content
    assert "flock -n 8" in content
    assert "flock -n 9" in content
    assert content.index("acquire_operation_locks") < content.index(
        "remove_systemd_units", content.index("main()")
    )
    assert "easypi-restore.service" in content


def test_package_mutations_share_a_root_controlled_lock() -> None:
    for script in (
        ROOT / "scripts/setup/install_ffmpeg.sh",
        ROOT / "scripts/security/update_system.sh",
    ):
        content = script.read_text(encoding="utf-8")
        assert 'PACKAGE_LOCK_FILE="/run/lock/easypi-package-manager.lock"' in content
        assert '[[ -d /run/lock && ! -L /run/lock ]]' in content
        assert 'exec 9>"${PACKAGE_LOCK_FILE}"' in content


def test_ffmpeg_install_uses_only_the_reviewed_privileged_runner() -> None:
    service = (ROOT / "backend/app/services/recording_service.py").read_text(
        encoding="utf-8"
    )
    runner = (ROOT / "scripts/runner").read_text(encoding="utf-8")
    helper = (ROOT / "scripts/setup/install_ffmpeg.sh").read_text(encoding="utf-8")

    assert '"setup/install_ffmpeg.sh"' in service
    assert '["setup/install_ffmpeg.sh"]=1' in runner
    assert "sudo apt-get" not in service
    assert "sudo apt-get" not in helper
