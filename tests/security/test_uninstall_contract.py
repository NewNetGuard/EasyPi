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
    }
    assert not {unit for unit in expected if unit not in content}


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
