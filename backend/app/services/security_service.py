"""
Security Service

Handles security scanning, vulnerability detection, and fixes.
All operations use sudo for privileged access.
"""

import asyncio
import os
import re
import shutil
import subprocess
import logging
import json
import time
from datetime import datetime, timezone
from app.utils.time import utc_now
from pathlib import Path
from typing import List, Dict, Optional
from sqlalchemy.orm import Session

from app.models.security import SecurityScan, PasswordChangeLog
from app.schemas.security import SecurityIssue, SecurityScanResponse, FixResponse, FixJobStartResponse, FixJobStatusResponse
from app.core.paths import get_data_dir
from app.core.installer import (
    create_install_job,
    get_installer_log_path,
    read_installer_log,
    start_install_job,
)
from app.services.operation_event_service import OperationEventService

logger = logging.getLogger(__name__)

class SecurityService:
    """Service for security scanning and fixes"""

    def __init__(self):
        self.ssh_config_path = "/etc/ssh/sshd_config"
        self.active_processes: Dict[str, subprocess.Popen] = {}
        self._username_regex = re.compile(r"^[a-z_][a-z0-9_-]{0,31}$")
        self._fsck_state_path = "/opt/EasyPi/data/security/fsck_state.json"
        self._update_job_state_path = get_data_dir() / "security" / "update_job.json"
        self._apt_update_min_interval_sec = int(os.getenv("EASYPI_SECURITY_APT_UPDATE_MIN_INTERVAL_SEC", "600"))
        self._last_apt_update_ts = 0.0
        self._status_cache_ttl_sec = 1.0
        self._status_cache: Dict[str, tuple[float, FixJobStatusResponse]] = {}
        self.operation_event_service = OperationEventService()

    def _record_action_event(
        self,
        *,
        action_id: str,
        title: str,
        subtitle: str,
        route: str,
        status: str,
        message: str,
        started_at: str | None = None,
    ) -> None:
        try:
            self.operation_event_service.record_event(
                action_id=action_id,
                status=status,
                title=title,
                subtitle=subtitle,
                route=route,
                message=message,
                started_at=started_at,
                updated_at=datetime.now(timezone.utc).isoformat(),
            )
        except Exception as exc:
            logger.warning("Failed to record security action event %s: %s", action_id, exc)

    def _sudo_available(self) -> bool:
        try:
            result = subprocess.run(
                ['sudo', '-n', 'true'],
                capture_output=True,
                timeout=3
            )
            return result.returncode == 0
        except Exception:
            return False

    def _validate_username(self, username: str) -> Optional[str]:
        username = (username or "").strip()
        if not username:
            return "Username is required"
        if ":" in username or "\n" in username or "\r" in username:
            return "Username contains invalid characters"
        if not self._username_regex.match(username):
            return "Username is invalid"
        return None

    def _validate_password(self, password: str) -> Optional[str]:
        if not password:
            return "Password is required"
        if "\n" in password or "\r" in password:
            return "Password contains invalid characters"
        if len(password) < 8:
            return "Password must be at least 8 characters"
        return None

    def _ufw_path(self) -> Optional[str]:
        for path in ("/usr/sbin/ufw", "/usr/bin/ufw"):
            if os.path.exists(path):
                return path
        return shutil.which("ufw")

    def _runner_path(self) -> Optional[str]:
        runner = os.getenv("EASYPI_RUNNER", "/opt/EasyPi/scripts/runner")
        if os.path.exists(runner):
            return runner
        return None

    async def _run_installer_job(self, script: str, args: List[str], timeout: int) -> tuple[int, str]:
        """Run a script via the root installer job and wait for completion."""
        job_id = create_install_job(script, args)
        start = start_install_job(job_id, timeout=30)
        if start.returncode != 0:
            err = (start.stderr or start.stdout or "Failed to start installer job").strip()
            return start.returncode, err

        deadline = time.time() + timeout
        last_log = ""
        exit_code: int | None = None
        while time.time() < deadline:
            log = read_installer_log(job_id, max_bytes=16384)
            if log:
                last_log = log
                match = re.search(r"finished \(exit=(\d+)\)", log)
                if match:
                    exit_code = int(match.group(1))
                    break
            import asyncio
            await asyncio.sleep(2)

        if exit_code is None:
            # One more attempt to extract exit code from the last log chunk
            match = re.search(r"finished \(exit=(\d+)\)", last_log)
            if match:
                return int(match.group(1)), last_log
            return 124, (last_log[-500:] if last_log else "Installer job timed out")

        return exit_code, last_log

    def _read_only_mounts(self) -> list[str]:
        """Return list of critical mountpoints that are read-only."""
        mounts: list[str] = []
        seen: set[str] = set()
        root_opts = ""

        def _unescape_mount(path: str) -> str:
            return (
                path.replace("\\040", " ")
                .replace("\\011", "\t")
                .replace("\\012", "\n")
                .replace("\\134", "\\")
            )

        def _opts_from_findmnt(path: str) -> str:
            try:
                result = subprocess.run(
                    ["findmnt", "-no", "OPTIONS", "-T", path],
                    capture_output=True,
                    text=True,
                    timeout=2
                )
                if result.returncode == 0:
                    return result.stdout.strip()
            except Exception as exc:
                logger.debug("findmnt failed for %s: %s", path, exc)
            return ""

        def _opts_from_proc_best(path: str, proc_path: str) -> str:
            try:
                best_opts = ""
                best_len = -1
                with open(proc_path, "r", encoding="utf-8") as handle:
                    for raw in handle:
                        parts = raw.split()
                        if len(parts) < 4:
                            continue
                        mp = _unescape_mount(parts[1])
                        if path == mp or path.startswith(mp.rstrip("/") + "/") or (mp == "/" and path.startswith("/")):
                            if len(mp) > best_len:
                                best_opts = parts[3]
                                best_len = len(mp)
                return best_opts
            except Exception as exc:
                logger.debug("Could not inspect %s for %s: %s", proc_path, path, exc)
            return ""

        def _opts_from_host(path: str) -> str:
            return _opts_from_proc_best(path, "/proc/1/mounts") or _opts_from_proc_best(path, "/proc/mounts")

        for mp in ("/", "/usr", "/var"):
            if mp in seen:
                continue
            opts = _opts_from_host(mp) or _opts_from_findmnt(mp)
            if opts:
                opt_list = opts.split(",")
                if mp == "/" and "rw" in opt_list:
                    root_opts = opts
                if "ro" in opt_list:
                    if mp == "/usr" and ("rw" in root_opts):
                        source, _fstype = self._mount_info(mp)
                        if "[/usr]" in source:
                            continue
                    mounts.append(mp)
                    seen.add(mp)
        return mounts

    def _mount_info(self, mountpoint: str) -> tuple[str, str]:
        """Return (source, fstype) for a mountpoint if available."""
        source = ""
        fstype = ""
        try:
            result = subprocess.run(
                ["findmnt", "-no", "SOURCE,FSTYPE", "-T", mountpoint],
                capture_output=True,
                text=True,
                timeout=3
            )
            if result.returncode == 0:
                parts = result.stdout.strip().split()
                if len(parts) >= 1:
                    source = parts[0]
                if len(parts) >= 2:
                    fstype = parts[1]
        except Exception as exc:
            logger.debug("Could not determine mount information for %s: %s", mountpoint, exc)
        return source, fstype

    def _load_fsck_state(self) -> dict:
        try:
            if os.path.exists(self._fsck_state_path):
                with open(self._fsck_state_path, "r", encoding="utf-8") as handle:
                    return json.load(handle) or {}
        except Exception as exc:
            logger.warning("Could not load filesystem-check state: %s", exc)
        return {}

    def _save_fsck_state(self, state: dict) -> None:
        try:
            os.makedirs(os.path.dirname(self._fsck_state_path), exist_ok=True)
            with open(self._fsck_state_path, "w", encoding="utf-8") as handle:
                json.dump(state, handle)
        except Exception as exc:
            logger.warning("Could not save filesystem-check state: %s", exc)

    def _format_fsck_time(self, timestamp: float) -> str:
        try:
            return datetime.fromtimestamp(timestamp).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            return "unknown"

    def _load_update_job_state(self) -> dict:
        try:
            if self._update_job_state_path.exists():
                with self._update_job_state_path.open("r", encoding="utf-8") as handle:
                    return json.load(handle) or {}
        except Exception as exc:
            logger.warning("Could not load security update state: %s", exc)
        return {}

    def _save_update_job_state(self, job_id: str) -> None:
        try:
            self._update_job_state_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {"job_id": job_id, "started_at": utc_now().timestamp()}
            with self._update_job_state_path.open("w", encoding="utf-8") as handle:
                json.dump(payload, handle)
        except Exception as exc:
            logger.warning("Could not save security update state: %s", exc)

    def _clear_update_job_state(self) -> None:
        try:
            if self._update_job_state_path.exists():
                self._update_job_state_path.unlink()
        except Exception as exc:
            logger.warning("Could not clear security update state: %s", exc)

    def _update_job_file(self, job_id: str) -> Path:
        return get_data_dir() / "installer" / f"{job_id}.json"

    def _installer_log_path(self, job_id: str) -> Path:
        return get_installer_log_path(job_id)

    def _parse_progress(self, log_text: str) -> Optional[int]:
        if not log_text:
            return None
        matches = re.findall(r"(\d{1,3}(?:\.\d+)?)%", log_text)
        if not matches:
            return None
        try:
            value = float(matches[-1])
        except ValueError:
            return None
        value = max(0.0, min(100.0, value))
        return int(round(value))

    def _last_nonempty_line(self, log_text: str) -> str:
        if not log_text:
            return ""
        lines = [line.strip() for line in log_text.splitlines() if line.strip()]
        return lines[-1] if lines else ""

    def _installer_job_status(self, job_id: str) -> FixJobStatusResponse:
        log_tail = read_installer_log(job_id, max_bytes=65536)
        progress = self._parse_progress(log_tail)
        last_line = self._last_nonempty_line(log_tail)
        match = re.search(r"finished \(exit=(\d+)\)", log_tail)

        if match:
            exit_code = int(match.group(1))
            status = "success" if exit_code == 0 else "error"
            message = last_line or ("Update finished successfully" if exit_code == 0 else "Update failed")
            if status == "success":
                progress = 100
                # Surface a reboot hint emitted by update_system.sh (e.g. new kernel).
                reboot_match = re.search(r"\[REBOOT-REQUIRED\]\s*(.*)", log_tail)
                if reboot_match:
                    hint = (reboot_match.group(1) or "").strip() or "reboot recommended"
                    message = f"Update complete — {hint}"
            return FixJobStatusResponse(
                status=status,
                message=message,
                progress=progress,
                job_id=job_id,
            )

        job_file = self._update_job_file(job_id)
        log_file = self._installer_log_path(job_id)
        if not log_tail and not job_file.exists():
            if log_file.exists():
                return FixJobStatusResponse(
                    status="running",
                    message="Update job is starting...",
                    progress=progress,
                    job_id=job_id,
                )
            return FixJobStatusResponse(
                status="idle",
                message="No update job found",
                job_id=job_id,
            )

        return FixJobStatusResponse(
            status="running",
            message=last_line or "Updating packages...",
            progress=progress,
            job_id=job_id,
        )

    def _check_readonly_filesystem(self) -> Optional[SecurityIssue]:
        """Detect read-only filesystem that breaks installs/updates."""
        mounts = self._read_only_mounts()
        if not mounts:
            return None
        mount_list = ", ".join(mounts)
        details_parts: list[str] = [f"Read-only mountpoints: {mount_list}."]
        for mp in mounts:
            source, fstype = self._mount_info(mp)
            if source or fstype:
                details_parts.append(f"{mp}: {source or 'unknown'} {f'({fstype})' if fstype else ''}".strip())
        state = self._load_fsck_state()
        last_request = state.get("last_request")
        if last_request:
            details_parts.append(
                f"Last fsck scheduled: {self._format_fsck_time(last_request)}."
            )
            details_parts.append(
                "Filesystem is still read-only after reboot. This usually indicates disk errors that need manual repair."
            )
        return SecurityIssue(
            id="filesystem_readonly",
            message="Filesystem is read-only",
            status="critical",
            details=(
                " ".join(details_parts)
                + " Updates and installs will fail. Run filesystem check (fsck); "
                + "the fix will schedule a reboot."
            ),
            fixable=True
        )

    def _run_runner(self, script: str, args: Optional[List[str]] = None, timeout: int = 60) -> subprocess.CompletedProcess:
        runner = self._runner_path()
        if not runner:
            raise FileNotFoundError("Runner script not found")
        cmd = ["sudo", "-n", runner, script]
        if args:
            cmd += args
        return subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

    def _get_ssh_port(self) -> int:
        try:
            with open(self.ssh_config_path, "r", encoding="utf-8") as handle:
                port = None
                for raw in handle:
                    line = raw.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.lower().startswith("port"):
                        parts = line.split()
                        if len(parts) >= 2 and parts[1].isdigit():
                            port = int(parts[1])
                if port and 1 <= port <= 65535:
                    return port
        except Exception as exc:
            logger.warning("Failed to read SSH port: %s", exc)
        return 22

    async def run_security_scan(self, db: Session) -> SecurityScanResponse:
        """Run comprehensive security scan"""
        import asyncio

        critical_issues = []
        warnings = []
        passed_checks = []

        # Check 0: Read-only filesystem
        ro_issue = await asyncio.to_thread(self._check_readonly_filesystem)
        if ro_issue:
            critical_issues.append(ro_issue)

        # Check 1: SSH root login
        ssh_root_issue = await asyncio.to_thread(self._check_ssh_root_login)
        if ssh_root_issue:
            critical_issues.append(ssh_root_issue)
        else:
            passed_checks.append(SecurityIssue(
                id="ssh_root_login",
                message="SSH root login is disabled",
                status="passed",
                fixable=False
            ))

        # Check 3: Outdated packages (skip if filesystem is read-only)
        if ro_issue is None:
            outdated_issue = await asyncio.to_thread(self._check_outdated_packages)
            if outdated_issue:
                warnings.append(outdated_issue)
            else:
                passed_checks.append(SecurityIssue(
                    id="outdated_packages",
                    message="All packages are up to date",
                    status="passed",
                    fixable=False
                ))

        # Check 4: Firewall status
        firewall_issue = await asyncio.to_thread(self._check_firewall)
        if firewall_issue:
            warnings.append(firewall_issue)
        else:
            passed_checks.append(SecurityIssue(
                id="firewall_inactive",
                message="Firewall is active and configured",
                status="passed",
                fixable=False
            ))

        # Check 5: Password authentication
        pwd_auth_issue = await asyncio.to_thread(self._check_password_auth)
        if pwd_auth_issue:
            warnings.append(pwd_auth_issue)
        else:
            passed_checks.append(SecurityIssue(
                id="password_auth_enabled",
                message="Password authentication is properly configured",
                status="passed",
                fixable=False
            ))

        # Save scan to database
        scan_data = {
            "critical": [issue.model_dump() for issue in critical_issues],
            "warnings": [issue.model_dump() for issue in warnings],
            "passed": [issue.model_dump() for issue in passed_checks]
        }
        
        scan = SecurityScan(
            scan_date=utc_now(),
            critical_count=len(critical_issues),
            warning_count=len(warnings),
            passed_count=len(passed_checks),
            scan_data=json.dumps(scan_data)
        )
        db.add(scan)
        db.commit()

        return SecurityScanResponse(
            last_scan=scan.scan_date,
            critical=critical_issues,
            warnings=warnings,
            passed=passed_checks
        )

    def _sshd_effective_value(self, key: str) -> Optional[str]:
        """Return the EFFECTIVE value of an sshd directive via `sshd -T`.

        `sshd -T` resolves Include / sshd_config.d drop-ins (cloud-init, etc.).
        Grepping only the main sshd_config misses those drop-ins and produces
        false "secure" readings (e.g. PasswordAuthentication set by cloud-init).
        Returns the lowercased value, or None if it can't be determined.
        """
        try:
            result = subprocess.run(
                ['sudo', '/usr/sbin/sshd', '-T'],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return None
            key_l = key.lower()
            for line in result.stdout.splitlines():
                parts = line.strip().split(None, 1)
                if len(parts) == 2 and parts[0].lower() == key_l:
                    return parts[1].strip().lower()
        except Exception as e:
            logger.error(f"Error reading effective sshd config: {e}")
        return None

    def _check_ssh_root_login(self) -> Optional[SecurityIssue]:
        """Check if SSH root login is enabled (effective config, drop-in aware)."""
        if self._sshd_effective_value("permitrootlogin") == "yes":
            return SecurityIssue(
                id="ssh_root_login",
                message="SSH root login is enabled",
                status="critical",
                details="Direct root login via SSH is a security risk",
                fixable=True
            )
        return None

    def _check_outdated_packages(self) -> Optional[SecurityIssue]:
        """Check for outdated packages"""
        try:
            if self._read_only_mounts():
                return SecurityIssue(
                    id="outdated_packages",
                    message="Package updates unavailable",
                    status="warning",
                    details="Filesystem is read-only. Run filesystem check (fsck) first.",
                    fixable=False
                )

            state = self._load_update_job_state()
            existing_job = state.get("job_id")
            if existing_job:
                job_status = self._installer_job_status(existing_job)
                if job_status.status == "running":
                    return SecurityIssue(
                        id="outdated_packages",
                        message="Package update is in progress",
                        status="warning",
                        details=job_status.message or "EasyPi is updating system packages in the background.",
                        fixable=False,
                    )
                if job_status.status in {"success", "error", "idle"}:
                    self._clear_update_job_state()

            # Refresh apt metadata at most once per interval to avoid repeated heavy scans.
            now = time.time()
            should_refresh_apt = (now - self._last_apt_update_ts) >= self._apt_update_min_interval_sec
            if should_refresh_apt and self._sudo_available():
                runner = self._runner_path()
                if runner:
                    try:
                        self._run_runner("security/update_system.sh", ["update"], timeout=120)
                        self._last_apt_update_ts = now
                    except Exception as exc:
                        logger.warning("Runner update failed: %s", exc)
                else:
                    try:
                        subprocess.run(
                            ['sudo', 'apt', 'update'],
                            capture_output=True,
                            timeout=30
                        )
                        self._last_apt_update_ts = now
                    except Exception as exc:
                        logger.warning("apt update failed: %s", exc)
            
            # Check for upgradable packages
            result = subprocess.run(
                ['apt', 'list', '--upgradable'],
                capture_output=True,
                text=True,
                timeout=10
            )

            if result.returncode == 0:
                lines = result.stdout.strip().split('\n')
                # First line is header, count actual packages
                upgradable = [line for line in lines if '/' in line and 'upgradable' in line.lower()]
                
                if len(upgradable) > 0:
                    return SecurityIssue(
                        id="outdated_packages",
                        message=f"{len(upgradable)} packages need updating",
                        status="warning",
                        details=f"Found {len(upgradable)} outdated packages",
                        fixable=True
                    )
            else:
                error_output = "\n".join(
                    part.strip() for part in (result.stdout or "", result.stderr or "") if part and part.strip()
                )
                lower_output = error_output.lower()
                if (
                    "could not get lock" in lower_output
                    or "could not open lock file" in lower_output
                    or "unable to acquire the dpkg frontend lock" in lower_output
                    or "is another process using it" in lower_output
                    or "dpkg was interrupted" in lower_output
                ):
                    return SecurityIssue(
                        id="outdated_packages",
                        message="Package manager is busy",
                        status="warning",
                        details="Another package operation is still running. Wait for it to finish and scan again.",
                        fixable=False,
                    )
                logger.warning("Unable to verify outdated packages: %s", error_output or "unknown apt error")
                return SecurityIssue(
                    id="outdated_packages",
                    message="Package update status is temporarily unavailable",
                    status="warning",
                    details="EasyPi could not verify outdated packages right now. Try again in a moment.",
                    fixable=False,
                )
        except Exception as e:
            logger.error(f"Error checking packages: {e}")
            return SecurityIssue(
                id="outdated_packages",
                message="Package update status is temporarily unavailable",
                status="warning",
                details="EasyPi could not verify outdated packages right now. Try again in a moment.",
                fixable=False,
            )

        return None

    def _check_firewall(self) -> Optional[SecurityIssue]:
        """Check UFW firewall status"""
        try:
            ufw_bin = self._ufw_path()
            if ufw_bin is None:
                return SecurityIssue(
                    id="firewall_inactive",
                    message="Firewall is not configured",
                    status="warning",
                    details="UFW firewall is not installed",
                    fixable=True
                )
            runner = self._runner_path()
            if runner is None:
                return SecurityIssue(
                    id="firewall_inactive",
                    message="Firewall status is unavailable",
                    status="warning",
                    details="EasyPi privileged runner is not installed",
                    fixable=False,
                )
            result = subprocess.run(
                [
                    "sudo", "-n", runner,
                    "settings/network_firewall.sh", "ufw-status", "normal",
                ],
                capture_output=True,
                text=True,
                timeout=5
            )
            
            if result.returncode == 0:
                if 'inactive' in result.stdout.lower():
                    return SecurityIssue(
                        id="firewall_inactive",
                        message="Firewall is not configured",
                        status="warning",
                        details="UFW firewall is inactive",
                        fixable=True
                    )
        except Exception as e:
            logger.error(f"Error checking firewall: {e}")
            
        return None

    def _check_password_auth(self) -> Optional[SecurityIssue]:
        """Check if password authentication is enabled (effective config, drop-in aware)."""
        if self._sshd_effective_value("passwordauthentication") == "yes":
            return SecurityIssue(
                id="password_auth_enabled",
                message="Password authentication is enabled",
                status="warning",
                details="Consider using SSH keys instead of passwords",
                fixable=True
            )
        return None

    # ===== FIX METHODS =====

    async def fix_default_password(self, username: str, new_password: str) -> FixResponse:
        """Change user password"""
        from app.db.session import SessionLocal
        db = SessionLocal()
        started_at = datetime.now(timezone.utc).isoformat()
        
        try:
            username_error = self._validate_username(username)
            if username_error:
                self._record_action_event(
                    action_id="security.fix_default_password",
                    title="Change default password",
                    subtitle="Security · Account hardening",
                    route="/security",
                    status="failed",
                    message=username_error,
                    started_at=started_at,
                )
                return FixResponse(status="error", message=username_error)
            password_error = self._validate_password(new_password)
            if password_error:
                self._record_action_event(
                    action_id="security.fix_default_password",
                    title="Change default password",
                    subtitle="Security · Account hardening",
                    route="/security",
                    status="failed",
                    message=password_error,
                    started_at=started_at,
                )
                return FixResponse(status="error", message=password_error)

            user_check = (await asyncio.to_thread(subprocess.run, 
                ['getent', 'passwd', username],
                capture_output=True,
                text=True,
                timeout=5
            ))
            if user_check.returncode != 0:
                self._record_action_event(
                    action_id="security.fix_default_password",
                    title="Change default password",
                    subtitle="Security · Account hardening",
                    route="/security",
                    status="failed",
                    message="User not found",
                    started_at=started_at,
                )
                return FixResponse(status="error", message="User not found")

            runner = self._runner_path()
            if not runner:
                self._record_action_event(
                    action_id="security.fix_default_password",
                    title="Change default password",
                    subtitle="Security · Account hardening",
                    route="/security",
                    status="failed",
                    message="Runner script not found",
                    started_at=started_at,
                )
                return FixResponse(status="error", message="Runner script not found")

            process = await asyncio.to_thread(
                subprocess.Popen,
                ['sudo', '-n', runner, 'security/set_user_password.sh', username],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True
            )
            
            stdout, stderr = await asyncio.to_thread(process.communicate, f"{new_password}\n", 10)
            
            if process.returncode == 0:
                logger.info(f"Password changed for user {username}")
                
                # Record password change in database
                password_log = db.query(PasswordChangeLog).filter(
                    PasswordChangeLog.username == username
                ).first()
                
                if password_log:
                    password_log.changed_at = utc_now()
                else:
                    password_log = PasswordChangeLog(
                        username=username,
                        changed_at=utc_now(),
                        changed_by="security_module"
                    )
                    db.add(password_log)
                
                db.commit()
                self._record_action_event(
                    action_id="security.fix_default_password",
                    title="Change default password",
                    subtitle="Security · Account hardening",
                    route="/security",
                    status="success",
                    message=f"Password successfully changed for user '{username}'",
                    started_at=started_at,
                )
                
                return FixResponse(
                    status="success",
                    message=f"Password successfully changed for user '{username}'"
                )
            else:
                logger.error("Failed to change password: %s", stderr)
                self._record_action_event(
                    action_id="security.fix_default_password",
                    title="Change default password",
                    subtitle="Security · Account hardening",
                    route="/security",
                    status="failed",
                    message="Failed to change password",
                    started_at=started_at,
                )
                return FixResponse(
                    status="error",
                    message="Failed to change password"
                )
        except Exception as e:
            logger.error("Error changing password: %s", e)
            self._record_action_event(
                action_id="security.fix_default_password",
                title="Change default password",
                subtitle="Security · Account hardening",
                route="/security",
                status="failed",
                message="Failed to change password",
                started_at=started_at,
            )
            return FixResponse(
                status="error",
                message="Failed to change password"
            )
        finally:
            db.close()

    async def fix_ssh_root_login(self) -> FixResponse:
        """Disable SSH root login"""
        started_at = datetime.now(timezone.utc).isoformat()
        try:
            result = self._run_runner(
                "security/sshd_hardening.sh",
                ["disable-root-login"],
                timeout=10,
            )
            
            if result.returncode != 0:
                self._record_action_event(
                    action_id="security.fix_ssh_root_login",
                    title="Disable SSH root login",
                    subtitle="Security · SSH hardening",
                    route="/security",
                    status="failed",
                    message="Failed to write SSH config",
                    started_at=started_at,
                )
                return FixResponse(status="error", message="Failed to write SSH config")

            restart_result = (await asyncio.to_thread(subprocess.run, 
                ['sudo', 'systemctl', 'restart', 'ssh'],
                capture_output=True,
                timeout=10
            ))

            if restart_result.returncode == 0:
                logger.info("SSH root login disabled and service restarted")
                self._record_action_event(
                    action_id="security.fix_ssh_root_login",
                    title="Disable SSH root login",
                    subtitle="Security · SSH hardening",
                    route="/security",
                    status="success",
                    message="SSH root login disabled successfully",
                    started_at=started_at,
                )
                return FixResponse(
                    status="success",
                    message="SSH root login disabled successfully"
                )
            self._record_action_event(
                action_id="security.fix_ssh_root_login",
                title="Disable SSH root login",
                subtitle="Security · SSH hardening",
                route="/security",
                status="failed",
                message="Config updated but failed to restart SSH service",
                started_at=started_at,
            )
            return FixResponse(
                status="error",
                message="Config updated but failed to restart SSH service"
            )

        except Exception as e:
            logger.error(f"Error fixing SSH root login: {e}")
            self._record_action_event(
                action_id="security.fix_ssh_root_login",
                title="Disable SSH root login",
                subtitle="Security · SSH hardening",
                route="/security",
                status="failed",
                message="Failed to update SSH settings",
                started_at=started_at,
            )
            return FixResponse(status="error", message="Failed to update SSH settings")

    async def fix_outdated_packages(self) -> FixResponse:
        """Update all packages using runner script that handles filesystem issues.
        
        Uses asyncio subprocess to avoid blocking the event loop which can cause
        server crashes during long-running package upgrades.
        """
        import asyncio
        
        def _ro_message(raw: str) -> str | None:
            if not raw:
                return None
            lower = raw.lower()
            if "read-only file system" in lower or "readonly file system" in lower:
                return (
                    "Filesystem is read-only. This usually means disk/filesystem errors. "
                    "Reboot the device and run a filesystem check (fsck)."
                )
            return None

        try:
            ro_mounts = self._read_only_mounts()
            if ro_mounts:
                return FixResponse(
                    status="error",
                    message=(
                        "Filesystem is read-only. Run filesystem check (fsck) "
                        "from Security > Fix to restore write access."
                    )
                )

            def _tail(log: str, limit: int = 300) -> str:
                lines = [line for line in (log or "").splitlines() if line.strip()]
                if not lines:
                    return ""
                return lines[-1][:limit]
            
            # Step 1: Update package list (async)
            logger.info("Step 1: Updating package list...")
            update_code, update_log = await self._run_installer_job(
                "security/update_system.sh",
                ["update"],
                timeout=600
            )
            if update_code != 0:
                error_msg = update_log or "Unknown error"
                logger.error(f"apt-get update failed: {error_msg}")
                ro_hint = _ro_message(error_msg)
                if ro_hint:
                    return FixResponse(status="error", message=ro_hint)
                return FixResponse(status="error", message=f"Failed to update package list: {_tail(error_msg) or 'Unknown error'}")
            
            logger.info("Package list updated successfully")
            
            # Step 2: Check what needs upgrading (async)
            logger.info("Step 2: Checking upgradable packages...")
            check_process = await asyncio.create_subprocess_exec(
                "apt", "list", "--upgradable",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            
            try:
                check_stdout, _ = await asyncio.wait_for(
                    check_process.communicate(),
                    timeout=30
                )
            except asyncio.TimeoutError:
                check_process.kill()
                return FixResponse(status="error", message="Package check timed out")
            
            check_output = check_stdout.decode() if check_stdout else ""
            upgradable_count = len([line for line in check_output.split('\n') if '/' in line and 'upgradable' in line.lower()])
            logger.info(f"Found {upgradable_count} upgradable packages")
            
            if upgradable_count == 0:
                return FixResponse(status="success", message="All packages are up to date")
            
            # Step 3: Run upgrade (async with longer timeout)
            logger.info(f"Step 3: Starting upgrade of {upgradable_count} packages...")

            upgrade_code, upgrade_log = await self._run_installer_job(
                "security/update_system.sh",
                ["upgrade"],
                timeout=900  # 15 minutes for large upgrades
            )

            logger.info(f"Upgrade completed with return code: {upgrade_code}")
            if upgrade_log:
                logger.info(f"Upgrade log tail: {_tail(upgrade_log, 500)}")

            if upgrade_code == 0:
                # Verify packages were actually upgraded (async)
                verify_process = await asyncio.create_subprocess_exec(
                    "apt", "list", "--upgradable",
                    stdout=asyncio.subprocess.PIPE,
                    stderr=asyncio.subprocess.PIPE
                )
                
                try:
                    verify_stdout, _ = await asyncio.wait_for(
                        verify_process.communicate(),
                        timeout=30
                    )
                except asyncio.TimeoutError:
                    verify_process.kill()
                    # Don't fail just because verify timed out
                    return FixResponse(status="success", message=f"Upgraded {upgradable_count} packages")
                
                verify_output = verify_stdout.decode() if verify_stdout else ""
                remaining = len([line for line in verify_output.split('\n') if '/' in line and 'upgradable' in line.lower()])
                
                logger.info(f"After upgrade: {remaining} packages still need updating")
                
                if remaining == 0:
                    return FixResponse(
                        status="success",
                        message=f"Successfully upgraded {upgradable_count} packages"
                    )
                else:
                    return FixResponse(
                        status="success",
                        message=f"Upgraded some packages. {remaining} still pending (may require reboot)"
                    )
            else:
                error_msg = upgrade_log or "Unknown error"
                logger.error(f"Upgrade failed with code {upgrade_code}: {error_msg}")
                ro_hint = _ro_message(error_msg)
                if ro_hint:
                    return FixResponse(status="error", message=ro_hint)
                return FixResponse(status="error", message=f"Upgrade failed: {_tail(error_msg) or 'Unknown error'}")
                
        except Exception as e:
            logger.error(f"Error upgrading packages: {e}", exc_info=True)
            return FixResponse(status="error", message=f"Exception: {str(e)}")

    async def start_outdated_packages_fix(self) -> FixJobStartResponse:
        """Start package update via installer service and return a job id."""
        ro_mounts = self._read_only_mounts()
        if ro_mounts:
            return FixJobStartResponse(
                status="error",
                message=(
                    "Filesystem is read-only. Run filesystem check (fsck) "
                    "from Security > Fix to restore write access."
                ),
            )

        state = self._load_update_job_state()
        existing_job = state.get("job_id")
        if existing_job:
            status = self._installer_job_status(existing_job)
            if status.status == "running":
                # Treat as success so the UI doesn't show a false error
                return FixJobStartResponse(
                    status="success",
                    message="Package update is already running",
                    job_id=existing_job,
                )
            # cleanup stale state if job finished
            self._clear_update_job_state()

        try:
            job_id = create_install_job("security/update_system.sh", ["upgrade"])
            self._save_update_job_state(job_id)
            result = start_install_job(job_id, timeout=30, no_block=True)
            if result.returncode != 0:
                # The installer unit did not start (e.g. sudo denied the command).
                # Do NOT mask this as "running" вЂ” the job has no log and will never
                # progress, leaving the UI stuck. Surface the real error instead.
                err = (result.stderr or result.stdout or "Failed to start installer job").strip()
                self._clear_update_job_state()
                logger.error("Installer unit failed to start for job %s: %s", job_id, err)
                return FixJobStartResponse(status="error", message=err[:200] or "Failed to start update job")
            return FixJobStartResponse(
                status="success",
                message="Package update started",
                job_id=job_id,
            )
        except Exception as exc:
            logger.error("Failed to start package update: %s", exc, exc_info=True)
            return FixJobStartResponse(status="error", message="Failed to start package update")

    def get_outdated_packages_status(self, job_id: Optional[str] = None) -> FixJobStatusResponse:
        """Return status for an update job (running/success/error/idle)."""
        if not job_id:
            state = self._load_update_job_state()
            job_id = state.get("job_id")

        if not job_id:
            return FixJobStatusResponse(status="idle", message="No update job running")

        now = time.time()
        cached = self._status_cache.get(job_id)
        if cached and (now - cached[0]) < self._status_cache_ttl_sec:
            return cached[1]

        status = self._installer_job_status(job_id)
        self._status_cache[job_id] = (now, status)
        if status.status in ("success", "error", "idle"):
            self._status_cache.pop(job_id, None)
            self._clear_update_job_state()
        return status

    async def fix_filesystem_readonly(self) -> FixResponse:
        """Schedule filesystem check and reboot to recover read-only mounts."""
        started_at = datetime.now(timezone.utc).isoformat()
        try:
            if not self._sudo_available():
                self._record_action_event(
                    action_id="security.fix_filesystem_readonly",
                    title="Schedule filesystem recovery",
                    subtitle="Security · Filesystem maintenance",
                    route="/security",
                    status="failed",
                    message="sudo is required to schedule filesystem check",
                    started_at=started_at,
                )
                return FixResponse(status="error", message="sudo is required to schedule filesystem check")
            runner = self._runner_path()
            if not runner:
                self._record_action_event(
                    action_id="security.fix_filesystem_readonly",
                    title="Schedule filesystem recovery",
                    subtitle="Security · Filesystem maintenance",
                    route="/security",
                    status="failed",
                    message="Runner script not found. Cannot schedule filesystem check.",
                    started_at=started_at,
                )
                return FixResponse(status="error", message="Runner script not found. Cannot schedule filesystem check.")

            result = (await asyncio.to_thread(subprocess.run, 
                ["sudo", "-n", runner, "security/fsck_reboot.sh"],
                capture_output=True,
                text=True,
                timeout=10
            ))
            if result.returncode == 0:
                self._save_fsck_state({"last_request": utc_now().timestamp()})
                self._record_action_event(
                    action_id="security.fix_filesystem_readonly",
                    title="Schedule filesystem recovery",
                    subtitle="Security · Filesystem maintenance",
                    route="/security",
                    status="success",
                    message="Filesystem check scheduled. Device will reboot shortly.",
                    started_at=started_at,
                )
                return FixResponse(
                    status="success",
                    message="Filesystem check scheduled. Device will reboot shortly."
                )

            error_msg = (result.stderr or result.stdout or "Unknown error").strip()
            safe = error_msg.splitlines()[0][:200] if error_msg else "Failed to schedule filesystem check"
            self._record_action_event(
                action_id="security.fix_filesystem_readonly",
                title="Schedule filesystem recovery",
                subtitle="Security · Filesystem maintenance",
                route="/security",
                status="failed",
                message=safe,
                started_at=started_at,
            )
            return FixResponse(status="error", message=safe)
        except Exception as exc:
            logger.error("Failed to schedule filesystem check: %s", exc)
            self._record_action_event(
                action_id="security.fix_filesystem_readonly",
                title="Schedule filesystem recovery",
                subtitle="Security · Filesystem maintenance",
                route="/security",
                status="failed",
                message="Failed to schedule filesystem check",
                started_at=started_at,
            )
            return FixResponse(status="error", message="Failed to schedule filesystem check")
    
    def cancel_fix(self, fix_type: str) -> Dict[str, str]:
        """Cancel active fix operation.
        
        Note: With async subprocess, cancellation is handled by the async task.
        This method now just returns info that async operations can't be cancelled
        from here.
        """
        logger.info(f"Cancel request for fix operation: {fix_type}")
        # Async operations are managed by asyncio, not here
        return {"status": "info", "message": "Async operations will complete or timeout automatically"}

    async def fix_firewall(self) -> FixResponse:
        """Enable and configure UFW firewall"""
        started_at = datetime.now(timezone.utc).isoformat()
        try:
            if not self._sudo_available():
                self._record_action_event(
                    action_id="security.fix_firewall",
                    title="Enable firewall hardening",
                    subtitle="Security · Firewall",
                    route="/security",
                    status="failed",
                    message="sudo is required to configure firewall",
                    started_at=started_at,
                )
                return FixResponse(status="error", message="sudo is required to configure firewall")
            if shutil.which("apt-get") is None:
                self._record_action_event(
                    action_id="security.fix_firewall",
                    title="Enable firewall hardening",
                    subtitle="Security · Firewall",
                    route="/security",
                    status="failed",
                    message="apt-get not found on system",
                    started_at=started_at,
                )
                return FixResponse(status="error", message="apt-get not found on system")

            ufw_bin = self._ufw_path()
            if ufw_bin is None:
                install = (await asyncio.to_thread(subprocess.run, 
                    ['sudo', 'apt-get', 'install', '-y', 'ufw'],
                    capture_output=True,
                    text=True,
                    timeout=300
                ))
                if install.returncode != 0:
                    err = (install.stderr or install.stdout).strip()
                    safe = err.splitlines()[0][:200] if err else "UFW install failed"
                    self._record_action_event(
                        action_id="security.fix_firewall",
                        title="Enable firewall hardening",
                        subtitle="Security · Firewall",
                        route="/security",
                        status="failed",
                        message=safe,
                        started_at=started_at,
                    )
                    return FixResponse(status="error", message=safe)
                ufw_bin = self._ufw_path()
                if ufw_bin is None:
                    self._record_action_event(
                        action_id="security.fix_firewall",
                        title="Enable firewall hardening",
                        subtitle="Security · Firewall",
                        route="/security",
                        status="failed",
                        message="UFW install failed",
                        started_at=started_at,
                    )
                    return FixResponse(status="error", message="UFW install failed")

            ssh_port = self._get_ssh_port()
            # Allow SSH first to prevent lockout
            await asyncio.to_thread(
                self._run_runner,
                "settings/network_firewall.sh",
                ["ufw-rule", "add", "allow", "tcp", str(ssh_port), "any"],
                10,
            )
            # Allow web UI (HTTP/HTTPS) before enabling
            await asyncio.to_thread(
                self._run_runner,
                "settings/network_firewall.sh",
                ["ufw-rule", "add", "allow", "tcp", "80", "any"],
                10,
            )
            await asyncio.to_thread(
                self._run_runner,
                "settings/network_firewall.sh",
                ["ufw-rule", "add", "allow", "tcp", "443", "any"],
                10,
            )
            
            # Enable firewall
            result = await asyncio.to_thread(
                self._run_runner,
                "settings/network_firewall.sh",
                ["ufw-toggle", "enable"],
                10,
            )
            
            if result.returncode == 0:
                logger.info("Firewall enabled successfully")
                self._record_action_event(
                    action_id="security.fix_firewall",
                    title="Enable firewall hardening",
                    subtitle="Security · Firewall",
                    route="/security",
                    status="success",
                    message=f"Firewall enabled with SSH ({ssh_port}/tcp) and web access (80/443)",
                    started_at=started_at,
                )
                return FixResponse(
                    status="success",
                    message=f"Firewall enabled with SSH ({ssh_port}/tcp) and web access (80/443)"
                )
            else:
                err = (result.stderr or result.stdout).strip()
                safe = err.splitlines()[0][:200] if err else "Failed to enable firewall"
                self._record_action_event(
                    action_id="security.fix_firewall",
                    title="Enable firewall hardening",
                    subtitle="Security · Firewall",
                    route="/security",
                    status="failed",
                    message=f"Failed to enable firewall: {safe}",
                    started_at=started_at,
                )
                return FixResponse(
                    status="error",
                    message=f"Failed to enable firewall: {safe}"
                )
                
        except Exception as e:
            logger.error(f"Error enabling firewall: {e}")
            self._record_action_event(
                action_id="security.fix_firewall",
                title="Enable firewall hardening",
                subtitle="Security · Firewall",
                route="/security",
                status="failed",
                message="Failed to enable firewall",
                started_at=started_at,
            )
            return FixResponse(status="error", message="Failed to enable firewall")

    async def fix_password_auth(self) -> FixResponse:
        """Disable password authentication in SSH"""
        started_at = datetime.now(timezone.utc).isoformat()
        try:
            result = self._run_runner(
                "security/sshd_hardening.sh",
                ["disable-password-auth"],
                timeout=10,
            )
            
            if result.returncode != 0:
                self._record_action_event(
                    action_id="security.fix_password_auth",
                    title="Disable SSH password authentication",
                    subtitle="Security · SSH hardening",
                    route="/security",
                    status="failed",
                    message="Failed to write SSH config",
                    started_at=started_at,
                )
                return FixResponse(status="error", message="Failed to write SSH config")

            restart_result = (await asyncio.to_thread(subprocess.run, 
                ['sudo', 'systemctl', 'restart', 'ssh'],
                capture_output=True,
                timeout=10
            ))

            if restart_result.returncode == 0:
                logger.info("Password authentication disabled")
                self._record_action_event(
                    action_id="security.fix_password_auth",
                    title="Disable SSH password authentication",
                    subtitle="Security · SSH hardening",
                    route="/security",
                    status="success",
                    message="Password authentication disabled successfully",
                    started_at=started_at,
                )
                return FixResponse(
                    status="success",
                    message="Password authentication disabled successfully"
                )
            self._record_action_event(
                action_id="security.fix_password_auth",
                title="Disable SSH password authentication",
                subtitle="Security · SSH hardening",
                route="/security",
                status="failed",
                message="Config updated but failed to restart SSH",
                started_at=started_at,
            )
            return FixResponse(
                status="error",
                message="Config updated but failed to restart SSH"
            )

        except Exception as e:
            logger.error(f"Error disabling password auth: {e}")
            self._record_action_event(
                action_id="security.fix_password_auth",
                title="Disable SSH password authentication",
                subtitle="Security · SSH hardening",
                route="/security",
                status="failed",
                message="Failed to update SSH settings",
                started_at=started_at,
            )
            return FixResponse(status="error", message="Failed to update SSH settings")
