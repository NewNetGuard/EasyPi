from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import List


@dataclass
class InternalSecurityIssue:
    id: str
    title: str
    severity: str
    description: str
    recommendation: str
    status: str = "open"
    details: str | None = None


class SecurityScanner:
    """Runs lightweight security checks and returns detected issues."""

    def __init__(self) -> None:
        pass

    def run_scan(self) -> List[InternalSecurityIssue]:
        issues: List[InternalSecurityIssue] = []

        ssh_issue = self._check_ssh_root_login()
        if ssh_issue:
            issues.append(ssh_issue)

        ports_issue = self._check_open_ports()
        if ports_issue:
            issues.append(ports_issue)

        updates_issue = self._check_pending_updates()
        if updates_issue:
            issues.append(updates_issue)

        return issues

    def fix_issue(self, issue_id: str) -> str:
        if issue_id == "ssh_permit_root_login":
            return self._fix_ssh_root_login()
        if issue_id == "package_updates_available":
            return self._run_upgrade()
        if issue_id == "open_ports":
            return "Review the list of open ports and close or secure them manually."
        return "Unknown issue id."

    # ------------------------------------------------------------------ checks

    def _check_ssh_root_login(self) -> InternalSecurityIssue | None:
        ssh_config = Path("/etc/ssh/sshd_config")
        if not ssh_config.exists():
            return None
        try:
            for line in ssh_config.read_text(encoding="utf-8").splitlines():
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                if stripped.lower().startswith("permitrootlogin") and "yes" in stripped.lower():
                    return InternalSecurityIssue(
                        id="ssh_permit_root_login",
                        title="SSH root login enabled",
                        severity="high",
                        description="`PermitRootLogin yes` found in sshd_config.",
                        recommendation="Set `PermitRootLogin no` and restart the ssh service.",
                    )
        except Exception as exc:  # pragma: no cover
            return InternalSecurityIssue(
                id="ssh_permit_root_login",
                title="SSH root login check",
                severity="medium",
                description="Unable to read sshd_config to verify root login settings.",
                recommendation="Manually verify `PermitRootLogin` in /etc/ssh/sshd_config.",
                status="unknown",
                details=str(exc),
            )
        return None

    def _check_open_ports(self) -> InternalSecurityIssue | None:
        """Check open ports using native Python sockets."""
        import socket
        
        # Common ports to check on localhost
        ports_to_check = [
            (22, "SSH"), (80, "HTTP"), (443, "HTTPS"), (21, "FTP"), (23, "Telnet"),
            (3306, "MySQL"), (5432, "PostgreSQL"), (6379, "Redis"), (27017, "MongoDB"),
            (3389, "RDP"), (5900, "VNC"), (8080, "HTTP-Alt"), (8443, "HTTPS-Alt"),
            (25, "SMTP"), (110, "POP3"), (143, "IMAP"), (445, "SMB"), (139, "NetBIOS"),
        ]
        
        open_ports: list[str] = []
        
        for port, service in ports_to_check:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.5)
                result = sock.connect_ex(('127.0.0.1', port))
                sock.close()
                if result == 0:
                    open_ports.append(f"{port}/tcp ({service})")
            except Exception:
                pass
        
        if not open_ports:
            return None

        return InternalSecurityIssue(
            id="open_ports",
            title="Open network ports detected",
            severity="medium",
            description="Open ports on localhost: " + ", ".join(open_ports[:20]),
            recommendation="Confirm these ports are required or restrict access.",
            details="\n".join(open_ports),
        )

    def _check_pending_updates(self) -> InternalSecurityIssue | None:
        try:
            result = subprocess.run(
                ["apt", "list", "--upgradable"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
                timeout=60,
            )
        except FileNotFoundError:
            return InternalSecurityIssue(
                id="package_updates_available",
                title="Package update check",
                severity="medium",
                description="Package manager (apt) not found. Unable to check for updates.",
                recommendation="Ensure apt is installed or run updates manually.",
                status="unknown",
            )
        except subprocess.TimeoutExpired:
            return InternalSecurityIssue(
                id="package_updates_available",
                title="Package update check timed out",
                severity="medium",
                description="Timed out while checking for package updates.",
                recommendation="Run `apt list --upgradable` manually.",
                status="unknown",
            )

        if result.returncode != 0:
            return InternalSecurityIssue(
                id="package_updates_available",
                title="Package update check failed",
                severity="medium",
                description=result.stderr.strip() or "Failed to query apt for updates.",
                recommendation="Run `apt list --upgradable` manually.",
                status="unknown",
            )

        lines = [
            line
            for line in result.stdout.splitlines()
            if line and not line.startswith("Listing...")
        ]
        if len(lines) == 0:
            return None

        return InternalSecurityIssue(
            id="package_updates_available",
            title="Pending package updates",
            severity="medium",
            description=f"{len(lines)} packages have updates available.",
            recommendation="Run `sudo apt-get update && sudo apt-get upgrade`.",
            details="\n".join(lines[:50]),
        )

    # ------------------------------------------------------------------ fixes

    def _fix_ssh_root_login(self) -> str:
        config_path = Path("/etc/ssh/sshd_config")
        if not config_path.exists():
            return "sshd_config not found."
        try:
            content = config_path.read_text(encoding="utf-8").splitlines()
            updated = False
            new_lines: list[str] = []
            for line in content:
                stripped = line.strip()
                if stripped.lower().startswith("permitrootlogin"):
                    if "#" not in line[: line.lower().find("permitrootlogin")]:
                        new_lines.append("PermitRootLogin no")
                        updated = True
                        continue
                new_lines.append(line)
            if not updated:
                new_lines.append("PermitRootLogin no")
            config_path.write_text("\n".join(new_lines) + "\n", encoding="utf-8")
            subprocess.run(
                ["sudo", "systemctl", "reload", "ssh"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                check=False,
            )
            return "Updated sshd_config to disable root login."
        except PermissionError:
            return "Insufficient permissions to modify sshd_config."
        except Exception as exc:  # pragma: no cover
            return f"Failed to update sshd_config: {exc}"

    def _run_upgrade(self) -> str:
        try:
            update = subprocess.run(
                ["sudo", "apt-get", "update"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            if update.returncode != 0:
                return update.stderr.strip() or "apt-get update failed."

            upgrade = subprocess.run(
                ["sudo", "apt-get", "upgrade", "-y"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                check=False,
            )
            if upgrade.returncode != 0:
                return upgrade.stderr.strip() or "apt-get upgrade failed."
            return "System packages upgraded successfully."
        except FileNotFoundError:
            return "apt-get not found. Cannot upgrade packages automatically."
        except PermissionError:
            return "Insufficient permissions to run apt-get."
        except Exception as exc:  # pragma: no cover
            return f"Failed to upgrade packages: {exc}"


__all__ = ["SecurityScanner", "InternalSecurityIssue"]
