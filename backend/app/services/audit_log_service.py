from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass
from pathlib import Path


@dataclass
class AuditLogRecord:
    timestamp: str
    type: str
    title: str
    details: str
    source: str


class AuditLogService:
    """Read and normalize security-relevant auth and session logs."""

    def read_recent(self, limit: int = 50) -> list[AuditLogRecord]:
        safe_limit = max(1, min(limit, 200))
        logs: list[AuditLogRecord] = []
        auth_log = Path("/var/log/auth.log")

        if not auth_log.exists():
            for alt_path in ("/var/log/secure", "/var/log/messages"):
                if Path(alt_path).exists():
                    auth_log = Path(alt_path)
                    break

        if auth_log.exists():
            try:
                result = subprocess.run(
                    ["tail", "-n", str(safe_limit * 3), str(auth_log)],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    for line in reversed(result.stdout.strip().splitlines()):
                        if len(logs) >= safe_limit:
                            break
                        entry = self._parse_auth_log_line(line)
                        if entry:
                            logs.append(entry)
            except (subprocess.TimeoutExpired, PermissionError, Exception):
                pass

        if len(logs) < safe_limit:
            try:
                result = subprocess.run(
                    ["journalctl", "-u", "ssh", "-n", str(safe_limit), "--no-pager", "-o", "short"],
                    capture_output=True,
                    text=True,
                    timeout=10,
                )
                if result.returncode == 0:
                    for line in result.stdout.strip().splitlines():
                        if len(logs) >= safe_limit:
                            break
                        entry = self._parse_journalctl_line(line)
                        if entry:
                            logs.append(entry)
            except (subprocess.TimeoutExpired, FileNotFoundError, Exception):
                pass

        return logs[:safe_limit]

    def _parse_auth_log_line(self, line: str) -> AuditLogRecord | None:
        if not line.strip():
            return None

        patterns = [
            (r"Accepted (?:password|publickey) for (\S+) from (\S+)", "success", "Successful SSH login", "ssh"),
            (r"Failed password for (?:invalid user )?(\S+) from (\S+)", "warning", "Failed SSH login attempt", "ssh"),
            (r"Invalid user (\S+) from (\S+)", "warning", "Invalid user login attempt", "ssh"),
            (r"Connection closed by (?:authenticating user )?(\S+)? ?(\S+)?", "info", "SSH connection closed", "ssh"),
            (r"session opened for user (\S+)", "success", "Session started", "pam"),
            (r"session closed for user (\S+)", "info", "Session ended", "pam"),
            (r"(\S+) : .* COMMAND=(.+)", "info", "Sudo command executed", "sudo"),
            (r"(\S+) : .*authentication failure", "warning", "Sudo authentication failed", "sudo"),
            (r"message repeated (\d+) times.*Failed", "warning", "Multiple failed attempts", "ssh"),
        ]

        for pattern, log_type, title, source in patterns:
            match = re.search(pattern, line, re.IGNORECASE)
            if not match:
                continue

            timestamp_match = re.match(r"(\w{3}\s+\d+\s+\d+:\d+:\d+)", line)
            timestamp = timestamp_match.group(1) if timestamp_match else "Unknown"

            groups = [group for group in match.groups() if group]
            if source == "ssh" and len(groups) >= 2:
                details = f"User: {groups[0]} | From: {groups[1]}"
            elif source == "sudo" and len(groups) >= 2:
                details = f"User: {groups[0]} | Command arguments hidden"
            elif groups:
                details = f"User: {groups[0]}"
            else:
                details = line[20:120] if len(line) > 20 else line

            return AuditLogRecord(
                timestamp=timestamp,
                type=log_type,
                title=title,
                details=details,
                source=source,
            )

        return None

    def _parse_journalctl_line(self, line: str) -> AuditLogRecord | None:
        if not line.strip() or "-- " in line:
            return None

        match = re.match(r"(\w{3}\s+\d+\s+\d+:\d+:\d+)\s+\S+\s+(\S+?)(?:\[\d+\])?:\s*(.+)", line)
        if not match:
            return None

        timestamp, service, message = match.groups()
        structured = self._parse_auth_log_line(f"{timestamp} {message}")
        if structured is None:
            return None

        return AuditLogRecord(
            timestamp=timestamp,
            type=structured.type,
            title=structured.title,
            details=structured.details,
            source=service.replace("sshd", "ssh"),
        )


audit_log_service = AuditLogService()
