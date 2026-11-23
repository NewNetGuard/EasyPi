"""Security scan and fix diagnostics module."""

from __future__ import annotations

from app.agent.adapters.security import SecurityAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class SecurityAgent:
    """Explain security scan and fix state."""

    name = "security_agent"
    _KEYWORDS = (
        "security scan",
        "security",
        "hardening",
        "fix",
        "firewall",
        "root login",
        "password auth",
        "outdated packages",
        "package update",
        "read-only filesystem",
        "filesystem readonly",
        "audit log",
        "threat journal",
        "journal ingestion",
        "auth journal",
    )
    _ROUTES = ("security",)
    _FIX_GUIDANCE_WORDS = ("safe fix", "what fix", "which fix", "available fix", "fix action", "remediation")
    _REBOOT_WORDS = ("reboot", "restart after fix", "requires reboot", "need reboot")
    _AUDIT_WORDS = (
        "audit log",
        "audit logs",
        "auth log",
        "security log",
        "failed login",
        "authentication failure",
        "threat journal",
        "journal ingestion",
        "auth journal",
    )

    def __init__(self, adapter: SecurityAdapter) -> None:
        self.adapter = adapter

    def score(self, request: AgentRequest) -> int:
        question = request.question.lower()
        route = (request.route or "").lower()
        target = (request.target or "").lower()
        score = 0
        if any(keyword in question or keyword in target for keyword in self._KEYWORDS):
            score += 110
        if any(token in route for token in self._ROUTES):
            score += 45
        if request.target_type == "service":
            score += 20
        return score

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        question = request.question.lower()
        route = (request.route or "").lower()
        target = (request.target or "").lower()
        if not any(keyword in question or keyword in target for keyword in self._KEYWORDS) and not any(token in route for token in self._ROUTES):
            return None

        if any(token in question or token in target for token in self._AUDIT_WORDS):
            return self._audit_log_response()

        if any(token in question for token in ("outdated", "package", "update job", "upgrade")):
            return self._update_job_response()

        try:
            scan = self.adapter.get_latest_scan()
        except Exception as exc:
            return self._source_failure_response("security-scan", "Security scan source", exc)
        checks_run = ["latest_security_scan"]
        if not scan:
            return AgentResponse(
                category="service",
                target="security-scan",
                matched=True,
                title="Security scan diagnostics unavailable",
                summary="No saved security scan is available, so the current security state is unknown.",
                confidence="low",
                section="security",
                subsection="scan-fixes",
                module=self.name,
                checks_run=["latest_security_scan"],
                facts=[AgentFact("Saved scan", "Unavailable", "warning")],
                reason_chain=[
                    "The read-only diagnostics path checked for a saved scan.",
                    "It did not start a new scan because scans can change persisted state.",
                ],
                recommendations=[
                    "Run a security scan explicitly from System Security, then ask the agent to explain the saved result.",
                ],
            )
        issues = self._all_issues(scan)
        if any(token in question for token in self._REBOOT_WORDS):
            issue = self._reboot_issue(issues)
            if issue is not None:
                return self._reboot_response(issue, scan, checks_run)
        if any(token in question for token in self._FIX_GUIDANCE_WORDS):
            issue = self._preferred_fix_issue(issues)
            if issue is not None:
                return self._fix_guidance_response(issue, scan, checks_run)
        issue = self._select_issue(question, target, issues)
        if issue is not None:
            return self._issue_response(issue, scan, checks_run)
        return self._overview_response(scan, checks_run)

    def _update_job_response(self) -> AgentResponse:
        status = self.adapter.get_outdated_packages_status()
        if not status:
            return AgentResponse(
                category="service",
                target="security-update-job",
                matched=True,
                title="Security update job diagnostics",
                summary="Package update job state is unavailable and cannot be confirmed.",
                confidence="low",
                section="security",
                subsection="scan-fixes",
                module=self.name,
                checks_run=[],
                facts=[AgentFact("Update job", "Unknown", "warning")],
                reason_chain=["The update-status source returned no authoritative payload."],
                recommendations=["Check the package job backend before starting another update."],
            )
        state = str(status.get("status") or "unknown")
        facts = [
            AgentFact("Update job", state, "warning" if state in {"running", "error"} else "info"),
            AgentFact("Message", str(status.get("message") or "Unknown")),
        ]
        if status.get("job_id"):
            facts.append(AgentFact("Job ID", str(status.get("job_id"))))
        if status.get("progress") is not None:
            facts.append(AgentFact("Progress", f"{int(status.get('progress') or 0)}%"))

        if state == "running":
            summary = "A package update job is currently running."
            confidence = "high"
            reason_chain = [
                "The package update job status was inspected.",
                "A running job is still reported by the security service.",
            ]
        elif state == "error":
            summary = "The latest package update job ended with an error."
            confidence = "high"
            reason_chain = [
                "The package update job status was inspected.",
                "The latest job reports an error state.",
            ]
        elif state == "success":
            summary = "The latest package update job completed successfully."
            confidence = "high"
            reason_chain = [
                "The package update job status was inspected.",
                "The latest job reports success.",
            ]
        else:
            summary = "No package update job is currently running."
            confidence = "medium"
            reason_chain = [
                "The package update job status was inspected.",
                "No active job was found.",
            ]

        return AgentResponse(
            category="service",
            target="security-update-job",
            matched=True,
            title="Security update job diagnostics",
            summary=summary,
            confidence=confidence,
            section="security",
            subsection="scan-fixes",
            module=self.name,
            checks_run=["outdated_packages_status"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=[
                "Open System Security to inspect the latest update job details.",
                "If the job failed, review filesystem, package mirror, and sudo health.",
            ],
        )

    def _issue_response(
        self,
        issue: dict[str, object],
        scan: dict[str, object],
        checks_run: list[str],
    ) -> AgentResponse:
        severity = str(issue.get("status") or "warning")
        is_ok = severity in {"passed", "ok", "info"}
        facts = [
            AgentFact("Check", str(issue.get("id") or "unknown")),
            AgentFact(
                "Status",
                "passed" if is_ok else severity,
                "info" if is_ok else ("critical" if severity == "critical" else "warning"),
            ),
            AgentFact("Fixable", self._yes_no(bool(issue.get("fixable", True)))),
            AgentFact("Critical findings", str(len(scan.get("critical") or []))),
            AgentFact("Warnings", str(len(scan.get("warnings") or []))),
        ]
        last_scan = str(scan.get("last_scan") or "").strip()
        if last_scan:
            facts.append(AgentFact("Last scan", last_scan))
        details = str(issue.get("details") or "").strip()
        if details:
            facts.append(AgentFact("Details", details, "warning" if severity != "passed" else "info"))
        fix_label, requires_reboot = self._issue_fix_details(str(issue.get("id") or ""))
        if fix_label and not is_ok:
            facts.append(AgentFact("Suggested fix", fix_label))
        facts.append(
            AgentFact(
                "Reboot required",
                self._yes_no(requires_reboot),
                "warning" if requires_reboot else "info",
            )
        )

        scan_source = self._scan_source(checks_run)
        if is_ok:
            summary = str(issue.get("message") or "This security check passed.")
            reason_chain = [
                scan_source,
                f"The scan reported check '{issue.get('id')}' as passed.",
            ]
            recommendations = [
                "No action needed — this security check is passing.",
                "Re-run the full scan periodically to catch new issues early.",
            ]
        else:
            summary = str(issue.get("message") or "Security issue detected.")
            reason_chain = [
                scan_source,
                f"The scan reported issue '{issue.get('id')}' with severity '{severity}'.",
            ]
            recommendations = [
                "Apply the matching fix from System Security if the issue is still active.",
                "Re-run the scan after remediation to confirm the finding is cleared.",
            ]
            if requires_reboot:
                recommendations.insert(1, "Plan for a reboot after the remediation because this issue requires a restart to complete.")
            elif fix_label:
                recommendations.insert(1, f"The next safe remediation is: {fix_label}.")
        return AgentResponse(
            category="service",
            target=str(issue.get("id") or "security"),
            matched=True,
            title="Security issue diagnostics",
            summary=summary,
            confidence="high",
            section="security",
            subsection="scan-fixes",
            module=self.name,
            checks_run=checks_run,
            facts=facts,
            reason_chain=reason_chain,
            recommendations=recommendations,
        )

    def _overview_response(self, scan: dict[str, object], checks_run: list[str]) -> AgentResponse:
        critical = scan.get("critical") or []
        warnings = scan.get("warnings") or []
        passed = scan.get("passed") or []
        top_issue = critical[0] if critical else (warnings[0] if warnings else None)
        facts = [
            AgentFact("Critical findings", str(len(critical)), "critical" if critical else "info"),
            AgentFact("Warnings", str(len(warnings)), "warning" if warnings else "info"),
            AgentFact("Passed checks", str(len(passed))),
        ]
        last_scan = str(scan.get("last_scan") or "").strip()
        if last_scan:
            facts.append(AgentFact("Last scan", last_scan))
        if top_issue is not None:
            facts.append(
                AgentFact(
                    "Top issue",
                    str(top_issue.get("message") or top_issue.get("id") or "Unknown"),
                    "critical" if critical else "warning",
                )
            )
            fix_label, requires_reboot = self._issue_fix_details(str(top_issue.get("id") or ""))
            if fix_label:
                facts.append(AgentFact("Next safe fix", fix_label))
            facts.append(
                AgentFact(
                    "Reboot required",
                    self._yes_no(requires_reboot),
                    "warning" if requires_reboot else "info",
                )
            )

        if critical:
            summary = "System Security currently reports critical findings."
            confidence = "high"
            scan_source = self._scan_source(checks_run)
            reason_chain = [
                scan_source,
                "At least one critical finding is still active.",
            ]
        elif warnings:
            summary = "System Security reports warnings but no critical findings."
            confidence = "high"
            scan_source = self._scan_source(checks_run)
            reason_chain = [
                scan_source,
                "Only warning-level findings remain.",
            ]
        else:
            summary = "Security scan checks currently look healthy."
            confidence = "medium"
            scan_source = self._scan_source(checks_run)
            reason_chain = [
                scan_source,
                "No critical or warning findings were returned.",
            ]

        return AgentResponse(
            category="service",
            target="security-scan",
            matched=True,
            title="Security scan diagnostics",
            summary=summary,
            confidence=confidence,
            section="security",
            subsection="scan-fixes",
            module=self.name,
            checks_run=checks_run,
            facts=facts,
            reason_chain=reason_chain,
            recommendations=[
                "Open System Security to inspect individual findings and remediation actions.",
                "Re-run the scan after applying fixes to refresh the issue list.",
            ],
        )

    def _all_issues(self, scan: dict[str, object]) -> list[dict[str, object]]:
        issues: list[dict[str, object]] = []
        for key in ("critical", "warnings", "passed"):
            for issue in scan.get(key) or []:
                if isinstance(issue, dict):
                    issues.append(issue)
        return issues

    def _audit_log_response(self) -> AgentResponse:
        try:
            logs = self.adapter.get_audit_logs(limit=20)
        except Exception as exc:
            return self._source_failure_response("security-audit-logs", "Security audit log source", exc)
        suspicious = [
            entry
            for entry in logs
            if any(
                token in str(entry.get("message") or "").lower()
                for token in ("failed", "failure", "invalid", "denied", "error", "unauthorized")
            )
        ]
        facts = [
            AgentFact("Audit entries", str(len(logs))),
            AgentFact(
                "Suspicious entries",
                str(len(suspicious)),
                "warning" if suspicious else "info",
            ),
        ]
        if suspicious:
            latest = suspicious[-1]
            facts.append(AgentFact("Latest suspicious entry", self._truncate(str(latest.get("message") or "")), "warning"))
            if latest.get("source"):
                facts.append(AgentFact("Audit source", str(latest.get("source"))))
            summary = "Recent security audit logs contain suspicious authentication or access events."
            confidence = "high"
            reason_chain = [
                "Recent security audit logs were read from the local system.",
                "At least one recent log line indicates authentication failure, denied access, or sudo-related trouble.",
            ]
        elif logs:
            latest = logs[-1]
            facts.append(AgentFact("Latest entry", self._truncate(str(latest.get("message") or ""))))
            if latest.get("source"):
                facts.append(AgentFact("Audit source", str(latest.get("source"))))
            summary = "Recent security audit logs do not show an obvious failure pattern."
            confidence = "medium"
            reason_chain = [
                "Recent security audit logs were read from the local system.",
                "No recent suspicious authentication or permission failures were detected in the sampled lines.",
            ]
        else:
            summary = "No recent local security audit logs were available to inspect."
            confidence = "low"
            reason_chain = [
                "The agent tried to read local security audit logs.",
                "No supported audit log file was available or readable from the current backend context.",
            ]
        return AgentResponse(
            category="service",
            target="security-audit-logs",
            matched=True,
            title="Security audit diagnostics",
            summary=summary,
            confidence=confidence,
            section="security",
            subsection="audit-logs",
            module=self.name,
            checks_run=["audit_logs"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=[
                "Open System Security audit logs if you need the full event trail instead of the latest sample.",
                "If suspicious auth entries continue, review SSH, password auth, 2FA, and user access settings next.",
            ],
        )

    def _source_failure_response(self, target: str, source: str, exc: Exception) -> AgentResponse:
        return AgentResponse(
            category="service",
            target=target,
            matched=True,
            title=f"{source} unavailable",
            summary=f"{source} failed, so the current security state cannot be confirmed.",
            confidence="low",
            section="security",
            subsection="audit-logs" if "audit" in target else "scan-fixes",
            module=self.name,
            source_status="unavailable",
            source_errors=[f"{type(exc).__name__}: {exc}"],
            facts=[AgentFact("Source failure", f"{type(exc).__name__}: {exc}", "warning")],
            reason_chain=["The requested read-only security source raised an error."],
            recommendations=["Restore source access and retry before making a security decision."],
        )

    def _fix_guidance_response(
        self,
        issue: dict[str, object],
        scan: dict[str, object],
        checks_run: list[str],
    ) -> AgentResponse:
        issue_id = str(issue.get("id") or "")
        fix_label, requires_reboot = self._issue_fix_details(issue_id)
        facts = [
            AgentFact("Issue ID", issue_id or "unknown"),
            AgentFact("Suggested fix", fix_label or "No direct automated fix available"),
            AgentFact("Fixable", self._yes_no(bool(issue.get("fixable", True)))),
            AgentFact("Reboot required", self._yes_no(requires_reboot), "warning" if requires_reboot else "info"),
            AgentFact("Critical findings", str(len(scan.get("critical") or []))),
            AgentFact("Warnings", str(len(scan.get("warnings") or []))),
        ]
        summary = (
            f"The safest next remediation is '{fix_label}'."
            if fix_label
            else "No specific automated remediation is mapped for the current top security finding."
        )
        if requires_reboot:
            summary += " This remediation requires a reboot to finish cleanly."
        return AgentResponse(
            category="service",
            target=issue_id or "security",
            matched=True,
            title="Security remediation guidance",
            summary=summary,
            confidence="high" if fix_label else "medium",
            section="security",
            subsection="scan-fixes",
            module=self.name,
            checks_run=checks_run,
            facts=facts,
            reason_chain=[
                self._scan_source(checks_run),
                f"The most relevant fixable finding is '{issue_id or 'unknown'}'.",
                "The suggested fix was selected from the local security remediation map.",
            ],
            recommendations=[
                "Apply the suggested remediation from System Security.",
                "Re-run the scan after remediation to confirm the issue is cleared.",
            ],
        )

    def _reboot_response(
        self,
        issue: dict[str, object],
        scan: dict[str, object],
        checks_run: list[str],
    ) -> AgentResponse:
        issue_id = str(issue.get("id") or "security")
        fix_label, _ = self._issue_fix_details(issue_id)
        facts = [
            AgentFact("Issue ID", issue_id),
            AgentFact("Reboot required", "Yes", "warning"),
            AgentFact("Suggested fix", fix_label or "Manual remediation"),
            AgentFact("Critical findings", str(len(scan.get("critical") or []))),
            AgentFact("Warnings", str(len(scan.get("warnings") or []))),
        ]
        return AgentResponse(
            category="service",
            target=issue_id,
            matched=True,
            title="Security reboot guidance",
            summary="A reboot is required to complete the current security remediation safely.",
            confidence="high",
            section="security",
            subsection="scan-fixes",
            module=self.name,
            checks_run=checks_run,
            facts=facts,
            reason_chain=[
                self._scan_source(checks_run),
                f"The finding '{issue_id}' has a remediation path that requires restart or reboot.",
            ],
            recommendations=[
                "Schedule the remediation when a reboot is acceptable for this EasyPi instance.",
                "Run the matching security fix first, then allow the reboot to complete.",
            ],
        )

    def _select_issue(self, question: str, target: str, issues: list[dict[str, object]]) -> dict[str, object] | None:
        hint_map = {
            "filesystem": "filesystem_readonly",
            "read-only": "filesystem_readonly",
            "readonly": "filesystem_readonly",
            "root login": "ssh_root_login",
            "firewall": "firewall_inactive",
            "password auth": "password_auth_enabled",
            "outdated": "outdated_packages",
            "packages": "outdated_packages",
        }
        haystack = f"{question} {target}"
        for needle, issue_id in hint_map.items():
            if needle in haystack:
                for issue in issues:
                    if issue.get("id") == issue_id:
                        return issue
        return None

    def _preferred_fix_issue(self, issues: list[dict[str, object]]) -> dict[str, object] | None:
        for issue in issues:
            if bool(issue.get("fixable", True)) and str(issue.get("status") or "") in {"critical", "warning"}:
                return issue
        return issues[0] if issues else None

    def _reboot_issue(self, issues: list[dict[str, object]]) -> dict[str, object] | None:
        for issue in issues:
            if self._requires_reboot(issue):
                return issue
        return None

    def _issue_fix_details(self, issue_id: str) -> tuple[str | None, bool]:
        mapping = {
            "filesystem_readonly": ("Repair the filesystem and reboot", True),
            "firewall_inactive": ("Apply the firewall remediation", False),
            "password_auth_enabled": ("Disable SSH password authentication", False),
            "ssh_root_login": ("Disable SSH root login", False),
            "outdated_packages": ("Run the outdated packages remediation", False),
        }
        return mapping.get(issue_id, (None, False))

    def _requires_reboot(self, issue: dict[str, object]) -> bool:
        issue_id = str(issue.get("id") or "")
        _, mapped_requires_reboot = self._issue_fix_details(issue_id)
        if mapped_requires_reboot:
            return True
        text = f"{issue.get('message') or ''} {issue.get('details') or ''}".lower()
        return "reboot" in text or "restart" in text

    def _scan_source(self, checks_run: list[str]) -> str:
        if "security_scan" in checks_run:
            return "A fresh local security scan was executed."
        return "The latest saved security scan result was inspected."

    def _truncate(self, value: str, limit: int = 140) -> str:
        text = str(value or "").strip()
        if len(text) <= limit:
            return text or "Unknown"
        return text[: limit - 3].rstrip() + "..."

    def _yes_no(self, value: bool) -> str:
        return "Yes" if value else "No"
