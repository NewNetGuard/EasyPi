"""Cloud and PiCloud diagnostics module."""

from __future__ import annotations

from datetime import datetime, timezone

from app.agent.adapters.cloud import CloudAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class CloudAgent:
    """Explain cloud storage and Telegram upload state."""

    name = "cloud_agent"
    _KEYWORDS = (
        "cloud",
        "picloud",
        "cloud storage",
        "telegram bot",
        "telegram upload",
        "share link",
        "shares",
        "storage full",
        "trash",
        "duplicates",
        "thumbnail",
    )
    _TELEGRAM_KEYWORDS = ("telegram", "bot", "authorized users")
    _STORAGE_KEYWORDS = ("storage", "space", "full", "capacity", "disk")
    _SHARE_KEYWORDS = ("share", "link", "shares", "public link")
    _TRASH_KEYWORDS = ("trash", "deleted file", "restore file", "empty trash")
    _DUPLICATE_KEYWORDS = ("duplicate", "duplicates", "same file")
    _THUMBNAIL_KEYWORDS = ("thumbnail", "preview", "previews")
    _ROUTES = ("cloud", "picloud")

    def __init__(self, adapter: CloudAdapter) -> None:
        self.adapter = adapter

    def score(self, request: AgentRequest) -> int:
        question = request.question.lower()
        route = (request.route or "").lower()
        target = (request.target or "").lower()
        score = 0

        if any(keyword in question or keyword in target for keyword in self._KEYWORDS):
            score += 115
        if any(token in route for token in self._ROUTES):
            score += 70
        return score

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        tab = str(request.tab or "").strip().lower()
        question = " ".join(part for part in (request.question.lower(), tab) if part)
        route = (request.route or "").lower()
        target = (request.target or "").lower()
        if not any(keyword in question or keyword in target for keyword in self._KEYWORDS) and not any(token in route for token in self._ROUTES):
            return None

        if any(keyword in question or keyword in target for keyword in self._TELEGRAM_KEYWORDS):
            return self._telegram_response()
        if any(keyword in question or keyword in target for keyword in self._SHARE_KEYWORDS):
            return self._shares_response(question)
        if any(keyword in question or keyword in target for keyword in self._TRASH_KEYWORDS):
            return self._trash_response()
        if any(keyword in question or keyword in target for keyword in self._DUPLICATE_KEYWORDS):
            return self._duplicates_response()
        if any(keyword in question or keyword in target for keyword in self._THUMBNAIL_KEYWORDS):
            return self._thumbnail_response()
        if tab in {"files", "recent", "photos", "videos", "documents", "audio", "other", "encrypted"}:
            return self._storage_response()
        if any(keyword in question or keyword in target for keyword in self._STORAGE_KEYWORDS):
            return self._storage_response()
        return self._overview_response()

    def _storage_response(self) -> AgentResponse:
        stats = self.adapter.get_storage_stats()
        recent = self.adapter.get_recent_files(limit=5)
        if not stats and not recent:
            return AgentResponse(
                category="service",
                target="cloud-storage",
                matched=True,
                title="Cloud storage diagnostics",
                summary="Cloud storage state is unavailable; an empty adapter result cannot confirm that storage is empty.",
                confidence="low",
                section="cloud",
                subsection="storage",
                module=self.name,
                checks_run=[],
                facts=[AgentFact("Storage state", "Unknown", "warning")],
                reason_chain=["The storage sources returned no authoritative data."],
                recommendations=["Retry after checking the PiCloud service and storage API."],
            )
        try:
            percent = float(stats.get("percent") or 0)
            file_count = int(stats.get("file_count") or 0)
            folder_count = int(stats.get("folder_count") or 0)
            used = int(stats.get("used") or 0)
            free = int(stats.get("free") or 0)
        except (TypeError, ValueError):
            return AgentResponse(
                category="service",
                target="cloud-storage",
                matched=True,
                title="Cloud storage diagnostics",
                summary="Cloud storage returned invalid numeric data, so its health is currently unknown.",
                confidence="low",
                section="cloud",
                subsection="storage",
                module=self.name,
                checks_run=["cloud_storage_stats"],
                facts=[AgentFact("Storage data", "Invalid", "warning")],
                reason_chain=["One or more storage counters could not be parsed."],
                recommendations=["Check the PiCloud storage API response and retry."],
            )

        facts = [
            AgentFact("Used space", self._format_bytes(used)),
            AgentFact("Free space", self._format_bytes(free)),
            AgentFact("Usage percent", f"{percent:.1f}%", "warning" if percent >= 85 else "info"),
            AgentFact("Files", str(file_count)),
            AgentFact("Folders", str(folder_count)),
            AgentFact("Recent files", str(len(recent))),
        ]

        if percent >= 95:
            summary = f"Cloud storage is almost full ({percent:.1f}% used) — uploads may soon start failing."
            confidence = "high"
            reason_chain = [
                "The cloud storage statistics were loaded from local storage state.",
                "Used disk percentage is above the critical threshold.",
            ]
            recommendations = [
                "Free space now: delete large files and empty the Cloud trash.",
                "Storage shares the system disk — a full disk also affects services.",
            ]
        elif percent >= 85:
            summary = f"Cloud storage is getting full ({percent:.1f}% used)."
            confidence = "high"
            reason_chain = [
                "The cloud storage statistics were loaded from local storage state.",
                "Used disk percentage is approaching the warning threshold.",
            ]
            recommendations = [
                "Clean up large files or empty the Cloud trash before it fills up.",
            ]
        elif file_count == 0 and folder_count == 0 and len(recent) == 0:
            summary = "Cloud storage is set up but currently empty — no files or folders yet."
            confidence = "high"
            reason_chain = [
                "The cloud storage statistics were loaded from local storage state.",
                "No files, folders, or recent uploads were found.",
            ]
            recommendations = [
                "Upload files from the Cloud page to start using your personal storage.",
            ]
        elif file_count == 0 and folder_count == 0 and len(recent) > 0:
            summary = "Cloud storage has recent files, but the file/folder counter reads 0 — the storage sources are out of sync."
            confidence = "medium"
            reason_chain = [
                "The cloud storage statistics were loaded from local storage state.",
                f"The counter reports 0 files/folders, yet {len(recent)} recent file(s) are present.",
            ]
            recommendations = [
                "Open Cloud to compare the visible files with the counters before drawing a data-integrity conclusion.",
                "Refresh or rescan the file/folder counters and investigate if the conflict remains.",
            ]
        else:
            summary = f"Cloud storage looks healthy ({percent:.1f}% used, {file_count} files across {folder_count} folders)."
            confidence = "high"
            reason_chain = [
                "The cloud storage statistics were loaded from local storage state.",
                "No storage pressure was detected and content is present.",
            ]
            recommendations = [
                "No action needed — storage has plenty of free space.",
                "Open Cloud to manage files, shares, and trash.",
            ]

        return AgentResponse(
            category="service",
            target="cloud-storage",
            matched=True,
            title="Cloud storage diagnostics",
            summary=summary,
            confidence=confidence,
            section="cloud",
            subsection="storage",
            module=self.name,
            checks_run=["cloud_storage_stats", "cloud_recent_files"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=recommendations,
        )

    def _shares_response(self, question: str) -> AgentResponse:
        returned_shares = self.adapter.list_shares()
        shares = [share for share in returned_shares if not self._share_is_expired(share)]
        facts = [AgentFact("Active share links", str(len(shares)))]
        expired_count = len(returned_shares) - len(shares)
        if expired_count:
            facts.append(AgentFact("Expired share links", str(expired_count), "warning"))
        if shares:
            latest = shares[0]
            facts.append(AgentFact("Latest shared file", str(latest.get("file_name") or latest.get("file_id") or "Unknown")))
            if latest.get("expires_at"):
                facts.append(AgentFact("Latest expiry", str(latest.get("expires_at"))))
            if "delete" in question or "revoke" in question or "remove" in question:
                summary = "Cloud sharing has active links that can be revoked from the Cloud Shares panel."
                confidence = "high"
                reason_chain = [
                    "The local cloud share registry was inspected.",
                    "At least one active share link exists and can be deleted or revoked.",
                ]
            else:
                summary = "Cloud sharing has active public or password-protected links."
                confidence = "medium"
                reason_chain = [
                    "The local cloud share registry was inspected.",
                    "At least one active share link exists.",
                ]
        elif returned_shares:
            summary = "Cloud sharing has no current active links; all returned share records are expired."
            confidence = "high"
            reason_chain = [
                "The local cloud share registry was inspected.",
                "Expired links were excluded from the active-link count.",
            ]
        else:
            if "delete" in question or "revoke" in question or "remove" in question:
                summary = "There are no active cloud share links to revoke right now."
            else:
                summary = "There are no active cloud share links right now."
            confidence = "high"
            reason_chain = [
                "The share source returned no entries and exposes no success marker.",
                "An empty fallback cannot prove that no active shares exist.",
            ]
            summary = "Cloud share state is unavailable; no authoritative share result was returned."
            confidence = "low"

        return AgentResponse(
            category="service",
            target="cloud-shares",
            matched=True,
            title="Cloud share diagnostics",
            summary=summary,
            confidence=confidence,
            section="cloud",
            subsection="sharing",
            module=self.name,
            checks_run=["cloud_shares"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=[
                "Open Cloud Shares to review, revoke, or rotate public links.",
            ],
        )

    def _share_is_expired(self, share: dict[str, object]) -> bool:
        value = str(share.get("expires_at") or "").strip()
        if not value:
            return False
        if value.endswith("Z"):
            value = value[:-1] + "+00:00"
        try:
            expires_at = datetime.fromisoformat(value)
        except ValueError:
            return False
        expires_at = expires_at.replace(tzinfo=expires_at.tzinfo or timezone.utc).astimezone(timezone.utc)
        return expires_at <= datetime.now(timezone.utc)

    def _telegram_response(self) -> AgentResponse:
        status = self.adapter.get_telegram_status()
        uploads_getter = getattr(self.adapter, "get_telegram_uploads", None)
        uploads = uploads_getter(limit=10) if callable(uploads_getter) else []
        configured = bool(status.get("configured"))
        connected = bool(status.get("connected"))
        running = bool(status.get("is_running") or status.get("isRunning"))
        total_uploads = int(status.get("total_uploads") or status.get("totalUploads") or 0)
        authorized_users = status.get("authorized_users") or status.get("authorizedUsers") or []
        facts = [
            AgentFact("Configured", self._yes_no(configured)),
            AgentFact("Connected", self._yes_no(connected), "info" if connected else "warning"),
            AgentFact("Running", self._yes_no(running)),
            AgentFact("Authorized users", str(len(authorized_users))),
            AgentFact("Total uploads", str(total_uploads)),
            AgentFact("Recorded uploads", str(len(uploads))),
            AgentFact("Message", str(status.get("message") or "Unknown")),
        ]
        if uploads:
            latest_upload = uploads[0]
            facts.append(AgentFact("Latest upload", str(latest_upload.get("file_name") or "Unknown")))

        if not configured:
            summary = "The Cloud Telegram bot is not configured yet."
            confidence = "high"
            reason_chain = [
                "The local Telegram bot status was inspected.",
                "No saved Telegram bot configuration is active.",
            ]
        elif configured and connected and not running:
            summary = "The Cloud Telegram bot status is inconsistent: it is marked connected but its runtime is stopped."
            confidence = "low"
            reason_chain = [
                "The saved status reports a connected bot.",
                "The runtime flag reports that the bot is not running.",
            ]
        elif configured and connected and not authorized_users:
            summary = "The Cloud Telegram bot is connected, but no authorized Telegram users are configured yet."
            confidence = "high"
            reason_chain = [
                "The local Telegram bot status was inspected.",
                "The bot is online, but the authorized user list is empty.",
            ]
        elif configured and connected and total_uploads == 0:
            summary = "The Cloud Telegram bot is connected, but no uploads have been recorded yet."
            confidence = "high"
            reason_chain = [
                "The local Telegram bot status was inspected.",
                "The bot is connected, but the upload history is still empty.",
            ]
        elif configured and not connected:
            summary = "The Cloud Telegram bot is configured, but not connected."
            confidence = "high"
            reason_chain = [
                "The local Telegram bot status was inspected.",
                "Configuration exists, but the bot is not currently connected.",
            ]
        else:
            summary = "The Cloud Telegram bot looks healthy."
            confidence = "medium"
            reason_chain = [
                "The local Telegram bot status was inspected.",
                "The bot is configured and connected.",
            ]

        return AgentResponse(
            category="service",
            target="cloud-telegram",
            matched=True,
            title="Cloud Telegram diagnostics",
            summary=summary,
            confidence=confidence,
            section="cloud",
            subsection="telegram",
            module=self.name,
            checks_run=["cloud_telegram_status"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=[
                "Open the Cloud Telegram panel to review bot token, authorized users, and upload folder settings.",
            ],
        )

    def _trash_response(self) -> AgentResponse:
        trash = self.adapter.list_trash()
        facts = [AgentFact("Trash items", str(len(trash)))]
        if trash:
            latest = trash[0]
            facts.append(AgentFact("Latest trash item", str(latest.get("name") or latest.get("original") or latest.get("id") or "Unknown")))
            summary = "Cloud trash contains deleted items that can still be restored or permanently removed."
            confidence = "high"
            reason_chain = [
                "The cloud trash registry was inspected.",
                "Deleted items are still present in trash storage.",
            ]
        else:
            summary = "Cloud trash state is unavailable; an empty adapter result cannot confirm that trash is empty."
            confidence = "low"
            reason_chain = [
                "The trash source returned no entries and exposes no success marker.",
                "No authoritative empty-state result is available.",
            ]
        return AgentResponse(
            category="service",
            target="cloud-trash",
            matched=True,
            title="Cloud trash diagnostics",
            summary=summary,
            confidence=confidence,
            section="cloud",
            subsection="trash",
            module=self.name,
            checks_run=["cloud_trash"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=[
                "Open Cloud Trash to restore recently deleted files or empty trash permanently.",
            ],
        )

    def _duplicates_response(self) -> AgentResponse:
        duplicates = self.adapter.find_duplicates()
        facts = [AgentFact("Duplicate groups", str(len(duplicates)))]
        if duplicates:
            latest = duplicates[0]
            candidate_name = latest.get("name") or latest.get("file_name") or latest.get("hash") or "Unknown"
            facts.append(AgentFact("Example duplicate", str(candidate_name)))
            summary = "Cloud duplicate scanning found matching files that may be wasting storage."
            confidence = "high"
            reason_chain = [
                "The local duplicate-file analysis was inspected.",
                "At least one duplicate group was found in cloud storage.",
            ]
        else:
            summary = "The Cloud duplicate scan result is unavailable; an empty fallback does not prove that no duplicates exist."
            confidence = "low"
            reason_chain = [
                "The duplicate source returned no groups and exposes no completed-scan marker.",
                "No authoritative scan outcome is available.",
            ]
        return AgentResponse(
            category="service",
            target="cloud-duplicates",
            matched=True,
            title="Cloud duplicate diagnostics",
            summary=summary,
            confidence=confidence,
            section="cloud",
            subsection="duplicates",
            module=self.name,
            checks_run=["cloud_duplicates"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=[
                "Open Cloud duplicate cleanup before deleting files so you keep at least one known-good copy.",
            ],
        )

    def _thumbnail_response(self) -> AgentResponse:
        recent = self.adapter.get_recent_files(limit=20)
        thumbnail_capable = sum(1 for item in recent if "thumbnail" in item)
        missing = sum(1 for item in recent if "thumbnail" in item and not bool(item.get("thumbnail")))
        facts = [
            AgentFact("Recent files inspected", str(len(recent))),
            AgentFact("Files with thumbnail metadata", str(thumbnail_capable)),
            AgentFact("Missing thumbnails", str(missing), "warning" if missing else "info"),
        ]

        if not recent:
            summary = "Cloud has no recent files to inspect for preview or thumbnail generation."
            confidence = "high"
            reason_chain = [
                "Recent cloud file metadata was inspected.",
                "No recent files were available for thumbnail checks.",
            ]
        elif thumbnail_capable == 0:
            summary = "Recent cloud files do not expose thumbnail metadata yet."
            confidence = "medium"
            reason_chain = [
                "Recent cloud file metadata was inspected.",
                "Thumbnail capability was not exposed in the recent file entries.",
            ]
        elif missing:
            summary = "Some recent cloud files are missing generated thumbnails, which can affect previews."
            confidence = "high"
            reason_chain = [
                "Recent cloud file metadata was inspected.",
                "One or more recent files report missing thumbnail data.",
            ]
        else:
            summary = "Recent cloud files have thumbnail metadata available for previews."
            confidence = "medium"
            reason_chain = [
                "Recent cloud file metadata was inspected.",
                "Recent files that support thumbnails already have them.",
            ]

        return AgentResponse(
            category="service",
            target="cloud-thumbnails",
            matched=True,
            title="Cloud thumbnail diagnostics",
            summary=summary,
            confidence=confidence,
            section="cloud",
            subsection="previews",
            module=self.name,
            checks_run=["cloud_recent_files"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=[
                "Open Cloud previews and regenerate thumbnails if image or video previews look incomplete.",
            ],
        )

    def _overview_response(self) -> AgentResponse:
        stats = self.adapter.get_storage_stats()
        shares = self.adapter.list_shares()
        telegram = self.adapter.get_telegram_status()
        activity = self.adapter.get_activity(limit=10)
        percent = float(stats.get("percent") or 0)
        facts = [
            AgentFact("Usage percent", f"{percent:.1f}%", "warning" if percent >= 85 else "info"),
            AgentFact("Active shares", str(len(shares))),
            AgentFact("Telegram configured", self._yes_no(bool(telegram.get("configured")))),
            AgentFact("Recent activity items", str(len(activity))),
        ]

        issues: list[str] = []
        if percent >= 90:
            issues.append("Cloud storage is under high capacity pressure")
        if telegram and telegram.get("configured") and not telegram.get("connected"):
            issues.append("Telegram bot is configured but not connected")

        if issues:
            summary = "Cloud storage has active issues that need attention."
            confidence = "high"
            reason_chain = [
                "Cloud overview collected storage, sharing, Telegram, and activity facts.",
                *issues,
            ]
        else:
            summary = "Cloud storage overview looks stable."
            confidence = "medium"
            reason_chain = [
                "Cloud overview collected storage, sharing, Telegram, and activity facts.",
                "No critical cloud-wide issue was detected.",
            ]

        return AgentResponse(
            category="service",
            target="cloud",
            matched=True,
            title="Cloud overview diagnostics",
            summary=summary,
            confidence=confidence,
            section="cloud",
            subsection="overview",
            module=self.name,
            checks_run=["cloud_storage_stats", "cloud_shares", "cloud_telegram_status", "cloud_activity"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=[
                "Ask a narrower question about cloud storage, shares, or Telegram for a deeper explanation.",
            ],
        )

    def _format_bytes(self, value: int) -> str:
        size = float(max(0, value))
        units = ("B", "KB", "MB", "GB", "TB")
        for unit in units:
            if size < 1024 or unit == units[-1]:
                return f"{size:.1f} {unit}"
            size /= 1024
        return f"{size:.1f} TB"

    def _yes_no(self, value: bool) -> str:
        return "Yes" if value else "No"
