"""File manager agent module."""

from __future__ import annotations

import re

from fastapi import HTTPException

from app.agent.adapters.files import FilesAdapter
from app.agent.core.contracts import AgentFact, AgentRequest, AgentResponse


class FilesAgent:
    """Explain file manager path and file state."""

    name = "files_agent"
    _KEYWORDS = (
        "file",
        "files",
        "folder",
        "directory",
        "path",
        "upload",
        "download",
        "preview",
        "search",
        "find",
        "read file",
        "edit file",
        "write file",
        "delete file",
        "permission denied",
    )
    _ROUTES = ("file",)
    _PATH_RE = re.compile(r"(/[^\r\n?\"'<>|]+)")
    # File Manager is scoped to this root (see files_service ALLOWED_ROOTS).
    _FM_ROOT = "/opt/EasyPi"

    def __init__(self, adapter: FilesAdapter) -> None:
        self.adapter = adapter

    def score(self, request: AgentRequest) -> int:
        question = request.question.lower()
        route = (request.route or "").lower()
        target = str(request.target or "")
        path = self._extract_path(target or request.question)
        score = 0
        if any(keyword in question or keyword in target.lower() for keyword in self._KEYWORDS):
            score += 80
        if path:
            score += 70
        if any(token in route for token in self._ROUTES):
            score += 50
        return score

    async def explain(self, request: AgentRequest) -> AgentResponse | None:
        question = request.question.lower()
        route = (request.route or "").lower()
        target = str(request.target or "").strip()
        path = self._extract_path(target or request.question)
        if (
            not any(keyword in question or keyword in target.lower() for keyword in self._KEYWORDS)
            and not any(token in route for token in self._ROUTES)
            and not path
        ):
            return None

        try:
            if path:
                return self._path_response(path, question)
            if "search" in question or "find" in question:
                return self._search_response(question)
            return self._overview_response()
        except (OSError, ValueError, TypeError) as exc:
            return self._unavailable_response(f"{type(exc).__name__}: {exc}")

    def _path_response(self, path: str, question: str) -> AgentResponse:
        info = self.adapter.get_path_info(path)
        if not info:
            return AgentResponse(
                category="service",
                target=path,
                matched=True,
                title="File Manager diagnostics",
                summary="Path information is unavailable, so File Manager cannot determine whether this path exists or is safe.",
                confidence="low",
                section="file-manager",
                subsection="paths",
                module=self.name,
                checks_run=[],
                facts=[AgentFact("Path", path), AgentFact("Path state", "Unknown", "warning")],
                reason_chain=["The path-info source returned no authoritative result."],
                recommendations=["Retry after checking File Manager service access."],
            )
        write_target = self._get_write_target_info(path)
        facts = [
            AgentFact("Path", str(info.get("path") or path)),
            AgentFact("Exists", self._yes_no(bool(info.get("exists"))), "info" if info.get("exists") else "warning"),
            AgentFact("Directory", self._yes_no(bool(info.get("is_dir")))),
            AgentFact("File", self._yes_no(bool(info.get("is_file")))),
            AgentFact("Safe path", self._yes_no(bool(info.get("safe"))), "info" if info.get("safe") else "critical"),
        ]
        wants_preview = "preview" in question or "image" in question
        wants_write = any(token in question for token in ("write", "edit", "save", "upload"))
        wants_download = "download" in question
        wants_delete = "delete" in question or "remove" in question

        if not info.get("safe"):
            summary = "This path is blocked by File Manager safety rules."
            confidence = "high"
            reason_chain = [
                "The path was normalized and checked against File Manager safety rules.",
                "It falls outside allowed roots or inside a blacklisted area.",
            ]
            recommendations = [
                f"Use a path under {self._FM_ROOT} (the File Manager root).",
            ]
        elif not info.get("exists"):
            if wants_write:
                facts.append(AgentFact("Parent path", str(write_target.get("parent") or "Unknown")))
                facts.append(
                    AgentFact(
                        "Parent writable",
                        self._yes_no(bool(write_target.get("writable"))),
                        "warning" if not bool(write_target.get("writable")) else "info",
                    )
                )
                if not bool(write_target.get("writable")) and not bool(write_target.get("requires_sudo")):
                    summary = "The target file cannot currently be created because its parent directory is not writable."
                elif bool(write_target.get("requires_sudo")):
                    facts.append(AgentFact("Write mode", "sudo required", "warning"))
                    summary = "The target file does not exist yet, and writing there will likely require sudo."
                else:
                    summary = "The target file does not exist yet, but File Manager can create it if the parent path remains writable."
                confidence = "high"
                reason_chain = [
                    "The requested target path does not exist yet.",
                    "Parent directory writability was inspected for the requested write or upload operation.",
                ]
                recommendations = [
                    "Create or upload the file only under an allowed path with known write access.",
                ]
            else:
                summary = "The requested path does not exist."
                confidence = "high"
                reason_chain = [
                    "The path is allowed by File Manager safety rules.",
                    "No file or directory exists at that location.",
                ]
                recommendations = [
                    "Check the exact path spelling before creating or uploading files there.",
                ]
        elif info.get("is_dir"):
            items = self.adapter.list_directory(str(info.get("path")))
            usage = self.adapter.get_disk_usage(str(info.get("path")))
            facts.append(AgentFact("Items", str(len(items))))
            facts.append(AgentFact("Disk usage", f"{float(usage.get('used_percent') or 0):.1f}%"))
            if wants_write:
                facts.append(
                    AgentFact(
                        "Directory writable",
                        self._yes_no(bool(write_target.get("writable"))),
                        "warning" if not bool(write_target.get("writable")) else "info",
                    )
                )
                summary = (
                    "The directory is accessible, but write operations will likely require sudo."
                    if bool(write_target.get("requires_sudo"))
                    else "The directory is accessible and can be used as an upload or create target."
                )
                confidence = "high"
                reason_chain = [
                    "The path is safe and exists as a directory.",
                    "Directory writability was inspected for the requested write or upload operation.",
                ]
                recommendations = [
                    "Upload into this directory only if the target path is intended and writable.",
                ]
            elif wants_delete:
                summary = "The directory exists and is inside File Manager safe roots, but delete operations can be destructive."
                confidence = "medium"
                reason_chain = [
                    "The path is safe and exists as a directory.",
                    "Directory deletion is possible in File Manager but should be used carefully.",
                ]
                recommendations = [
                    "Delete directories only after checking their contents to avoid removing more than intended.",
                ]
            else:
                summary = "The directory is accessible through File Manager."
                confidence = "high"
                reason_chain = [
                    "The path is safe and exists as a directory.",
                    "Directory contents were listed successfully.",
                ]
                recommendations = [
                    "Use File Manager search if you need to find a file inside this directory tree.",
                ]
        else:
            try:
                file_data = self.adapter.read_file(str(info.get("path")))
                facts.append(AgentFact("Size", str(file_data.get("size_formatted") or "Unknown")))
                facts.append(AgentFact("Modified", str(file_data.get("modified") or "Unknown")))
                if wants_preview:
                    summary = "The file is readable, so File Manager preview has local access to the target file."
                    confidence = "high"
                    reason_chain = [
                        "The path is safe and exists as a file.",
                        "The file was opened successfully by File Manager preview logic.",
                    ]
                    recommendations = [
                        "If preview still fails in the UI, verify whether the file format is supported by the preview component.",
                    ]
                elif wants_download:
                    summary = "Download preflight confirms that the file is locally readable; the actual download response was not tested."
                    confidence = "medium"
                    reason_chain = [
                        "The path is safe and exists as a file.",
                        "The file can be read successfully by File Manager.",
                    ]
                    recommendations = [
                        "If download still fails in the browser, inspect response headers and browser-side download blocking.",
                    ]
                elif wants_write:
                    facts.append(
                        AgentFact(
                            "Parent writable",
                            self._yes_no(bool(write_target.get("writable"))),
                            "warning" if not bool(write_target.get("writable")) else "info",
                        )
                    )
                    if not bool(write_target.get("writable")) and not bool(write_target.get("requires_sudo")):
                        summary = "The file is readable but its parent directory is not writable, so it cannot currently be edited."
                    elif bool(write_target.get("requires_sudo")):
                        summary = "The file is readable, but editing will likely require sudo on the current path."
                    else:
                        summary = "The file is readable and the current path appears writable for editing."
                    confidence = "high"
                    reason_chain = [
                        "The path is safe and exists as a file.",
                        "The file was opened successfully, and parent writability was inspected for editing.",
                    ]
                    recommendations = [
                        "If save still fails, inspect the backend write error and parent directory permissions.",
                    ]
                elif wants_delete:
                    summary = "The file exists inside an allowed path and can be targeted by File Manager delete operations."
                    confidence = "medium"
                    reason_chain = [
                        "The path is safe and exists as a file.",
                        "File Manager can read the target file before a delete decision is made.",
                    ]
                    recommendations = [
                        "Delete the file only after confirming no other workflow depends on it.",
                    ]
                else:
                    summary = "The file is readable through File Manager."
                    confidence = "high"
                    reason_chain = [
                        "The path is safe and exists as a file.",
                        "The file was opened successfully by File Manager.",
                    ]
                    recommendations = [
                        "If editing still fails, check write permissions on the parent directory.",
                    ]
            except HTTPException as exc:
                summary = f"File access failed: {exc.detail}"
                confidence = "high"
                reason_chain = [
                    "The path exists but File Manager could not read it.",
                ]
                recommendations = [
                    "Check permissions and whether the file is binary or text.",
                ]

        return AgentResponse(
            category="service",
            target=str(info.get("path") or path),
            matched=True,
            title="File Manager diagnostics",
            summary=summary,
            confidence=confidence,
            section="file-manager",
            subsection="paths",
            module=self.name,
            checks_run=["path_info"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=recommendations,
        )

    def _search_response(self, question: str) -> AgentResponse:
        query = self._extract_search_term(question)
        if not query:
            return self._overview_response()

        try:
            results = self.adapter.search_files(query, root_path=self._FM_ROOT, limit=20)
            facts = [
                AgentFact("Search query", query),
                AgentFact("Matches", str(len(results))),
            ]
            if results:
                first = results[0]
                facts.append(AgentFact("First match", str(first.get("path") or first.get("name") or "Unknown")))
                summary = f"File Manager found {len(results)} matches for '{query}'."
                confidence = "high"
                reason_chain = [
                    "The search term was extracted from the question.",
                    "File Manager search returned matching local files or directories.",
                ]
                recommendations = [
                    "Open the first match path in File Manager for a narrower diagnosis.",
                ]
            else:
                summary = f"File Manager did not find matches for '{query}' under {self._FM_ROOT}."
                confidence = "high"
                reason_chain = [
                    "The search term was extracted from the question.",
                    f"File Manager search returned no local matches under {self._FM_ROOT}.",
                ]
                recommendations = [
                    "Try a shorter search term or ask about an exact path.",
                ]
        except HTTPException as exc:
            facts = [
                AgentFact("Search query", query),
                AgentFact("Default root", self._FM_ROOT),
                AgentFact("Search error", str(exc.detail), "warning"),
            ]
            summary = "File Manager could not search the default root on this system."
            confidence = "high"
            reason_chain = [
                "The search term was extracted from the question.",
                "The backend rejected the default search root for the current environment.",
            ]
            recommendations = [
                "Ask about an exact allowed path instead of a broad search query.",
            ]

        return AgentResponse(
            category="service",
            target="file-manager-search",
            matched=True,
            title="File Manager search diagnostics",
            summary=summary,
            confidence=confidence,
            section="file-manager",
            subsection="search",
            module=self.name,
            checks_run=["file_search"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=recommendations,
        )

    def _overview_response(self) -> AgentResponse:
        try:
            items = self.adapter.list_directory(self._FM_ROOT)
            summary = f"File Manager can access the default {self._FM_ROOT} directory."
            confidence = "medium"
            facts = [AgentFact("Root entries", str(len(items)))]
            reason_chain = [
                "The File Manager default root was listed successfully.",
            ]
            recommendations = [
                "Include an exact path in your question for a more specific diagnosis.",
            ]
        except HTTPException as exc:
            summary = f"File Manager could not inspect the default {self._FM_ROOT} directory in this environment."
            confidence = "medium"
            facts = [AgentFact("Directory access error", str(exc.detail), "warning")]
            reason_chain = [
                "The default File Manager root was requested.",
                "The backend rejected that root for the current environment.",
            ]
            recommendations = [
                "Ask about an exact allowed path or browse from a platform-specific safe root.",
            ]
        return AgentResponse(
            category="service",
            target="file-manager",
            matched=True,
            title="File Manager overview",
            summary=summary,
            confidence=confidence,
            section="file-manager",
            subsection="overview",
            module=self.name,
            checks_run=["directory_list"],
            facts=facts,
            reason_chain=reason_chain,
            recommendations=recommendations,
        )

    def _extract_path(self, value: str) -> str | None:
        match = self._PATH_RE.search(str(value or ""))
        if not match:
            return None
        return match.group(1).strip().rstrip(".,;:!" )

    def _extract_search_term(self, value: str) -> str | None:
        match = re.search(
            r"(?:search|find)(?:\s+for)?(?:\s+(?:file|files))?\s+([A-Za-z0-9._-]{2,})",
            str(value or ""),
            re.IGNORECASE,
        )
        if not match:
            return None
        return match.group(1)

    def _yes_no(self, value: bool) -> str:
        return "Yes" if value else "No"

    def _get_write_target_info(self, path: str) -> dict[str, object]:
        method = getattr(self.adapter, "get_write_target_info", None)
        if callable(method):
            result = method(path)
            return result if isinstance(result, dict) else {}
        return {
            "path": path,
            "parent": "",
            "parent_exists": False,
            "writable": False,
            "requires_sudo": False,
        }

    def _unavailable_response(self, detail: str) -> AgentResponse:
        return AgentResponse(
            category="service",
            target="file-manager",
            matched=True,
            title="File Manager diagnostics",
            summary=f"File Manager filesystem error: {detail}",
            confidence="low",
            section="file-manager",
            subsection="overview",
            module=self.name,
            checks_run=[],
            facts=[AgentFact("Filesystem state", "Unavailable", "warning")],
            reason_chain=["A filesystem operation failed before a complete result was available."],
            recommendations=["Check filesystem health and permissions, then retry."],
        )
