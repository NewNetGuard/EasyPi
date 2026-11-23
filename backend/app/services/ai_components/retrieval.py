"""Small, local-only knowledge retriever for EasyPi product documentation."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
import math
from pathlib import Path
import re

from app.core.paths import get_easypi_root


_SOURCE_PATHS = (
    "README.md",
    "frontend/src/data/helpContent.ts",
    "chameleon/README.md",
    "prism_dpi/README.md",
    "docs/NETWORK_SECURITY_MODEL.md",
    "docs/SIGNED_SECURITY_FEEDS.md",
)
_MAX_SOURCE_BYTES = 1_000_000
_CHUNK_CHARS = 1_800
_CHUNK_OVERLAP_CHARS = 240
_DEFAULT_MAX_CONTEXT_CHARS = 2_800
_DEFAULT_RESULT_LIMIT = 3
_TOKEN_RE = re.compile(r"[^\W_]{2,}", re.UNICODE)
_HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")
_STOP_WORDS = {
    "about",
    "after",
    "also",
    "and",
    "are",
    "can",
    "does",
    "explain",
    "easy",
    "easypi",
    "for",
    "from",
    "have",
    "happens",
    "how",
    "into",
    "if",
    "is",
    "its",
    "more",
    "not",
    "of",
    "on",
    "or",
    "prevent",
    "that",
    "tell",
    "the",
    "this",
    "use",
    "was",
    "were",
    "what",
    "when",
    "where",
    "which",
    "with",
    "would",
    "your",
    "как",
    "что",
    "это",
    "для",
    "или",
    "при",
    "про",
    "его",
    "она",
    "они",
    "есть",
}
_QUERY_ALIASES = {
    "claud": ("cloud", "picloud"),
    "облако": ("cloud", "picloud"),
    "хамелеон": ("chameleon", "stealth"),
    "стелс": ("stealth", "chameleon"),
    "quard": ("guard", "security"),
    "гард": ("guard", "security"),
    "призма": ("prism", "security"),
    "родительский": ("parental", "controls"),
    "тайлскейл": ("tailscale", "remote", "access"),
}
_SOURCE_WEIGHTS = {
    "README.md": 1.35,
    "chameleon/README.md": 1.35,
    "prism_dpi/README.md": 1.35,
    "docs/NETWORK_SECURITY_MODEL.md": 1.2,
    "docs/SIGNED_SECURITY_FEEDS.md": 1.2,
}
_PRODUCT_ENTITY_TERMS = {
    "backup",
    "camera",
    "chameleon",
    "cloud",
    "dns",
    "guard",
    "netprotection",
    "ollama",
    "openvpn",
    "outline",
    "parental",
    "picloud",
    "prism",
    "rollback",
    "stealth",
    "taildrop",
    "tailscale",
    "telegram",
    "terminal",
    "update",
    "vpn",
    "wireguard",
}


@dataclass(frozen=True)
class _KnowledgeChunk:
    source: str
    heading: str
    text: str
    terms: Counter[str]


@dataclass(frozen=True)
class _KnowledgeIndex:
    chunks: tuple[_KnowledgeChunk, ...]
    document_frequency: Counter[str]


def _tokenize(value: str) -> list[str]:
    return [
        token
        for token in _TOKEN_RE.findall(value.casefold())
        if token not in _STOP_WORDS
    ]


def _expand_query(value: str) -> list[str]:
    tokens = _tokenize(value)
    expanded = list(tokens)
    for token in tokens:
        expanded.extend(_QUERY_ALIASES.get(token, ()))
    return expanded


def _make_chunk(source: str, heading: str, body: str) -> _KnowledgeChunk:
    combined = f"{heading}\n{body}" if heading else body
    return _KnowledgeChunk(
        source=source,
        heading=heading,
        text=body,
        terms=Counter(_tokenize(combined)),
    )


def _split_help_content(source: str, text: str) -> list[_KnowledgeChunk]:
    """Keep each frontend help entry separate instead of mixing adjacent topics."""
    chunks: list[_KnowledgeChunk] = []
    blocks = re.split(r"(?m)^\s{2}\},?\s*$", text)
    for block in blocks:
        if not re.search(r"(?m)^\s+id:\s*'", block):
            continue
        heading_match = re.search(
            r"(?m)^\s+(?:title|question|code|name):\s*'((?:\\.|[^'])+)'",
            block,
        )
        heading = heading_match.group(1).replace("\\'", "'") if heading_match else source
        body = block.strip().lstrip("{,").strip()
        while body:
            if len(body) <= _CHUNK_CHARS:
                excerpt = body
                body = ""
            else:
                boundary = body.rfind("\n", 0, _CHUNK_CHARS)
                if boundary < _CHUNK_CHARS // 2:
                    boundary = body.rfind(" ", 0, _CHUNK_CHARS)
                if boundary < _CHUNK_CHARS // 2:
                    boundary = _CHUNK_CHARS
                excerpt = body[:boundary].strip()
                next_start = max(0, boundary - _CHUNK_OVERLAP_CHARS)
                body = body[next_start:].strip()
            if excerpt:
                chunks.append(_make_chunk(source, heading, excerpt))
    return chunks


def _split_document(source: str, text: str) -> list[_KnowledgeChunk]:
    if source == "frontend/src/data/helpContent.ts":
        return _split_help_content(source, text)

    chunks: list[_KnowledgeChunk] = []
    heading = source
    pending: list[str] = []
    pending_size = 0

    def flush(*, keep_overlap: bool) -> None:
        nonlocal pending, pending_size
        body = "\n".join(pending).strip()
        if body:
            chunks.append(_make_chunk(source, heading, body))
        if keep_overlap and body and len(body) > _CHUNK_OVERLAP_CHARS:
            pending = [body[-_CHUNK_OVERLAP_CHARS:]]
            pending_size = len(pending[0])
        else:
            pending = []
            pending_size = 0

    for raw_line in text.splitlines():
        line = raw_line.strip()
        heading_match = _HEADING_RE.match(line)
        if heading_match:
            flush(keep_overlap=False)
            heading = heading_match.group(2).strip()
            continue
        if not line:
            if pending and pending[-1] != "":
                pending.append("")
                pending_size += 1
            continue
        if pending_size + len(line) + 1 > _CHUNK_CHARS:
            flush(keep_overlap=True)
        pending.append(line)
        pending_size += len(line) + 1
    flush(keep_overlap=False)
    return chunks


def _safe_source(root: Path, relative_path: str) -> Path | None:
    root = root.resolve()
    candidate = root / relative_path
    if candidate.is_symlink():
        return None
    try:
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
    except (OSError, ValueError):
        return None
    if not resolved.is_file() or resolved.stat().st_size > _MAX_SOURCE_BYTES:
        return None
    return resolved


def _source_signature(root: Path) -> tuple[tuple[str, int, int], ...]:
    signature: list[tuple[str, int, int]] = []
    for relative_path in _SOURCE_PATHS:
        source = _safe_source(root, relative_path)
        if source is None:
            continue
        stat_result = source.stat()
        signature.append((relative_path, stat_result.st_mtime_ns, stat_result.st_size))
    return tuple(signature)


@lru_cache(maxsize=4)
def _build_index(
    root_value: str,
    signature: tuple[tuple[str, int, int], ...],
) -> _KnowledgeIndex:
    root = Path(root_value)
    chunks: list[_KnowledgeChunk] = []
    for relative_path, _mtime_ns, _size in signature:
        source = _safe_source(root, relative_path)
        if source is None:
            continue
        text = source.read_text(encoding="utf-8", errors="replace")
        chunks.extend(_split_document(relative_path, text))

    document_frequency: Counter[str] = Counter()
    for chunk in chunks:
        document_frequency.update(chunk.terms.keys())
    return _KnowledgeIndex(tuple(chunks), document_frequency)


def _score_chunk(
    chunk: _KnowledgeChunk,
    query_terms: Counter[str],
    index: _KnowledgeIndex,
) -> float:
    total_chunks = max(1, len(index.chunks))
    heading_terms = set(_tokenize(chunk.heading))
    score = 0.0
    matched_terms = 0
    for term, query_count in query_terms.items():
        term_count = chunk.terms.get(term, 0)
        if not term_count:
            continue
        matched_terms += 1
        frequency = index.document_frequency.get(term, 0)
        inverse_frequency = math.log((total_chunks + 1) / (frequency + 1)) + 1.0
        term_weight = 1.0 + math.log(min(term_count, 3))
        heading_weight = 1.8 if term in heading_terms else 1.0
        query_weight = 0.45 if term in _PRODUCT_ENTITY_TERMS else 1.0
        score += (
            min(query_count, 2)
            * inverse_frequency
            * term_weight
            * heading_weight
            * query_weight
        )
    coverage_weight = 1.0 + (0.6 * max(0, matched_terms - 1))
    return score * coverage_weight * _SOURCE_WEIGHTS.get(chunk.source, 1.0)


def retrieve_easypi_knowledge(
    question: str,
    *,
    root: Path | None = None,
    limit: int = _DEFAULT_RESULT_LIMIT,
    max_chars: int = _DEFAULT_MAX_CONTEXT_CHARS,
) -> str:
    """Return bounded, relevant excerpts from an explicit documentation allowlist."""
    query_terms = Counter(_expand_query(question))
    if not query_terms or limit <= 0 or max_chars <= 0:
        return ""

    resolved_root = (root or get_easypi_root()).resolve()
    signature = _source_signature(resolved_root)
    index = _build_index(str(resolved_root), signature)
    available_query_terms = [
        term for term in query_terms if index.document_frequency.get(term, 0) > 0
    ]
    anchor_terms = set(
        sorted(
            available_query_terms,
            key=lambda term: (index.document_frequency[term], term),
        )[:4]
    )
    entity_terms = set(query_terms).intersection(_PRODUCT_ENTITY_TERMS)
    scored = [
        (_score_chunk(chunk, query_terms, index), position, chunk)
        for position, chunk in enumerate(index.chunks)
        if not anchor_terms or any(chunk.terms.get(term, 0) for term in anchor_terms)
        if not entity_terms or any(chunk.terms.get(term, 0) for term in entity_terms)
    ]
    scored.sort(key=lambda item: (-item[0], item[1]))

    selected: list[str] = []
    used_chars = 0
    for score, _position, chunk in scored:
        if score <= 0 or len(selected) >= limit:
            break
        label = chunk.source
        if chunk.heading and chunk.heading != chunk.source:
            label = f"{label} — {chunk.heading}"
        excerpt = f"[{label}]\n{chunk.text.strip()}"
        remaining = max_chars - used_chars
        if remaining < 300:
            break
        if len(excerpt) > remaining:
            excerpt = excerpt[:remaining].rsplit(" ", 1)[0].rstrip() + "…"
        selected.append(excerpt)
        used_chars += len(excerpt) + 2
    return "\n\n".join(selected)
