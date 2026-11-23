"""Typed PTZ errors whose messages are scrubbed of credentials.

Adapters and the service layer raise these; the API layer maps ``status_code``
to an HTTP response. ``scrub()`` strips URL userinfo (``rtsp://user:pass@``) and
``key=value`` secrets so a credential can never reach a log line, an exception
string or an API response.
"""
from __future__ import annotations

import re

# rtsp://user:pass@host  ->  rtsp://***:***@host
_USERINFO_RE = re.compile(r"://[^/@\s]*:[^/@\s]*@")
# password=..., token: ..., Authorization=..., UsernameToken ...  -> key=***
_SECRET_KV_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|authorization|usernametoken|nonce|digest)\b"
    r"\s*[:=]\s*[^\s,;)\"']+"
)


def scrub(text: object) -> str:
    """Return ``text`` with any credential-looking substrings redacted."""
    s = str(text) if text is not None else ""
    if not s:
        return s
    s = _USERINFO_RE.sub("://***:***@", s)
    s = _SECRET_KV_RE.sub(lambda m: f"{m.group(1)}=***", s)
    return s


class PTZError(Exception):
    """Base class for PTZ errors. The message is always scrubbed."""

    status_code = 400
    code = "ptz_error"

    def __init__(self, message: str = "PTZ error"):
        self.message = scrub(message)
        super().__init__(self.message)


class PTZUnavailable(PTZError):
    """PTZ control is not available for this camera (no/unknown adapter)."""

    status_code = 409
    code = "ptz_unavailable"


class PTZUnsupported(PTZError):
    """The requested command is not supported by this camera's capabilities."""

    status_code = 400
    code = "ptz_unsupported"


class PTZValidationError(PTZError):
    """A command parameter was out of range or otherwise invalid."""

    status_code = 422
    code = "ptz_invalid"


class PTZUnreachable(PTZError):
    """The camera could not be reached within the timeout."""

    status_code = 502
    code = "ptz_unreachable"


class PTZAuthError(PTZError):
    """The camera rejected the stored credentials."""

    status_code = 502
    code = "ptz_camera_auth"


class PTZBusy(PTZError):
    """Another PTZ operation is already in progress for this camera."""

    status_code = 409
    code = "ptz_busy"


class PTZSecurityError(PTZError):
    """A request was blocked by the SSRF guard (target address not allowed)."""

    status_code = 400
    code = "ptz_blocked"


__all__ = [
    "scrub",
    "PTZError",
    "PTZUnavailable",
    "PTZUnsupported",
    "PTZValidationError",
    "PTZUnreachable",
    "PTZAuthError",
    "PTZBusy",
    "PTZSecurityError",
]
