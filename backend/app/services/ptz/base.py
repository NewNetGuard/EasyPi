"""The uniform PTZ adapter interface.

Every control protocol implements :class:`CameraPTZAdapter`. Coordinates passed
in are always in the EasyPi unit range ``[-1.0, +1.0]`` (speed ``[0.0, 1.0]``);
the adapter maps them to the concrete device range. Adapters MUST NOT execute
shell commands and MUST NOT leak credentials into logs, errors or return values.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import TYPE_CHECKING, Optional

from app.services.ptz.capabilities import PTZCapabilities

if TYPE_CHECKING:  # avoid importing the ORM model at runtime / import time
    pass


@dataclass(frozen=True)
class PTZPreset:
    """A camera preset position (opaque device token + human name)."""

    token: str
    name: str


@dataclass(frozen=True)
class PTZPosition:
    """A PTZ position in EasyPi unit range; ``None`` where not reported."""

    pan: Optional[float] = None
    tilt: Optional[float] = None
    zoom: Optional[float] = None


@dataclass(frozen=True)
class MoveRequest:
    """A validated, normalised movement request (unit range)."""

    pan: float = 0.0
    tilt: float = 0.0
    zoom: float = 0.0
    speed: float = 0.5
    mode: str = "continuous"  # continuous | relative | absolute


@dataclass(frozen=True)
class CameraSnapshot:
    """Immutable, DB-detached copy of the fields a PTZ adapter needs to act.

    Built once inside a request while the SQLAlchemy session is open
    (:meth:`from_camera`), then safe to use from a background timer or from
    shutdown -- after the ORM ``Camera`` is detached and its session closed. An
    adapter holds one of these, never a live ORM model. ``secret`` (a decrypted
    credential, populated only by adapters that need it in Stage 3/4) is redacted
    from ``repr`` so it can never reach a log line.
    """

    camera_id: str
    adapter_name: str
    ip: str = ""
    port: int = 0
    username: str = ""
    secret: Optional[str] = None
    # ONVIF control port (from WS-Discovery); None -> adapter default (80).
    onvif_port: Optional[int] = None

    @classmethod
    def from_camera(cls, camera) -> "CameraSnapshot":
        """Snapshot the minimal adapter data from a live ORM camera (session open).

        The stored password is decrypted once here (while the session is open) so
        an adapter that authenticates to the camera has it without touching the
        ORM later. It lives only in this immutable snapshot and is redacted from
        ``repr``; adapters that need no credential (Null) simply ignore it.
        """
        username = str(getattr(camera, "username", "") or "")
        secret = None
        get_creds = getattr(camera, "get_ptz_credentials", None)
        if callable(get_creds):
            try:
                cred_user, cred_secret = get_creds()
                username = cred_user or username
                secret = cred_secret or None
            except Exception:
                secret = None
        onvif_port = getattr(camera, "onvif_port", None)
        return cls(
            camera_id=str(getattr(camera, "id", "") or ""),
            adapter_name=(getattr(camera, "ptz_adapter", None) or "null"),
            ip=str(getattr(camera, "ip", "") or ""),
            port=int(getattr(camera, "port", 0) or 0),
            username=username,
            secret=secret,
            onvif_port=int(onvif_port) if onvif_port else None,
        )

    def __repr__(self) -> str:  # never expose the secret in logs/tracebacks
        return (
            "CameraSnapshot(camera_id=%r, adapter_name=%r, ip=%r, port=%r, "
            "username=%r, secret=%s)"
            % (
                self.camera_id,
                self.adapter_name,
                self.ip,
                self.port,
                self.username,
                "***" if self.secret else None,
            )
        )


class CameraPTZAdapter(ABC):
    """One camera-control protocol behind a uniform interface."""

    #: short adapter identifier, persisted on the camera row (e.g. "onvif")
    adapter_name: str = "base"

    def __init__(self, snapshot: "CameraSnapshot"):
        # Adapters hold an immutable, DB-detached snapshot -- never a live ORM
        # Camera or an open session -- so deferred actions (the auto-stop timer,
        # shutdown stop_all) are safe after the request's session has closed.
        self.snapshot = snapshot

    # -- discovery --------------------------------------------------------
    @abstractmethod
    def probe(self) -> PTZCapabilities:
        """Actively contact the camera and return its real capabilities."""

    @abstractmethod
    def get_capabilities(self) -> PTZCapabilities:
        """Return capabilities (cached/known) without necessarily contacting it."""

    # -- movement (unit range) -------------------------------------------
    @abstractmethod
    def continuous_move(self, pan: float, tilt: float, zoom: float, speed: float) -> None:
        ...

    @abstractmethod
    def relative_move(self, pan: float, tilt: float, zoom: float, speed: float) -> None:
        ...

    @abstractmethod
    def absolute_move(self, pan: float, tilt: float, zoom: float, speed: float) -> None:
        ...

    @abstractmethod
    def stop(self) -> None:
        """Stop all motion. MUST be safe to call at any time (highest priority)."""

    # -- home -------------------------------------------------------------
    @abstractmethod
    def go_home(self) -> None:
        ...

    @abstractmethod
    def set_home(self) -> None:
        ...

    # -- presets ----------------------------------------------------------
    @abstractmethod
    def get_presets(self) -> list[PTZPreset]:
        ...

    @abstractmethod
    def goto_preset(self, token: str) -> None:
        ...

    @abstractmethod
    def create_preset(self, name: str) -> PTZPreset:
        ...

    @abstractmethod
    def delete_preset(self, token: str) -> None:
        ...

    # -- feedback ---------------------------------------------------------
    @abstractmethod
    def get_position(self) -> PTZPosition:
        ...


__all__ = ["CameraPTZAdapter", "CameraSnapshot", "PTZPreset", "PTZPosition", "MoveRequest"]
