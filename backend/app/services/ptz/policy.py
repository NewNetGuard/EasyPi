"""PTZ authorization policy — the single swap point for access control.

EasyPi currently has only a global ``admin``/``user`` role, so PTZ actions are
mapped onto it here:

* **view**    (capabilities, position, presets, video)        -> any authenticated user
* **control** (move, stop, go_home, optical zoom, goto preset) -> any authenticated user
* **admin**   (detect, adapter change, PTZ settings, set_home,
               preset create/rename/delete)                    -> admin only

Every PTZ endpoint and the service layer call these functions — never a raw
``user.role`` check. When EasyPi gains granular per-camera permissions, replace
ONLY the bodies below (e.g. look up a per-camera grant); adapters, schemas and
endpoints stay untouched. ``view`` and ``control`` are deliberately kept as
separate predicates so a future "PTZ operator" tier can diverge from plain view.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

from fastapi import HTTPException, status

if TYPE_CHECKING:
    pass


def _is_admin(user) -> bool:
    return getattr(user, "role", None) == "admin"


def can_view(user, camera=None) -> bool:
    """May see PTZ capabilities/position/presets for this camera."""
    return user is not None


def can_control(user, camera=None) -> bool:
    """May drive the camera: move/stop/go_home/zoom/goto an existing preset."""
    return user is not None


def can_administer(user, camera=None) -> bool:
    """May change PTZ config: detect, adapter, settings, set_home, preset CRUD."""
    return user is not None and _is_admin(user)


def ensure_can_view(user, camera=None) -> None:
    if not can_view(user, camera):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Not permitted")


def ensure_can_control(user, camera=None) -> None:
    if not can_control(user, camera):
        raise HTTPException(status.HTTP_403_FORBIDDEN, "Not permitted")


def ensure_can_administer(user, camera=None) -> None:
    if not can_administer(user, camera):
        raise HTTPException(
            status.HTTP_403_FORBIDDEN, "PTZ administration requires an admin account"
        )


__all__ = [
    "can_view",
    "can_control",
    "can_administer",
    "ensure_can_view",
    "ensure_can_control",
    "ensure_can_administer",
]
