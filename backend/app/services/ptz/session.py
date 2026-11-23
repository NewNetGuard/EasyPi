"""PTZ session safety — one active session per camera + auto-stop.

Guarantees for continuous motion regardless of what the frontend does:

* commands to the same camera are serialised (a per-camera lock), so move / home
  / preset cannot race each other; a caller that cannot acquire it fails with
  ``PTZBusy`` rather than interleaving;
* ``stop`` has highest priority: it never waits on the lock and always cancels
  the active session's auto-stop timer;
* a continuous move arms a backend-enforced max-duration timer that calls the
  camera's stop even if no explicit Stop and no frontend ever arrive;
* every command gets a unique request id (for the audit log / de-dup);
* ``stop_all`` is a best-effort stop of every active session (called on backend
  shutdown).
"""
from __future__ import annotations

import threading
import uuid
from collections import defaultdict
from typing import Callable, Optional


class _CameraState:
    __slots__ = ("lock", "timer", "active_request", "stop_action")

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.timer: Optional[threading.Timer] = None
        self.active_request: Optional[str] = None
        # Snapshot-based callable to stop this camera; retained so BOTH the
        # auto-stop timer and shutdown stop_all can invoke it. It must never
        # hold a live ORM model / open DB session.
        self.stop_action: Optional[Callable[[], None]] = None


class PTZSessionManager:
    def __init__(self, max_duration_s: float = 5.0):
        self.max_duration_s = float(max_duration_s)
        self._states: dict[str, _CameraState] = defaultdict(_CameraState)
        self._guard = threading.Lock()

    def _state(self, camera_id: str) -> _CameraState:
        with self._guard:
            return self._states[camera_id]

    @staticmethod
    def new_request_id() -> str:
        return uuid.uuid4().hex

    # -- per-camera serialisation ----------------------------------------
    def acquire(self, camera_id: str, timeout: float = 2.0) -> bool:
        """Try to take the per-camera command lock; False if busy."""
        return self._state(camera_id).lock.acquire(timeout=timeout)

    def release(self, camera_id: str) -> None:
        try:
            self._state(camera_id).lock.release()
        except RuntimeError:
            pass  # not held

    # -- continuous-move auto-stop ---------------------------------------
    def start_continuous(
        self, camera_id: str, request_id: str, stop_action: Callable[[], None]
    ) -> None:
        """Register an active continuous move + arm the max-duration auto-stop.

        ``stop_action`` must be self-contained (built from an immutable
        CameraSnapshot, not a live ORM model), so the deferred stop stays valid
        after the request's DB session has closed.
        """
        st = self._state(camera_id)
        self._cancel_timer(st)
        st.active_request = request_id
        st.stop_action = stop_action
        if self.max_duration_s and self.max_duration_s > 0:
            timer = threading.Timer(
                self.max_duration_s, self._auto_stop, args=(camera_id, request_id)
            )
            timer.daemon = True
            st.timer = timer
            timer.start()

    def stop(self, camera_id: str) -> None:
        """Cancel the auto-stop timer + clear the session (highest priority).

        Idempotent: safe to call when nothing is active.
        """
        st = self._state(camera_id)
        self._cancel_timer(st)
        st.active_request = None
        st.stop_action = None

    def active_request(self, camera_id: str) -> Optional[str]:
        return self._state(camera_id).active_request

    def _auto_stop(self, camera_id: str, request_id: str) -> None:
        st = self._state(camera_id)
        if st.active_request != request_id:
            return  # superseded by a newer command / explicit stop
        action = st.stop_action
        st.active_request = None
        st.stop_action = None
        st.timer = None
        self._safe_call(action)

    @staticmethod
    def _cancel_timer(st: _CameraState) -> None:
        if st.timer is not None:
            st.timer.cancel()
            st.timer = None

    @staticmethod
    def _safe_call(action: Optional[Callable[[], None]]) -> None:
        """Invoke a stop action, swallowing any error and logging nothing.

        Best-effort by contract: a failure must never crash the timer thread,
        block another camera's stop, or abort shutdown. Nothing is logged here,
        so a credential embedded in an exception cannot leak.
        """
        if action is None:
            return
        try:
            action()
        except Exception:
            pass

    def stop_all(self) -> None:
        """Best-effort Stop of every active PTZ session (called on shutdown).

        Sends each active camera's stop, then clears its session. One camera's
        failure is isolated and never blocks the others or the shutdown. The
        stop actions run without holding the manager lock so a slow/hung camera
        cannot stall shutdown of the rest.
        """
        with self._guard:
            states = list(self._states.values())
        for st in states:
            self._cancel_timer(st)
            action = st.stop_action
            st.active_request = None
            st.stop_action = None
            self._safe_call(action)


def _default_max_duration() -> float:
    try:
        from config import get_settings

        return float(get_settings().PTZ_CONTINUOUS_MAX_DURATION_S)
    except Exception:
        return 5.0


# Process-wide session manager used by the endpoints.
session_manager = PTZSessionManager(max_duration_s=_default_max_duration())


__all__ = ["PTZSessionManager", "session_manager"]
