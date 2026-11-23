"""Thingino PTZ adapter -- pan/tilt stepper motors over the local Thingino web API.

The motors are STEP-based: there is no server-side "move until stop", so this
adapter advertises relative + absolute moves (not continuous), Stop is a safe
no-op, and home = go to the configured park position. Everything the camera
reports (step ranges, park position) is read from the camera itself, never
assumed. All requests go through the SSRF guard to the camera's pinned LAN IP
with short timeouts and no redirects. Authentication mirrors the camera's own web
UI (verified against Thingino on a Cinnado D1): POST the web password
base64-encoded to ``/x/login.cgi`` to get a session cookie, which then authorises
the motor API. The base64 is the transport encoding the firmware requires, not
secrecy; the password is never logged. The session cookie is reused for the life
of the adapter and re-established once on expiry.

API (the login session cookie authorises every /x/*.cgi call):
  POST /x/login.cgi  {"username","password":<base64>,"encoding":"base64"} -> cookie
  GET  /x/json-motor-params.cgi  -> {steps_pan, steps_tilt, pos_0_x, pos_0_y, ...}
  GET  /x/json-motor.cgi?d=g&x=<dx>&y=<dy>   relative step  (l=-x r=+x  d=-y u=+y)
  GET  /x/json-motor.cgi?d=x&x=<X>&y=<Y>       absolute position (center = max/2)
"""
from __future__ import annotations

import base64
import json as _json
from typing import Optional

import httpx

from app.services.ptz.base import CameraPTZAdapter, PTZPosition, PTZPreset
from app.services.ptz.capabilities import PTZCapabilities
from app.services.ptz.errors import (
    PTZAuthError,
    PTZError,
    PTZUnreachable,
    PTZUnsupported,
    scrub,
)
from app.services.ptz.normalize import clamp_speed, clamp_unit
from app.services.ptz.ssrf import validate_ip, validate_port

HTTP_PORT = 80
MAX_RESPONSE_BYTES = 256 * 1024


def _read_bounded(response: httpx.Response, limit: int) -> bytes:
    """Read a decoded response incrementally and reject it at the byte limit."""
    length = response.headers.get("content-length")
    if length:
        try:
            if int(length) > limit:
                raise PTZError("camera response is too large")
        except ValueError:
            pass
    content = bytearray()
    for chunk in response.iter_bytes(chunk_size=64 * 1024):
        if len(content) + len(chunk) > limit:
            raise PTZError("camera response is too large")
        content.extend(chunk)
    return bytes(content)


def _make_client(base_url: str, timeout: float) -> httpx.Client:
    """Build the HTTP client (module-level so tests can substitute a transport)."""
    return httpx.Client(base_url=base_url, timeout=timeout, follow_redirects=False)


def _command_timeout() -> float:
    try:
        from config import get_settings

        return float(get_settings().PTZ_COMMAND_TIMEOUT_S)
    except Exception:
        return 4.0


class ThinginoPTZAdapter(CameraPTZAdapter):
    adapter_name = "thingino"

    def __init__(self, snapshot):
        super().__init__(snapshot)
        self._client: Optional[httpx.Client] = None
        self._params: Optional[dict] = None
        self._logged_in = False

    # -- HTTP plumbing ---------------------------------------------------
    def _base_url(self) -> str:
        ip = str(validate_ip(self.snapshot.ip))  # SSRF: LAN-only, never EasyPi itself
        validate_port(HTTP_PORT)
        return "http://%s:%d" % (ip, HTTP_PORT)

    def _get_client(self) -> httpx.Client:
        if self._client is None:
            self._client = _make_client(self._base_url(), _command_timeout())
        return self._client

    def _login(self) -> None:
        secret = self.snapshot.secret
        if not secret:
            raise PTZAuthError("Thingino requires the camera's web password (none stored)")
        user = self.snapshot.username or "root"
        client = self._get_client()
        # The firmware wants the password base64-encoded in a JSON body (exactly
        # what its own login page posts); the session cookie it returns is kept on
        # the client. The password is base64 for transport only, never logged.
        pw_b64 = base64.b64encode(secret.encode("utf-8")).decode("ascii")
        # Compact JSON (no spaces): this firmware's login.cgi parser rejects a body
        # with whitespace ("Username required"); the browser posts compact JSON too.
        body = _json.dumps(
            {"username": user, "password": pw_b64, "encoding": "base64"},
            separators=(",", ":"),
        )
        try:
            # Mirror the browser's login flow, but never download an unbounded page.
            with client.stream("GET", "/login.html"):
                pass
            with client.stream(
                "POST",
                "/x/login.cgi",
                content=body.encode("utf-8"),
                headers={"Content-Type": "application/json"},
            ) as response:
                status_code = response.status_code
        except httpx.HTTPError as e:
            raise PTZUnreachable("camera login failed: %s" % scrub(str(e)))
        if status_code in (401, 403):
            raise PTZAuthError("camera rejected the web credentials")
        if status_code >= 400:
            raise PTZError("camera login error (%d)" % status_code)
        self._logged_in = True

    def _api_get(self, path: str, params: Optional[dict] = None, _retry: bool = True) -> dict:
        client = self._get_client()
        if not self._logged_in:
            self._login()
        try:
            with client.stream("GET", path, params=params) as response:
                status_code = response.status_code
                if status_code not in (401, 403):
                    content = _read_bounded(response, MAX_RESPONSE_BYTES).strip()
        except httpx.HTTPError as e:
            raise PTZUnreachable("camera request failed: %s" % scrub(str(e)))
        if status_code in (401, 403) and _retry:
            self._logged_in = False  # session expired -> re-login once and retry
            self._login()
            return self._api_get(path, params, _retry=False)
        if status_code in (401, 403):
            raise PTZAuthError("camera rejected the web credentials")
        if status_code >= 400:
            raise PTZError("camera error (%d)" % status_code)
        if content.startswith(b"{"):
            try:
                data = _json.loads(content)
                return data if isinstance(data, dict) else {}
            except Exception:
                return {}
        return {}

    def _motor_params(self) -> dict:
        if self._params is None:
            self._params = self._api_get("/x/json-motor-params.cgi") or {}
        return self._params

    @staticmethod
    def _int(params: dict, key: str) -> int:
        try:
            return int(params.get(key, 0) or 0)
        except (TypeError, ValueError):
            return 0

    # -- discovery -------------------------------------------------------
    def probe(self) -> PTZCapabilities:
        params = self._motor_params()
        steps_pan = self._int(params, "steps_pan")
        steps_tilt = self._int(params, "steps_tilt")
        if steps_pan <= 0 and steps_tilt <= 0:
            return PTZCapabilities(available=False, adapter="thingino")
        return PTZCapabilities(
            available=True,
            adapter="thingino",
            pan=steps_pan > 0,
            tilt=steps_tilt > 0,
            optical_zoom=False,
            continuous_move=False,  # step-based motors -> no server continuous move
            relative_move=True,
            absolute_move=True,
            stop=True,
            home=True,
            presets=False,
            position_feedback=False,
        )

    def get_capabilities(self) -> PTZCapabilities:
        return self.probe()

    # -- movement (EasyPi unit range -> motor steps) ---------------------
    @staticmethod
    def _step_fraction(speed: float) -> float:
        # 2%..12% of the full range per relative step, scaled by speed
        return 0.02 + 0.10 * clamp_speed(speed)

    def relative_move(self, pan: float, tilt: float, zoom: float, speed: float) -> None:
        params = self._motor_params()
        x_range = self._int(params, "steps_pan")
        y_range = self._int(params, "steps_tilt")
        frac = self._step_fraction(speed)
        dx = int(round(clamp_unit(pan) * frac * x_range))   # +x = right, -x = left
        dy = int(round(clamp_unit(tilt) * frac * y_range))  # +y = up,    -y = down
        if dx == 0 and dy == 0:
            return
        self._api_get("/x/json-motor.cgi", params={"d": "g", "x": dx, "y": dy})

    def absolute_move(self, pan: float, tilt: float, zoom: float, speed: float) -> None:
        params = self._motor_params()
        x_range = self._int(params, "steps_pan")
        y_range = self._int(params, "steps_tilt")
        absx = int(round((clamp_unit(pan) + 1.0) / 2.0 * x_range))
        absy = int(round((clamp_unit(tilt) + 1.0) / 2.0 * y_range))
        self._api_get("/x/json-motor.cgi", params={"d": "x", "x": absx, "y": absy})

    def continuous_move(self, pan: float, tilt: float, zoom: float, speed: float) -> None:
        # Thingino motors are step-based; there is no continuous move -> fail closed.
        raise PTZUnsupported("Thingino motors do not support continuous move")

    def stop(self) -> None:
        # A step move completes on its own; there is nothing to stop. Safe no-op.
        return None

    # -- home ------------------------------------------------------------
    def go_home(self) -> None:
        params = self._motor_params()
        x0 = self._int(params, "pos_0_x")
        y0 = self._int(params, "pos_0_y")
        self._api_get("/x/json-motor.cgi", params={"d": "x", "x": x0, "y": y0})

    def set_home(self) -> None:
        raise PTZUnsupported("set-home is not yet supported by the Thingino adapter")

    # -- presets (not supported by the Thingino motor API) ---------------
    def get_presets(self) -> list[PTZPreset]:
        return []

    def goto_preset(self, token: str) -> None:
        raise PTZUnsupported("presets are not supported by the Thingino adapter")

    def create_preset(self, name: str) -> PTZPreset:
        raise PTZUnsupported("presets are not supported by the Thingino adapter")

    def delete_preset(self, token: str) -> None:
        raise PTZUnsupported("presets are not supported by the Thingino adapter")

    def get_position(self) -> PTZPosition:
        return PTZPosition()

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None
            self._logged_in = False

    def __del__(self):
        self.close()


__all__ = ["ThinginoPTZAdapter"]
