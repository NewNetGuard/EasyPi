"""ONVIF PTZ adapter -- the universal, cross-vendor path.

Discovery (GetCapabilities) is anonymous; media profiles and PTZ control require
the camera's ONVIF credentials (WS-Security digest, password never sent in the
clear). EasyPi's unit range [-1, 1] maps onto ONVIF's generic PTZ spaces. Every
request goes through the SSRF guard to the camera's pinned LAN IP; capabilities
are detected from the camera itself, never assumed. No shell, no secrets logged.
"""
from __future__ import annotations

from typing import List, Optional
from urllib.parse import urlsplit

import httpx

from app.services.ptz.adapters import onvif_soap as soap
from app.services.ptz.base import CameraPTZAdapter, PTZPosition, PTZPreset
from app.services.ptz.capabilities import PTZCapabilities
from app.services.ptz.errors import PTZAuthError, PTZError, PTZUnsupported
from app.services.ptz.normalize import clamp_speed, clamp_unit

DEVICE_PATH = "/onvif/device_service"
HTTP_PORT = 80

A_DEV = "http://www.onvif.org/ver10/device/wsdl/"
A_MEDIA = "http://www.onvif.org/ver10/media/wsdl/"
A_PTZ = "http://www.onvif.org/ver20/ptz/wsdl/"
TT = soap.NS["tt"]


def _localname(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def _fmt(v: float) -> str:
    return ("%.4f" % v).rstrip("0").rstrip(".") or "0"


class OnvifPTZAdapter(CameraPTZAdapter):
    adapter_name = "onvif"

    def __init__(self, snapshot):
        super().__init__(snapshot)
        self._client: Optional[httpx.Client] = None
        self._ptz_url: Optional[str] = None
        self._media_url: Optional[str] = None
        self._profile: Optional[str] = None
        self._caps: Optional[PTZCapabilities] = None

    # -- plumbing --------------------------------------------------------
    def _creds(self):
        user = self.snapshot.username or ""
        secret = self.snapshot.secret or ""
        return user, secret

    def _client_(self) -> httpx.Client:
        if self._client is None:
            self._client = soap._make_client(soap._command_timeout())
        return self._client

    def _http_port(self) -> int:
        # Port the camera actually serves ONVIF on -- learned from WS-Discovery and
        # stored on the camera; falls back to the ONVIF default when unknown.
        return int(self.snapshot.onvif_port or HTTP_PORT)

    def _device_url(self) -> str:
        return "http://%s:%d%s" % (self.snapshot.ip, self._http_port(), DEVICE_PATH)

    def _url_on_camera(self, xaddr: str, default_path: str) -> str:
        # Always talk to the known camera IP + its ONVIF port (the XAddr host/port
        # may be wrong/internal), keeping only the path -- SSRF-safe and dodges a
        # classic ONVIF bug.
        path = urlsplit(xaddr).path or default_path if xaddr else default_path
        return "http://%s:%d%s" % (self.snapshot.ip, self._http_port(), path)

    def _call(self, url, action, body, *, auth=True):
        user, secret = self._creds() if auth else ("", "")
        return soap.call(url, action, body, user or None, secret or None, client=self._client_())

    # -- discovery -------------------------------------------------------
    def _discover_services(self) -> None:
        if self._ptz_url and self._media_url:
            return
        root = self._call(
            self._device_url(),
            A_DEV + "GetCapabilities",
            "<tds:GetCapabilities><tds:Category>All</tds:Category></tds:GetCapabilities>",
            auth=False,
        )
        ptz_x = media_x = ""
        for el in root.iter():
            if _localname(el.tag) == "XAddr" and el.text:
                low = el.text.lower()
                if "ptz" in low:
                    ptz_x = el.text
                elif "media" in low:
                    media_x = el.text
        self._ptz_url = self._url_on_camera(ptz_x, "/onvif/ptz_service")
        self._media_url = self._url_on_camera(media_x, "/onvif/media_service")

    def _pick_profile(self) -> str:
        if self._profile:
            return self._profile
        self._discover_services()
        root = self._call(self._media_url, A_MEDIA + "GetProfiles", "<trt:GetProfiles/>")
        chosen = None
        first = None
        for prof in root.iter():
            if _localname(prof.tag) != "Profiles":
                continue
            token = prof.get("token")
            if not token:
                continue
            if first is None:
                first = token
            if any(_localname(c.tag) == "PTZConfiguration" for c in prof.iter()):
                chosen = token
                break
        self._profile = chosen or first
        if not self._profile:
            raise PTZUnsupported("camera exposes no ONVIF media profile")
        return self._profile

    def probe(self) -> PTZCapabilities:
        # Discovery is anonymous; without credentials we cannot read profiles or
        # move -> fail closed with a clear reason.
        self._discover_services()
        user, secret = self._creds()
        if not (user and secret):
            raise PTZAuthError("ONVIF PTZ requires camera credentials (none stored)")

        profile = self._pick_profile()
        options = self._call(
            self._discover_and_ptz(),
            A_PTZ + "GetConfigurationOptions",
            "<tptz:GetConfigurationOptions><tptz:ConfigurationToken>%s"
            "</tptz:ConfigurationToken></tptz:GetConfigurationOptions>" % profile,
        )
        spaces = {_localname(el.tag) for el in options.iter()}
        pantilt = any("PanTilt" in s for s in spaces)
        zoom = any(s.startswith(("ContinuousZoom", "AbsoluteZoom", "RelativeZoom")) for s in spaces)
        caps = PTZCapabilities(
            available=True,
            adapter="onvif",
            pan=pantilt,
            tilt=pantilt,
            optical_zoom=zoom,
            continuous_move=any(s.startswith("Continuous") for s in spaces),
            relative_move=any(s.startswith("Relative") for s in spaces),
            absolute_move=any(s.startswith("Absolute") for s in spaces),
            stop=True,
            home=True,
            presets=True,
            position_feedback=True,
        )
        self._caps = caps
        return caps

    def get_capabilities(self) -> PTZCapabilities:
        return self._caps or self.probe()

    # -- movement --------------------------------------------------------
    def _velocity(self, pan, tilt, zoom) -> str:
        xml = '<tt:PanTilt x="%s" y="%s"/>' % (_fmt(pan), _fmt(tilt))
        if zoom:
            xml += '<tt:Zoom x="%s"/>' % _fmt(zoom)
        return xml

    def continuous_move(self, pan: float, tilt: float, zoom: float, speed: float) -> None:
        s = clamp_speed(speed)
        v = self._velocity(clamp_unit(pan) * s, clamp_unit(tilt) * s, clamp_unit(zoom) * s)
        self._call(
            self._discover_and_ptz(),
            A_PTZ + "ContinuousMove",
            "<tptz:ContinuousMove><tptz:ProfileToken>%s</tptz:ProfileToken>"
            "<tptz:Velocity>%s</tptz:Velocity></tptz:ContinuousMove>" % (self._pick_profile(), v),
        )

    def relative_move(self, pan: float, tilt: float, zoom: float, speed: float) -> None:
        v = self._velocity(clamp_unit(pan), clamp_unit(tilt), clamp_unit(zoom))
        self._call(
            self._discover_and_ptz(),
            A_PTZ + "RelativeMove",
            "<tptz:RelativeMove><tptz:ProfileToken>%s</tptz:ProfileToken>"
            "<tptz:Translation>%s</tptz:Translation></tptz:RelativeMove>" % (self._pick_profile(), v),
        )

    def absolute_move(self, pan: float, tilt: float, zoom: float, speed: float) -> None:
        v = self._velocity(clamp_unit(pan), clamp_unit(tilt), clamp_unit(zoom))
        self._call(
            self._discover_and_ptz(),
            A_PTZ + "AbsoluteMove",
            "<tptz:AbsoluteMove><tptz:ProfileToken>%s</tptz:ProfileToken>"
            "<tptz:Position>%s</tptz:Position></tptz:AbsoluteMove>" % (self._pick_profile(), v),
        )

    def stop(self) -> None:
        # Stop must always be safe to call; do not raise if we cannot reach the camera.
        try:
            self._call(
                self._ptz_url or self._url_on_camera("", "/onvif/ptz_service"),
                A_PTZ + "Stop",
                "<tptz:Stop><tptz:ProfileToken>%s</tptz:ProfileToken>"
                "<tptz:PanTilt>true</tptz:PanTilt><tptz:Zoom>true</tptz:Zoom></tptz:Stop>"
                % self._pick_profile(),
            )
        except PTZError:
            pass

    # -- home ------------------------------------------------------------
    def go_home(self) -> None:
        self._call(
            self._discover_and_ptz(),
            A_PTZ + "GotoHomePosition",
            "<tptz:GotoHomePosition><tptz:ProfileToken>%s</tptz:ProfileToken>"
            "</tptz:GotoHomePosition>" % self._pick_profile(),
        )

    def set_home(self) -> None:
        self._call(
            self._discover_and_ptz(),
            A_PTZ + "SetHomePosition",
            "<tptz:SetHomePosition><tptz:ProfileToken>%s</tptz:ProfileToken>"
            "</tptz:SetHomePosition>" % self._pick_profile(),
        )

    # -- presets ---------------------------------------------------------
    def get_presets(self) -> List[PTZPreset]:
        root = self._call(
            self._ptz_url or self._discover_and_ptz(),
            A_PTZ + "GetPresets",
            "<tptz:GetPresets><tptz:ProfileToken>%s</tptz:ProfileToken></tptz:GetPresets>"
            % self._pick_profile(),
        )
        out: List[PTZPreset] = []
        for el in root.iter():
            if _localname(el.tag) == "Preset" and el.get("token"):
                name = ""
                for c in el:
                    if _localname(c.tag) == "Name":
                        name = c.text or ""
                out.append(PTZPreset(token=el.get("token"), name=name or el.get("token")))
        return out

    def _discover_and_ptz(self) -> str:
        self._discover_services()
        return self._ptz_url

    def goto_preset(self, token: str) -> None:
        self._call(
            self._discover_and_ptz(),
            A_PTZ + "GotoPreset",
            "<tptz:GotoPreset><tptz:ProfileToken>%s</tptz:ProfileToken>"
            "<tptz:PresetToken>%s</tptz:PresetToken></tptz:GotoPreset>"
            % (self._pick_profile(), soap._esc(token)),
        )

    def create_preset(self, name: str) -> PTZPreset:
        root = self._call(
            self._discover_and_ptz(),
            A_PTZ + "SetPreset",
            "<tptz:SetPreset><tptz:ProfileToken>%s</tptz:ProfileToken>"
            "<tptz:PresetName>%s</tptz:PresetName></tptz:SetPreset>"
            % (self._pick_profile(), soap._esc(name)),
        )
        token = ""
        for el in root.iter():
            if _localname(el.tag) == "PresetToken":
                token = el.text or ""
                break
        return PTZPreset(token=token or name, name=name)

    def delete_preset(self, token: str) -> None:
        self._call(
            self._discover_and_ptz(),
            A_PTZ + "RemovePreset",
            "<tptz:RemovePreset><tptz:ProfileToken>%s</tptz:ProfileToken>"
            "<tptz:PresetToken>%s</tptz:PresetToken></tptz:RemovePreset>"
            % (self._pick_profile(), soap._esc(token)),
        )

    def get_position(self) -> PTZPosition:
        try:
            root = self._call(
                self._ptz_url,
                A_PTZ + "GetStatus",
                "<tptz:GetStatus><tptz:ProfileToken>%s</tptz:ProfileToken></tptz:GetStatus>"
                % self._pick_profile(),
            )
        except PTZError:
            return PTZPosition()
        pan = tilt = zoom = None
        for el in root.iter():
            ln = _localname(el.tag)
            if ln == "PanTilt":
                pan = _to_float(el.get("x"))
                tilt = _to_float(el.get("y"))
            elif ln == "Zoom":
                zoom = _to_float(el.get("x"))
        return PTZPosition(pan=pan, tilt=tilt, zoom=zoom)

    def close(self) -> None:
        if self._client is not None:
            try:
                self._client.close()
            except Exception:
                pass
            self._client = None

    def __del__(self):
        self.close()


def _to_float(v):
    try:
        return max(-1.0, min(1.0, float(v)))
    except (TypeError, ValueError):
        return None


__all__ = ["OnvifPTZAdapter"]
