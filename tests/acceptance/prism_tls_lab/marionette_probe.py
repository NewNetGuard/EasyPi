"""Read certificate metadata from an explicitly instrumented temporary Firefox.

Only the opt-in test profile enables Marionette/system context. No ordinary
browser is attached and certificate validation is never disabled.
"""

import json
import socket
import time


class MarionetteProbe:
    def __init__(self, port, timeout=10):
        deadline = time.monotonic() + timeout
        while True:
            try:
                self.socket = socket.create_connection(("127.0.0.1", port), timeout=1)
                break
            except OSError:
                if time.monotonic() >= deadline:
                    raise RuntimeError("temporary Firefox Marionette did not start")
                time.sleep(0.1)
        self.socket.settimeout(15)
        self.sequence = 0
        greeting = self.receive()
        if (
            greeting.get("applicationType") != "gecko"
            or greeting.get("marionetteProtocol") != 3
        ):
            raise RuntimeError("unexpected Marionette endpoint")

    def receive(self):
        prefix = bytearray()
        while True:
            value = self.socket.recv(1)
            if not value:
                raise RuntimeError("Marionette connection closed")
            if value == b":":
                break
            if len(prefix) >= 8 or value not in b"0123456789":
                raise ValueError("invalid Marionette frame")
            prefix.extend(value)
        size = int(prefix)
        if size > 1024 * 1024:
            raise ValueError("Marionette frame limit")
        body = bytearray()
        while len(body) < size:
            value = self.socket.recv(size - len(body))
            if not value:
                raise RuntimeError("truncated Marionette response")
            body.extend(value)
        return json.loads(body)

    def command(self, name, parameters):
        self.sequence += 1
        body = json.dumps([0, self.sequence, name, parameters]).encode()
        self.socket.sendall(str(len(body)).encode() + b":" + body)
        response = self.receive()
        if len(response) != 4 or response[0] != 1 or response[1] != self.sequence:
            raise RuntimeError("unexpected Marionette response")
        if response[2]:
            raise RuntimeError(
                "Marionette " + response[2].get("error", "command failed")
            )
        return response[3]

    def certificate(self, url):
        self.command(
            "WebDriver:NewSession",
            {"capabilities": {"alwaysMatch": {"acceptInsecureCerts": False}}},
        )
        self.command("WebDriver:Navigate", {"url": url})
        self.command("Marionette:SetContext", {"value": "chrome"})
        return self.current_certificate()

    def current_certificate(self):
        self.command("Marionette:SetContext", {"value": "chrome"})
        result = self.command(
            "WebDriver:ExecuteScript",
            {
                "script": """
            const win = Services.wm.getMostRecentWindow('navigator:browser');
            const info = win.gBrowser.selectedBrowser.securityUI.secInfo;
            if (!info || !info.serverCert) return {available:false};
            const cert = info.serverCert;
            return {available:true, subject:cert.commonName, issuer:cert.issuerCommonName,
                    issuerOrganization:cert.issuerOrganization, sha256:cert.sha256Fingerprint,
                    cipher:info.cipherName, protocolVersion:info.protocolVersion};
            """,
                "args": [],
                "newSandbox": True,
                "sandbox": "prism-certificate-probe",
            },
        )
        return result.get("value", result)

    def close(self):
        self.socket.close()
