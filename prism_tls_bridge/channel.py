"""Single-session capabilities carried only inside an authenticated SSH channel.

This framing attenuates an already authenticated SSH principal. It is not a
replacement for SSH, endpoint attestation or a public enrollment service.
"""

import hashlib
import hmac
import json
import re
import secrets
import time


class ChannelError(ValueError):
    pass


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("ascii")


class KeySender:
    def __init__(self, session, scope, ttl=120):
        if not re.fullmatch(r"[0-9a-f]{32}", session):
            raise ChannelError("invalid session")
        self.session, self.scope, self.ttl = session, scope, ttl
        self.token = secrets.token_bytes(32)
        self.sequence = 0

    def enrollment(self):
        return (
            canonical(
                dict(
                    type="grant",
                    session=self.session,
                    scope=self.scope,
                    ttl=self.ttl,
                    capability=self.token.hex(),
                )
            ).decode()
            + "\n"
        )

    def close(self):
        self.token = b""

    def frame(self, line):
        if not self.token:
            raise ChannelError("sender is closed")
        self.sequence += 1
        body = dict(type="key", session=self.session, sequence=self.sequence, line=line)
        body["mac"] = hmac.new(self.token, canonical(body), hashlib.sha256).hexdigest()
        return canonical(body).decode() + "\n"


class KeyReceiver:
    def __init__(self, session, scope, clock=time.monotonic):
        self.session, self.scope, self.clock = session, scope, clock
        self.token = None
        self.sequence = 0
        self.deadline = 0
        self.failed = False
        self.accepted = 0

    def receive(self, raw):
        if self.failed:
            raise ChannelError("channel is closed")
        try:
            if not isinstance(raw, str) or len(raw) > 2048:
                raise ChannelError("frame limit")
            value = json.loads(raw)
            if not isinstance(value, dict) or value.get("session") != self.session:
                raise ChannelError("session mismatch")
            if self.token is None:
                if (
                    set(value) != {"type", "session", "scope", "ttl", "capability"}
                    or value["type"] != "grant"
                ):
                    raise ChannelError("enrollment required")
                if value["scope"] != self.scope or self.scope.get("opt_in") is not True:
                    raise ChannelError("permission denied")
                ttl = value["ttl"]
                if type(ttl) is not int or not 1 <= ttl <= 600:
                    raise ChannelError("invalid lease")
                if not isinstance(value["capability"], str) or not re.fullmatch(
                    r"[0-9a-f]{64}", value["capability"]
                ):
                    raise ChannelError("invalid capability")
                self.token = bytes.fromhex(value["capability"])
                self.deadline = self.clock() + ttl
                return None
            if self.clock() >= self.deadline:
                raise ChannelError("lease expired")
            if (
                set(value) != {"type", "session", "sequence", "line", "mac"}
                or value["type"] != "key"
            ):
                raise ChannelError("invalid key frame")
            mac = value.pop("mac")
            if (
                type(value["sequence"]) is not int
                or value["sequence"] != self.sequence + 1
                or self.sequence >= 64
            ):
                raise ChannelError("replayed or excessive frame")
            if not isinstance(mac, str) or not hmac.compare_digest(
                mac, hmac.new(self.token, canonical(value), hashlib.sha256).hexdigest()
            ):
                raise ChannelError("authentication failed")
            line = value["line"]
            if not isinstance(line, str) or len(line) > 1024:
                raise ChannelError("key line limit")
            self.sequence += 1
            self.accepted += 1
            return line
        except (ValueError, KeyError, TypeError):
            self.close()
            raise ChannelError("key channel rejected") from None

    def close(self):
        self.failed = True
        self.token = None


def scope_for(transport, host, port, **capture_scope):
    result = dict(
        endpoint_id="managed-lab-client",
        capture_point="isolated-pi-capture",
        key_source="managed-keylog-collector",
        tls_leg="endpoint-origin",
        opt_in=True,
        transport=transport,
        host=host,
        port=port,
    )
    result.update(capture_scope)
    return result
