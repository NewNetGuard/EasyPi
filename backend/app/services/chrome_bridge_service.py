"""No TLS secrets enter files, logs, exception details, or response bodies."""
import json
import socket

PATH = "/run/easypi-chrome-bridge/mobile.sock"


def call(device, operation, payload=None):
    request = dict(payload or {})
    request.update(device=str(device), op=operation)
    raw = json.dumps(request, separators=(",", ":")).encode()+b"\n"
    if len(raw) > 12000:
        raise ValueError("Chrome bridge request limit")
    try:
        with socket.socket(socket.AF_UNIX) as conn:
            conn.settimeout(2)
            conn.connect(PATH)
            conn.sendall(raw)
            reply = bytearray()
            while b"\n" not in reply and len(reply) <= 8192:
                chunk = conn.recv(4096)
                if not chunk:
                    raise OSError()
                reply.extend(chunk)
        value = json.loads(reply)
        if not value.get("ok"):
            raise ValueError()
        return value["result"]
    except Exception:
        raise ValueError("Chrome bridge unavailable or device not authorized") from None
