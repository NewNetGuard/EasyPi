"""Controlled single-connection HTTP2 bulk client with verified server TLS."""

import json
from pathlib import Path
import socket
import ssl
import sys
import time
from hpack import Decoder, Encoder


def frame(kind, flags, stream, body=b""):
    return (
        len(body).to_bytes(3, "big")
        + bytes([kind, flags])
        + stream.to_bytes(4, "big")
        + body
    )


def main():
    host, proxy, keylog, nonce, output, port, path = sys.argv[1:]
    context = ssl.create_default_context()
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(["h2"])
    context.keylog_filename = keylog
    encoder = Encoder()
    decoder = Decoder(max_header_list_size=16384)
    statuses = {}
    sizes = {}
    completed = set()
    latencies = {}
    began = time.monotonic()
    with socket.create_connection(("127.0.0.1", int(proxy)), timeout=20) as raw:
        raw.sendall(
            (f"CONNECT {host}:{port} HTTP/1.1\r\nHost: {host}:{port}\r\n\r\n").encode()
        )
        response = bytearray()
        while not response.endswith(b"\r\n\r\n") and len(response) < 8192:
            byte = raw.recv(1)
            if not byte:
                raise RuntimeError("proxy closed")
            response.extend(byte)
        if not response.startswith(b"HTTP/1.1 200 "):
            raise RuntimeError("proxy rejected")
        with context.wrap_socket(raw, server_hostname=host) as tls:
            issuer = tls.getpeercert().get("issuer", ())
            if tls.selected_alpn_protocol() != "h2":
                Path(output).write_text(
                    json.dumps(
                        dict(
                            error="HTTP2 was not negotiated",
                            alpn=tls.selected_alpn_protocol(),
                            issuer=issuer,
                        )
                    ),
                    encoding="utf-8",
                )
                raise RuntimeError("HTTP2 was not negotiated")
            tls.sendall(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" + frame(4, 0, 0))
            for i in range(4):
                stream = i * 2 + 1
                sizes[stream] = 0
                separator = "&" if "?" in path else "?"
                block = encoder.encode(
                    [
                        (":method", "GET"),
                        (":scheme", "https"),
                        (":authority", host),
                        (
                            ":path",
                            path + separator + "prism_probe=" + nonce + "-" + str(i),
                        ),
                    ]
                )
                tls.sendall(frame(1, 5, stream, block))
            buffer = bytearray()
            pending = {}
            while len(completed) < 4:
                data = tls.recv(65536)
                if not data:
                    break
                buffer.extend(data)
                if len(buffer) > 131072:
                    raise RuntimeError("response buffer budget")
                while len(buffer) >= 9:
                    length = int.from_bytes(buffer[:3], "big")
                    if length > 65536:
                        raise RuntimeError("frame budget")
                    if len(buffer) < length + 9:
                        break
                    kind, flags = buffer[3:5]
                    stream = int.from_bytes(buffer[5:9], "big") & 0x7FFFFFFF
                    body = bytes(buffer[9 : 9 + length])
                    del buffer[: 9 + length]
                    if kind == 4 and not flags & 1:
                        tls.sendall(frame(4, 1, 0))
                    elif kind == 6 and not flags & 1:
                        tls.sendall(frame(6, 1, 0, body))
                    elif kind in (1, 9):
                        if kind == 1:
                            if flags & 8:
                                body = body[1 : len(body) - body[0]]
                            if flags & 32:
                                body = body[5:]
                        pending.setdefault(stream, bytearray()).extend(body)
                        if flags & 4:
                            headers = dict(decoder.decode(bytes(pending.pop(stream))))
                            if ":status" in headers:
                                statuses[stream] = int(headers[":status"])
                        if kind == 1 and flags & 1:
                            completed.add(stream)
                            latencies[stream] = (time.monotonic() - began) * 1000
                    elif kind == 0:
                        content = body[1 : len(body) - body[0]] if flags & 8 else body
                        sizes[stream] = sizes.get(stream, 0) + len(content)
                        if length:
                            tls.sendall(
                                frame(8, 0, 0, length.to_bytes(4, "big"))
                                + frame(8, 0, stream, length.to_bytes(4, "big"))
                            )
                        if flags & 1:
                            completed.add(stream)
                            latencies[stream] = (time.monotonic() - began) * 1000
                    elif kind == 3:
                        raise RuntimeError("server reset a stream")
            elapsed = time.monotonic() - began
            report = dict(
                version=tls.version(),
                alpn=tls.selected_alpn_protocol(),
                statuses=[statuses.get(i) for i in (1, 3, 5, 7)],
                sizes=[sizes.get(i, 0) for i in (1, 3, 5, 7)],
                response_ms=[latencies.get(i) for i in (1, 3, 5, 7)],
                total_seconds=elapsed,
                total_bytes=sum(sizes.values()),
                issuer=issuer,
            )
            Path(output).write_text(json.dumps(report), encoding="utf-8")
    if len(completed) != 4 or any(status != 200 for status in statuses.values()):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
