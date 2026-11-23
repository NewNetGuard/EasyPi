# Upstream for the bench: an HTTP/1.1 server that reads a (chunked or sized)
# request body made of records [4B length][8B send time, unix ns][data],
# optionally at a limited rate (header X-Slow-Rate, bytes/s), and answers with
# JSON statistics: bytes, records, per-record delay (send -> arrival here).
import asyncio
import json
import struct
import sys
import time


class Records:
    def __init__(self):
        self.buf = bytearray()
        self.bytes = 0
        self.small = []
        self.big = []
        self.first = None
        self.last = None

    def feed(self, data):
        now = time.time_ns()
        if self.first is None:
            self.first = now
        self.last = now
        self.bytes += len(data)
        self.buf += data
        pos = 0
        while len(self.buf) - pos >= 12:
            size, sent = struct.unpack_from(">IQ", self.buf, pos)
            if len(self.buf) - pos < 12 + size:
                break
            (self.small if size < 1024 else self.big).append((now - sent) / 1e6)
            pos += 12 + size
        del self.buf[:pos]

    def result(self):
        def stats(values):
            if not values:
                return None
            v = sorted(values)
            return {"n": len(v), "p50": round(v[len(v) // 2], 2),
                    "p99": round(v[min(len(v) - 1, int(len(v) * 0.99))], 2),
                    "max": round(v[-1], 2)}
        return {"bytes": self.bytes, "leftover": len(self.buf),
                "seconds": round(((self.last or 0) - (self.first or 0)) / 1e9, 3),
                "small_ms": stats(self.small), "big_ms": stats(self.big)}


async def handle(reader, writer):
    try:
        while True:
            head = (await reader.readuntil(b"\r\n\r\n")).decode("latin-1").split("\r\n")
            headers = {}
            for line in head[1:]:
                if ":" in line:
                    k, v = line.split(":", 1)
                    headers[k.strip().lower()] = v.strip()
            rate = float(headers.get("x-slow-rate", "0"))
            rec = Records()
            start = time.monotonic()
            # X-Early: answer headers at once (full duplex, like the carrier's
            # TCP streams) and send the statistics as the chunked body later.
            early = headers.get("x-early") == "1"
            if early:
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                             b"Transfer-Encoding: chunked\r\n\r\n")
                await writer.drain()

            async def take(n):
                while n:
                    piece = await reader.read(min(n, 65536))
                    if not piece:
                        raise ConnectionError("eof in body")
                    rec.feed(piece)
                    n -= len(piece)
                    if rate:
                        delay = start + rec.bytes / rate - time.monotonic()
                        if delay > 0:
                            await asyncio.sleep(delay)

            if headers.get("transfer-encoding", "").lower() == "chunked":
                while True:
                    size = int((await reader.readuntil(b"\r\n")).split(b";")[0], 16)
                    if size == 0:
                        await reader.readuntil(b"\r\n")
                        break
                    await take(size)
                    await reader.readexactly(2)
            else:
                await take(int(headers.get("content-length", "0")))
            body = json.dumps(rec.result()).encode()
            if early:
                writer.write(b"%x\r\n%s\r\n0\r\n\r\n" % (len(body), body))
            else:
                writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n"
                             b"Content-Length: %d\r\n\r\n" % len(body) + body)
            await writer.drain()
    except (asyncio.IncompleteReadError, ConnectionError):
        pass
    writer.close()


async def main():
    server = await asyncio.start_server(handle, "127.0.0.1", int(sys.argv[1]))
    async with server:
        await server.serve_forever()


asyncio.run(main())
