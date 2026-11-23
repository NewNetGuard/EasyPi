# Bench: stock vs patched nginx 1.28.3 (Ubuntu .12 sources), HTTP/2 cleartext,
# tunnel-like location (unbuffered request body), through a WAN emulator.
# Counts WINDOW_UPDATE frames, measures speed, delays and stalls. Local only.
import asyncio
import json
import os
import socket
import struct
import subprocess
import sys
import time

HOME = os.path.expanduser("~/ngx")
HERE = os.path.dirname(os.path.abspath(__file__))
BINARIES = {"stock": HOME + "/nginx-1.28.3/objs/nginx", "patched": HOME + "/patched/objs/nginx"}
NGINX_PORT, SINK_PORT, WAN_CAPPED, WAN_FREE = 18080, 18081, 18090, 18091
ONE_WAY_MS, CAP = 15, 20_000_000
MB25 = 25 * 1024 * 1024
STALL = 20.0

CONF = """
master_process off;
daemon off;
worker_processes 1;
pid nginx.pid;
error_log error.log info;
events {{ worker_connections 1024; }}
http {{
    access_log off;
    server {{
        listen 127.0.0.1:{port};
        http2 on;
        keepalive_requests 1000000;
        location /up {{
            proxy_pass http://127.0.0.1:{sink};
            proxy_http_version 1.1;
            proxy_set_header Connection "";
            proxy_request_buffering off;
            proxy_buffering off;
            client_body_buffer_size {buf};
            client_max_body_size 0;
            client_body_timeout 24h;
            proxy_read_timeout 24h;
            proxy_send_timeout 24h;
        }}
    }}
}}
"""


def frame(kind, flags, sid, payload=b""):
    return struct.pack(">I", len(payload))[1:] + bytes([kind, flags]) + struct.pack(">I", sid) + payload


def literal(index, value):
    value = value.encode()
    assert len(value) < 127
    return bytes([index]) + bytes([len(value)]) + value


class Source:
    """Byte stream of records [4B len][8B unix ns at creation][payload]."""

    def __init__(self, payload):
        self.payload = payload
        self.pending = b""
        self.sent = 0

    def take(self, n):
        out = bytearray()
        while len(out) < n:
            if not self.pending:
                self.pending = struct.pack(">IQ", self.payload, time.time_ns()) + bytes(self.payload)
            k = min(n - len(out), len(self.pending))
            out += self.pending[:k]
            self.pending = self.pending[k:]
        self.sent += n
        return bytes(out)


class Stream:
    def __init__(self, sid, window):
        self.sid = sid
        self.window = window
        self.body = bytearray()
        self.status_ok = None
        self.done = asyncio.Event()
        self.error = None
        self.updates = []
        self.blocked = 0.0
        self.max_block = 0.0
        self.blocks = 0


class Conn:
    async def open(self, port):
        self.reader, self.writer = await asyncio.open_connection("127.0.0.1", port)
        self.conn_window, self.initial, self.max_frame = 65535, 65535, 16384
        self.streams, self.next_sid, self.conn_updates = {}, 1, []
        self.cond = asyncio.Condition()
        self.dead = None
        self.settings = asyncio.Event()
        self.writer.write(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
                          + frame(4, 0, 0, struct.pack(">HI", 4, 1 << 30))
                          + frame(8, 0, 0, struct.pack(">I", (1 << 31) - 1 - 65535)))
        self.task = asyncio.create_task(self.read_loop())
        await asyncio.wait_for(self.settings.wait(), 5)
        return self

    async def read_loop(self):
        try:
            while True:
                head = await self.reader.readexactly(9)
                length = int.from_bytes(head[:3], "big")
                kind, flags = head[3], head[4]
                sid = int.from_bytes(head[5:9], "big") & 0x7FFFFFFF
                payload = await self.reader.readexactly(length) if length else b""
                now = time.monotonic()
                stream = self.streams.get(sid)
                if kind == 4 and not flags & 1:
                    for i in range(0, length, 6):
                        key, value = struct.unpack(">HI", payload[i:i + 6])
                        if key == 4:
                            for s in self.streams.values():
                                s.window += value - self.initial
                            self.initial = value
                        elif key == 5:
                            self.max_frame = value
                    self.writer.write(frame(4, 1, 0))
                    self.settings.set()
                elif kind == 8:
                    inc = struct.unpack(">I", payload)[0] & 0x7FFFFFFF
                    if sid == 0:
                        self.conn_window += inc
                        self.conn_updates.append((now, inc))
                    elif stream:
                        stream.window += inc
                        stream.updates.append((now, inc))
                    async with self.cond:
                        self.cond.notify_all()
                elif kind == 6 and not flags & 1:
                    self.writer.write(frame(6, 1, 0, payload))
                elif kind == 1 and stream:
                    stream.status_ok = payload[:1] == b"\x88"
                    if flags & 1:
                        stream.done.set()
                elif kind == 0 and stream:
                    data = payload[1:length - payload[0]] if flags & 8 else payload
                    stream.body += data
                    if length:
                        self.writer.write(frame(8, 0, 0, struct.pack(">I", length))
                                          + frame(8, 0, sid, struct.pack(">I", length)))
                    if flags & 1:
                        stream.done.set()
                elif kind == 3 and stream:
                    stream.error = "RST_STREAM %d" % struct.unpack(">I", payload)[0]
                    stream.done.set()
                elif kind == 7:
                    raise ConnectionError("GOAWAY %s" % payload[4:8].hex())
        except (asyncio.IncompleteReadError, ConnectionError) as exc:
            self.dead = str(exc) or "closed"
            for s in self.streams.values():
                s.error = s.error or self.dead
                s.done.set()
            async with self.cond:
                self.cond.notify_all()

    def request(self, headers=()):
        sid = self.next_sid
        self.next_sid += 2
        stream = Stream(sid, self.initial)
        self.streams[sid] = stream
        block = b"\x83\x86" + literal(0x04, "/up") + literal(0x01, "bench")
        for name, value in headers:
            block += b"\x00" + bytes([len(name)]) + name.encode() + bytes([len(value)]) + value.encode()
        self.writer.write(frame(1, 4, sid, block))
        return stream

    async def credit(self, stream):
        if min(self.conn_window, stream.window) > 0:
            return
        start = time.monotonic()
        async with self.cond:
            while min(self.conn_window, stream.window) <= 0:
                if self.dead or stream.error:
                    raise ConnectionError(stream.error or self.dead)
                await asyncio.wait_for(self.cond.wait(), STALL)
        waited = time.monotonic() - start
        stream.blocked += waited
        stream.max_block = max(stream.max_block, waited)
        stream.blocks += 1

    async def send(self, stream, n, source, end=False):
        if end and n == 0:
            self.writer.write(frame(0, 1, stream.sid))
        while n > 0:
            await self.credit(stream)
            k = min(n, self.conn_window, stream.window, self.max_frame)
            n -= k
            self.writer.write(frame(0, 1 if end and n == 0 else 0, stream.sid, source.take(k)))
            self.conn_window -= k
            stream.window -= k
            await self.writer.drain()

    def finish(self, stream):
        self.writer.write(frame(0, 1, stream.sid))

    async def result(self, stream, started):
        await asyncio.wait_for(stream.done.wait(), STALL * 3)
        elapsed = time.monotonic() - started
        if stream.error or not stream.status_ok:
            raise ConnectionError(stream.error or "bad status")
        sink = json.loads(bytes(stream.body))
        incs = [inc for _, inc in stream.updates]
        return {"seconds": round(elapsed, 3), "sink": sink, "stream_wu": len(incs),
                "conn_wu": len(self.conn_updates),
                "wu_avg_kb": round(sum(incs) / len(incs) / 1024, 1) if incs else 0,
                "client_blocked_s": round(stream.blocked, 3),
                "client_max_block_ms": round(stream.max_block * 1000, 1),
                "client_blocks": stream.blocks}

    def close(self):
        self.task.cancel()
        self.writer.close()


async def bulk(port, total=MB25, headers=()):
    conn = await Conn().open(port)
    stream = conn.request(headers)
    source = Source(16384 - 12)
    started = time.monotonic()
    await conn.send(stream, total, source, end=True)
    out = await conn.result(stream, started)
    out["mb_s"] = round(total / out["seconds"] / 1e6, 2)
    out["ok"] = out["sink"]["bytes"] == total and out["sink"]["leftover"] == 0
    conn.close()
    return out


async def interactive(port):
    conn = await Conn().open(port)
    big, small = conn.request(), conn.request()
    big_src, small_src = Source(16384 - 12), Source(64)
    started = time.monotonic()
    upload = asyncio.create_task(conn.send(big, MB25, big_src, end=True))
    while not upload.done():
        await conn.send(small, 76, small_src)
        await asyncio.sleep(0.02)
    await upload
    conn.finish(small)
    out_big = await conn.result(big, started)
    out_small = await conn.result(small, started)
    conn.close()
    return {"bulk_mb_s": round(MB25 / out_big["seconds"] / 1e6, 2), "bulk_wu": out_big["stream_wu"],
            "probe_ms": out_small["sink"]["small_ms"],
            "ok": out_big["sink"]["bytes"] == MB25 and out_small["sink"]["leftover"] == 0}


async def trickle(port):
    conn = await Conn().open(port)
    stream = conn.request()
    source = Source(100)
    started = time.monotonic()
    for i in range(400):
        await conn.send(stream, 112, source, end=i == 399)
        await asyncio.sleep(0.005)
    out = await conn.result(stream, started)
    conn.close()
    return {"small_ms": out["sink"]["small_ms"], "stream_wu": out["stream_wu"],
            "ok": out["sink"]["bytes"] == 400 * 112 and out["sink"]["leftover"] == 0}


async def pauses(port):
    """Bulk below the update threshold, then idle, then lone small records."""
    conn = await Conn().open(port)
    stream = conn.request()
    big = Source(16384 - 12)
    started = time.monotonic()
    await conn.send(stream, 200 * 16384, big)  # 3.2 MB: leaves an un-returned tail
    await asyncio.sleep(2)
    small = Source(100)
    await conn.send(stream, 112, small)
    await asyncio.sleep(2)
    await conn.send(stream, 112, small, end=True)
    out = await conn.result(stream, started)
    conn.close()
    return {"small_ms": out["sink"]["small_ms"], "stream_wu": out["stream_wu"],
            "client_blocked_s": out["client_blocked_s"],
            "ok": out["sink"]["bytes"] == 200 * 16384 + 224 and out["sink"]["leftover"] == 0}


async def exhaust(port):
    """Spend the whole stream credit exactly, then wait: an update must come."""
    conn = await Conn().open(port)
    stream = conn.request()
    source = Source(1000)
    started = time.monotonic()
    waits = []
    for _ in range(15):
        await conn.send(stream, stream.window, source)
        t0 = time.monotonic()
        try:
            await conn.credit(stream)
            waits.append(round((time.monotonic() - t0) * 1000, 1))
        except asyncio.TimeoutError:
            waits.append(None)
            break
    tail = len(source.pending)
    if tail:
        await conn.send(stream, tail, source)
    conn.finish(stream)
    out = await conn.result(stream, started)
    conn.close()
    ok = None not in waits and out["sink"]["leftover"] == 0 and out["sink"]["bytes"] == source.sent
    return {"wait_ms": waits, "ok": ok}


async def last_portion(port):
    """25 MB minus 1 byte, pause, last byte + END_STREAM; then data, pause, bare END_STREAM."""
    results = {}
    for mode in ("last_byte", "bare_end"):
        conn = await Conn().open(port)
        stream = conn.request()
        source = Source(16384 - 12)
        started = time.monotonic()
        if mode == "last_byte":
            await conn.send(stream, MB25 - 1, source)
            await asyncio.sleep(1)
            await conn.send(stream, 1, source, end=True)
        else:
            await conn.send(stream, MB25, source)
            await asyncio.sleep(1)
            conn.finish(stream)
        out = await conn.result(stream, started)
        conn.close()
        results[mode] = out["sink"]["bytes"] == MB25 and out["sink"]["leftover"] == 0
    return results


async def guarded(name, coro):
    try:
        return await asyncio.wait_for(coro, 300)
    except Exception as exc:  # a stall or protocol error is a result, not a crash
        return {"ok": False, "FAIL": "%s: %r" % (name, exc)}


async def suite():
    out = {}
    out["bulk_capped"] = [await guarded("bulk", bulk(WAN_CAPPED)) for _ in range(3)]
    out["bulk_free"] = [await guarded("bulk", bulk(WAN_FREE)) for _ in range(2)]
    out["slow_3mb"] = await guarded("slow", bulk(WAN_FREE, headers=[("x-slow-rate", "3000000")]))
    out["interactive"] = await guarded("interactive", interactive(WAN_CAPPED))
    out["trickle"] = await guarded("trickle", trickle(WAN_CAPPED))
    out["pauses"] = await guarded("pauses", pauses(WAN_CAPPED))
    out["exhaust"] = await guarded("exhaust", exhaust(WAN_CAPPED))
    out["last_portion"] = await guarded("last", last_portion(WAN_CAPPED))
    return out


def wait_port(port):
    for _ in range(100):
        with socket.socket() as s:
            if s.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.05)
    raise RuntimeError("port %d not up" % port)


def main():
    helpers = [subprocess.Popen([sys.executable, "-I", HERE + "/sink.py", str(SINK_PORT)]),
               subprocess.Popen([sys.executable, "-I", HERE + "/wan.py", str(WAN_CAPPED), str(NGINX_PORT),
                                 str(ONE_WAY_MS), str(CAP)]),
               subprocess.Popen([sys.executable, "-I", HERE + "/wan.py", str(WAN_FREE), str(NGINX_PORT),
                                 str(ONE_WAY_MS), "0"])]
    results = {}
    try:
        for port in (SINK_PORT, WAN_CAPPED, WAN_FREE):
            wait_port(port)
        for variant, buf in [(v, b) for b in sys.argv[1].split(",") for v in ("stock", "patched")]:
            prefix = "%s/run-%s-%s" % (HOME, variant, buf)
            os.makedirs(prefix + "/conf", exist_ok=True)
            os.makedirs(prefix + "/logs", exist_ok=True)
            with open(prefix + "/conf/nginx.conf", "w") as f:
                f.write(CONF.format(port=NGINX_PORT, sink=SINK_PORT, buf=buf))
            open(prefix + "/error.log", "w").close()
            nginx = subprocess.Popen([BINARIES[variant], "-p", prefix + "/", "-c", "conf/nginx.conf"])
            try:
                wait_port(NGINX_PORT)
                result = asyncio.run(suite())
            finally:
                nginx.terminate()
                nginx.wait(10)
            with open(prefix + "/error.log") as f:
                result["log_problems"] = [l.strip() for l in f
                                          if any(w in l for w in ("[alert]", "[crit]", "[error]", "[emerg]"))][:5]
            results["%s %s" % (variant, buf)] = result
            print("done", variant, buf, file=sys.stderr, flush=True)
    finally:
        for p in helpers:
            p.terminate()
    with open(sys.argv[2], "w") as f:
        json.dump(results, f, indent=1)


main()
