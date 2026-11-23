# WAN emulator between the bench client and nginx: fixed one-way delay in both
# directions, optional rate cap on the client -> nginx direction, bounded queue
# (so the sender feels backpressure like on a real path).
# usage: wan.py listen_port upstream_port one_way_ms up_rate_bytes_per_s
import asyncio
import sys
import time

LISTEN, UPSTREAM = int(sys.argv[1]), int(sys.argv[2])
DELAY = float(sys.argv[3]) / 1000
RATE = float(sys.argv[4])
QUEUE_LIMIT = 1 << 20
SLICE = 16384


async def pipe(src, dst, rate):
    queue = asyncio.Queue()
    queued = 0
    room = asyncio.Event()
    room.set()

    async def read():
        nonlocal queued
        while True:
            data = await src.read(65536)
            if not data:
                await queue.put(None)
                return
            for i in range(0, len(data), SLICE):
                await room.wait()
                piece = data[i:i + SLICE]
                queued += len(piece)
                if queued > QUEUE_LIMIT:
                    room.clear()
                await queue.put((time.monotonic() + DELAY, piece))

    async def write():
        nonlocal queued
        free_at = 0.0
        while True:
            item = await queue.get()
            if item is None:
                if dst.can_write_eof():
                    dst.write_eof()
                return
            due, piece = item
            at = max(due, free_at)
            wait = at - time.monotonic()
            if wait > 0:
                await asyncio.sleep(wait)
            dst.write(piece)
            await dst.drain()
            queued -= len(piece)
            if queued <= QUEUE_LIMIT:
                room.set()
            if rate:
                free_at = at + len(piece) / rate

    try:
        await asyncio.gather(read(), write())
    except (ConnectionError, asyncio.IncompleteReadError):
        pass


async def handle(client_reader, client_writer):
    try:
        up_reader, up_writer = await asyncio.open_connection("127.0.0.1", UPSTREAM)
    except OSError:
        client_writer.close()
        return
    await asyncio.gather(pipe(client_reader, up_writer, RATE),
                         pipe(up_reader, client_writer, 0),
                         return_exceptions=True)
    up_writer.close()
    client_writer.close()


async def main():
    server = await asyncio.start_server(handle, "127.0.0.1", LISTEN)
    async with server:
        await server.serve_forever()


asyncio.run(main())
