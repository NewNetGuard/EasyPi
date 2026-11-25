"""Private IPC adapter for authenticated Mobile API and passive packet copies."""
import argparse
import json
import os
from pathlib import Path
import signal
import socket
import threading

from .chrome import ChromeObserver, Rejected
from .models import Endpoint
from .pcap_live import LiveCapture

SOCKET = "/run/easypi-chrome-bridge/mobile.sock"


def capture_batch(observer, capture):
    """One bounded batch under the caller's lock; never output packet contents.

    Return whether the batch filled: callers then check the queue again without
    an obligatory 10-ms pause. Release the lock between batches for Mobile IPC.
    """
    drops = capture.counters()
    if drops:
        observer.counts["capture_dropped_packets"] += drops
    observer.loss(drops)
    count = 0
    for _ in range(64):
        packet = capture.read()
        if packet is None:
            break
        count += 1
        observer.counts["capture_packets_read"] += 1
        try:
            observer.packet(packet)
        except (ValueError, IndexError):
            observer.counts["unsupported_packet"] += 1
    observer.tick()
    full = count == 64
    if full:
        observer.counts["capture_full_batches"] += 1
    return full


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", type=Path, required=True)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    stat = args.config.stat()
    if stat.st_uid != 0 or stat.st_mode & 0o022:
        raise SystemExit("root-owned non-writable configuration required")
    cfg = json.loads(args.config.read_text())
    observer = ChromeObserver(cfg["device_id"], cfg["phone_ip"], cfg["destinations"],
                              diagnostics=cfg.get("request_category_diagnostics") is True)
    if args.check:
        observer.bridge.close()
        print('{"component":"chrome_bridge","configuration_valid":true,"default_enabled":false}')
        return
    capture = LiveCapture(cfg["interface"], Endpoint(observer.phone, 443),
                          Endpoint(next(iter(observer.destinations)), 443), "tcp",
                          device_destinations=observer.destinations,
                          immediate_mode=False)
    lock, stop = threading.RLock(), threading.Event()
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    signal.signal(signal.SIGINT, lambda *_: stop.set())

    def packets():
        try:
            full = False
            while not stop.wait(0 if full else .01):
                with lock:
                    full = capture_batch(observer, capture)
        except Exception:
            # Never log packet/parser exceptions, which can contain data.
            with lock:
                observer.reset("capture_failed")
            stop.set()

    path = Path(SOCKET)
    path.unlink(missing_ok=True)
    server = socket.socket(socket.AF_UNIX)
    server.bind(SOCKET)
    os.chmod(SOCKET, 0o660)
    server.listen(4)
    server.settimeout(.5)
    thread = threading.Thread(target=packets, daemon=True)
    thread.start()
    try:
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except socket.timeout:
                continue
            with conn:
                conn.settimeout(2)
                try:
                    raw = bytearray()
                    while b"\n" not in raw and len(raw) <= 12000:
                        chunk = conn.recv(min(4096, 12001-len(raw)))
                        if not chunk:
                            raise Rejected("incomplete_request")
                        raw.extend(chunk)
                    if len(raw) > 12000 or not raw.endswith(b"\n"):
                        raise Rejected("request_limit")
                    body = json.loads(raw)
                    with lock:
                        device = body.get("device")
                        if body.get("op") == "lease":
                            result = observer.lease_for(device)
                        elif body.get("op") == "keys":
                            result = observer.upload(device, body.get("lease"), body.get("sequence"), body.get("lines"))
                        elif body.get("op") == "status":
                            result = observer.status(device)
                        elif body.get("op") == "disable":
                            observer.authorized(device)
                            observer.reset("device_disabled")
                            result = dict(disabled=True)
                        else:
                            raise Rejected("invalid_operation")
                    response = dict(ok=True, result=result)
                except Exception:
                    response = dict(ok=False, error="chrome_bridge_request_rejected")
                try:
                    conn.sendall(json.dumps(response, separators=(",", ":")).encode()+b"\n")
                except OSError:
                    pass
    finally:
        stop.set()
        thread.join(3)
        server.close()
        capture.close()
        observer.reset("service_stopped")
        path.unlink(missing_ok=True)


if __name__ == "__main__":
    main()
