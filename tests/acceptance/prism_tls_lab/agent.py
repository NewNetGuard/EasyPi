"""Bounded opaque CONNECT relay for one controlled browser flow. No TLS decoder."""

import argparse
import getpass
import ipaddress
import json
from pathlib import Path
import re
import signal
import socket
import socketserver
import subprocess
import sys
import threading
import time


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--host", required=True)
    p.add_argument("--target-port", type=int, choices=(443, 8443), default=443)
    p.add_argument("--runtime", type=Path, required=True)
    p.add_argument("--seconds", type=int, default=90)
    p.add_argument("--forward-only", action="store_true")
    a = p.parse_args()
    if (
        not a.forward_only
        or not 1 <= a.seconds <= 180
        or not re.fullmatch("[a-z0-9][a-z0-9.-]*", a.host)
    ):
        p.error("bounded opaque relay required")
    target = next(
        v[4]
        for v in socket.getaddrinfo(
            a.host, a.target_port, socket.AF_INET, socket.SOCK_STREAM
        )
        if ipaddress.ip_address(v[4][0]).is_global
    )
    upstream = socket.socket()
    upstream.bind(("0.0.0.0", 0))
    source_port = upstream.getsockname()[1]
    claimed = threading.Lock()
    budget = threading.BoundedSemaphore(8)
    stop = threading.Event()

    class Relay(socketserver.BaseRequestHandler):
        def handle(self):
            if not budget.acquire(blocking=False):
                return
            self.request.settimeout(20)
            header = bytearray()
            connection = None
            try:
                while b"\r\n\r\n" not in header:
                    data = self.request.recv(1)
                    if not data or len(header) > 8192:
                        return
                    header.extend(data)
                if (
                    bytes(header).split(b"\r\n", 1)[0]
                    != (f"CONNECT {a.host}:{a.target_port} HTTP/1.1").encode()
                ):
                    self.request.sendall(
                        b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n"
                    )
                    return
                if claimed.acquire(blocking=False):
                    connection = upstream
                    connection.settimeout(20)
                    connection.connect(target)
                else:
                    connection = socket.create_connection(target, timeout=20)
                self.request.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                done = threading.Event()

                def copy(source, destination):
                    total = 0
                    try:
                        while not stop.is_set() and not done.is_set():
                            data = source.recv(32768)
                            if not data:
                                break
                            total += len(data)
                            if total > 32 * 1024 * 1024:
                                break
                            destination.sendall(data)
                    except OSError:
                        pass
                    finally:
                        done.set()
                        try:
                            destination.shutdown(socket.SHUT_WR)
                        except OSError:
                            pass

                reader = threading.Thread(
                    target=copy, args=(connection, self.request), daemon=True
                )
                reader.start()
                copy(self.request, connection)
                reader.join(timeout=2)
            except OSError:
                pass
            finally:
                if connection is not None:
                    connection.close()
                budget.release()

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True

    server = Server(("127.0.0.1", 0), Relay)
    port = server.server_address[1]
    capture = subprocess.Popen(
        [
            "sudo",
            "-n",
            "tcpdump",
            "-B",
            "4096",
            "-i",
            "lo",
            "-n",
            "-s",
            "0",
            "-U",
            "--immediate-mode",
            "-Z",
            getpass.getuser(),
            "-w",
            str(a.runtime / "capture.pcap"),
            "tcp",
            "port",
            str(port),
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    time.sleep(0.3)
    if capture.poll() is not None:
        raise RuntimeError("evidence capture failed")

    def control():
        while sys.stdin.buffer.read(1):
            pass
        stop.set()

    threading.Thread(target=control, daemon=True).start()
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(
        json.dumps(
            dict(
                type="ready",
                port=port,
                capture_client_port=source_port,
                capture_target=target[0],
                capture=True,
                legacy_decoders_enabled=False,
            )
        ),
        flush=True,
    )
    try:
        stop.wait(a.seconds)
    finally:
        stop.set()
        server.shutdown()
        server.server_close()
        upstream.close()
        time.sleep(0.15)
        capture.send_signal(signal.SIGINT)
        try:
            _, log = capture.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            capture.kill()
            _, log = capture.communicate()
        match = re.search(rb"(\d+) packets dropped by kernel", log)
        print(
            json.dumps(
                dict(
                    type="stopped",
                    legacy_decoders_enabled=False,
                    no_keys_requests=None,
                    capture_drops=int(match[1]) if match else None,
                )
            ),
            flush=True,
        )


if __name__ == "__main__":
    main()
