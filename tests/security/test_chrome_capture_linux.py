"""Explicitly enabled loopback-only capture lab; no phone/user traffic."""
import os
import socket
import sys
import threading
import time

import pytest

from prism_tls_bridge.models import Endpoint
from prism_tls_bridge.pcap_live import LiveCapture


pytestmark = pytest.mark.skipif(
    not sys.platform.startswith("linux") or os.environ.get("EASYPI_CAPTURE_LAB") != "1",
    reason="requires opt-in Linux loopback capture privileges",
)


@pytest.mark.parametrize("burst", [1, 128, 512])
def test_buffered_capture_survives_delayed_reader_burst(burst):
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sink, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sender:
        sink.bind(("127.0.0.1", 0))
        sender.bind(("127.0.0.1", 0))
        sink.settimeout(.05)
        cap = LiveCapture("lo", Endpoint(*sender.getsockname()), Endpoint(*sink.getsockname()), "quic", immediate_mode=False)
        stop = threading.Event()
        received = []

        def receive():
            while not stop.is_set():
                try:
                    received.append(int.from_bytes(sink.recv(2048)[:4], "big"))
                except socket.timeout:
                    pass

        thread = threading.Thread(target=receive)
        thread.start()
        captured = []
        try:
            for index in range(burst):
                sender.sendto(index.to_bytes(4, "big") + b"x" * 1196, sink.getsockname())
            # Reproduce a short scheduling / IPC / decoder interruption.
            time.sleep(.01)
            until = time.monotonic() + 1
            while time.monotonic() < until and len(captured) < burst:
                packet = cap.read()
                if packet is None:
                    time.sleep(.001)
                else:
                    captured.append(int.from_bytes(packet[28:32], "big"))
            assert cap.counters() == 0
            assert sorted(captured) == list(range(burst))
            assert sorted(received) == list(range(burst))
        finally:
            cap.close()
            stop.set()
            thread.join(1)
