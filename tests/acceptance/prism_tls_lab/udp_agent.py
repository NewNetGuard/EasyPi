"""Temporary, source-restricted UDP/443 relay; privilege is dropped before decoding."""

import argparse
import ipaddress
import json
import os
from pathlib import Path
import pwd
import re
import selectors
import signal
import socket
import subprocess
import sys
import threading
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--listen-ip", required=True)
    parser.add_argument("--client-ip", required=True)
    parser.add_argument("--client-port", type=int, required=True)
    parser.add_argument("--probe-cookie", required=True)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument(
        "--host", default="www.cloudflare.com", choices=("www.cloudflare.com",)
    )
    parser.add_argument("--seconds", type=int, default=90)
    parser.add_argument("--forward-only", action="store_true")
    args = parser.parse_args()
    if not args.forward_only:
        parser.error("opaque forwarding only")
    if (
        not ipaddress.ip_address(args.listen_ip).is_private
        or not ipaddress.ip_address(args.client_ip).is_private
    ):
        parser.error("private test addresses are required")
    if not 1 <= args.client_port <= 65535 or not re.fullmatch(
        r"[0-9a-f]{64}", args.probe_cookie
    ):
        parser.error("invalid startup probe")
    if not 1 <= args.seconds <= 120:
        parser.error("invalid duration")
    # -I -S at startup prevents user site hooks while binding the privileged port.
    username = (
        os.environ.get("SUDO_USER")
        if os.geteuid() == 0
        else pwd.getpwuid(os.getuid()).pw_name
    )
    account = pwd.getpwnam(username)
    if account.pw_uid == 0:
        raise RuntimeError("a non-root experiment owner is required")
    ingress = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    ingress.bind((args.listen_ip, 443))
    if os.geteuid() == 0:
        os.initgroups(account.pw_name, account.pw_gid)
        os.setgid(account.pw_gid)
        os.setuid(account.pw_uid)
    if os.geteuid() == 0:
        raise RuntimeError("privilege drop failed")
    os.umask(0o077)
    sys.path[:0] = [str(Path(__file__).resolve().parent), str(args.runtime / "deps")]
    stop = threading.Event()
    lock = threading.Lock()

    def emit(value):
        with lock:
            print(json.dumps(value), flush=True)

    target = next(
        (
            entry[4]
            for entry in socket.getaddrinfo(
                args.host, 443, socket.AF_INET, socket.SOCK_DGRAM
            )
            if ipaddress.ip_address(entry[4][0]).is_global
        ),
        None,
    )
    if target is None:
        raise RuntimeError("no public test target")
    upstream = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    upstream.connect(target)
    source_port = upstream.getsockname()[1]
    capture_filter = (
        "udp and ((host "
        + args.client_ip
        + " and port 443) or (host "
        + target[0]
        + " and port "
        + str(source_port)
        + "))"
    )
    capture = subprocess.Popen(
        [
            "sudo",
            "-n",
            "tcpdump",
            "-B",
            "4096",
            "-i",
            "any",
            "-n",
            "-s",
            "0",
            "-U",
            "--immediate-mode",
            "-Z",
            account.pw_name,
            "-w",
            str(args.runtime / "firefox-quic.pcap"),
            capture_filter,
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.PIPE,
    )
    time.sleep(0.4)
    if capture.poll() is not None:
        raise RuntimeError("scoped UDP capture failed")

    def read_keys():
        try:
            for _ in range(4096):
                line = sys.stdin.buffer.readline(1025)
                if not line or len(line) > 1024:
                    break
                # This relay receives no secrets; input is a lifetime channel.
                if line.strip():
                    raise RuntimeError("opaque relay refuses payload input")
        finally:
            stop.set()

    threading.Thread(target=read_keys, daemon=True).start()
    selector = selectors.DefaultSelector()
    selector.register(ingress, selectors.EVENT_READ, "client")
    selector.register(upstream, selectors.EVENT_READ, "server")
    peer, packets, bytes_seen = None, {"client": 0, "server": 0}, 0
    emit(
        {
            "capture_client_port": source_port,
            "capture_target": target[0],
            "type": "ready",
            "transport": "UDP",
            "listen_port": 443,
            "upstream_port": 443,
            "privileges_dropped": True,
        }
    )
    cookie = bytes.fromhex(args.probe_cookie)
    probe_peer = (args.client_ip, args.client_port)
    path_ready, next_probe = False, 0.0
    deadline = time.monotonic() + args.seconds
    try:
        while not stop.is_set() and time.monotonic() < deadline:
            if not path_ready and time.monotonic() >= next_probe:
                ingress.sendto(b"PRISM-UDP-PROBE:" + cookie, probe_peer)
                next_probe = time.monotonic() + 0.25
            for selected, _ in selector.select(0.05):
                if selected.data == "client":
                    data, address = ingress.recvfrom(65535)
                    if address != probe_peer or peer is not None and address != peer:
                        continue
                    if data == b"PRISM-UDP-ACK:" + cookie:
                        if not path_ready:
                            emit(
                                {
                                    "type": "udp_path_ready",
                                    "initiation": "bidirectional startup probes; existing conntrack policy",
                                }
                            )
                        path_ready = True
                        continue
                    if not path_ready:
                        continue
                    if peer is None:
                        if len(data) < 1200 or data[0] & 192 != 192:
                            continue
                        peer = address
                    upstream.send(data)
                    packets["client"] += 1
                    bytes_seen += len(data)

                else:
                    data = upstream.recv(65535)
                    if peer is not None:
                        ingress.sendto(data, peer)
                        packets["server"] += 1
                        bytes_seen += len(data)

                if bytes_seen > 16 * 1024 * 1024 or sum(packets.values()) > 16384:
                    raise RuntimeError("experiment byte budget")

    finally:
        selector.close()
        ingress.close()
        upstream.close()
        time.sleep(0.15)
        capture.send_signal(signal.SIGINT)
        try:
            _, log = capture.communicate(timeout=3)
        except subprocess.TimeoutExpired:
            capture.kill()
            _, log = capture.communicate()
        captured = re.search(rb"(\d+) packets captured", log)
        received = re.search(rb"(\d+) packets received by filter", log)
        dropped = re.search(rb"(\d+) packets dropped by kernel", log)
        emit(
            dict(
                type="stopped",
                packets=packets,
                legacy_decoders_enabled=False,
                authenticated_packets=None,
                no_keys_requests=None,
                wrong_keys_requests=None,
                key_entries=0,
                capture_drops=int(dropped[1]) if dropped else None,
                analysis_failed=None,
                capture_packets=int(captured[1]) if captured else None,
                capture_received=int(received[1]) if received else None,
            )
        )


if __name__ == "__main__":
    main()
