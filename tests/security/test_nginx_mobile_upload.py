"""Run the real templates against an isolated upstream; no host services used.

Set EASYPI_TEST_NGINX to a local nginx executable with auth_request and TLS.
The upstream is synthetic; token database/revocation is covered separately by
test_mobile_pairing_security.py. These tests exercise nginx's access/body order.
"""
from __future__ import annotations

import os
import re
import shutil
import socket
import ssl
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest

NGINX = os.environ.get("EASYPI_TEST_NGINX") or shutil.which("nginx")
pytestmark = pytest.mark.skipif(os.name != "posix" or not NGINX or not shutil.which("openssl"),
                                reason="requires local Linux nginx and openssl")
ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize("template", ["easypi.conf", "easypi-mobile-link.conf"])
def test_nginx_authenticates_before_upload_body(tmp_path, template):
    requests = []
    uploads = []
    active_tokens = {"Bearer paired-test-phone"}

    class Upstream(BaseHTTPRequestHandler):
        def log_message(self, *_args):
            pass

        def do_GET(self):
            requests.append((self.path, dict(self.headers)))
            assert self.path == "/api/v1/mobile/auth-check"
            assert not self.headers.get("Content-Length")
            assert not self.headers.get("Transfer-Encoding")
            accepted = self.headers.get("Authorization") in active_tokens
            self.send_response(204 if accepted else 401)
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_POST(self):
            uploads.append(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(201)
            self.send_header("Content-Length", "0")
            self.end_headers()

    upstream = ThreadingHTTPServer(("127.0.0.1", 0), Upstream)
    thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    thread.start()
    # Keep both sockets reserved until nginx is ready to bind distinct ports.
    reservations = [socket.socket(), socket.socket()]
    for reserved in reservations:
        reserved.bind(("127.0.0.1", 0))
    ports = [reserved.getsockname()[1] for reserved in reservations]
    port = ports[1]
    cert = tmp_path / "cert.pem"
    key = tmp_path / "key.pem"
    process = None
    try:
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=localhost", "-keyout", str(key), "-out", str(cert)],
                       check=True, capture_output=True)
        template_text = (ROOT / "templates/nginx" / template).read_text()
        template_text = re.sub(r"^\s*listen \[::\]:[^;]+;", "", template_text, flags=re.M)
        template_text = re.sub(r"listen 80;", f"listen 127.0.0.1:{ports[0]};", template_text)
        template_text = re.sub(r"listen (?:443|127\.0\.0\.1:9445) ssl;", f"listen 127.0.0.1:{port} ssl;", template_text)
        template_text = template_text.replace("/opt/EasyPi/certs/cert.pem", str(cert)).replace("/opt/EasyPi/certs/key.pem", str(key))
        template_text = template_text.replace("http://127.0.0.1:8000", f"http://127.0.0.1:{upstream.server_port}")
        config = tmp_path / "nginx.conf"
        config.write_text(
            ("user root;\n" if os.geteuid() == 0 else "")
            + f"pid {tmp_path}/nginx.pid;\nerror_log {tmp_path}/error.log;\n"
            + "events {}\nhttp {\naccess_log off;\n"
            + f"client_body_temp_path {tmp_path}/body;\nproxy_temp_path {tmp_path}/proxy;\n"
            + f"fastcgi_temp_path {tmp_path}/fastcgi;\nuwsgi_temp_path {tmp_path}/uwsgi;\nscgi_temp_path {tmp_path}/scgi;\n"
            + template_text + "\n}\n"
        )
        command = [str(NGINX), "-p", str(tmp_path), "-c", str(config)]
        validation = subprocess.run(command + ["-t"], capture_output=True, text=True)
        assert validation.returncode == 0, validation.stderr
        for reserved in reservations:
            reserved.close()
        process = subprocess.Popen(command + ["-g", "daemon off;"], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        deadline = time.monotonic() + 5
        while True:
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    break
            except OSError:
                if process.poll() is not None or time.monotonic() > deadline:
                    pytest.fail((tmp_path / "error.log").read_text())
                time.sleep(0.02)
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        def request(token=None, *, chunked=False, body=None, path="/api/v1/mobile/upload"):
            headers = [f"POST {path} HTTP/1.1", "Host: localhost", "Connection: close",
                       "Content-Type: multipart/form-data; boundary=test"]
            if token:
                headers.append(f"Authorization: {token}")
            headers.append("Transfer-Encoding: chunked" if chunked else f"Content-Length: {len(body) if body is not None else 4294968000}")
            if body is None:
                headers.append("Expect: 100-continue")
            with socket.create_connection(("127.0.0.1", port), timeout=3) as raw:
                with context.wrap_socket(raw, server_hostname="localhost") as tls:
                    tls.sendall(("\r\n".join(headers) + "\r\n\r\n").encode() + (body or b""))
                    response = b""
                    while b"\r\n\r\n" not in response:
                        chunk = tls.recv(4096)
                        if not chunk:
                            break
                        response += chunk
            return int(response.split(b" ", 2)[1])

        for token in (None, "Bearer invalid", "Bearer revoked-phone"):
            # Advertise >4 GiB but send zero body bytes. Rejection must precede
            # even 100 Continue, with no upload request reaching the upstream.
            assert request(token) == 401
            assert request(token, chunked=True) == 401
        assert len(requests) == 6
        assert uploads == []
        body = b'--test\r\nContent-Disposition: form-data; name="file"; filename="test.txt"\r\n\r\nhello\r\n--test--\r\n'
        assert request("Bearer paired-test-phone", body=body) == 201
        assert uploads == [body]
        active_tokens.clear()
        assert request("Bearer paired-test-phone") == 401
        assert uploads == [body]
        assert request(path="/_easypi_mobile_auth", body=b"") == 404
    finally:
        for reserved in reservations:
            reserved.close()
        if process is not None:
            process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
            if process.stderr:
                process.stderr.close()
        upstream.shutdown()
        upstream.server_close()
        thread.join(timeout=5)
