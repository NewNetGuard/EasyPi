# Prepares the isolated load stand's files in <work-dir> (run as root in WSL).
# Server config and nginx config follow the deployment templates in
# backend/app/services/stealth_components/tls.py; differences are marked TEST.
# usage: prepare.py <work-dir> <nginx-binary> <mime.types> <devices>
import hashlib
import hmac
import json
import os
import secrets
import shutil
import subprocess
import sys
import uuid

W, NGINX, MIME, DEVICES = sys.argv[1], sys.argv[2], sys.argv[3], int(sys.argv[4])
os.makedirs(W + "/srv/site", exist_ok=True)
os.makedirs(W + "/srv/tls", exist_ok=True)
os.makedirs(W + "/ngx/conf", exist_ok=True)
os.makedirs(W + "/ngx/logs", exist_ok=True)
shutil.copy(NGINX, W + "/nginx")
shutil.copy(MIME, W + "/ngx/conf/mime.types")
with open(W + "/srv/site/index.html", "w") as f:
    f.write("<!doctype html><title>Site</title><p>Welcome.</p>\n")

# Certificate for the VPS IP (clients pin it, as with IP Shield).
subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
                "-nodes", "-days", "7", "-subj", "/CN=10.200.0.1",
                "-addext", "subjectAltName=IP:10.200.0.1",
                "-keyout", W + "/srv/tls/privkey.pem", "-out", W + "/srv/tls/fullchain.pem"],
               check=True, capture_output=True)
der = subprocess.run(["openssl", "x509", "-in", W + "/srv/tls/fullchain.pem", "-outform", "DER"],
                     check=True, capture_output=True).stdout
cert_sha = hashlib.sha256(der).hexdigest()
# A valid X25519 public value for the client's marker (nginx ignores it).
key = subprocess.run(["openssl", "genpkey", "-algorithm", "X25519"], check=True, capture_output=True).stdout
pub = subprocess.run(["openssl", "pkey", "-pubout", "-outform", "DER"], input=key,
                     check=True, capture_output=True).stdout[-32:].hex()

psk, auth = secrets.token_hex(32), secrets.token_hex(32)
ids = [str(uuid.uuid4()) for _ in range(DEVICES)]
registry = {"version": 1, "devices": [{"id": d, "address": "10.10.0.%d" % (3 + i)} for i, d in enumerate(ids)]}
json.dump(registry, open(W + "/srv/mobile_clients.json", "w"))
server_cfg = {  # deployment template (tls.py _server_config_json)
    "listen_port": 443, "bootstrap_port": 8443, "frontend_mode": "nginx",
    "backend_address": "127.0.0.1:9080", "psk_key": psk, "client_auth_key": auth,
    "mobile_clients_file": W + "/srv/mobile_clients.json", "reality_public_key": pub,
    "shield_preset": "ip", "shield_domain": "", "probe_mode": "local", "probe_target": "127.0.0.1:9443",
    "block_quic_udp443": False,
    "upstream_dns": "127.0.0.1:53",  # TEST: never reach a public resolver
    "log_level": "info", "tls_cert": W + "/srv/tls/fullchain.pem", "tls_key": W + "/srv/tls/privkey.pem",
    "domain": "10.200.0.1", "site_dir": "site",
    "max_connections": 100, "max_requests_per_session": 8, "max_sessions_per_source": 8,
    "max_pre_auth_connections": 256, "max_pre_auth_per_ip": 32,
}
json.dump(server_cfg, open(W + "/srv/server_config.json", "w"), indent=2)
json.dump({"psk_key": psk, "client_auth_key": auth, "reality_public_key": pub,
           "device_ids": ids, "cert_sha256": cert_sha}, open(W + "/keys.json", "w"))

digest = hmac.new(bytes.fromhex(psk), b"chameleon-route-prefix-v1", hashlib.sha256).digest()
alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
prefix = "".join(alphabet[int.from_bytes(digest[i:i + 2], "big") % len(alphabet)] for i in range(0, 16, 2))
S = W + "/srv"
conf = f"""# Ubuntu nginx.conf main context (debian/conf/nginx.conf) + the deployed
# Chameleon server block (tls.py _nginx_frontend_config). TEST differences:
# paths, listen address, worker_processes 1 (= auto on a 1-vCPU VPS),
# client_body_buffer_size 1m (patched nginx), error_log level, 404 through
# try_files instead of return (this build has no rewrite module).
user sb;
worker_processes 1;
pid {W}/ngx/nginx.pid;
error_log {W}/ngx/error.log;
events {{
    worker_connections 768;
}}
http {{
    sendfile on;
    tcp_nopush on;
    types_hash_max_size 2048;
    server_tokens build;
    include mime.types;
    default_type application/octet-stream;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers off;
    access_log off;

server {{
    listen 10.200.0.1:443 ssl default_server;
    http2 on;
    server_name _;
    server_tokens off;

    ssl_certificate {S}/tls/fullchain.pem;
    ssl_certificate_key {S}/tls/privkey.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_session_cache shared:CHAMELEON:10m;
    ssl_session_timeout 1d;

    access_log off;
    error_log {W}/ngx/chameleon-error.log error;
    root {S}/site;
    index index.html;
    client_max_body_size 0;
    keepalive_requests 1000000;

    location ^~ /{prefix}/ {{
        proxy_pass http://127.0.0.1:9080;
        proxy_http_version 1.1;
        proxy_request_buffering off;
        proxy_buffering off;
        proxy_buffer_size 16k;
        proxy_buffers 8 16k;
        proxy_cache off;
        proxy_socket_keepalive on;
        proxy_read_timeout 24h;
        proxy_send_timeout 24h;
        send_timeout 24h;
        client_body_timeout 24h;
        client_body_buffer_size 1m;
        proxy_set_header Host $http_host;
        proxy_set_header Connection "";
        proxy_set_header X-Real-IP "";
        proxy_set_header X-Forwarded-For "";
        proxy_set_header X-Forwarded-Proto "";
        proxy_hide_header Server;
        proxy_intercept_errors on;
        error_page 401 403 404 405 =404 @not_found;
    }}

    location @not_found {{
        try_files /.none =404;  # TEST: return 404 (no rewrite module in this build)
    }}

    location = / {{
        try_files /index.html =404;
    }}

    location / {{
        try_files /.none =404;  # TEST: return 404 (no rewrite module in this build)
    }}
}}
}}
"""
open(W + "/ngx/conf/nginx.conf", "w").write(conf)
subprocess.run(["chown", "-R", "sb:sb", W], check=True)
print("prepared", W, "devices", DEVICES, "route prefix", prefix)
