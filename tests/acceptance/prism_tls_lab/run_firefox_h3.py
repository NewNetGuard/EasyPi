"""Opt-in Firefox -> Pi -> public UDP/443 QUIC experiment, with no TLS termination."""

import argparse
import http.server
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import selectors
import shlex
import socket
import subprocess
import sys
import threading
import time
import uuid
from marionette_probe import MarionetteProbe
from worker_probe import WorkerProbe, validate_worker_report
from pcap_evidence import inspect_udp_capture

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


class UDPForwarder:
    def __init__(self, target, cookie):
        self.local = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        if os.name == "nt":
            self.local.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        try:
            self.local.bind(("127.0.0.1", 443))
        except OSError:
            self.local.bind(("127.0.0.1", 0))
        self.port = self.local.getsockname()[1]
        self.network = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.network.connect(target)
        self.cookie = cookie
        self.ready = threading.Event()
        self.stop = threading.Event()
        self.peer = None
        self.packets = {"client": 0, "server": 0}
        self.error = None
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self):
        self.thread.start()

    def run(self):
        selector = selectors.DefaultSelector()
        selector.register(self.local, selectors.EVENT_READ, "client")
        selector.register(self.network, selectors.EVENT_READ, "server")
        total = 0
        try:
            while not self.stop.is_set():
                for selected, _ in selector.select(0.1):
                    if selected.data == "client":
                        data, address = self.local.recvfrom(65535)
                        if (
                            address[0] != "127.0.0.1"
                            or self.peer is not None
                            and address != self.peer
                        ):
                            continue
                        self.peer = address
                        self.network.send(data)
                        self.packets["client"] += 1
                    else:
                        data = self.network.recv(65535)
                        if data == b"PRISM-UDP-PROBE:" + self.cookie:
                            self.network.send(b"PRISM-UDP-ACK:" + self.cookie)
                            self.ready.set()
                            continue
                        if self.peer is not None:
                            self.local.sendto(data, self.peer)
                        self.packets["server"] += 1
                    total += len(data)
                    if total > 16 * 1024 * 1024 or sum(self.packets.values()) > 16384:
                        raise RuntimeError("UDP budget")
        except OSError as error:
            self.error = type(error).__name__
        finally:
            selector.close()

    def prime(self):
        self.network.send(b"PRISM-UDP-PRIME:" + self.cookie)

    def close(self):
        self.stop.set()
        self.thread.join(timeout=2)
        self.local.close()
        self.network.close()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--ssh", required=True)
    parser.add_argument("--pi-python", default="/opt/EasyPi/backend/.venv/bin/python")
    parser.add_argument(
        "--firefox", default=r"C:\Program Files\Mozilla Firefox\firefox.exe"
    )
    parser.add_argument("--worker", action="store_true")
    parser.add_argument(
        "--fault",
        choices=("none", "no-keys", "wrong-keys", "drop", "overflow", "exit"),
        default="none",
    )
    parser.add_argument(
        "--browser", choices=("firefox", "chrome", "edge"), default="firefox"
    )
    args = parser.parse_args()
    if not args.worker:
        parser.error("this target fixture requires the installed Shadow service")
    if args.fault != "none" and not args.worker:
        parser.error("fault requires isolated worker")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@:-]*", args.ssh):
        parser.error("invalid SSH destination")
    if not Path(args.firefox).is_file():
        parser.error("Firefox not found")
    nonce = os.environ.get("PRISM_TEST_RUN_ID") or uuid.uuid4().hex
    runtime = ROOT / ".build/tls-endpoint-bridge" / ("firefox-h3-" + nonce)
    runtime.mkdir(parents=True)
    if os.name == "nt":
        identity = os.environ["USERDOMAIN"] + "\\" + os.environ["USERNAME"]
        subprocess.run(
            [
                "icacls",
                str(runtime),
                "/inheritance:r",
                "/grant:r",
                identity + ":(OI)(CI)F",
                "SYSTEM:(OI)(CI)F",
            ],
            check=True,
            stdout=subprocess.DEVNULL,
        )
    ssh = [
        "ssh",
        "-o",
        "BatchMode=yes",
        "-o",
        "StrictHostKeyChecking=yes",
        "-o",
        "ConnectTimeout=5",
        "-o",
        "ServerAliveInterval=5",
        "-o",
        "ServerAliveCountMax=2",
    ]

    def remote(command, **kwargs):
        # One-shot commands never consume enrollment/key stream stdin.
        kwargs.setdefault("timeout", 20)
        print("bounded SSH command started", file=sys.stderr, flush=True)
        result = subprocess.run(ssh + ["-n", args.ssh, command], check=True, **kwargs)
        print("bounded SSH command completed", file=sys.stderr, flush=True)
        return result

    bootstrap = "import os,json; s=os.environ['SSH_CONNECTION'].split(); print(json.dumps({'client':s[0],'server':s[2]}))"
    addresses = json.loads(
        remote(
            "python3 -c " + shlex.quote(bootstrap), capture_output=True, text=True
        ).stdout
    )
    if not all(ipaddress.ip_address(v).is_private for v in addresses.values()):
        raise RuntimeError("private direct test path required")
    directory = remote(
        "umask 077; mktemp -d /tmp/prism-firefox-h3-XXXXXXXX",
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not re.fullmatch(r"/tmp/prism-firefox-h3-[A-Za-z0-9]{8}", directory):
        raise RuntimeError("unexpected run directory")
    log = (runtime / "process-errors.log").open("w", encoding="utf-8")
    ready, stop_keys = threading.Event(), threading.Event()
    events, sent = [], [0]
    agent = browser = event_thread = key_thread = forwarder = automation = None
    summary = {
        "firefox_http3": "failed",
        "browser": args.browser,
        "run_id": nonce,
        "target_host": "www.cloudflare.com",
        "target_udp_port": 443,
        "path": "Firefox -> loopback UDP relay -> Pi UDP/443 relay -> public UDP/443 server",
        "prototype_tls_termination": False,
        "production_modified": False,
    }
    failure = None
    control = None
    worker = None
    try:
        subprocess.run(
            [
                "scp",
                "-q",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                str(HERE / "udp_agent.py"),
                args.ssh + ":" + directory + "/",
            ],
            check=True,
        )
        cookie = secrets.token_bytes(32)
        forwarder = UDPForwarder((addresses["server"], 443), cookie)
        forwarder.start()
        command = (
            "exec sudo -n python3 -I -S -B "
            + shlex.quote(directory + "/udp_agent.py")
            + " --runtime "
            + shlex.quote(directory)
            + " --listen-ip "
            + shlex.quote(addresses["server"])
            + " --client-ip "
            + shlex.quote(addresses["client"])
            + " --client-port "
            + str(forwarder.network.getsockname()[1])
            + " --probe-cookie "
            + cookie.hex()
        )
        if args.worker:
            command += " --forward-only"
        agent = subprocess.Popen(
            ssh + [args.ssh, command],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=log,
            text=True,
            bufsize=1,
        )

        def read_events():
            with (runtime / "events.jsonl").open("w", encoding="utf-8") as output:
                for line in agent.stdout:
                    try:
                        event = json.loads(line)
                    except ValueError:
                        continue
                    events.append(event)
                    output.write(json.dumps(event) + "\n")
                    output.flush()
                    if event.get("type") == "ready":
                        ready.set()

        event_thread = threading.Thread(target=read_events, daemon=True)
        event_thread.start()
        if not ready.wait(12):
            raise RuntimeError("Pi UDP/443 relay did not start")
        forwarder.prime()
        if not forwarder.ready.wait(5):
            raise RuntimeError("bidirectional UDP startup probe did not complete")
        summary["udp_path_initiation"] = (
            "bidirectional startup probes; no firewall changes"
        )
        if args.worker:
            relay_ready = next(e for e in events if e.get("type") == "ready")
            worker = WorkerProbe(
                ssh + [args.ssh],
                directory,
                args.pi_python,
                nonce,
                "quic",
                "www.cloudflare.com",
                443,
                log,
                runtime,
                args.fault,
                dict(
                    client_port=relay_ready["capture_client_port"],
                    target_address=relay_ready["capture_target"],
                ),
            )
        keys = runtime / "session.keys"

        def send_keys():
            position, partial = 0, ""
            while not stop_keys.wait(0.05):
                if not keys.exists():
                    continue
                with keys.open(encoding="ascii", errors="ignore") as source:
                    source.seek(position)
                    data = source.read(65536)
                    position = source.tell()
                partial += data
                lines = partial.split("\n")
                partial = lines.pop()
                try:
                    for line in lines:
                        parts = line.split()
                        if len(parts) == 3 and parts[0] in {
                            "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                            "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                            "CLIENT_TRAFFIC_SECRET_0",
                            "SERVER_TRAFFIC_SECRET_0",
                        }:
                            if worker:
                                worker.send_key(line.strip())
                            else:
                                agent.stdin.write(line.strip() + "\n")
                            sent[0] += 1
                    agent.stdin.flush()
                except (OSError, ValueError):
                    break

        key_thread = threading.Thread(target=send_keys, daemon=True)
        key_thread.start()
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            control_port = reserved.getsockname()[1]
        profile = runtime / "firefox-profile"
        profile.mkdir()
        prefs = {
            "network.proxy.type": 0,
            "network.trr.mode": 5,
            "network.dns.forceResolve": "127.0.0.1",
            "network.dns.disableIPv6": True,
            "network.http.http3.enable": True,
            "network.http.http3.enable_0rtt": False,
            "network.http.http3.alt-svc-mapping-for-testing": 'www.cloudflare.com;h3=":'
            + str(forwarder.port)
            + '"',
            "network.http.http3.force-use-alt-svc-mapping-for-testing": True,
            "network.http.http3.backup_timer_delay": 60000,
            "security.tls.version.min": 4,
            "security.tls.version.max": 4,
            "security.tls.enable_0rtt_data": False,
            "marionette.port": control_port,
            "browser.chrome.site_icons": False,
            "browser.chrome.favicons": False,
            "browser.shell.checkDefaultBrowser": False,
            "browser.aboutwelcome.enabled": False,
            "browser.startup.homepage_override.mstone": "ignore",
            "browser.startup.page": 0,
            "toolkit.telemetry.enabled": False,
            "datareporting.healthreport.uploadEnabled": False,
            "network.captive-portal-service.enabled": False,
            "network.connectivity-service.enabled": False,
            "network.prefetch-next": False,
            "network.dns.disablePrefetch": True,
        }
        (profile / "user.js").write_text(
            "\n".join(
                "user_pref(" + json.dumps(k) + ", " + json.dumps(v) + ");"
                for k, v in prefs.items()
            ),
            encoding="utf-8",
        )
        env = os.environ.copy()
        env.update(
            SSLKEYLOGFILE=str(keys),
            MOZ_HEADLESS="1",
            MOZ_AUTOMATION="1",
            MOZ_REMOTE_ALLOW_SYSTEM_ACCESS="1",
        )
        if args.browser != "firefox":
            if forwarder.port != 443:
                raise RuntimeError(
                    "Chromium QUIC test requires a free loopback UDP 443"
                )
            urls = [
                "https://www.cloudflare.com/cdn-cgi/trace?prism_probe="
                + nonce
                + "-"
                + str(i)
                for i in range(4)
            ]
            responses = []
            response_ready = threading.Event()

            class Control(http.server.BaseHTTPRequestHandler):
                def log_message(self, *unused):
                    pass

                def do_GET(self):
                    if self.path != "/" + nonce:
                        self.send_error(404)
                        return
                    page = (
                        "<!doctype html><script>const urls="
                        + json.dumps(urls)
                        + "; const one=async u=>{const t0=performance.now();const r=await fetch(u,{credentials:'omit',cache:'no-store'});const t=await r.text();return {status:r.status,serverProtocol:(t.match(/^http=(.*)$/m)||[])[1],browserProtocol:performance.getEntriesByName(u).slice(-1)[0]?.nextHopProtocol,elapsed_ms:performance.now()-t0}}; (async()=>[await one(urls[0]),...await Promise.all(urls.slice(1).map(one))])().then(r=>fetch('/done/"
                        + nonce
                        + "',{method:'POST',body:JSON.stringify(r)})).catch(e=>fetch('/done/"
                        + nonce
                        + "',{method:'POST',body:JSON.stringify({error:e.name})}));</script>"
                    ).encode()
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.send_header("Content-Length", str(len(page)))
                    self.end_headers()
                    self.wfile.write(page)

                def do_POST(self):
                    if self.path != "/done/" + nonce:
                        self.send_error(404)
                        return
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 0 < length <= 4096:
                        self.send_error(413)
                        return
                    value = json.loads(self.rfile.read(length))
                    responses.extend(value if isinstance(value, list) else [value])
                    response_ready.set()
                    self.send_response(204)
                    self.end_headers()

            control = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Control)
            threading.Thread(target=control.serve_forever, daemon=True).start()
            executable = (
                Path(os.environ["PROGRAMFILES"])
                / "Google/Chrome/Application/chrome.exe"
                if args.browser == "chrome"
                else Path(os.environ["PROGRAMFILES(X86)"])
                / "Microsoft/Edge/Application/msedge.exe"
            )
            browser = subprocess.Popen(
                [
                    str(executable),
                    "--headless=new",
                    "--no-first-run",
                    "--no-default-browser-check",
                    "--disable-background-networking",
                    "--disable-component-update",
                    "--disable-sync",
                    "--disable-default-apps",
                    "--enable-quic",
                    "--origin-to-force-quic-on=www.cloudflare.com:443",
                    "--host-resolver-rules=MAP www.cloudflare.com 127.0.0.1,EXCLUDE localhost",
                    "--user-data-dir=" + str(profile),
                    "--ssl-key-log-file=" + str(keys),
                    "http://127.0.0.1:" + str(control.server_address[1]) + "/" + nonce,
                ],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=log,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            if not response_ready.wait(35):
                raise RuntimeError("managed Chromium HTTP3 requests did not finish")
            results = responses
            certificate = {"available": False, "reason": "not_exported_by_this_control"}
        else:
            browser = subprocess.Popen(
                [
                    args.firefox,
                    "-headless",
                    "-wait-for-browser",
                    "-no-remote",
                    "-new-instance",
                    "-profile",
                    str(profile),
                    "-marionette",
                    "about:blank",
                ],
                env=env,
                stdout=subprocess.DEVNULL,
                stderr=log,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            automation = MarionetteProbe(control_port)
            automation.socket.settimeout(22)
            automation.command(
                "WebDriver:NewSession",
                {"capabilities": {"alwaysMatch": {"acceptInsecureCerts": False}}},
            )
            automation.command(
                "WebDriver:SetTimeouts", {"pageLoad": 15000, "script": 15000}
            )
            urls = [
                "https://www.cloudflare.com/cdn-cgi/trace?prism_probe="
                + nonce
                + "-"
                + str(i)
                for i in range(4)
            ]
            automation.command("WebDriver:Navigate", {"url": urls[0]})
            first = automation.command(
                "WebDriver:ExecuteScript",
                {
                    "script": "const t=document.body.innerText; return {status:performance.getEntriesByType('navigation')[0].responseStatus,serverProtocol:(t.match(/^http=(.*)$/m)||[])[1],browserProtocol:performance.getEntriesByType('navigation')[0].nextHopProtocol};",
                    "args": [],
                    "newSandbox": True,
                },
            ).get("value")
            certificate = automation.current_certificate()
            automation.command("Marionette:SetContext", {"value": "content"})
            script = (
                "const done=arguments[arguments.length-1]; Promise.all("
                + json.dumps(urls[1:])
                + ".map(async u=>{const r=await fetch(u,{credentials:'omit',cache:'no-store'});const t=await r.text();return {status:r.status,serverProtocol:(t.match(/^http=(.*)$/m)||[])[1],browserProtocol:performance.getEntriesByName(u).slice(-1)[0].nextHopProtocol}})).then(done).catch(e=>done({error:e.name}));"
            )
            remaining = automation.command(
                "WebDriver:ExecuteAsyncScript",
                {"script": script, "args": [], "newSandbox": True},
            ).get("value")
            results = [first] + remaining
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            decoded = (
                worker.decoded("/cdn-cgi/trace")
                if worker
                else [
                    e
                    for e in events
                    if e.get("type") == "http_request" and nonce in e.get("path", "")
                ]
            )
            if len({e["diagnostic_id"] for e in decoded}) == 4:
                break
            time.sleep(0.05)
        summary.update(
            browser_results=results,
            firefox_certificate=certificate,
            keys_sent=sent[0],
            decoded_requests=len(decoded),
            external_tls_interception="local_filter_certificate_observed"
            if certificate.get("issuer") == "ESET SSL Filter CA"
            else "not_identified_by_certificate_issuer",
            diagnostic_event_ids=sorted({e["diagnostic_id"] for e in decoded}),
            key_correlations=[
                e for e in events if e.get("type") == "quic_key_correlation"
            ],
            analysis_errors=[
                e for e in events if e.get("type") == "quic_analysis_unavailable"
            ],
        )
        expected = 0 if args.fault != "none" else 4
        success = (
            len({e["diagnostic_id"] for e in decoded}) == expected
            and len(results) == 4
            and all(
                (args.browser != "firefox" or r.get("browserProtocol") == "h3")
                and r.get("serverProtocol") == "http/3"
                and r.get("status") == 200
                for r in results
            )
        )
        summary["firefox_http3"] = "passed" if success else "failed"
    except Exception as error:
        failure = type(error).__name__ + ": " + str(error)[:240]
        summary["error"] = failure
    finally:
        if control:
            control.shutdown()
            control.server_close()
        if automation:
            try:
                automation.close()
            except OSError:
                pass
        if browser and browser.poll() is None:
            if os.name == "nt":
                subprocess.run(
                    ["taskkill", "/PID", str(browser.pid), "/T", "/F"],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
            else:
                browser.terminate()
            try:
                browser.wait(timeout=5)
            except subprocess.TimeoutExpired:
                browser.kill()
        if forwarder:
            forwarder.close()
            summary["windows_relay_packets"] = forwarder.packets
            summary["windows_relay_error"] = forwarder.error
        stop_keys.set()
        if key_thread:
            key_thread.join(timeout=2)
        if worker:
            summary["worker_report"] = worker.close()
            summary["decoder_path"] = "target_systemd_shadow_candidate"
            summary["injected_fault"] = args.fault
            summary["worker_validation_passed"] = validate_worker_report(
                summary["worker_report"], args.fault
            )
            if not summary["worker_validation_passed"]:
                summary["firefox_http3"] = "failed"
        if agent:
            try:
                agent.stdin.close()
                agent.wait(timeout=6)
            except (OSError, subprocess.TimeoutExpired):
                agent.terminate()
        if event_thread:
            event_thread.join(timeout=2)
        stops = [e for e in events if e.get("type") == "stopped"]
        if stops:
            summary["pi_relay"] = stops[-1]
        try:
            subprocess.run(
                [
                    "scp",
                    "-q",
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "StrictHostKeyChecking=yes",
                    args.ssh + ":" + directory + "/firefox-quic.pcap",
                    str(runtime / "firefox-quic.pcap"),
                ],
                check=True,
                stdout=log,
                stderr=log,
            )
        except subprocess.CalledProcessError:
            summary["capture_downloaded"] = False
        if (runtime / "firefox-quic.pcap").exists():
            try:
                summary["capture_evidence"] = inspect_udp_capture(
                    runtime / "firefox-quic.pcap",
                    addresses["server"],
                    addresses["client"],
                )
            except Exception as error:
                summary["capture_evidence_error"] = type(error).__name__
        pi = summary.get("pi_relay", {})
        evidence = summary.get("capture_evidence", {})
        if summary["firefox_http3"] == "passed" and not (
            (
                args.worker
                or (
                    pi.get("no_keys_requests") == 0
                    and pi.get("wrong_keys_requests") == 0
                    and pi.get("authenticated_packets", 0) >= 4
                    and not pi.get("analysis_failed", True)
                )
            )
            and pi.get("capture_drops") == 0
            and not summary.get("analysis_errors")
            and evidence.get("client_payloads_preserved")
            and evidence.get("server_payloads_preserved")
            and evidence.get("fragment_packets") == 0
        ):
            summary["firefox_http3"] = "failed"
            summary["evidence_check_failed"] = True
        cleanup = (
            "import pathlib,shutil; p=pathlib.Path("
            + repr(directory)
            + "); assert p.parent==pathlib.Path('/tmp') and p.name.startswith('prism-firefox-h3-'); shutil.rmtree(p)"
        )
        try:
            remote("python3 -c " + shlex.quote(cleanup), stdout=log, stderr=log)
        finally:
            (runtime / "session.keys").unlink(missing_ok=True)
            log.close()
            summary["local_keylog_deleted"] = not (runtime / "session.keys").exists()
            (runtime / "summary.json").write_text(
                json.dumps(summary, indent=2), encoding="utf-8"
            )
            print(json.dumps(summary, indent=2))
    if summary["firefox_http3"] != "passed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
