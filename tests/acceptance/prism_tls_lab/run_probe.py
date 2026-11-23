"""Run a scoped Firefox -> SSH relay -> TLS server experiment on a Pi."""

import argparse
import http.server
import json
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import sys
import threading
import time
import uuid

from marionette_probe import MarionetteProbe
from worker_probe import WorkerProbe, validate_worker_report

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--ssh", required=True, help="Existing trusted OpenSSH destination"
    )
    parser.add_argument("--host", default="www.cloudflare.com")
    parser.add_argument("--target-port", type=int, choices=(443, 8443), default=8443)
    parser.add_argument("--path", default="/cdn-cgi/trace")
    parser.add_argument("--client", choices=("firefox", "python"), default="firefox")
    parser.add_argument(
        "--observe-certificate",
        action="store_true",
        help="Opt-in metadata probe in this temporary Firefox only",
    )
    parser.add_argument("--pi-python", default="/opt/EasyPi/backend/.venv/bin/python")
    parser.add_argument(
        "--firefox", default=r"C:\Program Files\Mozilla Firefox\firefox.exe"
    )
    parser.add_argument("--worker", action="store_true")
    parser.add_argument(
        "--fault",
        choices=(
            "none",
            "no-keys",
            "wrong-keys",
            "drop",
            "overflow",
            "exit",
            "hang",
            "memory",
        ),
        default="none",
    )
    parser.add_argument(
        "--browser", choices=("firefox", "chrome", "edge"), default="firefox"
    )
    parser.add_argument(
        "--network-only",
        action="store_true",
        help="measure transfer success without asserting supported application decoding",
    )
    args = parser.parse_args()
    if not args.worker:
        parser.error("this target fixture requires the installed Shadow service")
    if args.fault != "none" and not args.worker:
        parser.error("fault requires isolated worker")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@:-]*", args.ssh):
        parser.error("invalid SSH destination")
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]*", args.host):
        parser.error("invalid test host")
    if args.observe_certificate and args.client != "firefox":
        parser.error("certificate observation requires Firefox")
    if args.client == "firefox" and not Path(args.firefox).is_file():
        parser.error("Firefox executable not found")
    nonce = os.environ.get("PRISM_TEST_RUN_ID") or uuid.uuid4().hex
    runtime = ROOT / ".build/tls-endpoint-bridge" / nonce
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

    directory = remote(
        "umask 077; mktemp -d /tmp/prism-bridge-XXXXXXXX",
        capture_output=True,
        text=True,
    ).stdout.strip()
    if not re.fullmatch(r"/tmp/prism-bridge-[A-Za-z0-9]{8}", directory):
        raise RuntimeError("unexpected remote run directory")
    processes = []
    errors = (runtime / "process-errors.log").open("w", encoding="utf-8")
    events, ready, done, stop_keys = (
        [],
        threading.Event(),
        threading.Event(),
        threading.Event(),
    )
    summary = {
        "test": "Opt-in passive TLS decryption",
        "client": args.browser if args.client == "firefox" else args.client,
        "run_id": nonce,
        "tls13_http2": "failed",
        "quic_http3": "not_tested",
        "production_modified": False,
        "prototype_certificate_substitution": False,
        "external_tls_interception": "not_assessed",
        "pi_secrets_persisted": False,
        "target_host": args.host,
        "target_port": args.target_port,
        "target_path": args.path,
    }
    control = browser = key_thread = agent = None
    event_thread = None
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
                str(HERE / "agent.py"),
                args.ssh + ":" + directory + "/",
            ],
            check=True,
        )
        command = (
            "cd "
            + shlex.quote(directory)
            + " && exec "
            + shlex.quote(args.pi_python)
            + " -B -u agent.py --host "
            + shlex.quote(args.host)
            + " --target-port "
            + str(args.target_port)
            + " --runtime "
            + shlex.quote(directory)
            + " --seconds 90"
        )
        if args.worker:
            command += " --forward-only"
        agent = subprocess.Popen(
            ssh + [args.ssh, command],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=errors,
            text=True,
            bufsize=1,
        )
        processes.append(agent)

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
        if not ready.wait(15):
            raise RuntimeError(
                "Pi relay/capture did not become ready; inspect private process-errors.log"
            )
        port = next(e["port"] for e in events if e.get("type") == "ready")
        with socket.socket() as reserve:
            reserve.bind(("127.0.0.1", 0))
            local_port = reserve.getsockname()[1]
        tunnel = subprocess.Popen(
            ssh
            + [
                "-o",
                "ExitOnForwardFailure=yes",
                "-N",
                "-L",
                "127.0.0.1:" + str(local_port) + ":127.0.0.1:" + str(port),
                args.ssh,
            ],
            stdout=subprocess.DEVNULL,
            stderr=errors,
        )
        processes.append(tunnel)
        deadline = time.monotonic() + 10
        while True:
            try:
                with socket.create_connection(("127.0.0.1", local_port), timeout=0.2):
                    break
            except OSError:
                if time.monotonic() > deadline:
                    raise RuntimeError("SSH forwarding did not start")
                time.sleep(0.1)
        if args.worker:
            relay_ready = next(e for e in events if e.get("type") == "ready")
            worker = WorkerProbe(
                ssh + [args.ssh],
                directory,
                args.pi_python,
                nonce,
                "tcp",
                args.host,
                args.target_port,
                errors,
                runtime,
                args.fault,
                dict(
                    client_port=relay_ready["capture_client_port"],
                    target_address=relay_ready["capture_target"],
                ),
            )
        keys = runtime / "session.keys"
        sent_keys = [0]

        def send_keys():
            position, partial = 0, ""
            while not stop_keys.wait(0.05):
                if not keys.exists():
                    continue
                with keys.open(encoding="ascii", errors="ignore") as source:
                    source.seek(position)
                    data = source.read(65536)
                    position = source.tell()
                if not data:
                    continue
                partial += data
                lines = partial.split("\n")
                partial = lines.pop()
                try:
                    for line in lines:
                        if len(line.split()) == 3 and line.split()[0] in {
                            "CLIENT_HANDSHAKE_TRAFFIC_SECRET",
                            "SERVER_HANDSHAKE_TRAFFIC_SECRET",
                            "CLIENT_TRAFFIC_SECRET_0",
                            "SERVER_TRAFFIC_SECRET_0",
                        }:
                            if worker:
                                worker.send_key(line.strip())
                            else:
                                agent.stdin.write(line.strip() + "\n")
                            sent_keys[0] += 1
                    agent.stdin.flush()
                except (BrokenPipeError, OSError, ValueError):
                    break

        key_thread = threading.Thread(target=send_keys, daemon=True)
        key_thread.start()
        urls = [
            "https://"
            + args.host
            + (":" + str(args.target_port) if args.target_port != 443 else "")
            + args.path
            + "?prism_probe="
            + nonce
            + "-"
            + str(i)
            for i in range(4)
        ]
        result = []

        class Control(http.server.BaseHTTPRequestHandler):
            def log_message(self, *unused):
                pass

            def do_GET(self):
                if self.path != "/" + nonce:
                    self.send_error(404)
                    return
                page = (
                    "<!doctype html><title>Prism opt-in TLS probe</title><p>Four test requests only.</p><script>"
                    "(async()=>{const urls="
                    + json.dumps(urls)
                    + ";const run=async u=>{const t0=performance.now();try{const r=await fetch(u,{credentials:'omit',cache:'no-store'});const body=await r.arrayBuffer();const text=body.byteLength<8192?new TextDecoder().decode(body):'';return {ok:r.ok,status:r.status,bytes:body.byteLength,elapsed_ms:performance.now()-t0,server_protocol:(text.match(/^http=(.*)$/m)||[])[1]}}catch(e){return {ok:false,error:e.name}}};const first=await run(urls[0]);return [first,...await Promise.all(urls.slice(1).map(run))]})()"
                    ".then(r=>fetch('/done/"
                    + nonce
                    + "',{method:'POST',body:JSON.stringify(r)}));</script>"
                ).encode()
                self.send_response(200)
                self.send_header("Content-Type", "text/html; charset=utf-8")
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
                result.extend(json.loads(self.rfile.read(length)))
                self.send_response(204)
                self.end_headers()
                done.set()

        control = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Control)
        threading.Thread(target=control.serve_forever, daemon=True).start()
        profile = runtime / "firefox-profile"
        profile.mkdir()
        prefs = {
            "network.proxy.type": 1,
            "network.proxy.http": "127.0.0.1",
            "network.proxy.http_port": local_port,
            "network.proxy.ssl": "127.0.0.1",
            "network.proxy.ssl_port": local_port,
            "network.proxy.no_proxies_on": "localhost,127.0.0.1",
            "network.proxy.failover_direct": False,
            "network.http.http3.enable": False,
            "network.trr.mode": 5,
            "security.tls.version.min": 4,
            "security.tls.version.max": 4,
            "security.tls.enable_0rtt_data": False,
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
        marionette_port = None
        if args.observe_certificate:
            if args.client != "firefox":
                raise ValueError("certificate observation requires Firefox")
            with socket.socket() as reserve:
                reserve.bind(("127.0.0.1", 0))
                marionette_port = reserve.getsockname()[1]
            prefs["marionette.port"] = marionette_port
        (profile / "user.js").write_text(
            "\n".join(
                "user_pref(" + json.dumps(k) + ", " + json.dumps(v) + ");"
                for k, v in prefs.items()
            ),
            encoding="utf-8",
        )
        environment = os.environ.copy()
        environment["SSLKEYLOGFILE"] = str(keys)
        environment["MOZ_HEADLESS"] = "1"
        environment["MOZ_AUTOMATION"] = "1"
        if args.observe_certificate:
            environment["MOZ_REMOTE_ALLOW_SYSTEM_ACCESS"] = "1"
        if args.client == "firefox":
            if args.browser != "firefox":
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
                        "--disable-quic",
                        "--user-data-dir=" + str(profile),
                        "--ssl-key-log-file=" + str(keys),
                        "--proxy-server=http://127.0.0.1:" + str(local_port),
                        "--proxy-bypass-list=localhost;127.0.0.1",
                        "http://127.0.0.1:"
                        + str(control.server_address[1])
                        + "/"
                        + nonce,
                    ],
                    env=environment,
                    stdout=subprocess.DEVNULL,
                    stderr=errors,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                )
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
                        *(["-marionette"] if args.observe_certificate else []),
                        "http://127.0.0.1:"
                        + str(control.server_address[1])
                        + "/"
                        + nonce,
                    ],
                    env=environment,
                    stdout=subprocess.DEVNULL,
                    stderr=errors,
                    creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
                )
        else:
            environment.pop("SSLKEYLOGFILE", None)
            environment["PYTHONPATH"] = str(ROOT / ".build/tls-endpoint-bridge/deps")
            browser = subprocess.Popen(
                [
                    sys.executable,
                    "-B",
                    str(HERE / "h2_client.py"),
                    args.host,
                    str(local_port),
                    str(keys),
                    nonce,
                    str(runtime / "h2-result.json"),
                    str(args.target_port),
                    args.path,
                ],
                env=environment,
                stdout=subprocess.DEVNULL,
                stderr=errors,
            )
        started = time.monotonic()
        deadline = started + 40
        while time.monotonic() < deadline:
            decoded = (
                worker.decoded(args.path)
                if worker
                else [
                    e
                    for e in events
                    if e.get("type") == "http_request" and nonce in e.get("path", "")
                ]
            )
            if (
                args.client == "python"
                and (runtime / "h2-result.json").exists()
                and not done.is_set()
            ):
                report = json.loads((runtime / "h2-result.json").read_text())
                result.extend(
                    {
                        "ok": status == 200,
                        "status": status,
                        "bytes": report["sizes"][i],
                        "elapsed_ms": report["response_ms"][i],
                    }
                    for i, status in enumerate(report["statuses"])
                )
                done.set()
            if len({e["diagnostic_id"] for e in decoded}) == 4 and done.is_set():
                break
            if done.is_set() and time.monotonic() - started > 8:
                break
            if browser.poll() is not None and not done.is_set():
                raise RuntimeError("isolated client exited before completing the probe")
            time.sleep(0.1)
        decoded = (
            worker.decoded(args.path)
            if worker
            else [
                e
                for e in events
                if e.get("type") == "http_request" and nonce in e.get("path", "")
            ]
        )
        if args.observe_certificate:
            metadata = MarionetteProbe(marionette_port)
            try:
                origin = (
                    "https://"
                    + args.host
                    + (":" + str(args.target_port) if args.target_port != 443 else "")
                )
                certificate = metadata.certificate(
                    origin + args.path + "?prism_certificate_probe=1"
                )
                summary["firefox_certificate"] = certificate
                summary["certificate_observation_scope"] = (
                    "additional navigation in the same temporary profile"
                )
                summary["external_tls_interception"] = (
                    "local_filter_certificate_observed"
                    if certificate.get("issuer") == "ESET SSL Filter CA"
                    else "not_identified_by_certificate_issuer"
                )
            finally:
                metadata.close()
        expected = (
            0
            if args.fault != "none" or os.environ.get("PRISM_TEST_BASELINE") == "1"
            else 4
        )
        success = (
            (
                args.network_only
                or len({e["diagnostic_id"] for e in decoded}) == expected
            )
            and len(result) == 4
            and all(r.get("ok") for r in result)
        )
        summary.update(
            tls13_http2="network_only"
            if args.network_only
            else ("passed" if success else "failed"),
            network_transfer_passed=success,
            decoded_requests=len(decoded),
            keys_sent=sent_keys[0],
            browser_responses=result,
            diagnostic_event_ids=sorted({e["diagnostic_id"] for e in decoded}),
            observed_flows=len({e["flow"] for e in decoded}),
            tls_versions=sorted(
                {e["version"] for e in events if e.get("type") == "tls_parameters"}
            ),
            analysis_errors=[
                e for e in events if e.get("type") == "analysis_unavailable"
            ],
        )
    finally:
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
        stop_keys.set()
        if key_thread:
            key_thread.join(timeout=2)
        if worker:
            summary["worker_report"] = worker.close()
            summary["decoder_path"] = "target_systemd_shadow_candidate"
            summary["injected_fault"] = args.fault
            summary["worker_validation_passed"] = (
                None
                if args.network_only
                else validate_worker_report(summary["worker_report"], args.fault)
            )
            if not args.network_only and not summary["worker_validation_passed"]:
                summary["tls13_http2"] = "failed"
        if agent:
            try:
                agent.stdin.close()
                agent.wait(timeout=8)
            except (OSError, subprocess.TimeoutExpired):
                agent.terminate()
        if event_thread:
            event_thread.join(timeout=2)
        stopped_events = [e for e in events if e.get("type") == "stopped"]
        if stopped_events:
            summary["no_keys_requests"] = stopped_events[-1]["no_keys_requests"]
            summary["capture_drops"] = stopped_events[-1]["capture_drops"]
        capture_health = summary.get("worker_report", {}).get("capture_health")
        if capture_health:
            summary["capture_drops"] = max(
                capture_health.get("dropped", 0),
                summary.get("worker_report", {}).get("observed_capture_loss", 0),
            )
        if args.network_only:
            summary["fault_validation_passed"] = (
                validate_worker_report(summary["worker_report"], args.fault)
                if worker and args.fault != "none"
                else None
            )
        if control:
            control.shutdown()
            control.server_close()
        for process in processes:
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.kill()
        # Download the narrowly scoped encrypted packet evidence, never TLS keys.
        try:
            subprocess.run(
                [
                    "scp",
                    "-q",
                    "-o",
                    "BatchMode=yes",
                    "-o",
                    "StrictHostKeyChecking=yes",
                    args.ssh + ":" + directory + "/capture.pcap",
                    str(runtime / "capture.pcap"),
                ],
                check=True,
                stdout=errors,
                stderr=errors,
            )
        finally:
            cleanup = (
                "import pathlib,shutil; p=pathlib.Path("
                + repr(directory)
                + "); assert p.parent==pathlib.Path('/tmp') and p.name.startswith('prism-bridge-'); shutil.rmtree(p)"
            )
            remote("python3 -c " + shlex.quote(cleanup), stdout=errors, stderr=errors)
            (runtime / "session.keys").unlink(missing_ok=True)
            errors.close()
            summary["local_keylog_deleted"] = not (runtime / "session.keys").exists()
            (runtime / "summary.json").write_text(
                json.dumps(summary, indent=2), encoding="utf-8"
            )
        print(json.dumps(summary, indent=2))
    if not summary.get("network_transfer_passed", False) or (
        not args.network_only and summary.get("worker_validation_passed") is not True
    ):
        raise SystemExit(1)


if __name__ == "__main__":
    main()
