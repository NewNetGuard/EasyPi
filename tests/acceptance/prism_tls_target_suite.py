"""Six-hour controlled browser acceptance driver. Requires explicit test-network metadata.

The executable is an experimental candidate, never the working backend.
Runtime targets, profiles, keys, captures and raw evidence stay under .build.
"""

import argparse
from collections import Counter
import datetime
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import time
import uuid

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))
from prism_tls_target_support import META, RUNTIME, remote  # noqa: E402

SNAPSHOT = r"""import hashlib,json,pathlib,re,subprocess,shutil,os
out={}
for key,args in [('firewall',['sudo','-n','iptables-save']),('ipsets',['sudo','-n','ipset','save'])]:
 p=subprocess.run(args,capture_output=True,text=True,check=True,timeout=10)
 lines=p.stdout.splitlines()
 data='\n'.join(re.sub(r'\[\d+:\d+\]','[counter]',line) for line in lines if not line.startswith('#')) if key=='firewall' else '\n'.join(sorted(line for line in lines if line.startswith('create ')))
 out[key]=hashlib.sha256(data.encode()).hexdigest()
 out.setdefault('filter_fingerprint_inputs',{})[key]=data
for unit in ('easypi-backend.service','easypi-prism-shadow.service','easypi-prism-flowgraph.service'):
 out[unit]=subprocess.run(['systemctl','is-active',unit],capture_output=True,text=True).stdout.strip()
out['mem_available_kib']=next(int(line.split()[1]) for line in pathlib.Path('/proc/meminfo').read_text().splitlines() if line.startswith('MemAvailable:'))
out['disk_free_bytes']=shutil.disk_usage('/opt/EasyPi').free
out['load1']=os.getloadavg()[0]
out['memory_controller']='memory' in pathlib.Path('/sys/fs/cgroup/cgroup.controllers').read_text().split()
print(json.dumps(out))
"""
CLEANUP = r"""import json,pathlib,subprocess
subprocess.run(['systemctl','stop','easypi-prism-endpoint-bridge.socket'],check=False)
p=subprocess.run(['systemctl','list-units','easypi-prism-endpoint-bridge@*.service','--state=activating,active','--no-legend','--plain'],capture_output=True,text=True)
for line in p.stdout.splitlines():
 fields=line.split()
 if fields and fields[0].startswith('easypi-prism-endpoint-bridge@'):subprocess.run(['systemctl','stop',fields[0]],check=False)
enable=pathlib.Path('/run/easypi-prism-tls/enabled')
if enable.is_file() and not enable.is_symlink():enable.unlink()
print(json.dumps({'observer_stopped':True,'filtering_modified':False}))
"""


def write(path, value):
    temporary = path.with_suffix(path.suffix + ".new")
    temporary.write_text(json.dumps(value, indent=2), encoding="utf-8")
    os.replace(temporary, path)


def ratio(decoded, eligible):
    if (
        type(decoded) is not int
        or type(eligible) is not int
        or decoded < 0
        or eligible <= 0
        or decoded > eligible
    ):
        return None
    return round(100 * decoded / eligible, 3)


def run_case(browser, protocol, fault="none", baseline=False, bulk=False):
    lab = ROOT / "tests/acceptance/prism_tls_lab"
    run_id = uuid.uuid4().hex
    tag = (
        f"{browser}-{protocol}-{fault}"
        + ("-baseline" if baseline else "")
        + ("-bulk" if bulk else "")
        + "-"
        + run_id
    )
    output = RUNTIME / (tag + ".json")
    errors = RUNTIME / (tag + ".stderr.log")
    command = [
        sys.executable,
        "-B",
        str(lab / ("run_probe.py" if protocol == "h2" else "run_firefox_h3.py")),
        "--ssh",
        META["ssh"],
        "--worker",
        "--browser",
        browser,
        "--fault",
        fault,
    ]
    if protocol == "h2":
        command += ["--target-port", "443"]
    if bulk:
        command += [
            "--host",
            "speed.cloudflare.com",
            "--path",
            "/__down?bytes=1000000&probe=",
        ]
    environment = os.environ.copy()
    environment["PRISM_TEST_RUN_ID"] = run_id
    if baseline:
        environment["PRISM_TEST_BASELINE"] = "1"
    else:
        environment.pop("PRISM_TEST_BASELINE", None)
    started = time.monotonic()
    process = None
    try:
        with (
            output.open("w", encoding="utf-8") as out,
            errors.open("w", encoding="utf-8") as err,
        ):
            process = subprocess.Popen(
                command,
                cwd=ROOT,
                env=environment,
                stdout=out,
                stderr=err,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            try:
                code = process.wait(timeout=110)
            except subprocess.TimeoutExpired:
                if os.name == "nt":
                    subprocess.run(
                        ["taskkill", "/PID", str(process.pid), "/T", "/F"],
                        capture_output=True,
                    )
                else:
                    process.kill()
                process.wait(timeout=5)
                code = 124
        text = output.read_text(encoding="utf-8")
        try:
            report = json.JSONDecoder().raw_decode(text.lstrip())[0]
        except (ValueError, IndexError):
            report = {}
        responses = report.get("browser_responses", report.get("browser_results", []))
        returned = sum(v.get("status") == 200 for v in responses if isinstance(v, dict))
        decoded = report.get("decoded_requests", 0)
        worker = report.get("worker_report", {})
        reasons = sorted(
            {
                v.get("reason")
                for v in worker.get("visibility_reasons", [])
                if v.get("state") == "Unknown"
                and v.get("reason") not in (None, "operator_disabled")
            }
        )
        cg = worker.get("cgroup_samples", [])
        memories = [
            int(v["MemoryCurrent"])
            for v in cg
            if str(v.get("MemoryCurrent", "")).isdigit()
        ]
        cpus = [
            int(v["CPUUsageNSec"])
            for v in cg
            if str(v.get("CPUUsageNSec", "")).isdigit()
        ]
        return dict(
            case=tag,
            browser=browser,
            protocol=protocol,
            fault=fault,
            baseline=baseline,
            bulk=bulk,
            exit_code=code,
            attempted=4,
            returned_http200=returned,
            decoded=decoded,
            request_header_coverage_percent=None
            if baseline
            else ratio(decoded, returned),
            unknown_reasons=reasons,
            key_diagnostics=sorted(
                {
                    v["diagnostic"]
                    for v in worker.get("visibility_reasons", [])
                    if v.get("diagnostic") not in (None, "none")
                }
            ),
            secret_leak_detected=worker.get("tls_secret_leak_detected"),
            fault_injected=worker.get("fault_injected"),
            capture=worker.get("capture_health"),
            max_service_memory_bytes=max(memories, default=None),
            max_service_cpu_ns=max(cpus, default=None),
            response_ms=[
                v.get("elapsed_ms")
                for v in responses
                if v.get("elapsed_ms") is not None
            ],
            download_bytes=sum(v.get("bytes", 0) for v in responses),
            elapsed_seconds=round(time.monotonic() - started, 3),
        )
    finally:
        # The fixture nonce is assigned before launch, so cleanup can identify
        # only this run's exported file even if its wrapper timed out.
        directory = (
            ROOT
            / ".build/tls-endpoint-bridge"
            / (("firefox-h3-" if protocol == "h3" else "") + run_id)
        )
        keys = directory / "session.keys"
        if keys.is_file():
            keys.unlink()


def network_gap():
    # Restoration is owned by PID1 and scheduled BEFORE dropping the link.
    code = r"""import json,subprocess
import uuid
unit='easypi-prism-tls-link-restore-'+uuid.uuid4().hex[:8]
subprocess.run(['systemd-run','--quiet','--collect','--unit='+unit,'--on-active=10s','/usr/sbin/ip','link','set','dev','eth0','up'],check=True)
print(json.dumps({'restore_scheduled':True}),flush=True)
subprocess.run(['ip','link','set','dev','eth0','down'],check=True)
"""
    response = ""
    try:
        response = remote(code, root=True, timeout=15).stdout
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired) as error:
        response = error.stdout or ""
        if isinstance(response, bytes):
            response = response.decode(errors="replace")
    if '"restore_scheduled": true' not in response:
        raise RuntimeError(
            "link restoration was not scheduled; network test not counted"
        )
    deadline = time.monotonic() + 90
    while time.monotonic() < deadline:
        try:
            return json.loads(remote(SNAPSHOT, timeout=10).stdout)
        except Exception:
            time.sleep(3)
    raise RuntimeError("network restoration did not complete")


def reboot():
    previous_boot = remote(
        "import pathlib; print(pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip())"
    ).stdout.strip()
    try:
        remote(
            "import subprocess; subprocess.run(['systemctl','reboot'],check=True)",
            root=True,
            timeout=10,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        pass
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        time.sleep(5)
        try:
            current_boot = remote(
                "import pathlib; print(pathlib.Path('/proc/sys/kernel/random/boot_id').read_text().strip())",
                timeout=10,
            ).stdout.strip()
            if current_boot == previous_boot:
                continue
            result = json.loads(remote(SNAPSHOT, timeout=10).stdout)
            if all(
                result.get(v) == "active"
                for v in (
                    "easypi-backend.service",
                    "easypi-prism-shadow.service",
                    "easypi-prism-flowgraph.service",
                )
            ):
                return result
        except Exception:
            pass
    raise RuntimeError("core services did not recover after test reboot")


def require_core_services(snapshot):
    for unit in (
        "easypi-backend.service",
        "easypi-prism-shadow.service",
        "easypi-prism-flowgraph.service",
    ):
        if snapshot.get(unit) != "active":
            raise RuntimeError("core service unavailable: " + unit)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--hours", type=float, default=6)
    parser.add_argument("--max-cases", type=int)
    parser.add_argument("--allow-reboot", action="store_true")
    parser.add_argument("--allow-network-disruption", action="store_true")
    args = parser.parse_args()
    if (
        not 0.01 <= args.hours <= 12
        or args.max_cases is not None
        and args.max_cases <= 0
    ):
        parser.error("invalid bounded run")
    if META.get("test_network_confirmed") is not True:
        parser.error("isolated test network must be confirmed")
    import math

    if not math.isfinite(args.hours):
        parser.error("invalid duration")
    import ctypes

    state_path = RUNTIME / "long-run-status.json"
    started = time.monotonic()
    deadline = started + args.hours * 3600
    state = dict(
        status="running",
        acceptance_policy_version=2,
        started_utc=datetime.datetime.now(datetime.timezone.utc).isoformat(),
        requested_hours=args.hours,
        cases=[],
        network_gap_done=False,
        reboot_done=False,
        tests_are_scoped=True,
        filtering_modified=False,
    )
    initial = json.loads(remote(SNAPSHOT).stdout)
    if not initial.get("memory_controller") and not args.max_cases:
        state.update(
            status="blocked_memory_controller",
            error="kernel memory controller unavailable; no long stress run started",
        )
        write(state_path, state)
        raise SystemExit("memory cgroup must be enabled before unattended stress")
    state["baseline"] = initial
    write(state_path, state)
    combinations = [(b, p) for b in ("firefox", "chrome", "edge") for p in ("h2", "h3")]
    index = 0
    if os.name == "nt":
        ctypes.windll.kernel32.SetThreadExecutionState(0x80000001)
    try:
        require_core_services(initial)
        while time.monotonic() < deadline and not (RUNTIME / "STOP").exists():
            if args.max_cases is not None and index >= args.max_cases:
                break
            current = json.loads(remote(SNAPSHOT).stdout)
            require_core_services(current)
            if not current.get("memory_controller") and not args.max_cases:
                raise RuntimeError("memory controller became unavailable")
            if (
                current["firewall"] != initial["firewall"]
                or current["ipsets"] != initial["ipsets"]
            ):
                state["filtering_mismatch"] = dict(
                    observed_utc=datetime.datetime.now(
                        datetime.timezone.utc
                    ).isoformat(),
                    changed=[
                        key
                        for key in ("firewall", "ipsets")
                        if current[key] != initial[key]
                    ],
                    snapshot=current,
                )
                # Keep the exact inputs that produced the changed hash. A later
                # read can already have missed a transient runtime update.
                write(state_path, state)
                raise RuntimeError(
                    "filtering configuration fingerprint changed; no repair attempted"
                )
            if (
                current["mem_available_kib"] < 1024 * 1024
                or current["disk_free_bytes"] < 2 * 1024**3
                or shutil.disk_usage(ROOT).free < 2 * 1024**3
            ):
                raise RuntimeError("resource safety floor reached")
            browser, protocol = combinations[index % len(combinations)]
            fault = "none"
            if index >= 12 and index % 11 == 0:
                fault = "no-keys"
            elif index >= 12 and index % 13 == 0:
                fault = "wrong-keys"
            elif index >= 12 and index % 17 == 0 and protocol == "h2":
                fault = "exit"
            result = run_case(browser, protocol, fault)
            state["cases"].append(result)
            index += 1
            if result["secret_leak_detected"]:
                raise RuntimeError(
                    "secret detected in observer diagnostics; test stopped"
                )
            state["elapsed_seconds"] = round(time.monotonic() - started, 3)
            state["last_update_utc"] = datetime.datetime.now(
                datetime.timezone.utc
            ).isoformat()
            state["failed_cases"] = sum(
                v["exit_code"] != 0 or v["returned_http200"] != 4
                for v in state["cases"]
            )
            state["attempted_requests"] = sum(v["attempted"] for v in state["cases"])
            state["known_http200"] = sum(v["returned_http200"] for v in state["cases"])
            state["http_success_percent_of_attempted"] = ratio(
                state["known_http200"], state["attempted_requests"]
            )
            state["decoded_with_keys"] = sum(
                v["decoded"] for v in state["cases"] if v["fault"] == "none"
            )
            known = sum(
                v["returned_http200"] for v in state["cases"] if v["fault"] == "none"
            )
            state["scoped_header_coverage_with_keys_percent"] = ratio(
                state["decoded_with_keys"], known
            )
            state["unknown_reasons"] = dict(
                Counter(
                    reason for v in state["cases"] for reason in v["unknown_reasons"]
                )
            )
            write(state_path, state)
            if (
                args.allow_network_disruption
                and not state["network_gap_done"]
                and time.monotonic() - started > 600
            ):
                remote(CLEANUP, root=True)
                state["network_gap_pending"] = True
                write(state_path, state)
                state["after_network_gap"] = network_gap()
                state["network_gap_done"] = True
                write(state_path, state)
            if (
                args.allow_reboot
                and not state["reboot_done"]
                and time.monotonic() - started > args.hours * 1800
            ):
                remote(CLEANUP, root=True)
                state["reboot_pending"] = True
                write(state_path, state)
                state["after_reboot"] = reboot()
                state["reboot_done"] = True
                write(state_path, state)
            if not args.max_cases:
                time.sleep(10)
        state["status"] = (
            "stopped_by_operator"
            if (RUNTIME / "STOP").exists()
            else ("smoke_complete" if args.max_cases else "completed")
        )
        state["failed_cases"] = sum(
            case["exit_code"] != 0 or case["returned_http200"] != 4
            for case in state["cases"]
        )
        if state["failed_cases"]:
            state["status"] = "failed"
            state["error"] = (
                "one or more browser cases did not meet acceptance criteria"
            )
    except Exception as error:
        state["status"] = "failed"
        state["error"] = type(error).__name__ + ": " + str(error)[:300]
    finally:
        state["elapsed_seconds"] = round(time.monotonic() - started, 3)
        try:
            state["cleanup"] = json.loads(remote(CLEANUP, root=True).stdout)
        except Exception:
            state["cleanup"] = {"complete": False}
        state["finished_utc"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
        write(state_path, state)
        if os.name == "nt":
            ctypes.windll.kernel32.SetThreadExecutionState(0x80000000)
    print(json.dumps({k: v for k, v in state.items() if k != "cases"}, indent=2))
    if state["status"] == "failed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
