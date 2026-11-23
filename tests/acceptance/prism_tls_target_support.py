import json
import os
import pathlib
import re
import shlex
import subprocess
import sys
import threading
import time
import uuid

ROOT = pathlib.Path.cwd()
META = json.loads((ROOT / ".build/prism-target-current.json").read_text())
RUNTIME = pathlib.Path(META["runtime"]).resolve()
if not RUNTIME.is_relative_to((ROOT / ".build").resolve()):
    raise ValueError("evidence must stay under .build")
if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@:-]*", META["ssh"]):
    raise ValueError("invalid SSH destination")
SSH = [
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
    META["ssh"],
]


def remote(code, data=None, root=False, timeout=30):
    cmd = ("sudo -n " if root else "") + "python3 -c " + shlex.quote(code)
    return subprocess.run(
        SSH + [cmd],
        input=json.dumps(data) if data is not None else None,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=True,
    )


PREPARE = r"""import ipaddress,json,os,pathlib,pwd,re,subprocess,sys
v=json.load(sys.stdin);assert re.fullmatch('[0-9a-f]{32}',v['session']);assert v['interface'] in ('lo','eth0');assert v['transport'] in ('tcp','quic')
for endpoint in (v['client'],v['server']):ipaddress.ip_address(endpoint['address']);assert type(endpoint['port']) is int and 1<=endpoint['port']<=65535
account=pwd.getpwnam('easypi-prism-tls');assert 0<account.pw_uid<1000
p=pathlib.Path('/etc/default/easypi-prism-endpoint-bridge');assert not p.is_symlink()
values=dict(INTERFACE=v['interface'],CLIENT_IP=v['client']['address'],CLIENT_PORT=v['client']['port'],SERVER_IP=v['server']['address'],SERVER_PORT=v['server']['port'],TRANSPORT=v['transport'],SESSION=v['session'])
fd=os.open(p,os.O_WRONLY|os.O_CREAT|os.O_TRUNC|os.O_NOFOLLOW,0o600)
with os.fdopen(fd,'w') as f:f.write(''.join('PRISM_TLS_'+k+'='+str(x)+'\n' for k,x in values.items()))
os.chown(p,0,0);os.chmod(p,0o600)
folder=pathlib.Path('/run/easypi-prism-tls');folder.mkdir(mode=0o750,exist_ok=True);os.chown(folder,0,account.pw_gid);os.chmod(folder,0o750)
enable=folder/'enabled';assert not enable.is_symlink()
fd=os.open(enable,os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW,0o600);os.close(fd);os.chown(enable,account.pw_uid,account.pw_gid);os.chmod(enable,0o600)
subprocess.run(['systemctl','start','easypi-prism-endpoint-bridge.socket'],check=True)
print(json.dumps({'prepared':True}))
"""
CONNECT = """import os,socket,sys,threading
s=socket.socket(socket.AF_UNIX,socket.SOCK_STREAM);s.connect('/run/easypi-prism-endpoint-bridge.sock')
def send():
 try:
  while True:
   data=os.read(0,4096)
   if not data:break
   s.sendall(data)
 finally:
  try:s.shutdown(socket.SHUT_WR)
  except OSError:pass
threading.Thread(target=send,daemon=True).start()
while True:
 data=s.recv(32768)
 if not data:break
 os.write(1,data)
"""
sys.path.insert(0, str(ROOT))
from prism_tls_bridge.channel import KeySender  # noqa: E402


class ServiceProbe:
    def __init__(self, transport, client, server, interface="eth0", fault="none"):
        self.session = uuid.uuid4().hex
        self.scope = dict(
            endpoint_id="managed-shadow-client",
            capture_point="shadow-pcap",
            key_source="authenticated-collector",
            tls_leg="endpoint-origin",
            opt_in=True,
            transport=transport,
            client=client,
            server=server,
            interface=interface,
        )
        self.events = []
        self.ready = threading.Event()
        self.sender = KeySender(self.session, self.scope, 120)
        self.fault = fault
        self.secret_values = [self.sender.token.hex()]
        self.secret_leak = False
        self.key_frames_submitted = 0
        self.key_frames_suppressed = 0
        self.key_frames_corrupted = 0
        self.folder = RUNTIME / ("session-" + self.session)
        self.folder.mkdir()
        remote(PREPARE, dict(self.scope, session=self.session), root=True)
        cursor_output = remote(
            "import subprocess; p=subprocess.run(['sudo','-n','journalctl','-n','1','--show-cursor','--no-pager'],capture_output=True,text=True,check=True); print(p.stdout.split('-- cursor: ')[-1].strip())"
        ).stdout.strip()
        self.errors = (self.folder / "connector-errors.log").open("w")
        journal_command = (
            "sudo -n journalctl --follow --no-pager -o json --after-cursor "
            + shlex.quote(cursor_output)
            + " -u "
            + shlex.quote("easypi-prism-endpoint-bridge@*")
        )
        cmd = "sudo -n -u easypi-prism-tls python3 -I -u -c " + shlex.quote(CONNECT)
        self.process = subprocess.Popen(
            SSH + [cmd],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=self.errors,
            text=True,
            bufsize=1,
        )
        unit_code = "import subprocess; p=subprocess.run(['systemctl','list-units','easypi-prism-endpoint-bridge@*.service','--state=activating,active','--plain','--no-legend'],capture_output=True,text=True); print(p.stdout)"
        unit = None
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            units = [
                line for line in remote(unit_code).stdout.splitlines() if line.strip()
            ]
            if units:
                unit = units[-1].split()[0]
                break
            time.sleep(0.1)
        if unit is None:
            raise RuntimeError("observer instance did not activate")
        self.unit = unit
        self.resource_samples = []
        self.metrics_stop = threading.Event()

        def sample_resources():
            while not self.metrics_stop.wait(0.8):
                try:
                    args = [
                        "systemctl",
                        "show",
                        self.unit,
                        "--property=MemoryCurrent,MemoryPeak,CPUUsageNSec,TasksCurrent,Result,MainPID",
                    ]
                    data = remote(
                        "import json,subprocess; p=subprocess.run("
                        + repr(args)
                        + ',capture_output=True,text=True); print(json.dumps(dict(l.split("=",1) for l in p.stdout.splitlines() if "=" in l)))'
                    ).stdout
                    self.resource_samples.append(json.loads(data))
                except Exception:
                    pass

        self.metrics_thread = threading.Thread(target=sample_resources, daemon=True)
        self.metrics_thread.start()
        journal_command = (
            "sudo -n journalctl --follow --no-pager -o json --after-cursor "
            + shlex.quote(cursor_output)
            + " -u "
            + shlex.quote(unit)
        )
        self.journal = subprocess.Popen(
            SSH + [journal_command],
            stdout=subprocess.PIPE,
            stderr=self.errors,
            text=True,
            bufsize=1,
        )
        self.reader = threading.Thread(target=self.read, daemon=True)
        self.reader.start()
        self.process.stdin.write(self.sender.enrollment())
        self.process.stdin.flush()

    def read(self):
        with (self.folder / "events.jsonl").open("w", encoding="utf-8") as f:
            for line in self.journal.stdout:
                if any(value in line for value in list(self.secret_values)):
                    self.secret_leak = True
                    continue
                try:
                    event = json.loads(json.loads(line).get("MESSAGE", ""))
                except ValueError:
                    continue
                self.events.append(event)
                f.write(json.dumps(event) + "\n")
                f.flush()
                if event.get("type") == "shadow_ready":
                    self.ready.set()

    def key(self, line):
        fields = line.split()
        if len(fields) == 3 and len(self.secret_values) < 129:
            self.secret_values.append(fields[2])
        if self.fault in ("exit", "hang", "memory", "overflow"):
            if not getattr(self, "fault_injected", False):
                code = "import json,pathlib,os,signal,subprocess,sys; v=json.load(sys.stdin); unit=v['unit']; assert unit.startswith('easypi-prism-endpoint-bridge@') and unit.endswith('.service'); group=subprocess.check_output(['systemctl','show',unit,'--property=ControlGroup','--value'],text=True).strip(); pids=[int(x) for x in (pathlib.Path('/sys/fs/cgroup'+group)/'cgroup.procs').read_text().split()]; children=[p for p in pids if b'--prism-tls-child' in (pathlib.Path('/proc')/str(p)/'cmdline').read_bytes()]; leaves=[p for p in children if not (pathlib.Path('/proc')/str(p)/'task'/str(p)/'children').read_text().strip()]; assert leaves; action=v['action']; assert action!='memory' or 'memory' in pathlib.Path('/sys/fs/cgroup/cgroup.controllers').read_text().split(), 'memory controller unavailable'; subprocess.run(['systemctl','set-property','--runtime',unit,'MemorySwapMax=0','MemoryMax=24M'],check=True) if action=='memory' else os.kill(leaves[-1],signal.SIGKILL if action=='exit' else signal.SIGSTOP); print(json.dumps({'injected':action,'decoder_only':action!='memory'}))"
                self.fault_detail = json.loads(
                    remote(
                        code, dict(unit=self.unit, action=self.fault), root=True
                    ).stdout
                )
                self.fault_injected = True
            return

        if self.fault == "no-keys":
            self.key_frames_suppressed += 1
            return
        if self.fault == "wrong-keys":
            fields = line.split()
            fields[2] = os.urandom(len(fields[2]) // 2).hex()
            line = " ".join(fields)
            self.key_frames_corrupted += 1
        if len(line.split()) == 3 and len(self.secret_values) < 129:
            self.secret_values.append(line.split()[2])
        self.process.stdin.write(self.sender.frame(line))
        self.process.stdin.flush()
        self.key_frames_submitted += 1

    def close(self):
        try:
            self.process.stdin.close()
            self.process.wait(timeout=15)
        except (OSError, ValueError, subprocess.TimeoutExpired):
            self.process.terminate()
        # SSH EOF precedes journald delivery. Preserve the final capture counters
        # before ending the journal follower; stale zero counters are not proof.
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            if any(e.get("type") == "shadow_stopped" for e in list(self.events)):
                break
            time.sleep(0.02)
        self.journal.terminate()
        self.journal.wait(timeout=3)
        self.reader.join(timeout=2)
        self.sender.close()
        self.errors.close()
        self.metrics_stop.set()
        self.metrics_thread.join(timeout=6)
        try:
            command = [
                "systemctl",
                "show",
                self.unit,
                "--property=Result,ExecMainCode,ExecMainStatus,MemoryPeak",
            ]
            output = remote(
                "import subprocess,json; p=subprocess.run("
                + repr(command)
                + ",capture_output=True,text=True); print(json.dumps(dict(l.split('=',1) for l in p.stdout.splitlines() if '=' in l)))"
            ).stdout
            self.final_service_result = json.loads(output)
        except Exception:
            self.final_service_result = {"unavailable": True}
        (self.folder / "cgroup.json").write_text(
            json.dumps(self.resource_samples, indent=2)
        )
        self.secret_values.clear()
        return dict(
            service_result=self.final_service_result,
            transport=self.scope["transport"],
            key_frames_submitted=self.key_frames_submitted,
            key_frames_suppressed=self.key_frames_suppressed,
            key_frames_corrupted=self.key_frames_corrupted,
            fault_injected=getattr(self, "fault_injected", False),
            fault_detail=getattr(self, "fault_detail", None),
            cgroup_samples=self.resource_samples,
            tls_secret_leak_detected=self.secret_leak,
            session=self.session,
            ready=self.ready.is_set(),
            headers=sum(e.get("type") == "headers" for e in self.events),
            events=len(self.events),
            stopped=[e for e in self.events if e.get("type") == "shadow_stopped"],
        )
