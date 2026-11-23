#!/usr/bin/env python3
"""Exercise backend -> sudo(use_pty) -> runner -> root supervisor timeout."""

from __future__ import annotations

import os
import pwd
import shutil
import subprocess
import tempfile
import textwrap
import time
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]


def main() -> int:
    if os.name != "posix" or os.geteuid() != 0:
        raise SystemExit("run this acceptance test as root on Linux")
    if not shutil.which("sudo") or not shutil.which("visudo"):
        raise SystemExit("sudo and visudo are required")
    pwd.getpwnam("nobody")

    with tempfile.TemporaryDirectory(
        prefix="easypi-runner-timeout-", dir="/tmp"
    ) as directory:
        base = Path(directory)
        base.chmod(0o755)
        scripts = base / "scripts"
        settings = scripts / "settings"
        settings.mkdir(parents=True)
        scripts.chmod(0o755)
        settings.chmod(0o755)

        helper = scripts / "privileged_timeout.py"
        shutil.copy2(ROOT / "scripts/privileged_timeout.py", helper)
        helper.chmod(0o644)

        started_marker = base / "root-operation-started"
        marker = base / "late-root-mutation"
        target = settings / "stealth_vpn.sh"
        target.write_text(
            "#!/usr/bin/python3\n"
            "import signal, time\n"
            "from pathlib import Path\n"
            "signal.signal(signal.SIGTERM, signal.SIG_IGN)\n"
            f"Path({str(started_marker)!r}).write_text('started')\n"
            "time.sleep(4)\n"
            f"Path({str(marker)!r}).write_text('late')\n",
            encoding="utf-8",
        )
        target.chmod(0o755)

        runner = scripts / "runner"
        runner_text = (ROOT / "scripts/runner").read_text(encoding="utf-8")
        runner_text = runner_text.replace(
            'SCRIPTS_BASE="/opt/EasyPi/scripts"', f'SCRIPTS_BASE="{scripts}"'
        ).replace(
            'LOG_FILE="/var/log/easypi/runner.log"',
            f'LOG_FILE="{base / "runner.log"}"',
        )
        runner_text = runner_text.replace("-g easypi", "-g root").replace(
            "root:easypi", "root:root"
        )
        runner.write_text(runner_text, encoding="utf-8")
        runner.chmod(0o755)

        harness = base / "backend_timeout.py"
        harness.write_text(
            textwrap.dedent(
                f"""
                import ast
                import asyncio
                import os
                import signal
                import time
                from pathlib import Path
                from typing import Any, Dict

                source = Path({str(ROOT / 'backend/app/services/stealth_components/client.py')!r})
                tree = ast.parse(source.read_text(encoding='utf-8'))
                original = next(
                    node for node in tree.body
                    if isinstance(node, ast.ClassDef) and node.name == 'StealthClientMixin'
                )
                original.body = [
                    node for node in original.body
                    if isinstance(node, ast.AsyncFunctionDef)
                    and node.name in ('_run', '_stop_timed_out_process')
                ]
                get_easypi_root = lambda: Path({str(base)!r})
                SCRIPT_REL = 'settings/stealth_vpn.sh'
                exec(
                    compile(ast.Module(body=[original], type_ignores=[]), str(source), 'exec'),
                    globals(),
                )

                async def main():
                    result = await asyncio.wait_for(
                        StealthClientMixin()._run('down', timeout=0.25), timeout=3
                    )
                    assert result == {{
                        'success': False,
                        'error': "timeout running 'down'",
                    }}, result
                    print('BACKEND_TIMEOUT_RETURNED=PASS', flush=True)

                asyncio.run(main())
                """
            ).lstrip(),
            encoding="utf-8",
        )
        harness.chmod(0o644)

        sudoers = Path("/etc/sudoers.d") / f"easypi-runner-timeout-{os.getpid()}"
        try:
            sudoers.write_text(
                "Defaults:nobody use_pty\n"
                f"nobody ALL=(root) NOPASSWD: {runner}\n",
                encoding="utf-8",
            )
            sudoers.chmod(0o440)
            subprocess.run(["visudo", "-cf", str(sudoers)], check=True)

            started = time.monotonic()
            result = subprocess.run(
                ["sudo", "-u", "nobody", "--", "python3", str(harness)],
                check=False,
                capture_output=True,
                text=True,
                timeout=4,
            )
            elapsed = time.monotonic() - started
            if result.returncode != 0:
                raise AssertionError(result.stdout + result.stderr)
            if elapsed >= 3:
                raise AssertionError(f"backend returned too late: {elapsed:.3f}s")
            if not started_marker.exists():
                raise AssertionError("root operation did not start")
            time.sleep(4.1)
            if marker.exists():
                raise AssertionError("root operation continued after backend timeout")
            print("SUDO_RUNNER_TIMEOUT=PASS")
        finally:
            sudoers.unlink(missing_ok=True)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
