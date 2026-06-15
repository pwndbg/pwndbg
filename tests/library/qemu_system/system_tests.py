from __future__ import annotations

import contextlib
import json
import os
import platform
import signal
import subprocess
import time
from dataclasses import dataclass
from os.path import dirname
from pathlib import Path
from select import select

from elftools.elf.elffile import ELFFile


@dataclass
class Target:
    dir: Path
    vmlinux: Path
    gdb: str
    name: str


ANSI_BRIGHT_GREEN = "\u001b[32;1m"
ANSI_YELLOW = "\u001b[33m"
ANSI_BLUE = "\u001b[34m"
ANSI_RED = "\u001b[31m"
ANSI_RESET = "\u001b[0m"


def warn(*args, **kwargs):
    print(f"{ANSI_YELLOW}[*]{ANSI_RESET}", *args, **kwargs)


def info(*args, **kwargs):
    print(f"{ANSI_BLUE}[+]{ANSI_RESET}", *args, **kwargs)


def error(*args, **kwargs):
    print(f"{ANSI_RED}[-]{ANSI_RESET}", *args, **kwargs)
    exit(-1)


def runcmd(*args: str, fail_on_error=False, verbose=True) -> str | None:
    stderr = stdout = None
    try:
        p = subprocess.run(args, capture_output=True, timeout=30)
        stdout, stderr = p.stdout, p.stderr
    except subprocess.TimeoutExpired:
        warn("timer expired")
        return None
    except subprocess.CalledProcessError as e:
        error(f"subprocess error: {e}")
    if stderr and verbose:
        with contextlib.suppress(UnicodeDecodeError):
            stderr = stderr.decode("utf-8")
        if fail_on_error:
            error(stderr)
        else:
            warn(stderr)
    if stdout:
        return stdout.decode("utf-8")
    return None


def get_base(vmlinux: str) -> int | None:
    vmlinux_info = runcmd("readelf", "-l", vmlinux, fail_on_error=True)
    if vmlinux_info is None:
        return None
    base = None
    elf = ELFFile(open(vmlinux, "rb"))
    for line in vmlinux_info.splitlines():
        if "LOAD" in line:
            base = int(line.split()[2], 16) + (
                0x10000 if elf.get_machine_arch() == "AArch64" else 0
            )
            break
    if not base:
        error(f"Cannot find kernel base: {vmlinux_info}")
    return base


def get_targets() -> list[Target]:
    # TODO
    return []


PORT = 1234
TIMEOUT = 60
WAIT = 5
NUM_TESTS = 16
PWNDBG_ROOT = dirname(dirname(dirname(dirname(os.path.abspath(__file__)))))

TEMPLATE = """
target remote localhost:{port}
python
vmlinux = "{vmlinux}"
kbase = int(gdb.execute("kbase", to_string=True).strip().split(" ")[-1][:18], 16)
print(f"found kbase: {{hex(kbase)}}")
offset = kbase - {start}
gdb.execute(f"symbol-file {{vmlinux}} -o {{hex(offset)}}")
gdb.execute("si",  to_string=True)

import pytest
pytest.main(["{pwndbg_root}/tests/library/qemu_system/tests/test_commands_kernel.py", "-vvv", "-s", "--showlocals", "--color=yes"])
end
quit
"""


def process_line(target: Target, line: str | None, fails: list[str]) -> None:
    if line is None:
        return
    a = line.split("::")[1]
    print(a, end="")
    if "FAIL" in line:
        fails.append(f"{target.name} {a}")


def readline(p) -> str | None:
    if p.poll() is not None:
        return None
    poll_result = select([p.stdout], [], [], TIMEOUT)[0]
    if not poll_result:
        p.terminate()
        p.wait()
        return None
    line = p.stdout.readline().decode()
    return line


def run() -> list[str]:
    pwd = Path(os.getcwd())

    fails: list[str] = []
    targets = get_targets()
    for target in targets:
        dir = target.dir
        os.chdir(dir)
        assert (dir / "launch.sh").exists()
        proc = None
        try:
            proc = subprocess.Popen(
                ["./launch.sh", "--port", str(PORT)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,
            )
        except Exception:
            error(f"{dir} failed to start")
        assert proc
        time.sleep(WAIT)
        if proc.poll() is not None:
            error(f"{dir} failed to start")
        info(f"testing {target.name}")
        f = open(pwd / "script.gdb", "w+")
        script = TEMPLATE.format(
            pwndbg_root=PWNDBG_ROOT,
            port=PORT,
            vmlinux=target.vmlinux,
            start=get_base(str(target.vmlinux)),
        )
        f.write(script)
        f.flush()
        try:
            p = subprocess.Popen(
                [target.gdb],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            assert p.stdin and p.stdout
            p.stdin.write(f"source {f.name}\n".encode())
            p.stdin.flush()
            while True:
                line = readline(p)
                if line is None or (
                    (a := line.split("::"))
                    and len(a) == 2
                    and any(s in line for s in ("FAIL", "PASS", "SKIP"))
                ):
                    break
            process_line(target, line, fails)
            for _ in range(NUM_TESTS - 1):
                line = readline(p)
                process_line(target, line, fails)
            line = readline(p)
            line = readline(p)
            if line is None:
                fails.append(f"{target.name} TIMEOUT\n")
            while line is not None:
                print(line, end="")
                line = readline(p)
            p.wait()
        except Exception as e:
            warn(str(e))
        os.killpg(proc.pid, signal.SIGTERM)
        proc.wait()
        info(f"{target.name} succeeded")
    return fails


os.environ.setdefault("NO_COLOR", "1")
for fail in run():
    print(fail, end="")
