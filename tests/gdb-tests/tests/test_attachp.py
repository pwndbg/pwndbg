from __future__ import annotations

import getpass
import os
import re
import subprocess
import tempfile

import pytest

from .utils import run_gdb_with_script

can_attach = False

if os.getuid() == 0:
    can_attach = True
else:
    # see `man ptrace`
    with open("/proc/sys/kernel/yama/ptrace_scope") as f:
        result = f.read()
        if len(result) >= 1 and result[0] == "0":
            can_attach = True

REASON_CANNOT_ATTACH = (
    "Test skipped due to inability to attach (needs sudo or sysctl -w kernel.yama.ptrace_scope=0"
)


@pytest.fixture
def launched_bash_binary():
    path = tempfile.mktemp()
    subprocess.check_output(["cp", "/bin/bash", path])

    process = subprocess.Popen([path], stdout=subprocess.PIPE, stdin=subprocess.PIPE)

    yield process.pid, path

    process.kill()

    os.remove(path)  # Cleanup


@pytest.mark.skipif(can_attach is False, reason=REASON_CANNOT_ATTACH)
def test_attachp_command_attaches_to_procname(launched_bash_binary):
    pid, binary_path = launched_bash_binary

    binary_name = binary_path.split("/")[-1]
    result = run_gdb_with_script(pyafter=f"attachp {binary_name}")

    matches = re.search(r"Attaching to ([0-9]+)", result).groups()
    assert matches == (str(pid),)

    assert re.search(rf"Detaching from program: {binary_path}, process {pid}", result)


@pytest.mark.skipif(can_attach is False, reason=REASON_CANNOT_ATTACH)
def test_attachp_command_attaches_to_pid(launched_bash_binary):
    pid, binary_path = launched_bash_binary

    result = run_gdb_with_script(pyafter=f"attachp {pid}")

    matches = re.search(r"Attaching to ([0-9]+)", result).groups()
    assert matches == (str(pid),)

    assert re.search(rf"Detaching from program: {binary_path}, process {pid}", result)


@pytest.mark.skipif(can_attach is False, reason=REASON_CANNOT_ATTACH)
def test_attachp_command_attaches_to_procname_resolve_none(launched_bash_binary):
    pid, binary_path = launched_bash_binary

    process = subprocess.Popen(
        [binary_path] + ["-i"] * 1000, stdout=subprocess.PIPE, stdin=subprocess.PIPE
    )

    binary_name = binary_path.split("/")[-1]
    result = run_gdb_with_script(
        pyafter=["set attachp-resolution-method none", f"attachp {binary_name}"]
    )

    process.kill()

    regex = r"pid +user +elapsed +command\n"
    regex += r"-+  -+  -+  -+\n"
    regex += r" *([0-9]+) +(\S+) +[0-9:-]+ +(.*)\n"
    regex += r" *([0-9]+) +(\S+) +[0-9:-]+ +(.*)\n"
    regex += r"use `attach \<pid\>` to attach\n"
    matches = re.search(regex, result).groups()

    expected = (str(pid), getpass.getuser(), binary_path, str(process.pid), getpass.getuser())

    assert matches[:-1] == expected
    assert matches[-1].startswith(f"{binary_path} -i -i") and " ... " in matches[-1]


@pytest.mark.skipif(can_attach is False, reason=REASON_CANNOT_ATTACH)
def test_attachp_command_attaches_to_procname_resolve_none_no_truncate(launched_bash_binary):
    pid, binary_path = launched_bash_binary

    process = subprocess.Popen(
        [binary_path] + ["-i"] * 1000, stdout=subprocess.PIPE, stdin=subprocess.PIPE
    )

    binary_name = binary_path.split("/")[-1]
    result = run_gdb_with_script(
        pyafter=["set attachp-resolution-method none", f"attachp --no-truncate {binary_name}"]
    )

    process.kill()

    regex = r"pid +user +elapsed +command\n"
    regex += r"-+  -+  -+  -+\n"
    regex += r" *([0-9]+) +(\S+) +[0-9:-]+ +(.*)\n"
    regex += r" *([0-9]+) +(\S+) +[0-9:-]+ +(.*)\n"
    regex += r"(?: +-?(?: -i)+(?: | -)?\n)+"
    regex += r"use `attach \<pid\>` to attach\n"
    matches = re.search(regex, result).groups()

    expected = (str(pid), getpass.getuser(), binary_path, str(process.pid), getpass.getuser())

    assert matches[:-1] == expected
    assert matches[-1].startswith(f"{binary_path} -i -i")


@pytest.mark.skipif(can_attach is False, reason=REASON_CANNOT_ATTACH)
def test_attachp_command_attaches_to_procname_resolve_ask(launched_bash_binary):
    pid, binary_path = launched_bash_binary

    process = subprocess.Popen(
        [binary_path] + ["-i"] * 1000, stdout=subprocess.PIPE, stdin=subprocess.PIPE
    )

    binary_name = binary_path.split("/")[-1]
    result = run_gdb_with_script(
        pyafter=["set attachp-resolution-method ask", f"attachp {binary_name}"],
        stdin_input=b"0\n1\n",
    )

    process.kill()

    regex = r"pid +user +elapsed +command\n"
    regex += r"-+  -+  -+  -+  -+\n"
    regex += r" 1 +([0-9]+) +(\S+) +[0-9:-]+ +(.*)\n"
    regex += r" 2 +([0-9]+) +(\S+) +[0-9:-]+ +(.*)\n"
    regex += r"which process to attach\?\(1-2\) "
    regex += r"which process to attach\?\(1-2\) "
    matches = re.search(regex, result).groups()

    expected = (
        str(pid),
        getpass.getuser(),
        binary_path,
        str(process.pid),
        getpass.getuser(),
    )

    assert matches[:-1] == expected
    assert matches[-1].startswith(f"{binary_path} -i -i") and " ... " in matches[-1]

    matches = re.search(r"Attaching to ([0-9]+)", result).groups()
    assert matches == (str(pid),)

    assert re.search(rf"Detaching from program: {binary_path}, process {pid}", result)


@pytest.mark.skipif(can_attach is False, reason=REASON_CANNOT_ATTACH)
def test_attachp_command_attaches_to_procname_resolve_oldest(launched_bash_binary):
    pid, binary_path = launched_bash_binary

    process = subprocess.Popen(
        [binary_path] + ["-i"] * 1000, stdout=subprocess.PIPE, stdin=subprocess.PIPE
    )

    binary_name = binary_path.split("/")[-1]
    result = run_gdb_with_script(
        pyafter=["set attachp-resolution-method oldest", f"attachp {binary_name}"]
    )

    process.kill()

    matches = re.search(r"Attaching to ([0-9]+)", result).groups()
    assert matches == (str(pid),)

    assert re.search(rf"Detaching from program: {binary_path}, process {pid}", result)


@pytest.mark.skipif(can_attach is False, reason=REASON_CANNOT_ATTACH)
def test_attachp_command_attaches_to_procname_resolve_newest(launched_bash_binary):
    pid, binary_path = launched_bash_binary

    process = subprocess.Popen(
        [binary_path] + ["-i"] * 1000, stdout=subprocess.PIPE, stdin=subprocess.PIPE
    )

    binary_name = binary_path.split("/")[-1]
    result = run_gdb_with_script(
        pyafter=["set attachp-resolution-method newest", f"attachp {binary_name}"]
    )

    process.kill()

    matches = re.search(r"Attaching to ([0-9]+)", result).groups()
    assert matches == (str(process.pid),)

    assert re.search(rf"Detaching from program: {binary_path}, process {process.pid}", result)


@pytest.mark.skipif(can_attach is False, reason=REASON_CANNOT_ATTACH)
def test_attachp_command_nonexistent_procname():
    result = run_gdb_with_script(
        pyafter="attachp some-nonexistent-process-name"
    )  # No chance there is a process name like this
    assert "Process some-nonexistent-process-name not found" in result


def test_attachp_command_no_pids():
    try:
        # On some machines/GDB versions this halts/waits forever, so we add a timeout here
        result = run_gdb_with_script(
            pyafter="attachp 99999999", timeout=5
        )  # No chance there is a PID like this
    except subprocess.TimeoutExpired:
        # Assume it works
        return

    assert "Error: ptrace: No such process." in result
