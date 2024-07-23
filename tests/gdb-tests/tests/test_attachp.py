from __future__ import annotations

import getpass
import os
import re
import subprocess
import tempfile

import pytest
import time
from unittest.mock import patch, MagicMock

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
    bash_path = subprocess.check_output(["which", "bash"]).decode().strip()
    subprocess.check_output(["cp", bash_path, path])

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

@pytest.mark.skipif(can_attach is False, reason=REASON_CANNOT_ATTACH)
def test_attachp_retry_successful():
    # Mock the process creation to simulate a process starting after a delay
    with patch('subprocess.Popen') as mock_popen:
        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_popen.side_effect = [
            subprocess.CalledProcessError(1, 'pidof'),  # First attempt fails
            MagicMock(return_value=mock_process)  # Second attempt succeeds
        ]

        result = run_gdb_with_script(
            pyafter="attachp --retry --retry-interval 0.1 test_process"
        )

        assert "Process test_process not found. Retrying in 0.1 seconds..." in result
        assert "Attaching to 12345" in result
        assert mock_popen.call_count == 2

@pytest.mark.skipif(can_attach is False, reason=REASON_CANNOT_ATTACH)
def test_attachp_retry_timeout():
    # Mock the process creation to simulate a process that never starts
    with patch('subprocess.Popen') as mock_popen:
        mock_popen.side_effect = subprocess.CalledProcessError(1, 'pidof')

        result = run_gdb_with_script(
            pyafter="attachp --retry --retry-interval 0.1 --retry-timeout 0.5 test_process"
        )

        assert "Process test_process not found. Retrying in 0.1 seconds..." in result
        assert "Retry timeout reached after 0.5 seconds" in result
        assert mock_popen.call_count > 1

@pytest.mark.skipif(can_attach is False, reason=REASON_CANNOT_ATTACH)
def test_attachp_retry_multiple_processes():
    # Mock the process creation to simulate multiple processes starting after a delay
    with patch('subprocess.Popen') as mock_popen, \
         patch('subprocess.check_output') as mock_check_output:
        mock_process1 = MagicMock()
        mock_process1.pid = 12345
        mock_process2 = MagicMock()
        mock_process2.pid = 12346
        
        mock_popen.side_effect = [
            subprocess.CalledProcessError(1, 'pidof'),  # First attempt fails
            MagicMock(return_value=[mock_process1, mock_process2])  # Second attempt succeeds with multiple processes
        ]
        mock_check_output.return_value = b"12345 12346"

        result = run_gdb_with_script(
            pyafter="attachp --retry --retry-interval 0.1 test_process",
            stdin_input=b"1\n"  # Select the first process
        )

        assert "Process test_process not found. Retrying in 0.1 seconds..." in result
        assert "Multiple processes found" in result
        assert "Attaching to 12345" in result
        assert mock_popen.call_count == 2

@pytest.mark.skipif(can_attach is False, reason=REASON_CANNOT_ATTACH)
def test_attachp_retry_with_existing_process():
    # Mock the process creation to simulate an already existing process
    with patch('subprocess.Popen') as mock_popen:
        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_popen.return_value = mock_process

        result = run_gdb_with_script(
            pyafter="attachp --retry --retry-interval 0.1 test_process"
        )

        assert "Attaching to 12345" in result
        assert mock_popen.call_count == 1
        assert "Retrying" not in result

@pytest.mark.skipif(can_attach is False, reason=REASON_CANNOT_ATTACH)
def test_attachp_retry_with_gdb_error():
    # Mock the process creation and gdb.execute to simulate a GDB error
    with patch('subprocess.Popen') as mock_popen, \
         patch('gdb.execute') as mock_gdb_execute:
        mock_process = MagicMock()
        mock_process.pid = 12345
        mock_popen.return_value = mock_process
        mock_gdb_execute.side_effect = [
            gdb.error("Test GDB error"),  # First attempt fails
            None  # Second attempt succeeds
        ]

        result = run_gdb_with_script(
            pyafter="attachp --retry --retry-interval 0.1 test_process"
        )

        assert "Attaching to 12345" in result
        assert "Error: Test GDB error" in result
        assert "Failed to attach. Retrying in 0.1 seconds..." in result
        assert mock_gdb_execute.call_count == 2