from __future__ import annotations

import os
import shutil
import signal
import subprocess

import gdb

import pwndbg.aglib.proc
import tests

REFERENCE_BINARY_NET = tests.binaries.get("reference-binary-net.out")


def test_command_procinfo(start_binary):
    start_binary(REFERENCE_BINARY_NET)

    # Check if netcat exists
    nc_path = shutil.which("nc")
    assert nc_path is not None, "netcat is not installed"

    # Spawn netcat
    netcat_process = subprocess.Popen(
        [nc_path, "-l", "-p", "31337"],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )

    bin_path = pwndbg.aglib.proc.exe
    pid = str(pwndbg.aglib.proc.pid)

    gdb.execute("break break_here")
    gdb.execute("continue")

    result = gdb.execute("procinfo", to_string=True)
    res_list = result.split("\n")

    assert bin_path in res_list[0]
    assert pid in res_list[3]
    assert "127.0.0.1:31337" in result

    # Close netcat
    os.killpg(os.getpgid(netcat_process.pid), signal.SIGTERM)


def test_command_procinfo_before_binary_start():
    result = gdb.execute("procinfo", to_string=True)
    assert "The program is not being run" in result
