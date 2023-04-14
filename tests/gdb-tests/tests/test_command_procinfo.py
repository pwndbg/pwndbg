import os
import shutil

import gdb

import tests

REFERENCE_BINARY_NET = tests.binaries.get("reference-binary-net.out")


def test_command_procinfo(start_binary):
    start_binary(REFERENCE_BINARY_NET)

    # Sanity check, netcat must exist at this point
    assert shutil.which("nc") is not None
    os.system("nc -l -p 31337 2>/dev/null 1>&2 &")

    bin_path = gdb.execute("pi pwndbg.gdblib.proc.exe", to_string=True).strip("\n")
    pid = gdb.execute("pi pwndbg.gdblib.proc.pid", to_string=True).strip("\n")

    gdb.execute("break break_here")
    gdb.execute("continue")

    result = gdb.execute("procinfo", to_string=True)
    res_list = result.split("\n")

    assert bin_path in res_list[0]
    assert pid in res_list[1]
    assert "127.0.0.1:31337" in result


def test_command_procinfo_before_binary_start():
    result = gdb.execute("procinfo", to_string=True)
    assert "The program is not being run" in result
