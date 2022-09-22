import gdb

import tests

REFERENCE_BINARY = tests.binaries.get("reference-binary.out")


def test_command_procinfo(start_binary):
    start_binary(REFERENCE_BINARY)

    bin_path = gdb.execute("pi pwndbg.proc.exe", to_string=True).strip("\n")
    pid = gdb.execute("pi pwndbg.proc.pid", to_string=True).strip("\n")
    result = gdb.execute("procinfo", to_string=True)
    res_list = result.split("\n")

    assert bin_path in res_list[0]
    assert pid in res_list[1]


def test_command_procinfo_before_binary_start():
    result = gdb.execute("procinfo", to_string=True)
    assert "The program is not being run" in result
