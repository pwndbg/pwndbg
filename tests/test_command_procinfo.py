import gdb

import tests

REFERENCE_BINARY = tests.binaries.get("reference-binary.out")


def test_command_procinfo(start_binary):
    start_binary(REFERENCE_BINARY)

    gdb.execute("entry")
    bin_path = gdb.execute("pi pwndbg.proc.exe", to_string=True).strip("\n")
    pid = gdb.execute("pi pwndbg.proc.pid", to_string=True).strip("\n")
    result = gdb.execute("procinfo", to_string=True)
    res_list = result.split("\n")

    assert bin_path in res_list[0]
    assert pid in res_list[1]
