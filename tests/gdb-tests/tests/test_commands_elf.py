import re

import gdb

import tests

NO_SECTS_BINARY = tests.binaries.get("gosample.x86")
REFERENCE_BINARY = tests.binaries.get("reference-binary.out")


def test_commands_plt_gotplt_no_section(start_binary):
    start_binary(NO_SECTS_BINARY)
    assert gdb.execute("plt", to_string=True) == "Could not find section .plt\n"
    assert gdb.execute("gotplt", to_string=True) == "Could not find section .got.plt\n"


def test_command_plt():
    gdb.execute(f"file {REFERENCE_BINARY}")

    out = gdb.execute("plt", to_string=True).splitlines()

    assert len(out) == 2
    assert re.match(r"Section \.plt 0x[0-9a-f]+-0x[0-9a-f]+:", out[0])
    assert re.match(r"0x[0-9a-f]+: puts@plt", out[1])

    gdb.execute("starti")

    out2 = gdb.execute("plt", to_string=True).splitlines()

    assert out != out2

    assert len(out2) == 2
    assert re.match(r"Section \.plt 0x[0-9a-f]+-0x[0-9a-f]+:", out2[0])
    assert re.match(r"0x[0-9a-f]+: puts@plt", out2[1])
