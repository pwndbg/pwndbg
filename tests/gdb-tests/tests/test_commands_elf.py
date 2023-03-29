import re

import gdb
import pytest

import tests

NO_SECTS_BINARY = tests.binaries.get("gosample.x86")
PIE_BINARY_WITH_PLT = "reference_bin_pie.out"
NOPIE_BINARY_WITH_PLT = "reference_bin_nopie.out"


def test_commands_plt_gotplt_got_when_no_sections(start_binary):
    start_binary(NO_SECTS_BINARY)

    # elf.py commands
    assert gdb.execute("plt", to_string=True) == "Could not find section .plt\n"
    assert gdb.execute("gotplt", to_string=True) == "Could not find section .got.plt\n"

    # got.py command
    assert gdb.execute("got", to_string=True) == "NO JUMP_SLOT entries available in the GOT\n"


@pytest.mark.parametrize(
    "binary_name,is_pie", ((PIE_BINARY_WITH_PLT, True), (NOPIE_BINARY_WITH_PLT, False))
)
def test_command_plt(binary_name, is_pie):
    binary = tests.binaries.get(binary_name)
    gdb.execute(f"file {binary}")

    out = gdb.execute("plt", to_string=True).splitlines()

    assert len(out) == 2
    assert re.match(r"Section \.plt 0x[0-9a-f]+-0x[0-9a-f]+:", out[0])
    assert re.match(r"0x[0-9a-f]+: puts@plt", out[1])

    gdb.execute("starti")

    out2 = gdb.execute("plt", to_string=True).splitlines()

    if is_pie:
        assert out != out2
    else:
        assert out == out2

    assert len(out2) == 2
    assert re.match(r"Section \.plt 0x[0-9a-f]+-0x[0-9a-f]+:", out2[0])
    assert re.match(r"0x[0-9a-f]+: puts@plt", out2[1])


@pytest.mark.parametrize(
    "binary_name,is_pie", ((PIE_BINARY_WITH_PLT, True), (NOPIE_BINARY_WITH_PLT, False))
)
def test_command_got(binary_name, is_pie):
    binary = tests.binaries.get(binary_name)
    gdb.execute(f"file {binary}")

    out = gdb.execute("got", to_string=True).splitlines()

    assert out == ["got: The program is not being run."]

    gdb.execute("starti")

    out2 = gdb.execute("got", to_string=True).splitlines()

    assert out != out2

    assert len(out2) == 2
    assert out2[0] == "GOT protection: Full RELRO | GOT functions: 1"
    assert re.match(r"\[0x[0-9a-f]+\] puts@GLIBC_[0-9.]+ -> .*", out2[1])
