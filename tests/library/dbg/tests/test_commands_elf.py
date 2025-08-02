from __future__ import annotations

import re

import pytest

from ....host import Controller
from . import get_binary
from . import pwndbg_test

NO_SECTS_BINARY = get_binary("gosample.x86")
PIE_BINARY_WITH_PLT = "reference_bin_pie.out"
NOPIE_BINARY_WITH_PLT = "reference_bin_nopie.out"
NOPIE_I386_BINARY_WITH_PLT = "reference_bin_nopie.i386.out"


@pwndbg_test
async def test_commands_plt_gotplt_got_when_no_sections(ctrl: Controller) -> None:
    await ctrl.launch(NO_SECTS_BINARY)

    # elf.py commands
    assert (await ctrl.execute_and_capture("plt")) == "No .plt.* sections found\n"
    assert (await ctrl.execute_and_capture("gotplt")) == "Could not find section .got.plt\n"


@pytest.mark.parametrize(
    "binary_name,is_pie", ((PIE_BINARY_WITH_PLT, True), (NOPIE_BINARY_WITH_PLT, False))
)
@pwndbg_test
async def test_command_plt(ctrl: Controller, binary_name: str, is_pie: bool) -> None:
    import pwndbg

    binary = get_binary(binary_name)

    if pwndbg.dbg.is_gdblib_available():
        # Currently only GDB has pre-launch inferiors that let us run commands
        # like `plt`.
        import gdb

        gdb.execute(f"file {binary}")

        out = gdb.execute("plt -a", to_string=True).splitlines()

        assert len(out) == 2
        assert re.match(r"Section \.plt 0x[0-9a-f]+ - 0x[0-9a-f]+:", out[0])
        assert re.match(r"0x[0-9a-f]+: puts(@plt)?", out[1])

    await ctrl.launch(binary)

    out2 = (await ctrl.execute_and_capture("plt -a")).splitlines()

    assert len(out2) == 2
    assert re.match(r"Section \.plt 0x[0-9a-f]+ - 0x[0-9a-f]+:", out2[0])
    assert re.match(r"0x[0-9a-f]+: puts(@plt)?", out2[1])

    if pwndbg.dbg.is_gdblib_available():
        if is_pie:
            assert out != out2
        else:
            assert out == out2


@pytest.mark.parametrize(
    "binary_name,is_pie", ((NOPIE_BINARY_WITH_PLT, False), (PIE_BINARY_WITH_PLT, True))
)
@pwndbg_test
async def test_command_elf(ctrl: Controller, binary_name: str, is_pie: bool) -> None:
    binary = get_binary(binary_name)

    await ctrl.launch(binary)

    out = (await ctrl.execute_and_capture("elf")).splitlines()
    assert len(out) == 25

    # test for default
    for section in out[2:]:
        assert re.match(
            r"^\s*0x[\da-fA-F]+\s+0x[\da-fA-F]+\s+(?:[RWX-]{3})\s+0x[\da-fA-F]+\s+\.([^\s]+)$",
            section,
        )
        if is_pie:
            address = section.split()
            assert address[0].startswith("0x55555555")

    # if this is a pie binary, test for --no-rebase
    if is_pie:
        out = (await ctrl.execute_and_capture("elf -R")).splitlines()
        assert len(out) == 25

        for section in out[2:]:
            assert re.match(
                r"^\s*0x[\da-fA-F]+\s+0x[\da-fA-F]+\s+(?:[RWX-]{3})\s+0x[\da-fA-F]+\s+\.([^\s]+)$",
                section,
            )
