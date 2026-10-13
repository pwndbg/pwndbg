from __future__ import annotations

import re

import pytest

from ....host import Controller
from . import get_binary
from . import pwndbg_test

NO_SECTS_BINARY = get_binary("gosample.i386.out")
PIE_BINARY_WITH_PLT = "reference_bin_pie.native.out"
NOPIE_BINARY_WITH_PLT = "reference_bin_nopie.native.out"
NOPIE_I386_BINARY_WITH_PLT = "reference_bin_nopie.i386.out"
STATIC_BINARY_WITH_IFUNC = get_binary("static_ifunc.native.out")


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

        assert len(out) >= 2
        assert re.match(r"Section \.plt 0x[0-9a-f]+ - 0x[0-9a-f]+:", out[0])
        line_puts = next((line for line in out if "puts" in line), "")
        assert re.match(r"0x[0-9a-f]+: puts(@plt)?", line_puts)

    await ctrl.launch(binary)

    out2 = (await ctrl.execute_and_capture("plt -a")).splitlines()

    assert len(out2) >= 2
    assert re.match(r"Section \.plt 0x[0-9a-f]+ - 0x[0-9a-f]+:", out2[0])
    line_puts = next((line for line in out2 if "puts" in line), "")
    assert re.match(r"0x[0-9a-f]+: puts(@plt)?", line_puts)

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
    import pwndbg.aglib

    binary = get_binary(binary_name)

    await ctrl.launch(binary)

    if pwndbg.aglib.arch.name != "x86-64":
        pytest.skip("TODO multiarch")

    out = (await ctrl.execute_and_capture("elf")).splitlines()
    # Newer versions of gcc emit an additional `.sframe` section.
    assert len(out) == 25 or len(out) == 26

    # test for default
    for section in out[2:]:
        assert re.match(
            r"^\s*0x[\da-fA-F]+\s+0x[\da-fA-F]+\s+(?:[RWX-]{3})\s+0x[\da-fA-F]+\s+\.([^\s]+)$",
            section,
        )
        if is_pie:
            address = section.split()
            addr = int(address[0], 16)
            assert 0x0000550000000000 <= addr <= 0x00007FFFFFFFFFFF

    # if this is a pie binary, test for --no-rebase
    if is_pie:
        out = (await ctrl.execute_and_capture("elf -R")).splitlines()
        # Never versions of gcc emit an additional `.sframe` section.
        assert len(out) == 25 or len(out) == 26

        for section in out[2:]:
            assert re.match(
                r"^\s*0x[\da-fA-F]+\s+0x[\da-fA-F]+\s+(?:[RWX-]{3})\s+0x[\da-fA-F]+\s+\.([^\s]+)$",
                section,
            )


@pwndbg_test
async def test_command_got_for_static_binary(ctrl: Controller) -> None:
    import pwndbg.aglib
    import pwndbg.aglib.elf
    import pwndbg.aglib.symbol

    await ctrl.launch(STATIC_BINARY_WITH_IFUNC)

    if pwndbg.aglib.arch.name != "x86-64":
        # pyelftools does not name IRELATIVE relocations correctly on aarch64, arm and riscv
        pytest.skip("TODO multiarch")

    # The slot of the ifunc is the only one in .got.plt. Its IRELATIVE relocation has no
    # symbol, so the entry is named after its addend: the address of the resolver
    got_plt = pwndbg.aglib.elf.section_by_name(str(STATIC_BINARY_WITH_IFUNC), ".got.plt")
    assert got_plt is not None
    resolver = pwndbg.aglib.symbol.lookup_symbol_addr("resolve_one")

    out = (await ctrl.execute_and_capture("got")).splitlines()
    assert out == [
        "Filtering out read-only entries (display them with -r or --show-readonly)",
        "",
        f"State of the GOT of {STATIC_BINARY_WITH_IFUNC}:",
        "GOT protection: Partial RELRO | Found 1 GOT entries passing the filter",
        f"[{got_plt[0]:#x}] *ABS*+{resolver:#x} -> 0",
    ]
