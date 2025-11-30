from __future__ import annotations

import pytest

from ....host import Controller
from . import break_at_sym
from . import get_binary
from . import launch_to
from . import pwndbg_test

REFERENCE_BINARY = get_binary("reference-binary.out")
CRASH_SIMPLE_BINARY = get_binary("crash_simple.out.hardcoded")

NEXT_COMMANDS = (
    "pc",
    "nextcall",
    "nextjmp",
    "nextproginstr",
    "nextret",
    "nextsyscall",
    "stepret",
    "stepsyscall",
)


@pwndbg_test
async def test_command_nextproginstr(ctrl: Controller) -> None:
    import pwndbg.aglib.proc
    import pwndbg.aglib.regs
    import pwndbg.aglib.vmmap

    await launch_to(ctrl, REFERENCE_BINARY, "main")

    out = await ctrl.execute_and_capture("nextproginstr")
    assert out == "The pc is already at the binary objfile code. Not stepping.\n"

    # Sanity check
    exec_bin_pages = [
        p for p in pwndbg.aglib.vmmap.get() if p.objfile == pwndbg.aglib.proc.exe and p.execute
    ]
    assert any(pwndbg.aglib.regs.pc in p for p in exec_bin_pages)
    main_page = pwndbg.aglib.vmmap.find(pwndbg.aglib.regs.pc)

    break_at_sym("puts")
    await ctrl.cont()

    # Sanity check that we are in libc
    assert "libc" in pwndbg.aglib.vmmap.find(pwndbg.aglib.regs.rip).objfile

    # Execute nextproginstr and see if we came back to the same vmmap page
    await ctrl.execute("nextproginstr")
    assert pwndbg.aglib.regs.pc in main_page

    # Ensure that nextproginstr won't jump now
    out = await ctrl.execute_and_capture("nextproginstr")
    assert out == "The pc is already at the binary objfile code. Not stepping.\n"


@pytest.mark.parametrize("command", NEXT_COMMANDS)
@pwndbg_test
async def test_next_command_doesnt_freeze_crashed_binary(ctrl: Controller, command: str) -> None:
    import pwndbg.aglib.regs

    await ctrl.launch(CRASH_SIMPLE_BINARY)

    # The nextproginstr won't step if we are already on the binary address
    # and interestingly, other commands won't step if the address can't be disassemblied
    if command == "nextproginstr":
        pwndbg.aglib.regs.pc = 0x1234

    # This should not halt/freeze the program
    await ctrl.execute(command)
