from __future__ import annotations

import pytest

from ....host import Controller
from . import break_at_sym
from . import get_binary
from . import launch_to
from . import pwndbg_test

REFERENCE_BINARY = get_binary("reference-binary.native.out")
CRASH_SIMPLE_BINARY = get_binary("crash_simple.native.out")

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
    import pwndbg.aglib
    import pwndbg.aglib.proc
    import pwndbg.aglib.vmmap

    await launch_to(ctrl, REFERENCE_BINARY, "main")

    out = await ctrl.execute_and_capture("nextproginstr")
    assert out == "The pc is already at the binary objfile code. Not stepping.\n"

    # Sanity check
    exec_bin_pages = [
        p for p in pwndbg.aglib.vmmap.get() if p.objfile == pwndbg.aglib.proc.exe() and p.execute
    ]
    assert any(pwndbg.aglib.regs.pc in p for p in exec_bin_pages)
    main_page = pwndbg.aglib.vmmap.find(pwndbg.aglib.regs.pc)

    break_at_sym("puts")
    await ctrl.cont()

    # Sanity check that we are in libc
    assert "libc" in pwndbg.aglib.vmmap.find(pwndbg.aglib.regs.pc).objfile

    # Execute nextproginstr and see if we came back to the same vmmap page
    await ctrl.execute("nextproginstr")
    assert pwndbg.aglib.regs.pc in main_page

    # Ensure that nextproginstr won't jump now
    out = await ctrl.execute_and_capture("nextproginstr")
    assert out == "The pc is already at the binary objfile code. Not stepping.\n"


@pytest.mark.parametrize("command", NEXT_COMMANDS)
@pwndbg_test
async def test_next_command_doesnt_freeze_crashed_binary(ctrl: Controller, command: str) -> None:
    import pwndbg.aglib

    await ctrl.launch(CRASH_SIMPLE_BINARY)

    # The nextproginstr won't step if we are already on the binary address
    # and interestingly, other commands won't step if the address can't be disassemblied
    if command == "nextproginstr":
        pwndbg.aglib.regs.pc = 0x1234

    # This should not halt/freeze the program
    await ctrl.execute(command)


LOOP_BINARY = get_binary("loop_instruction_ending_in_ret.x86-64.out")


@pwndbg_test
async def test_nextret_loop(ctrl: Controller) -> None:
    """
    Test nextret on a program that will encounter an loop
    """

    from capstone6pwndbg.x86 import X86_INS_RET

    import pwndbg.aglib.disasm.disassembly

    await ctrl.launch(LOOP_BINARY)

    # WORKAROUND FOR LLDB BUG: https://github.com/pwndbg/pwndbg/issues/4097
    # Need to step once so that nextret works
    await ctrl.step_instruction()

    await ctrl.execute("nextret")

    current_instruction = pwndbg.aglib.disasm.disassembly.one()

    assert current_instruction.id == X86_INS_RET
