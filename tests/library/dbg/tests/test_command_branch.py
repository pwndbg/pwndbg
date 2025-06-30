from __future__ import annotations

import pytest
from host import Controller

import tests

CONDBR_X64_BINARY = tests.get_binary("conditional_branch_breakpoints_x64.out")


@tests.pwndbg_test
@pytest.mark.parametrize("binary", [CONDBR_X64_BINARY], ids=["x86-64"])
async def test_command_break_if_x64(ctrl: Controller, binary: str) -> None:
    """
    Tests the chain for a non-nested linked list
    """
    import pwndbg

    if not pwndbg.dbg.is_gdblib_available():
        # Not yet available outside GDB.
        return

    await tests.launch_to(ctrl, binary, "break_here")

    tests.break_at_sym("break_here0")
    tests.break_at_sym("break_here1")

    await ctrl.execute("break-if-taken branch0")
    await ctrl.execute("break-if-taken branch1")
    await ctrl.execute("break-if-not-taken branch2")
    await ctrl.execute("break-if-not-taken branch3")

    await continue_and_test_pc(ctrl, "branch0")
    await continue_and_test_pc(ctrl, "break_here0")
    await continue_and_test_pc(ctrl, "break_here1")
    await continue_and_test_pc(ctrl, "branch3")


async def continue_and_test_pc(ctrl: Controller, stop_label: str) -> None:
    import pwndbg

    await ctrl.cont()

    address = int(pwndbg.dbg.selected_inferior().lookup_symbol(stop_label))
    assert pwndbg.aglib.regs.pc == address
