from __future__ import annotations

import pytest

from ....host import Controller
from . import break_at_sym
from . import get_binary
from . import launch_to
from . import pwndbg_test

CONDBR_X64_BINARY = get_binary("conditional_branch_breakpoints_x64.out")


@pwndbg_test
@pytest.mark.parametrize("binary", [CONDBR_X64_BINARY], ids=["x86-64"])
async def test_command_break_if_x64(ctrl: Controller, binary: str) -> None:
    """
    Tests the chain for a non-nested linked list
    """
    import pwndbg

    if not pwndbg.dbg.is_gdblib_available():
        pytest.skip("Not yet available outside GDB")
        return

    await launch_to(ctrl, binary, "break_here")

    break_at_sym("break_here0")
    break_at_sym("break_here1")

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
