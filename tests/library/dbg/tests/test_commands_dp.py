from __future__ import annotations

import pytest

from ....host import Controller
from . import get_binary
from . import pwndbg_test

EXITHANDLERS_BINARY = get_binary("exithandlers.native.out")


@pwndbg_test
async def test_command_dp(ctrl: Controller) -> None:
    """
    Tests that dp prints a formatted message, including the caller chain, on
    every breakpoint hit.
    """
    import pwndbg
    from pwndbg.dbg_mod import DebuggerType

    if pwndbg.dbg.name() != DebuggerType.GDB:
        pytest.skip("The LLDB test harness cannot capture output printed from a stop handler")
        return

    await ctrl.launch(EXITHANDLERS_BINARY)

    # The breakpoint is set by symbol, before the program has started running,
    # so this also covers position independent executables.
    await ctrl.execute('dp break_here "hit(%d)" 42 -d 1')
    output = await ctrl.execute_and_capture("continue")

    assert "main > hit(42)" in output
