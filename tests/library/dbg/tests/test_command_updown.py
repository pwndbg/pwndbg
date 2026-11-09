from __future__ import annotations

import pytest

from ....host import Controller
from . import get_binary
from . import launch_to
from . import pwndbg_test

REFERENCE_BINARY = get_binary("reference-binary.native.out")


@pwndbg_test
async def test_command_updown(ctrl: Controller) -> None:
    import pwndbg
    from pwndbg.dbg_mod import DebuggerType

    if pwndbg.dbg.name() != DebuggerType.GDB:
        pytest.skip("up/down are only overridden by Pwndbg in GDB")
        return

    import gdb

    await launch_to(ctrl, REFERENCE_BINARY, "break_here")

    frame_info_before = gdb.parameter("print frame-info")

    await ctrl.execute("up")
    assert gdb.selected_frame().name() == "main"

    # `list` must be centered on the caller's line (the `break_here();` call in main),
    # not on `break_here` itself (see #632).
    assert "8\t    break_here();" in gdb.execute("list", to_string=True)

    # `up` temporarily changes `print frame-info` and must put it back (see #4186).
    assert gdb.parameter("print frame-info") == frame_info_before

    # The same has to hold for `down`, also with a non-default value.
    gdb.execute("set print frame-info source-and-location")
    await ctrl.execute("down")
    assert gdb.selected_frame().name() == "break_here"
    assert gdb.parameter("print frame-info") == "source-and-location"
