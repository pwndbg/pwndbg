from __future__ import annotations

import re

import pytest

from ....host import Controller
from . import get_binary
from . import pwndbg_test

REFERENCE_BINARY = get_binary("reference-binary.native.out")


@pwndbg_test
async def test_config(ctrl: Controller) -> None:
    await ctrl.launch(REFERENCE_BINARY)

    await ctrl.execute("set context-disasm-lines 8")
    assert "8 (10)" in (await ctrl.execute_and_capture("config"))

    await ctrl.execute("set banner-separator #")
    # \u2500 is ─
    assert "'#' ('\u2500')" in (await ctrl.execute_and_capture("theme"))


@pwndbg_test
async def test_config_filtering(ctrl: Controller) -> None:
    await ctrl.launch(REFERENCE_BINARY)

    out = (await ctrl.execute_and_capture("config context-disasm-lines")).splitlines()

    assert re.match(r"Name\s+Documentation\s+Value\s+\(Default\)", out[0])
    assert re.match(r"-+", out[1])
    assert re.match(
        r"context-disasm-lines\s+number of additional lines to print in the disasm context\s+10",
        out[2],
    )
    assert (
        out[3]
        == "You can set a config variable with `set <config-var> <value>`, and read more about it with `help set <config-var>`."
    )
    assert (
        out[4]
        == "You can generate a configuration file using `configfile` - then put it in your .gdbinit after initializing pwndbg."
    )


@pwndbg_test
async def test_config_filtering_missing(ctrl: Controller):
    await ctrl.launch(REFERENCE_BINARY)

    out = await ctrl.execute_and_capture("config asdasdasdasd")
    assert out == 'No config parameter found with filter "asdasdasdasd"\n'


@pwndbg_test
async def test_config_color_validation(ctrl: Controller) -> None:
    import pwndbg
    from pwndbg.dbg_mod import DebuggerType
    from pwndbg.dbg_mod import Error

    await ctrl.launch(REFERENCE_BINARY)

    # set valid color
    await ctrl.execute("set telescope-register-color red,bold")
    assert "red,bold" in (await ctrl.execute_and_capture("theme telescope-register-color"))
    if pwndbg.dbg.name() == DebuggerType.GDB:
        assert "red,bold" in (await ctrl.execute_and_capture("show telescope-register-color"))

    # set invalid color
    if pwndbg.dbg.name() == DebuggerType.GDB:
        with pytest.raises(Error, match="Invalid color 'meow'"):
            await ctrl.execute("set telescope-register-color meow")
    else:
        ret = await ctrl.execute_and_capture("set telescope-register-color meow")
        assert "error" in ret and "invalid color" in ret

    # check that it was successfully reverted
    assert "red,bold" in (await ctrl.execute_and_capture("theme telescope-register-color"))
    if pwndbg.dbg.name() == DebuggerType.GDB:
        assert "red,bold" in (await ctrl.execute_and_capture("show telescope-register-color"))


@pwndbg_test
async def test_can_add_new_colours(ctrl: Controller) -> None:
    import pwndbg
    from pwndbg.color import color
    from pwndbg.dbg_mod import DebuggerType
    from pwndbg.dbg_mod import Error

    await ctrl.launch(REFERENCE_BINARY)

    # set valid color
    await ctrl.execute("set telescope-register-color red,bold")
    assert "red,bold" in (await ctrl.execute_and_capture("theme telescope-register-color"))
    if pwndbg.dbg.name() == DebuggerType.GDB:
        assert "red,bold" in (await ctrl.execute_and_capture("show telescope-register-color"))

    # set invalid color
    if pwndbg.dbg.name() == DebuggerType.GDB:
        with pytest.raises(Error, match="Invalid color 'meow'"):
            await ctrl.execute("set telescope-register-color meow")
    else:
        ret = await ctrl.execute_and_capture("set telescope-register-color meow")
        assert "error" in ret and "invalid color" in ret

    # register a new colour
    @color
    def meow(s: str) -> str:
        return f"foo {s} bar"

    await ctrl.execute("set telescope-register-color meow")

    assert "meow" in (await ctrl.execute_and_capture("theme telescope-register-color"))
    if pwndbg.dbg.name() == DebuggerType.GDB:
        assert "meow" in (await ctrl.execute_and_capture("show telescope-register-color"))
