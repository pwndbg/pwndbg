from __future__ import annotations

from ....host import Controller
from . import get_binary
from . import pwndbg_test

REFERENCE_BINARY = get_binary("reference-binary.native.out")


def inferior_args() -> list[str]:
    import pwndbg.aglib.argv
    import pwndbg.aglib.memory

    args = []
    for i in range(1, pwndbg.aglib.argv.argc()):
        arg = pwndbg.aglib.argv.argv(i)
        assert arg is not None
        args.append(pwndbg.aglib.memory.string(int(arg)).decode())
    return args


@pwndbg_test
async def test_launch_uses_configured_args(ctrl: Controller) -> None:
    """
    Launching without arguments uses the ones configured in the debugger
    (`set args` in GDB, `target.run-args` in LLDB)
    """
    import pwndbg
    from pwndbg.dbg_mod import DebuggerType

    if pwndbg.dbg.name() == DebuggerType.GDB:
        await ctrl.execute("set args foo bar")
    else:
        await ctrl.execute("settings set -- target.run-args foo bar")

    await ctrl.launch(REFERENCE_BINARY)
    assert inferior_args() == ["foo", "bar"]


@pwndbg_test
async def test_launch_saves_args(ctrl: Controller) -> None:
    """
    Launching with arguments saves them for subsequent runs
    """
    import pwndbg
    from pwndbg.dbg_mod import DebuggerType

    await ctrl.launch(REFERENCE_BINARY, args=["foo", "bar"])
    assert inferior_args() == ["foo", "bar"]

    if pwndbg.dbg.name() == DebuggerType.GDB:
        result = await ctrl.execute_and_capture("show args")
        assert '"foo bar"' in result
    else:
        result = await ctrl.execute_and_capture("settings show target.run-args")
        assert '[0]: "foo"' in result
        assert '[1]: "bar"' in result
