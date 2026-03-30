from __future__ import annotations

from pathlib import Path

import pytest

from ....host import Controller
from . import get_binary
from . import pwndbg_test

GOSAMPLE_X64 = get_binary("gosample.x86-64.out")
GOSAMPLE_X86 = get_binary("gosample.i386.out")


@pwndbg_test
@pytest.mark.parametrize("binary", [GOSAMPLE_X64, GOSAMPLE_X86], ids=["x86-64", "i386"])
async def test_go_dumping(ctrl: Controller, binary: Path) -> None:
    import pwndbg
    import pwndbg.commands.godbg
    from pwndbg.dbg_mod import DebuggerType

    if pwndbg.dbg.name() == DebuggerType.LLDB:
        pytest.skip("Go tests are not supported in LLDB")

    await ctrl.launch(binary, env={"GOMAXPROCS": "1"})

    await ctrl.execute("b gosample.native.go:6")
    await ctrl.cont()

    dump = await ctrl.execute_and_capture("go-dump any &x")
    assert dump.strip() == """(map[uint8]uint64) &{1: 2, 3: 4, 5: 6}"""
    await ctrl.cont()

    dump = await ctrl.execute_and_capture("go-dump any &x")
    assert dump.strip() == """(map[string]int) &{"a": 1, "b": 2, "c": 3}"""
    await ctrl.cont()

    dump = await ctrl.execute_and_capture("go-dump any &x")
    assert (
        dump.strip()
        == """([]struct { a int; b string }) [struct {a: 1, b: "first"}, struct {a: 2, b: "second"}]"""
    )
    await ctrl.cont()

    dump = await ctrl.execute_and_capture("go-dump -f 1 any &x")
    assert dump.strip() == """([3]complex64) [(1.1 + 2.2i), (-2.5 - 5.0i), (4.2 - 2.1i)]"""
