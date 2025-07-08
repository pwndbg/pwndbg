from __future__ import annotations

from host import Controller

import tests

GOSAMPLE_X64 = tests.get_binary("gosample.x64")
GOSAMPLE_X86 = tests.get_binary("gosample.x86")


async def helper_test_dump(ctrl: Controller, target: str) -> None:
    await ctrl.launch(target, env={"GOMAXPROCS": "1"})

    await ctrl.execute("b gosample.go:6")
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


@tests.pwndbg_test
async def test_go_dumping_x64(ctrl: Controller) -> None:
    await helper_test_dump(ctrl, GOSAMPLE_X64)


@tests.pwndbg_test
async def test_go_dumping_x86(ctrl: Controller) -> None:
    await helper_test_dump(ctrl, GOSAMPLE_X86)
