from __future__ import annotations

import re

from ....host import Controller
from . import get_binary
from . import get_expr
from . import launch_to
from . import pwndbg_test

TELESCOPE_BINARY = get_binary("telescope_binary.out")


@pwndbg_test
async def test_command_telescope(ctrl: Controller) -> None:
    """
    Tests simple telescope
    """
    await ctrl.execute("set telescope-skip-repeating-val off")
    await launch_to(ctrl, TELESCOPE_BINARY, "break_here")
    await ctrl.execute("up")

    result_str = await ctrl.execute_and_capture("telescope &a")
    result_lines = result_str.split("\n")

    value = get_expr("a")
    fields = value.type.fields()
    for i in range(len(fields)):
        expected_addr = int(value.address) + fields[i].bitpos // 8
        assert f"{expected_addr:x}" in result_lines[fields[i].bitpos // 64]


@pwndbg_test
async def test_command_telescope_reverse(ctrl: Controller) -> None:
    """
    Tests reversed telescope
    """
    await ctrl.execute("set telescope-skip-repeating-val off")
    await launch_to(ctrl, TELESCOPE_BINARY, "break_here")
    await ctrl.execute("up")

    result_str = await ctrl.execute_and_capture("telescope ((uint8_t*)&a)+0x38 -r")
    result_lines = result_str.split("\n")

    value = get_expr("a")
    fields = value.type.fields()
    for i in range(len(fields)):
        expected_addr = int(value.address) + fields[i].bitpos // 8
        assert f"{expected_addr:x}" in result_lines[fields[i].bitpos // 64]


@pwndbg_test
async def test_command_telescope_n_records(ctrl: Controller) -> None:
    """
    Tests telescope defined number of records
    """
    await ctrl.launch(TELESCOPE_BINARY)

    n = 3
    # ???
    # gdb.execute("entry")
    result = (await ctrl.execute_and_capture(f"telescope $rsp {n}")).strip().splitlines()
    assert len(result) == n


@pwndbg_test
async def test_telescope_command_with_address_as_count(ctrl: Controller) -> None:
    import pwndbg.aglib.proc
    import pwndbg.aglib.regs

    await ctrl.launch(TELESCOPE_BINARY)

    out = (await ctrl.execute_and_capture("telescope 2")).splitlines()
    rsp = pwndbg.aglib.regs.rsp

    assert len(out) == 2
    assert out[0] == "00:0000│ rsp %#x ◂— 1" % rsp

    expected = rf"01:0008│     {rsp + 8:#x} —▸ 0x[0-9a-f]+ ◂— '{pwndbg.aglib.proc.exe}'"
    assert re.search(expected, out[1])


@pwndbg_test
async def test_telescope_command_with_address_as_count_and_reversed_flag(ctrl: Controller) -> None:
    import pwndbg.aglib.regs

    await ctrl.launch(TELESCOPE_BINARY)

    out = (await ctrl.execute_and_capture("telescope -r 2")).splitlines()
    rsp = pwndbg.aglib.regs.rsp

    assert out == ["00:0000│     %#x ◂— 0" % (rsp - 8), "01:0008│ rsp %#x ◂— 1" % rsp]


@pwndbg_test
async def test_command_telescope_reverse_skipped_records_shows_input_address(
    ctrl: Controller,
) -> None:
    """
    Tests reversed telescope with skipped records shows input address
    """
    import pwndbg.aglib.memory
    import pwndbg.aglib.regs

    await launch_to(ctrl, TELESCOPE_BINARY, "break_here")
    await ctrl.execute("up")

    pwndbg.aglib.memory.write(pwndbg.aglib.regs.rsp - 8 * 3, b"\x00" * 8 * 4)

    expected_value = hex(pwndbg.aglib.regs.rsp)
    result_str = await ctrl.execute_and_capture("telescope -r $rsp")
    result_lines = result_str.strip("\n").split("\n")

    assert expected_value in result_lines[-1]


@pwndbg_test
async def test_command_telescope_frame(ctrl: Controller) -> None:
    """
    Tests telescope --frame
    """
    import pwndbg.aglib.regs

    await launch_to(ctrl, TELESCOPE_BINARY, "break_here")

    rsp = hex(pwndbg.aglib.regs.sp)
    rbp = hex(pwndbg.aglib.regs[pwndbg.aglib.regs.frame])

    result_str = await ctrl.execute_and_capture("telescope --frame")
    result_lines = result_str.strip().split("\n")

    assert rsp in result_lines[0]
    assert rbp in result_lines[-2]


@pwndbg_test
async def test_command_telescope_frame_bp_below_sp(ctrl: Controller) -> None:
    """
    Tests telescope --frame when base pointer is below stack pointer
    """
    import pwndbg.aglib.regs

    await launch_to(ctrl, TELESCOPE_BINARY, "break_here")
    await ctrl.execute("memoize")  # turn off cache

    pwndbg.aglib.regs.sp = pwndbg.aglib.regs[pwndbg.aglib.regs.frame] + 1

    result_str = await ctrl.execute_and_capture("telescope --frame")

    assert "Cannot display stack frame because base pointer is below stack pointer" in result_str


@pwndbg_test
async def test_command_telescope_frame_bp_sp_different_vmmaps(ctrl: Controller) -> None:
    """
    Tests telescope --frame when base pointer and stack pointer are on different vmmap pages
    """
    import pwndbg.aglib.regs
    import pwndbg.aglib.vmmap

    await launch_to(ctrl, TELESCOPE_BINARY, "break_here")
    await ctrl.execute("memoize")  # turn off cache

    pages = pwndbg.aglib.vmmap.get()

    pwndbg.aglib.regs.sp = pages[0].start
    pwndbg.aglib.regs.rbp = pages[1].start

    result_str = await ctrl.execute_and_capture("telescope --frame")

    assert (
        "Cannot display stack frame because base pointer is not on the same page with stack pointer"
        in result_str
    )
