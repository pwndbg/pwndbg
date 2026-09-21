from __future__ import annotations

import re

from ....host import Controller
from . import get_binary
from . import get_expr
from . import launch_to
from . import pwndbg_test

TELESCOPE_BINARY = get_binary("telescope_binary.native.out")


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
    assert value.address is not None
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

    result_str = await ctrl.execute_and_capture("telescope ((char*)&a)+0x38 -r")
    result_lines = result_str.split("\n")

    value = get_expr("a")
    assert value.address is not None
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
    result = (await ctrl.execute_and_capture(f"telescope $sp {n}")).strip().splitlines()
    assert len(result) == n


@pwndbg_test
async def test_telescope_command_with_address_as_count(ctrl: Controller) -> None:
    import pwndbg.aglib
    import pwndbg.aglib.proc

    await ctrl.launch(TELESCOPE_BINARY)

    out = (await ctrl.execute_and_capture("telescope 2")).splitlines()
    sp = pwndbg.aglib.regs.sp
    assert sp is not None

    assert len(out) == 2
    expected = rf"00:0000│ (.*?)sp {sp:#x} ◂— 1"
    assert re.search(expected, out[0])

    expected = rf"01:0008│     {sp + 8:#x} —▸ 0x[0-9a-f]+ ◂— '{pwndbg.aglib.proc.exe()}'"
    assert re.search(expected, out[1])


@pwndbg_test
async def test_telescope_command_with_address_as_count_and_reversed_flag(ctrl: Controller) -> None:
    import pwndbg.aglib

    await ctrl.launch(TELESCOPE_BINARY)

    out = (await ctrl.execute_and_capture("telescope -r 2")).splitlines()
    sp = pwndbg.aglib.regs.sp
    assert sp is not None

    assert len(out) == 2
    assert re.match(rf"00:0000│\s+{sp - 8:#x} ◂— 0", out[0])
    assert re.match(rf"01:0008│\s+\w+\s+{sp:#x} ◂— 1", out[1])


@pwndbg_test
async def test_command_telescope_reverse_skipped_records_shows_input_address(
    ctrl: Controller,
) -> None:
    """
    Tests reversed telescope with skipped records shows input address
    """
    import pwndbg.aglib
    import pwndbg.aglib.memory

    await launch_to(ctrl, TELESCOPE_BINARY, "break_here")
    await ctrl.execute("up")

    sp = pwndbg.aglib.regs.sp
    assert sp is not None

    pwndbg.aglib.memory.write(sp - 8 * 3, b"\x00" * 8 * 4)

    expected_value = hex(sp)
    result_str = await ctrl.execute_and_capture("telescope -r $sp")
    result_lines = result_str.strip("\n").split("\n")

    assert expected_value in result_lines[-1]


@pwndbg_test
async def test_command_telescope_frame(ctrl: Controller) -> None:
    """
    Tests telescope --frame
    """
    import pwndbg.aglib

    await launch_to(ctrl, TELESCOPE_BINARY, "break_here")

    _rsp = pwndbg.aglib.regs.sp
    _frame = pwndbg.aglib.regs.frame
    assert _rsp is not None and _frame is not None
    _rbp = pwndbg.aglib.regs.read_reg(_frame)
    assert _rbp is not None

    rsp = hex(_rsp)
    rbp = hex(_rbp)

    result_str = await ctrl.execute_and_capture("telescope --frame")
    result_lines = result_str.strip().split("\n")

    assert rsp in result_lines[0]
    assert rbp in result_lines[-2]


@pwndbg_test
async def test_command_telescope_frame_bp_below_sp(ctrl: Controller) -> None:
    """
    Tests telescope --frame when base pointer is below stack pointer
    """
    import pwndbg.aglib

    await launch_to(ctrl, TELESCOPE_BINARY, "break_here")
    await ctrl.execute("memoize")  # turn off cache

    frame = pwndbg.aglib.regs.frame
    assert frame is not None
    rbp = pwndbg.aglib.regs.read_reg(frame)
    assert rbp is not None

    pwndbg.aglib.regs.sp = rbp + 1

    result_str = await ctrl.execute_and_capture("telescope --frame")

    assert "Cannot display stack frame because base pointer is below stack pointer" in result_str


@pwndbg_test
async def test_command_telescope_frame_bp_sp_different_vmmaps(ctrl: Controller) -> None:
    """
    Tests telescope --frame when base pointer and stack pointer are on different vmmap pages
    """
    import pwndbg.aglib
    import pwndbg.aglib.vmmap

    await launch_to(ctrl, TELESCOPE_BINARY, "break_here")
    await ctrl.execute("memoize")  # turn off cache

    pages = pwndbg.aglib.vmmap.get()
    frame_reg_name = pwndbg.aglib.regs.frame
    stack_reg_name = pwndbg.aglib.regs.stack
    assert frame_reg_name is not None

    pwndbg.aglib.regs.write_reg(stack_reg_name, pages[0].start)
    pwndbg.aglib.regs.write_reg(frame_reg_name, pages[1].start)

    result_str = await ctrl.execute_and_capture("telescope --frame")

    assert (
        "Cannot display stack frame because base pointer is not on the same page with stack pointer"
        in result_str
    )


@pwndbg_test
async def test_command_telescope_truncated_chain_uses_right_arrow(ctrl: Controller) -> None:
    """
    Tests that a deref chain cut off by dereference-limit ends with the right
    arrow before the contiguous marker, and the left arrow otherwise.

    See https://github.com/pwndbg/pwndbg/issues/4114
    """
    await ctrl.launch(get_binary("linked-lists.native.out"))

    # &node_a.next -> node_b -> node_b.value (1, not a pointer, chain ends here)
    await ctrl.execute("set dereference-limit 2")
    result_str = await ctrl.execute_and_capture("telescope &node_a.next 1")
    assert "—▸ ..." in result_str
    assert "◂—" not in result_str

    # High enough limit that the chain terminates on its own, i.e. is not truncated
    await ctrl.execute("set dereference-limit 16")
    result_str = await ctrl.execute_and_capture("telescope &node_a.next 1")
    assert "..." not in result_str
    assert "◂—" in result_str
