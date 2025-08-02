from __future__ import annotations

import re

from .....host import Controller
from .. import get_binary
from .. import launch_to
from .. import pwndbg_test

HEAP_FIND_FAKE_FAST = get_binary("heap_find_fake_fast.out")

target_address = None


def check_result(result: str, expected_size: int) -> None:
    import pwndbg.aglib.arch

    ptrsize = pwndbg.aglib.arch.ptrsize

    matches = re.findall(r"\bAddr: (0x[0-9a-f]+)", result)
    assert len(matches) == 1
    addr = int(matches[0], 16)

    matches = re.findall(r"\bsize: (0x[0-9a-f]+)", result)
    assert len(matches) == 1
    size = int(matches[0], 16)

    assert size == expected_size

    # The chunk can't start too close to the target address
    assert addr <= target_address - (2 * ptrsize)

    # Clear the flags
    size &= ~0xF

    # The chunk should overlap the target address
    assert addr + ptrsize + size > target_address


def check_no_results(result: str) -> None:
    matches = re.findall(r"\bAddr: (0x[0-9a-f]+)", result)
    assert len(matches) == 0


@pwndbg_test
async def test_find_fake_fast_command(ctrl: Controller) -> None:
    import pwndbg
    import pwndbg.aglib.heap
    import pwndbg.aglib.memory
    import pwndbg.aglib.symbol

    global target_address

    await launch_to(ctrl, HEAP_FIND_FAKE_FAST, "break_here")

    # Ensure memory at fake_chunk's heap_info struct isn't mapped.
    unmapped_heap_info = pwndbg.aglib.heap.ptmalloc.heap_for_ptr(
        pwndbg.aglib.symbol.lookup_symbol_value("fake_chunk")
    )
    assert pwndbg.aglib.memory.peek(unmapped_heap_info) is None

    # A gdb.MemoryError raised here indicates a regression from PR #1145
    await ctrl.execute("find-fake-fast fake_chunk+0x80")

    target_address = pwndbg.aglib.symbol.lookup_symbol_addr("target_address")
    assert target_address is not None
    print(hex(target_address))

    # setup_mem(0x20, 0x8)
    result = await ctrl.execute_and_capture("find-fake-fast &target_address")
    check_result(result, 0x20)

    result = await ctrl.execute_and_capture("find-fake-fast --align &target_address")
    check_result(result, 0x20)
    await ctrl.cont()

    # setup_mem(0x2F, 0x8)
    result = await ctrl.execute_and_capture("find-fake-fast &target_address")
    check_result(result, 0x28)

    result = await ctrl.execute_and_capture("find-fake-fast --align &target_address")
    check_result(result, 0x28)
    await ctrl.cont()

    # setup_mem(0x20, 0x9)
    result = await ctrl.execute_and_capture("find-fake-fast &target_address")
    check_result(result, 0x20)

    result = await ctrl.execute_and_capture("find-fake-fast --align &target_address")
    check_no_results(result)
    await ctrl.cont()

    # setup_mem(0x20, 0x0)
    result = await ctrl.execute_and_capture("find-fake-fast &target_address")
    check_no_results(result)

    result = await ctrl.execute_and_capture("find-fake-fast --align &target_address")
    check_no_results(result)
    await ctrl.cont()

    # setup_mem(0x20, 0x7)
    result = await ctrl.execute_and_capture("find-fake-fast &target_address")
    check_no_results(result)

    result = await ctrl.execute_and_capture("find-fake-fast --align &target_address")
    check_no_results(result)
    await ctrl.cont()

    # setup_mem(0x1F, 0x8)
    result = await ctrl.execute_and_capture("find-fake-fast &target_address")
    check_no_results(result)

    result = await ctrl.execute_and_capture("find-fake-fast --align &target_address")
    check_no_results(result)
    await ctrl.cont()

    # setup_mem(0x80, 0x78)
    result = await ctrl.execute_and_capture("find-fake-fast &target_address")
    check_result(result, 0x80)

    result = await ctrl.execute_and_capture("find-fake-fast --align &target_address")
    check_result(result, 0x80)
    await ctrl.cont()

    # # setup_mem(0x80, 0x7F)
    # result = await ctrl.execute_and_capture("find-fake-fast &target_address")
    # check_result(result, 0x80)
    # await ctrl.cont()

    # setup_mem(0x80, 0x80)
    result = await ctrl.execute_and_capture("find-fake-fast &target_address")
    check_no_results(result)

    result = await ctrl.execute_and_capture("find-fake-fast --align &target_address")
    check_no_results(result)
    await ctrl.cont()

    # setup_mem(0x100, 0x10)
    result = await ctrl.execute_and_capture("find-fake-fast &target_address")
    check_no_results(result)

    result = await ctrl.execute_and_capture("find-fake-fast &target_address 0x100")
    check_result(result, 0x100)
    await ctrl.cont()

    # setup_mem(0x100, 0x90)
    result = await ctrl.execute_and_capture("find-fake-fast &target_address")
    check_no_results(result)

    result = await ctrl.execute_and_capture("find-fake-fast &target_address 0x100")
    check_result(result, 0x100)
    await ctrl.cont()

    # setup_mem(0x100, 0x100)
    result = await ctrl.execute_and_capture("find-fake-fast &target_address")
    check_no_results(result)

    result = await ctrl.execute_and_capture("find-fake-fast &target_address 0x100")
    check_no_results(result)
    await ctrl.cont()

    # setup_mem(0xAABBCCDD00000020, 0x8)
    result = await ctrl.execute_and_capture("find-fake-fast &target_address")
    check_no_results(result)

    result = await ctrl.execute_and_capture("find-fake-fast &target_address --glibc-fastbin-bug")
    check_result(result, 0xAABBCCDD00000020)
    await ctrl.cont()

    # setup_mem(0x8000, 0x80)
    result = await ctrl.execute_and_capture("find-fake-fast &target_address")
    check_no_results(result)

    result = await ctrl.execute_and_capture("find-fake-fast &target_address --partial-overwrite")
    check_result(result, 0x80)
