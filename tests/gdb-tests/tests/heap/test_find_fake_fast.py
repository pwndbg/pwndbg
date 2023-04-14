import re

import gdb

import pwndbg
import tests

HEAP_FIND_FAKE_FAST = tests.binaries.get("heap_find_fake_fast.out")

target_address = None


def check_result(result, expected_size):
    ptrsize = pwndbg.gdblib.arch.ptrsize

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


def check_no_results(result):
    matches = re.findall(r"\bAddr: (0x[0-9a-f]+)", result)
    assert len(matches) == 0


def test_find_fake_fast_command(start_binary):
    global target_address

    start_binary(HEAP_FIND_FAKE_FAST)
    gdb.execute("break break_here")
    gdb.execute("continue")

    # Ensure memory at fake_chunk's heap_info struct isn't mapped.
    unmapped_heap_info = pwndbg.heap.ptmalloc.heap_for_ptr(
        int(gdb.lookup_global_symbol("fake_chunk").value())
    )
    assert pwndbg.gdblib.memory.peek(unmapped_heap_info) is None

    # A gdb.MemoryError raised here indicates a regression from PR #1145
    gdb.execute("find_fake_fast fake_chunk+0x80")

    target_address = pwndbg.gdblib.symbol.address("target_address")
    assert target_address is not None
    print(hex(target_address))

    # setup_mem(0x20, 0x8)
    result = gdb.execute("find_fake_fast &target_address", to_string=True)
    check_result(result, 0x20)

    result = gdb.execute("find_fake_fast --align &target_address", to_string=True)
    check_result(result, 0x20)
    gdb.execute("continue")

    # setup_mem(0x2F, 0x8)
    result = gdb.execute("find_fake_fast &target_address", to_string=True)
    check_result(result, 0x2F)

    result = gdb.execute("find_fake_fast --align &target_address", to_string=True)
    check_result(result, 0x2F)
    gdb.execute("continue")

    # setup_mem(0x20, 0x9)
    result = gdb.execute("find_fake_fast &target_address", to_string=True)
    check_result(result, 0x20)

    result = gdb.execute("find_fake_fast --align &target_address", to_string=True)
    check_no_results(result)
    gdb.execute("continue")

    # setup_mem(0x20, 0x0)
    result = gdb.execute("find_fake_fast &target_address", to_string=True)
    check_no_results(result)

    result = gdb.execute("find_fake_fast --align &target_address", to_string=True)
    check_no_results(result)
    gdb.execute("continue")

    # setup_mem(0x20, 0x7)
    result = gdb.execute("find_fake_fast &target_address", to_string=True)
    check_no_results(result)

    result = gdb.execute("find_fake_fast --align &target_address", to_string=True)
    check_no_results(result)
    gdb.execute("continue")

    # setup_mem(0x1F, 0x8)
    result = gdb.execute("find_fake_fast &target_address", to_string=True)
    check_no_results(result)

    result = gdb.execute("find_fake_fast --align &target_address", to_string=True)
    check_no_results(result)
    gdb.execute("continue")

    # setup_mem(0x80, 0x78)
    result = gdb.execute("find_fake_fast &target_address", to_string=True)
    check_result(result, 0x80)

    result = gdb.execute("find_fake_fast --align &target_address", to_string=True)
    check_result(result, 0x80)
    gdb.execute("continue")

    # # setup_mem(0x80, 0x7F)
    # result = gdb.execute("find_fake_fast &target_address", to_string=True)
    # check_result(result, 0x80)
    # gdb.execute("continue")

    # setup_mem(0x80, 0x80)
    result = gdb.execute("find_fake_fast &target_address", to_string=True)
    check_no_results(result)

    result = gdb.execute("find_fake_fast --align &target_address", to_string=True)
    check_no_results(result)
    gdb.execute("continue")

    # setup_mem(0x100, 0x10)
    result = gdb.execute("find_fake_fast &target_address", to_string=True)
    check_no_results(result)

    result = gdb.execute("find_fake_fast &target_address 0x100", to_string=True)
    check_result(result, 0x100)
    gdb.execute("continue")

    # setup_mem(0x100, 0x90)
    result = gdb.execute("find_fake_fast &target_address", to_string=True)
    check_no_results(result)

    result = gdb.execute("find_fake_fast &target_address 0x100", to_string=True)
    check_result(result, 0x100)
    gdb.execute("continue")

    # setup_mem(0x100, 0x100)
    result = gdb.execute("find_fake_fast &target_address", to_string=True)
    check_no_results(result)

    result = gdb.execute("find_fake_fast &target_address 0x100", to_string=True)
    check_no_results(result)
    gdb.execute("continue")
