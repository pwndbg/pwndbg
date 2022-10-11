import gdb

import pwndbg
import tests

HEAP_FIND_FAKE_FAST = tests.binaries.get("heap_find_fake_fast.out")


# Ensure find_fake_fast command doesn't error when fake chunk's heap_info
# struct isn't mapped.
def test_find_fake_fast_command(start_binary):
    start_binary(HEAP_FIND_FAKE_FAST)
    gdb.execute("break break_here")
    gdb.execute("continue")

    # Ensure memory at fake_chunk's heap_info struct isn't mapped.
    unmapped_heap_info = pwndbg.heap.ptmalloc.heap_for_ptr(
        pwndbg.gdblib.symbol.address("fake_chunk")
    )
    assert pwndbg.gdblib.memory.peek(unmapped_heap_info) is None

    # A gdb.MemoryError raised here indicates a regression from PR #1145
    gdb.execute("find_fake_fast (void*)&fake_chunk+0x70")
