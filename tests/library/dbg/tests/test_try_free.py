from __future__ import annotations

import contextlib
import os
import tempfile
from pathlib import Path

import pytest

from ....host import Controller
from . import get_binary
from . import pwndbg_test

HEAP_BINARY = get_binary("heap_bugs.x86-64.out")
HEAP_CODE = get_binary("heap_bugs.x86-64.c")
_, OUTPUT_FILE = tempfile.mkstemp()


def binary_parse_breakpoints(binary_code: Path) -> dict[int, tuple[int, int]]:
    """
    Find comments with breakpoints in binary code
    and map them to function's cmd line ids
    """
    # map bug id to function name (f.e: 2 -> invalid_pointer_misaligned())
    with open(binary_code) as f:
        func_names: dict[int, str] = {}
        for line in f:
            if "case " in line:
                bug_id = int(line.split(":")[0].split()[-1])
                func_name = line.split(":")[1].split(";")[0].strip()
                func_names[bug_id] = func_name

    # map bug id to breakpoint line numbers
    with open(binary_code) as f:
        breakpoints: dict[int, tuple[int, int]] = {}
        lines = f.readlines()
        line_no = 0

        # find functions
        while line_no < len(lines) and len(breakpoints) < len(func_names):
            line = lines[line_no]
            line_no += 1
            for bug_id, func_name in func_names.items():
                if f"void {func_name}" in line:
                    # find break1 and break2 inside function
                    b1, b2 = None, None
                    while line_no < len(lines) and (b1 is None or b2 is None):
                        line = lines[line_no]
                        line_no += 1

                        if "break1" in line:
                            b1 = line_no
                        if "break2" in line:
                            b2 = line_no

                    assert b1 is not None and b2 is not None
                    breakpoints[bug_id] = (b1, b2)

    return breakpoints


# breakpoints: (line after setup_heap, line before the one triggering the bug)
breakpoints = binary_parse_breakpoints(HEAP_CODE)


async def setup_heap(ctrl: Controller, bug_no: int) -> dict[str, int]:
    """
    Start binary
    Pause after (valid) heap is set-up
    Save valid chunks
    Continue up until buggy code line
    """
    global breakpoints

    # for communication python<->HEAP_BINARY
    with contextlib.suppress(FileNotFoundError):
        os.remove(OUTPUT_FILE)

    await ctrl.launch(HEAP_BINARY, args=[str(bug_no), f"{OUTPUT_FILE}"])
    await ctrl.execute("b " + str(breakpoints[bug_no][0]))
    await ctrl.execute("b " + str(breakpoints[bug_no][1]))

    await ctrl.cont()
    await ctrl.cont()

    chunks = {}
    with open(OUTPUT_FILE) as f:
        chunk_id = "a"
        for _ in range(7):
            chunk = int(f.readline().split("=")[1], 16)
            chunks[chunk_id] = chunk
            chunk_id = chr(ord(chunk_id) + 1)
    return chunks


@pwndbg_test
async def test_try_free_invalid_overflow(ctrl: Controller) -> None:
    chunks = await setup_heap(ctrl, 1)

    result = await ctrl.execute_and_capture(f"try-free {hex(chunks['a'])}")
    assert "free(): invalid pointer -> &chunk + chunk->size > max memory" in result
    os.remove(OUTPUT_FILE)


@pwndbg_test
async def test_try_free_invalid_misaligned(ctrl: Controller) -> None:
    chunks = await setup_heap(ctrl, 2)

    result = await ctrl.execute_and_capture(f"try-free {hex(chunks['a'] + 2)}")
    assert "free(): invalid pointer -> misaligned chunk" in result
    os.remove(OUTPUT_FILE)


@pwndbg_test
async def test_try_free_invalid_size_minsize(ctrl: Controller) -> None:
    chunks = await setup_heap(ctrl, 3)

    result = await ctrl.execute_and_capture(f"try-free {hex(chunks['a'])}")
    assert "free(): invalid size -> chunk's size smaller than MINSIZE" in result
    os.remove(OUTPUT_FILE)


@pwndbg_test
async def test_try_free_invalid_size_misaligned(ctrl: Controller) -> None:
    chunks = await setup_heap(ctrl, 4)

    result = await ctrl.execute_and_capture(f"try-free {hex(chunks['a'])}")
    assert "free(): invalid size -> chunk's size is not aligned" in result
    os.remove(OUTPUT_FILE)


@pwndbg_test
async def test_try_free_double_free_tcache(ctrl: Controller) -> None:
    chunks = await setup_heap(ctrl, 5)

    result = await ctrl.execute_and_capture(f"try-free {hex(chunks['a'])}")
    assert "Will do checks for tcache double-free" in result
    os.remove(OUTPUT_FILE)


@pwndbg_test
async def test_try_free_invalid_next_size_fast(ctrl: Controller) -> None:
    chunks = await setup_heap(ctrl, 6)

    result = await ctrl.execute_and_capture(f"try-free {hex(chunks['a'])}")
    assert "free(): invalid next size (fast)" in result
    os.remove(OUTPUT_FILE)


@pwndbg_test
async def test_try_free_double_free(ctrl: Controller) -> None:
    chunks = await setup_heap(ctrl, 7)

    result = await ctrl.execute_and_capture(f"try-free {hex(chunks['a'])}")
    assert "double free or corruption (fasttop)" in result
    os.remove(OUTPUT_FILE)


@pwndbg_test
async def test_try_free_invalid_fastbin_entry(ctrl: Controller) -> None:
    chunks = await setup_heap(ctrl, 8)

    result = await ctrl.execute_and_capture(f"try-free {hex(chunks['c'])}")
    assert "invalid fastbin entry (free)" in result
    os.remove(OUTPUT_FILE)


@pwndbg_test
async def test_try_free_double_free_or_corruption_top(ctrl: Controller) -> None:
    import pwndbg.aglib
    import pwndbg.aglib.heap
    from pwndbg.aglib.heap.ptmalloc import GlibcMemoryAllocator

    await setup_heap(ctrl, 9)
    assert isinstance(pwndbg.aglib.heap.current, GlibcMemoryAllocator)
    allocator = pwndbg.aglib.heap.current

    ptr_size = pwndbg.aglib.arch.ptrsize
    arena = allocator.thread_arena or allocator.main_arena
    assert arena is not None
    top = arena.top
    assert top is not None
    top_chunk = top + (2 * ptr_size)

    result = await ctrl.execute_and_capture(f"try-free {hex(top_chunk)}")
    assert "double free or corruption (top)" in result
    os.remove(OUTPUT_FILE)


@pwndbg_test
async def test_try_free_double_free_or_corruption_out(ctrl: Controller) -> None:
    chunks = await setup_heap(ctrl, 10)

    result = await ctrl.execute_and_capture(f"try-free {hex(chunks['d'])}")
    assert "double free or corruption (out)" in result
    os.remove(OUTPUT_FILE)


@pwndbg_test
async def test_try_free_double_free_or_corruption_prev(ctrl: Controller) -> None:
    chunks = await setup_heap(ctrl, 11)

    result = await ctrl.execute_and_capture(f"try-free {hex(chunks['d'])}")
    assert "double free or corruption (!prev)" in result
    os.remove(OUTPUT_FILE)


@pwndbg_test
async def test_try_free_invalid_next_size_normal(ctrl: Controller) -> None:
    chunks = await setup_heap(ctrl, 12)

    result = await ctrl.execute_and_capture(f"try-free {hex(chunks['d'])}")
    assert "free(): invalid next size (normal)" in result
    os.remove(OUTPUT_FILE)


@pwndbg_test
async def test_try_free_corrupted_consolidate_backward(ctrl: Controller) -> None:
    chunks = await setup_heap(ctrl, 13)

    result = await ctrl.execute_and_capture(f"try-free {hex(chunks['e'])}")
    assert "corrupted size vs. prev_size while consolidating" in result
    os.remove(OUTPUT_FILE)


@pytest.mark.skip(
    reason="Needs review. In the heap.py on the line 972 the condition is true always. The heap_bug.c file has the function: corrupted_unsorted_chunks()"
)
@pwndbg_test
async def test_try_free_corrupted_unsorted_chunks(ctrl: Controller) -> None:
    chunks = await setup_heap(ctrl, 14)

    result = await ctrl.execute_and_capture(f"try-free {hex(chunks['f'])}")
    assert "free(): corrupted unsorted chunks" in result
    os.remove(OUTPUT_FILE)
