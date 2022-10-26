import os
import tempfile

import gdb
import pytest

import pwndbg
import tests

HEAP_BINARY = tests.binaries.get("heap_bugs.out")
HEAP_CODE = tests.binaries.get("heap_bugs.c")
_, OUTPUT_FILE = tempfile.mkstemp()


def binary_parse_breakpoints(binary_code):
    """
    Find comments with breakpoints in binary code
    and map them to function's cmd line ids
    """
    # map bug id to function name (f.e: 2 -> invalid_pointer_misaligned())
    with open(binary_code, "r") as f:
        func_names = {}
        for line in f:
            if "case " in line:
                bug_id = int(line.split(":")[0].split()[-1])
                func_name = line.split(":")[1].split(";")[0].strip()
                func_names[bug_id] = func_name

    # map bug id to breakpoint line numbers
    with open(binary_code, "r") as f:
        breakpoints = {}
        lines = f.readlines()
        line_no = 0

        # find functions
        while line_no < len(lines) and len(breakpoints) < len(func_names):
            line = lines[line_no]
            line_no += 1
            for bug_id, func_name in func_names.items():
                if "void {}".format(func_name) in line:

                    # find break1 and break2 inside function
                    b1, b2 = None, None
                    while line_no < len(lines) and (b1 is None or b2 is None):
                        line = lines[line_no]
                        line_no += 1

                        if "break1" in line:
                            b1 = line_no
                        if "break2" in line:
                            b2 = line_no

                    breakpoints[bug_id] = (b1, b2)

    return breakpoints


# breakpoints: (line after setup_heap, line before the one triggering the bug)
breakpoints = binary_parse_breakpoints(HEAP_CODE)


def setup_heap(start_binary, bug_no):
    """
    Start binary
    Pause after (valid) heap is set-up
    Save valid chunks
    Continue up until buggy code line
    """
    global breakpoints

    # for communication python<->HEAP_BINARY
    try:
        os.remove(OUTPUT_FILE)
    except FileNotFoundError:
        pass

    start_binary(HEAP_BINARY, str(bug_no), "> {}".format(OUTPUT_FILE))
    gdb.execute("break " + str(breakpoints[bug_no][0]))
    gdb.execute("break " + str(breakpoints[bug_no][1]))

    gdb.execute("continue")
    gdb.execute("continue")

    chunks = {}
    with open(OUTPUT_FILE, "r") as f:
        chunk_id = "a"
        for _ in range(7):
            chunk = int(f.readline().split("=")[1], 16)
            chunks[chunk_id] = chunk
            chunk_id = chr(ord(chunk_id) + 1)
    return chunks


def test_try_free_invalid_overflow(start_binary):
    chunks = setup_heap(start_binary, 1)

    result = gdb.execute("try_free {}".format(hex(chunks["a"])), to_string=True)
    assert "free(): invalid pointer -> &chunk + chunk->size > max memory" in result
    os.remove(OUTPUT_FILE)


def test_try_free_invalid_misaligned(start_binary):
    chunks = setup_heap(start_binary, 2)

    result = gdb.execute("try_free {}".format(hex(chunks["a"] + 2)), to_string=True)
    assert "free(): invalid pointer -> misaligned chunk" in result
    os.remove(OUTPUT_FILE)


def test_try_free_invalid_size_minsize(start_binary):
    chunks = setup_heap(start_binary, 3)

    result = gdb.execute("try_free {}".format(hex(chunks["a"])), to_string=True)
    assert "free(): invalid size -> chunk's size smaller than MINSIZE" in result
    os.remove(OUTPUT_FILE)


def test_try_free_invalid_size_misaligned(start_binary):
    chunks = setup_heap(start_binary, 4)

    result = gdb.execute("try_free {}".format(hex(chunks["a"])), to_string=True)
    assert "free(): invalid size -> chunk's size is not aligned" in result
    os.remove(OUTPUT_FILE)


def test_try_free_double_free_tcache(start_binary):
    chunks = setup_heap(start_binary, 5)

    result = gdb.execute("try_free {}".format(hex(chunks["a"])), to_string=True)
    assert "Will do checks for tcache double-free" in result
    os.remove(OUTPUT_FILE)


def test_try_free_invalid_next_size_fast(start_binary):
    chunks = setup_heap(start_binary, 6)

    result = gdb.execute("try_free {}".format(hex(chunks["a"])), to_string=True)
    assert "free(): invalid next size (fast)" in result
    os.remove(OUTPUT_FILE)


def test_try_free_double_free(start_binary):
    chunks = setup_heap(start_binary, 7)

    result = gdb.execute("try_free {}".format(hex(chunks["a"])), to_string=True)
    assert "double free or corruption (fasttop)" in result
    os.remove(OUTPUT_FILE)


def test_try_free_invalid_fastbin_entry(start_binary):
    chunks = setup_heap(start_binary, 8)

    result = gdb.execute("try_free {}".format(hex(chunks["c"])), to_string=True)
    assert "invalid fastbin entry (free)" in result
    os.remove(OUTPUT_FILE)


def test_try_free_double_free_or_corruption_top(start_binary):
    setup_heap(start_binary, 9)
    allocator = pwndbg.heap.current

    ptr_size = pwndbg.gdblib.arch.ptrsize
    arena = allocator.thread_arena or allocator.main_arena
    top_chunk = arena.top + (2 * ptr_size)

    result = gdb.execute("try_free {}".format(hex(top_chunk)), to_string=True)
    assert "double free or corruption (top)" in result
    os.remove(OUTPUT_FILE)


def test_try_free_double_free_or_corruption_out(start_binary):
    chunks = setup_heap(start_binary, 10)

    result = gdb.execute("try_free {}".format(hex(chunks["d"])), to_string=True)
    assert "double free or corruption (out)" in result
    os.remove(OUTPUT_FILE)


def test_try_free_double_free_or_corruption_prev(start_binary):
    chunks = setup_heap(start_binary, 11)

    result = gdb.execute("try_free {}".format(hex(chunks["d"])), to_string=True)
    assert "double free or corruption (!prev)" in result
    os.remove(OUTPUT_FILE)


def test_try_free_invalid_next_size_normal(start_binary):
    chunks = setup_heap(start_binary, 12)

    result = gdb.execute("try_free {}".format(hex(chunks["d"])), to_string=True)
    assert "free(): invalid next size (normal)" in result
    os.remove(OUTPUT_FILE)


def test_try_free_corrupted_consolidate_backward(start_binary):
    chunks = setup_heap(start_binary, 13)

    result = gdb.execute("try_free {}".format(hex(chunks["e"])), to_string=True)
    assert "corrupted size vs. prev_size while consolidating" in result
    os.remove(OUTPUT_FILE)


def test_try_free_corrupted_consolidate_backward(start_binary):
    chunks = setup_heap(start_binary, 13)

    result = gdb.execute("try_free {}".format(hex(chunks["e"])), to_string=True)
    assert "corrupted size vs. prev_size while consolidating" in result
    os.remove(OUTPUT_FILE)


@pytest.mark.skip(
    reason="Needs review. In the heap.py on the line 972 the condition is true always. The heap_bug.c file has the function: corrupted_unsorted_chunks()"
)
def test_try_free_corrupted_unsorted_chunks(start_binary):
    chunks = setup_heap(start_binary, 14)

    result = gdb.execute("try_free {}".format(hex(chunks["f"])), to_string=True)
    assert "free(): corrupted unsorted chunks" in result
    os.remove(OUTPUT_FILE)
