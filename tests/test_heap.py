import os
import tempfile

import gdb
import pytest

import pwndbg
import tests

HEAP_BINARY = tests.binaries.get("heap_bugs.out")
HEAP_CODE = tests.binaries.get("heap_bugs.c")
_, OUTPUT_FILE = tempfile.mkstemp()

HEAP_VIS = tests.binaries.get("heap_vis.out")
HEAP_FIND_FAKE_FAST = tests.binaries.get("heap_find_fake_fast.out")


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

    ptr_size = pwndbg.gdblib.arch.ptrsize
    top_chunk = int(pwndbg.heap.current.get_arena()["top"]) + 2 * ptr_size

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


def test_vis_heap_chunk_command(start_binary):
    start_binary(HEAP_VIS)
    gdb.execute("break break_here")
    gdb.execute("continue")

    # TODO/FIXME: Shall we have a standard method to do this kind of filtering?
    # Note that we have `pages_filter` in pwndbg/pwndbg/commands/vmmap.py heh
    heap_page = next(page for page in pwndbg.vmmap.get() if page.objfile == "[heap]")

    first_chunk_size = pwndbg.gdblib.memory.u64(heap_page.start + pwndbg.gdblib.arch.ptrsize)

    # Just a sanity check...
    assert (heap_page.start & 0xFFF) == 0

    result = gdb.execute("vis_heap_chunk 1", to_string=True).splitlines()

    # We will use `heap_addr` variable to fill in proper addresses below
    heap_addr = heap_page.start
    heap_end = heap_page.end

    # We sometimes need that value, so let's cache it
    dq2 = None

    def heap_iter(offset=0x10):
        nonlocal heap_addr
        heap_addr += offset
        return heap_addr

    def hexdump_16B(gdb_symbol):
        from pwndbg.commands.heap import bin_ascii

        first, second = gdb.execute("x/16xb %s" % gdb_symbol, to_string=True).splitlines()
        first = [int(v, 16) for v in first.split(":")[1].split("\t")[1:]]
        second = [int(v, 16) for v in second.split(":")[1].split("\t")[1:]]

        return bin_ascii(first + second)

    def vis_heap_line(heap_iter_offset=0x10, suffix=""):
        """Returns data to format a vis_heap_chunk line"""
        addr = heap_iter(heap_iter_offset)
        hexdump = hexdump_16B(addr)

        nonlocal dq2
        dq1, dq2 = map(pwndbg.gdblib.memory.u64, (addr, addr + 8))

        formatted = "%#x\t%#018x\t%#018x\t%s" % (addr, dq1, dq2, hexdump)
        formatted += suffix

        return formatted

    first_hexdump = hexdump_16B(hex(heap_page.start))

    expected = [
        "",
        "%#x\t0x0000000000000000\t%#018x\t%s" % (heap_iter(0), first_chunk_size | 1, first_hexdump),
    ]
    for _ in range(first_chunk_size // 16 - 1):
        expected.append(
            "%#x\t0x0000000000000000\t0x0000000000000000\t................" % heap_iter()
        )
    expected.append("%#x\t0x0000000000000000" % heap_iter())
    assert result == expected

    del result

    ## Test vis_heap_chunk with count=2
    result2 = gdb.execute("vis_heap_chunk 2", to_string=True).splitlines()

    # Note: we copy expected here but we truncate last line as it is easier
    # to provide it in full here
    expected2 = expected[:-1] + [
        "%#x\t0x0000000000000000\t0x0000000000000021\t........!......." % heap_iter(0),
        "%#x\t0x0000000000000000\t0x0000000000000000\t................" % heap_iter(),
        "%#x\t0x0000000000000000" % heap_iter(),
    ]
    assert result2 == expected2

    del expected
    del result2

    ## Test vis_heap_chunk with count=3
    result3 = gdb.execute("vis_heap_chunk 3", to_string=True).splitlines()

    # Note: we copy expected here but we truncate last line as it is easier
    # to provide it in full here
    expected3 = expected2[:-1] + [
        "%#x\t0x0000000000000000\t0x0000000000000021\t........!......." % heap_iter(0),
        "%#x\t0x0000000000000000\t0x0000000000000000\t................" % heap_iter(),
        vis_heap_line(suffix="\t <-- Top chunk"),
    ]
    assert result3 == expected3

    del expected2
    del result3

    ## Test vis_heap_chunk with count=4
    result4 = gdb.execute("vis_heap_chunk 4", to_string=True).splitlines()

    # Since on this breakpoint we only have 4 chunks, the output should probably be the same?
    # TODO/FIXME: Shall we maybe print user that there are only 3 chunks?
    assert result4 == expected3

    del result4

    ## Test vis_heap_chunk with no flags
    result_all = gdb.execute("vis_heap_chunk", to_string=True).splitlines()
    assert result_all == expected3

    del result_all

    # Continue, so that another allocation is made
    gdb.execute("continue")

    ## Test vis_heap_chunk with count=4 again
    result4_b = gdb.execute("vis_heap_chunk 4", to_string=True).splitlines()

    expected4_b = expected3[:-1] + [
        "%#x\t0x0000000000000000\t0x0000000000000031\t........1......." % heap_iter(0),
        "%#x\t0x0000000000000000\t0x0000000000000000\t................" % heap_iter(),
        "%#x\t0x0000000000000000\t0x0000000000000000\t................" % heap_iter(),
        vis_heap_line(suffix="\t <-- Top chunk"),
    ]

    assert result4_b == expected4_b

    del expected3
    del result4_b

    ## Test vis_heap_chunk with no flags
    result_all2 = gdb.execute("vis_heap_chunk", to_string=True).splitlines()
    assert result_all2 == expected4_b

    del result_all2

    ## Continue, so that alloc[1] is freed
    gdb.execute("continue")

    result_all3 = gdb.execute("vis_heap_chunk", to_string=True).splitlines()

    # The tcache chunks have two fields: next and key
    # We are fetching it from the glibc's TLS tcache variable :)
    tcache_next = int(gdb.parse_and_eval("tcache->entries[0]->next"))
    tcache_key = int(gdb.parse_and_eval("tcache->entries[0]->key"))

    tcache_hexdump = hexdump_16B("tcache->entries[0]")
    freed_chunk = "%#x\t%#018x\t%#018x\t%s\t " % (
        heap_iter(-0x40),
        tcache_next,
        tcache_key,
        tcache_hexdump,
    )
    freed_chunk += "<-- tcachebins[0x20][0/1]"

    heap_addr = heap_page.start

    # This is not ideal, but hopefully it works on different builds // feel free to name it better
    some_addr = heap_addr + 0x2C0
    some_addr_hexdump = hexdump_16B(hex(heap_addr + 0x90))

    expected_all3 = [""]

    # Add the biggest chunk, the one from libc
    expected_all3.append(vis_heap_line(0))

    last_chunk_size = dq2
    for _ in range(last_chunk_size // 16):
        expected_all3.append(vis_heap_line())

    last_chunk_size = dq2
    for _ in range(last_chunk_size // 16):
        expected_all3.append(vis_heap_line())
    expected_all3.append(vis_heap_line(suffix="\t <-- tcachebins[0x20][0/1]"))

    expected_all3.append(vis_heap_line())
    last_chunk_size = dq2
    for _ in range(last_chunk_size // 16 - 1):
        expected_all3.append(vis_heap_line())
    expected_all3.append(vis_heap_line(suffix="\t <-- Top chunk"))

    assert result_all3 == expected_all3


# Ensure find_fake_fast command doesn't error when fake chunk's heap_info
# struct isn't mapped.
def test_find_fake_fast_command(start_binary):
    start_binary(HEAP_FIND_FAKE_FAST)
    gdb.execute("break break_here")
    gdb.execute("continue")

    # Ensure memory at fake_chunk's heap_info struct isn't mapped.
    unmapped_heap_info = pwndbg.heap.ptmalloc.heap_for_ptr(pwndbg.symbol.address("fake_chunk"))
    assert pwndbg.gdblib.memory.peek(unmapped_heap_info) is None

    # A gdb.MemoryError raised here indicates a regression from PR #1145
    gdb.execute("find_fake_fast (void*)&fake_chunk+0x70")

