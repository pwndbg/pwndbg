import gdb

import pwndbg
import tests

HEAP_VIS = tests.binaries.get("heap_vis.out")


def test_vis_heap_chunk_command(start_binary):
    start_binary(HEAP_VIS)
    gdb.execute("break break_here")
    gdb.execute("continue")

    # TODO/FIXME: Shall we have a standard method to do this kind of filtering?
    # Note that we have `pages_filter` in pwndbg/pwndbg/commands/vmmap.py heh
    heap_page = next(page for page in pwndbg.gdblib.vmmap.get() if page.objfile == "[heap]")

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
    del expected4_b

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

    del result_all3
    del expected_all3

    # Continue, malloc two large chunks and free one
    gdb.execute("continue")

    # Get default result without max-visualize-chunk-size setting
    default_result = gdb.execute("vis_heap_chunk", to_string=True).splitlines()
    assert len(default_result) > 0x300

    # Set max display size to 100 (no "0x" for misalignment)
    gdb.execute("set max-visualize-chunk-size 100")

    omitted_result = gdb.execute("vis_heap_chunk", to_string=True).splitlines()
    assert len(omitted_result) < 0x30
    for omitted_line in omitted_result:
        assert omitted_line in default_result or set(omitted_line) == {"."}

    display_all_result = gdb.execute("vis_heap_chunk -a", to_string=True).splitlines()
    assert display_all_result == default_result

    del default_result
    del omitted_result
    del display_all_result

    # Continue, mock overflow changing the chunk size
    gdb.execute("continue")

    overflow_result = gdb.execute("vis_heap_chunk", to_string=True)
    assert "\t0x0000000000000000\t0x4141414141414141\t........AAAAAAAA" in overflow_result
    assert len(overflow_result.splitlines()) < 0x500

    del overflow_result
