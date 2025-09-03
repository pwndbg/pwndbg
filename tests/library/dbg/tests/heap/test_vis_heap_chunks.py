from __future__ import annotations

from .....host import Controller
from .. import get_binary
from .. import launch_to
from .. import pwndbg_test

HEAP_VIS = get_binary("heap_vis.out")


@pwndbg_test
async def test_vis_heap_chunk_command(ctrl: Controller) -> None:
    import pwndbg.aglib.arch
    import pwndbg.aglib.memory
    import pwndbg.aglib.vmmap

    await launch_to(ctrl, HEAP_VIS, "break_here")

    # TODO/FIXME: Shall we have a standard method to do this kind of filtering?
    # Note that we have `pages_filter` in pwndbg/pwndbg/commands/vmmap.py heh
    heap_page = next(page for page in pwndbg.aglib.vmmap.get() if page.objfile == "[heap]")

    first_chunk_size = pwndbg.aglib.memory.u64(heap_page.start + pwndbg.aglib.arch.ptrsize)

    # Just a sanity check...
    assert (heap_page.start & 0xFFF) == 0

    result = (await ctrl.execute_and_capture("vis-heap-chunk 1")).splitlines()

    # We will use `heap_addr` variable to fill in proper addresses below
    heap_addr = heap_page.start

    # We sometimes need that value, so let's cache it
    dq2 = None

    def heap_iter(offset=0x10):
        nonlocal heap_addr
        heap_addr += offset
        return heap_addr

    async def hexdump_16B(gdb_symbol):
        from pwndbg.commands.ptmalloc2 import bin_ascii

        first, second = (await ctrl.execute_and_capture(f"x/16xb {gdb_symbol}")).splitlines()
        first = [int(v, 16) for v in first.split(":")[1].split()]
        second = [int(v, 16) for v in second.split(":")[1].split()]

        return bin_ascii(first + second)

    async def vis_heap_line(heap_iter_offset=0x10, suffix=""):
        """Returns data to format a vis_heap_chunk line"""
        addr = heap_iter(heap_iter_offset)
        hexdump = await hexdump_16B(addr)

        nonlocal dq2
        dq1, dq2 = map(pwndbg.aglib.memory.u64, (addr, addr + 8))

        formatted = f"{addr:#x}\t{dq1:#018x}\t{dq2:#018x}\t{hexdump}"
        formatted += suffix

        return formatted

    first_hexdump = await hexdump_16B(hex(heap_page.start))

    expected = [
        "",
        f"{heap_iter(0):#x}\t0x0000000000000000\t{first_chunk_size | 1:#018x}\t{first_hexdump}",
    ]
    for _ in range(first_chunk_size // 16 - 1):
        expected.append(
            "%#x\t0x0000000000000000\t0x0000000000000000\t................" % heap_iter()
        )
    expected.append("%#x\t0x0000000000000000\t                  \t........" % heap_iter())
    assert result == expected

    ## This time using `default-visualize-chunk-number` to set `count`, to make sure that the config can work
    await ctrl.execute("set default-visualize-chunk-number 1")
    assert pwndbg.config.default_visualize_chunk_number == 1
    result = (await ctrl.execute_and_capture("vis-heap-chunk")).splitlines()
    # No parameters were passed and top isn't reached so help text is shown
    no_params_help = "Not all chunks were shown, see `vis --help` for more information."
    assert result == expected + [no_params_help]
    await ctrl.execute(
        "set default-visualize-chunk-number %d"
        % pwndbg.config.default_visualize_chunk_number.default
    )

    del result

    ## Test vis_heap_chunk with count=2
    result2 = (await ctrl.execute_and_capture("vis-heap-chunk 2")).splitlines()

    # Note: we copy expected here but we truncate last line as it is easier
    # to provide it in full here
    expected2 = expected[:-1] + [
        "%#x\t0x0000000000000000\t0x0000000000000021\t........!......." % heap_iter(0),
        "%#x\t0x0000000000000000\t0x0000000000000000\t................" % heap_iter(),
        "%#x\t0x0000000000000000\t                  \t........" % heap_iter(),
    ]
    assert result2 == expected2

    del expected
    del result2

    ## Test vis_heap_chunk with count=3
    result3 = (await ctrl.execute_and_capture("vis-heap-chunk 3")).splitlines()

    # Note: we copy expected here but we truncate last line as it is easier
    # to provide it in full here
    expected3 = expected2[:-1] + [
        "%#x\t0x0000000000000000\t0x0000000000000021\t........!......." % heap_iter(0),
        "%#x\t0x0000000000000000\t0x0000000000000000\t................" % heap_iter(),
        await vis_heap_line(suffix="\t <-- Top chunk"),
    ]
    assert result3 == expected3

    del expected2
    del result3

    ## Test vis_heap_chunk with count=4
    result4 = (await ctrl.execute_and_capture("vis-heap-chunk 4")).splitlines()

    # Since on this breakpoint we only have 4 chunks, the output should probably be the same?
    # TODO/FIXME: Shall we maybe print user that there are only 3 chunks?
    assert result4 == expected3

    del result4

    ## Test vis_heap_chunk with no flags
    result_all = (await ctrl.execute_and_capture("vis-heap-chunk")).splitlines()
    assert result_all == expected3

    del result_all

    # Continue, so that another allocation is made
    await ctrl.cont()

    ## Test vis_heap_chunk with count=4 again
    result4_b = (await ctrl.execute_and_capture("vis-heap-chunk 4")).splitlines()

    expected4_b = expected3[:-1] + [
        "%#x\t0x0000000000000000\t0x0000000000000031\t........1......." % heap_iter(0),
        "%#x\t0x0000000000000000\t0x0000000000000000\t................" % heap_iter(),
        "%#x\t0x0000000000000000\t0x0000000000000000\t................" % heap_iter(),
        await vis_heap_line(suffix="\t <-- Top chunk"),
    ]

    assert result4_b == expected4_b

    del expected3
    del result4_b

    ## Test vis_heap_chunk with no flags
    result_all2 = (await ctrl.execute_and_capture("vis-heap-chunk")).splitlines()
    assert result_all2 == expected4_b

    del result_all2
    del expected4_b

    ## Continue, so that alloc[1] is freed
    await ctrl.cont()

    result_all3 = (await ctrl.execute_and_capture("vis-heap-chunk")).splitlines()

    # The tcache chunks have two fields: next and key
    # We are fetching it from the glibc's TLS tcache variable :)
    tcache_next = int(pwndbg.dbg.selected_frame().evaluate_expression("tcache->entries[0]->next"))
    tcache_key = int(pwndbg.dbg.selected_frame().evaluate_expression("tcache->entries[0]->key"))

    tcache_hexdump = await hexdump_16B("tcache->entries[0]")
    freed_chunk = "{:#x}\t{:#018x}\t{:#018x}\t{}\t ".format(
        heap_iter(-0x40),
        tcache_next,
        tcache_key,
        tcache_hexdump,
    )
    freed_chunk += "<-- tcachebins[0x20][0/1]"

    heap_addr = heap_page.start

    expected_all3 = [""]

    # Add the biggest chunk, the one from libc
    expected_all3.append(await vis_heap_line(0))

    last_chunk_size = dq2
    for _ in range(last_chunk_size // 16):
        expected_all3.append(await vis_heap_line())

    last_chunk_size = dq2
    for _ in range(last_chunk_size // 16):
        expected_all3.append(await vis_heap_line())
    expected_all3.append(await vis_heap_line(suffix="\t <-- tcachebins[0x20][0/1]"))

    expected_all3.append(await vis_heap_line())
    last_chunk_size = dq2
    for _ in range(last_chunk_size // 16 - 1):
        expected_all3.append(await vis_heap_line())
    expected_all3.append(await vis_heap_line(suffix="\t <-- Top chunk"))

    assert result_all3 == expected_all3

    del result_all3
    del expected_all3

    # Continue, malloc two large chunks and free one
    await ctrl.cont()

    # Get default result without max-visualize-chunk-size setting
    default_result = (await ctrl.execute_and_capture("vis-heap-chunk")).splitlines()
    assert len(default_result) > 0x300

    # Set max display size to 100 (no "0x" for misalignment)
    await ctrl.execute("set max-visualize-chunk-size 100")

    omitted_result = (await ctrl.execute_and_capture("vis-heap-chunk")).splitlines()
    assert len(omitted_result) < 0x30
    for omitted_line in omitted_result:
        assert omitted_line in default_result or set(omitted_line) == {"."}

    no_truncate_result = (await ctrl.execute_and_capture("vis-heap-chunk -n")).splitlines()
    assert no_truncate_result == default_result

    del default_result
    del omitted_result
    del no_truncate_result

    # Continue, mock overflow changing the chunk size
    await ctrl.cont()

    overflow_result = await ctrl.execute_and_capture("vis-heap-chunk")
    assert "\t0x0000000000000000\t0x4141414141414141\t........AAAAAAAA" in overflow_result
    assert len(overflow_result.splitlines()) < 0x500

    del overflow_result
