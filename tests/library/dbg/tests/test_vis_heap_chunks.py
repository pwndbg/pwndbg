from __future__ import annotations

import pytest

from ....host import Controller
from . import break_at_sym
from . import get_binary
from . import launch_to
from . import pwndbg_test

HEAP_VIS = get_binary("heap_vis.native.out")
HEAP_2_43 = get_binary("heap_glibc2.43.native.out")


@pwndbg_test
async def test_vis_heap_chunk_command(ctrl: Controller) -> None:
    import pwndbg.aglib
    import pwndbg.aglib.memory
    import pwndbg.aglib.vmmap
    import pwndbg.libc

    # Disable collapsible output for existing test expectations
    await ctrl.execute("set vis-skip-repeating-val off")

    await launch_to(ctrl, HEAP_VIS, "break_here")

    if pwndbg.aglib.arch.name != "x86-64":
        pytest.skip("TODO multiarch")

    if pwndbg.libc.version() >= (2, 43):
        pytest.skip("Test is not applicable above glibc 2.43")

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

    # Since glibc 2.42 we don't store the amount of chunks in the tcache bin, but rather
    # the amount of chunks still needed to fill the bin.
    num_slots_check = pwndbg.aglib.memory.u8(heap_page.start + pwndbg.aglib.arch.ptrsize * 2)
    using_num_slots = num_slots_check == 7

    expected = [
        f"{heap_iter(0):#x}\t0x0000000000000000\t{first_chunk_size | 1:#018x}\t{first_hexdump}",
    ]

    if using_num_slots:
        # The tcache struct is made up of 2-byte num_slots values and 8-byte pointers to the starts
        # of the bins.
        ntcachebins: int = first_chunk_size // (2 + 8)
        nslotslines: float = ntcachebins * 2 / 0x10
        nptrlines: int = first_chunk_size // 0x10 - int(nslotslines)

        for _ in range(int(nslotslines)):
            expected.append(
                f"{heap_iter():#x}\t0x0007000700070007\t0x0007000700070007\t................"
            )
        if nslotslines - int(nslotslines) == 0.5:
            expected.append(
                f"{heap_iter():#x}\t0x0007000700070007\t0x0000000000000000\t................"
            )
            nptrlines -= 1
        for _ in range(nptrlines - 1):
            expected.append(
                f"{heap_iter():#x}\t0x0000000000000000\t0x0000000000000000\t................"
            )
        expected.append(f"{heap_iter():#x}\t0x0000000000000000\t                  \t........")

    else:
        for _ in range(first_chunk_size // 16 - 1):
            expected.append(
                f"{heap_iter():#x}\t0x0000000000000000\t0x0000000000000000\t................"
            )
        expected.append(f"{heap_iter():#x}\t0x0000000000000000\t                  \t........")

    assert result == expected

    ## This time using `default-visualize-chunk-number` to set `count`, to make sure that the config can work
    await ctrl.execute("set default-visualize-chunk-number 1")
    assert pwndbg.config.default_visualize_chunk_number == 1
    result = (await ctrl.execute_and_capture("vis-heap-chunk")).splitlines()
    # No parameters were passed and top isn't reached so help text is shown
    no_params_help = "Not all chunks were shown, see `vis --help` for more information."
    assert result == expected + [no_params_help]
    await ctrl.execute(
        f"set default-visualize-chunk-number {pwndbg.config.default_visualize_chunk_number.default}"
    )

    del result

    ## Test vis_heap_chunk with count=2
    result2 = (await ctrl.execute_and_capture("vis-heap-chunk 2")).splitlines()

    # Note: we copy expected here but we truncate last line as it is easier
    # to provide it in full here
    expected2 = expected[:-1] + [
        f"{heap_iter(0):#x}\t0x0000000000000000\t0x0000000000000021\t........!.......",
        f"{heap_iter():#x}\t0x0000000000000000\t0x0000000000000000\t................",
        f"{heap_iter():#x}\t0x0000000000000000\t                  \t........",
    ]
    assert result2 == expected2

    del expected
    del result2

    ## Test vis_heap_chunk with count=3
    result3 = (await ctrl.execute_and_capture("vis-heap-chunk 3")).splitlines()

    # Note: we copy expected here but we truncate last line as it is easier
    # to provide it in full here
    expected3 = expected2[:-1] + [
        f"{heap_iter(0):#x}\t0x0000000000000000\t0x0000000000000021\t........!.......",
        f"{heap_iter():#x}\t0x0000000000000000\t0x0000000000000000\t................",
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
        f"{heap_iter(0):#x}\t0x0000000000000000\t0x0000000000000031\t........1.......",
        f"{heap_iter():#x}\t0x0000000000000000\t0x0000000000000000\t................",
        f"{heap_iter():#x}\t0x0000000000000000\t0x0000000000000000\t................",
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
    frame = pwndbg.dbg.selected_frame()
    assert frame
    tcache_next = int(frame.evaluate_expression("tcache->entries[0]->next"))
    tcache_key = int(frame.evaluate_expression("tcache->entries[0]->key"))

    tcache_hexdump = await hexdump_16B("tcache->entries[0]")
    freed_chunk = (
        f"{heap_iter(-0x40):#x}\t{tcache_next:#018x}\t{tcache_key:#018x}\t{tcache_hexdump}\t "
    )
    freed_chunk += "<-- tcachebins[0x20][0/1]"

    heap_addr = heap_page.start

    expected_all3 = []

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

    ## Test vis-skip-repeating-val config (collapsible output)
    # Test collapsible output on default_result which has many repeated lines
    # First ensure it's disabled (already should be from test start)
    await ctrl.execute("set vis-skip-repeating-val off")
    full_result_no_collapse = (await ctrl.execute_and_capture("vis-heap-chunk")).splitlines()

    # Should NOT contain collapse messages
    collapse_lines_disabled = [
        line for line in full_result_no_collapse if "repeated lines skipped" in line
    ]
    assert len(collapse_lines_disabled) == 0, (
        "Should have no collapse messages when skip-repeating is disabled"
    )

    # Now test with skip-repeating enabled on the same state
    await ctrl.execute("set vis-skip-repeating-val on")
    collapsed_result = (await ctrl.execute_and_capture("vis-heap-chunk")).splitlines()

    # Should contain collapse messages
    collapse_lines = [line for line in collapsed_result if "repeated lines skipped" in line]
    assert len(collapse_lines) > 0, "Should have collapse messages when skip-repeating is enabled"

    # Verify format of collapse message (should have tab prefix and right-aligned count)
    for collapse_line in collapse_lines:
        assert collapse_line.strip().startswith("... ↓"), (
            "Collapse message should start with '... ↓'"
        )
        assert "repeated lines skipped" in collapse_line, "Should say 'repeated lines skipped'"

    # Full result should have more lines than collapsed result
    assert len(full_result_no_collapse) > len(collapsed_result), (
        "Full output should have more lines than collapsed output"
    )

    # Set back to off for any remaining tests
    await ctrl.execute("set vis-skip-repeating-val off")

    del collapsed_result
    del full_result_no_collapse


@pwndbg_test
async def test_vis_heap_chunk_command_2_43(ctrl: Controller) -> None:
    import pwndbg.aglib
    import pwndbg.aglib.memory
    import pwndbg.aglib.vmmap
    import pwndbg.libc
    from pwndbg.commands.ptmalloc2 import bin_ascii

    # Disable collapsible output for existing test expectations
    await ctrl.execute("set vis-skip-repeating-val off")

    await ctrl.launch(HEAP_2_43, env={"GLIBC_TUNABLES": "glibc.malloc.tcache_max=0x1000"})
    break_at_sym("break_step")
    await ctrl.cont()

    if pwndbg.aglib.arch.name != "x86-64":
        pytest.skip("TODO multiarch")

    if pwndbg.libc.version() < (2, 43):
        pytest.skip("Test is not applicable below glibc 2.43")

    # TODO/FIXME: Shall we have a standard method to do this kind of filtering?
    # Note that we have `pages_filter` in pwndbg/pwndbg/commands/vmmap.py heh
    heap_page = next(page for page in pwndbg.aglib.vmmap.get() if page.objfile == "[heap]")

    first_chunk_size = pwndbg.aglib.memory.u64(heap_page.start + pwndbg.aglib.arch.ptrsize)

    def sz_class(size: int) -> int:
        return 1 << size.bit_length()

    # Just a sanity check...
    assert (heap_page.start & 0xFFF) == 0

    result = (await ctrl.execute_and_capture("vis-heap-chunk 1")).splitlines()

    # We will use `heap_addr` variable to fill in proper addresses below
    heap_addr = heap_page.start

    def heap_iter(offset: int = 0x10) -> int:
        nonlocal heap_addr
        heap_addr += offset
        return heap_addr

    frame = pwndbg.dbg.selected_frame()
    assert frame
    chunk1_next = int(frame.evaluate_expression("tcache->entries[65]->next"))
    tcache_key = int(frame.evaluate_expression("tcache->entries[65]->key"))

    def hexdump_line(qword1: int = 0, qword2: int = 0) -> str:
        from pwnlib.util.packing import p64

        return f"{qword1:#018x}\t{qword2:#018x}\t{bin_ascii(p64(qword1) + p64(qword2))}"

    expected1 = [
        f"{heap_iter(0):#x}\t{hexdump_line(0, first_chunk_size)}",
        f"{heap_iter():#x}\t{hexdump_line(chunk1_next, tcache_key)}\t <-- tcachebins[{sz_class(first_chunk_size):#x}][0/2]",
        *[f"{heap_iter():#x}\t{hexdump_line()}" for _ in range(first_chunk_size // 16 - 2)],
        f"{heap_iter():#x}\t{0:#018x}\t                  \t........",
    ]
    assert result == expected1

    result = (await ctrl.execute_and_capture("vis-heap-chunk")).splitlines()

    frame = pwndbg.dbg.selected_frame()
    assert frame
    tcache64 = int(frame.evaluate_expression("tcache->entries[64]"))
    tcache65 = int(frame.evaluate_expression("tcache->entries[65]"))
    top_size = pwndbg.aglib.memory.u64(int(frame.evaluate_expression("main_arena.top")) + 8)

    def pack2x4(wordl1: int, wordl2: int, wordl3: int, wordl4: int) -> int:
        return wordl1 | wordl2 << 16 | wordl3 << 32 | wordl4 << 48

    slots_qword = pack2x4(0x10, 0x10, 0x10, 0x10)

    chunk2_size: int
    chunk3_size: int
    expected = [
        *expected1[:-1],
        f"{heap_iter(0):#x}\t{hexdump_line(0, (chunk2_size := pwndbg.aglib.memory.u64(heap_iter(8))))}",
        f"{heap_iter(8):#x}\t{hexdump_line(heap_iter(0) >> 12, tcache_key)}\t <-- tcachebins[{sz_class(chunk2_size):#x}][1/2]",
        *[f"{heap_iter():#x}\t{hexdump_line()}" for _ in range(chunk2_size // 16 - 2)],
        f"{heap_iter():#x}\t{hexdump_line(0, (chunk3_size := pwndbg.aglib.memory.u64(heap_iter(8))))}",
        f"{heap_iter(8):#x}\t{hexdump_line(heap_iter(0) >> 12, tcache_key)}\t <-- tcachebins[{sz_class(chunk3_size):#x}][0/1]",
        *[f"{heap_iter():#x}\t{hexdump_line()}" for _ in range(chunk3_size // 16 - 2)],
        f"{heap_iter():#x}\t{hexdump_line(0, 0x301)}",  # tcache metadata
        *[f"{heap_iter():#x}\t{hexdump_line(slots_qword, slots_qword)}" for _ in range(8)],
        f"{heap_iter():#x}\t{hexdump_line(pack2x4(15, 14, 16, 16), slots_qword)}",
        f"{heap_iter():#x}\t{hexdump_line(slots_qword, 0)}",
        *[f"{heap_iter():#x}\t{hexdump_line()}" for _ in range(0x1F)],
        f"{heap_iter():#x}\t{hexdump_line(0, tcache64)}",
        f"{heap_iter():#x}\t{hexdump_line(tcache65, 0)}",
        *[f"{heap_iter():#x}\t{hexdump_line()}" for _ in range(4)],
        f"{heap_iter():#x}\t{hexdump_line(0, top_size)}\t <-- Top chunk",
    ]

    assert result == expected
