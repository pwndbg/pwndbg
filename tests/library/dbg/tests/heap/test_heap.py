from __future__ import annotations

import re
from typing import Dict

import pytest

from .....host import Controller
from .. import break_at_sym
from .. import get_binary
from .. import launch_to
from .. import pwndbg_test

HEAP_MALLOC_CHUNK = get_binary("heap_malloc_chunk.out")
HEAP_MALLOC_CHUNK_DUMP = get_binary("heap_malloc_chunk_dump.out")


def generate_expected_malloc_chunk_output(chunks: Dict[str, ...]) -> Dict[str, ...]:
    import pwndbg.aglib.heap

    expected = {}

    size = int(
        chunks["allocated"][
            (
                "mchunk_size"
                if "mchunk_size" in (f.name for f in chunks["allocated"].type.fields())
                else "size"
            )
        ]
    )
    real_size = size & (0xFFFFFFFFFFFFFFF - 0b111)
    expected["allocated"] = [
        "Allocated chunk | PREV_INUSE",
        f"Addr: {int(chunks['allocated'].address):#x}",
        f"Size: 0x{real_size:02x} (with flag bits: 0x{size:02x})",
        "",
    ]

    size = int(
        chunks["tcache"][
            (
                "mchunk_size"
                if "mchunk_size" in (f.name for f in chunks["tcache"].type.fields())
                else "size"
            )
        ]
    )
    real_size = size & (0xFFFFFFFFFFFFFFF - 0b111)
    expected["tcache"] = [
        f"Free chunk ({'tcachebins' if pwndbg.aglib.heap.current.has_tcache else 'fastbins'}) | PREV_INUSE",
        f"Addr: {int(chunks['tcache'].address):#x}",
        f"Size: 0x{real_size:02x} (with flag bits: 0x{size:02x})",
        f"fd: 0x{int(chunks['tcache']['fd']):02x}",
        "",
    ]

    size = int(
        chunks["fast"][
            (
                "mchunk_size"
                if "mchunk_size" in (f.name for f in chunks["fast"].type.fields())
                else "size"
            )
        ]
    )
    real_size = size & (0xFFFFFFFFFFFFFFF - 0b111)
    expected["fast"] = [
        "Free chunk (fastbins) | PREV_INUSE",
        f"Addr: {int(chunks['fast'].address):#x}",
        f"Size: 0x{real_size:02x} (with flag bits: 0x{size:02x})",
        f"fd: 0x{int(chunks['fast']['fd']):02x}",
        "",
    ]

    size = int(
        chunks["small"][
            (
                "mchunk_size"
                if "mchunk_size" in (f.name for f in chunks["small"].type.fields())
                else "size"
            )
        ]
    )
    real_size = size & (0xFFFFFFFFFFFFFFF - 0b111)
    expected["small"] = [
        "Free chunk (smallbins) | PREV_INUSE",
        f"Addr: {int(chunks['small'].address):#x}",
        f"Size: 0x{real_size:02x} (with flag bits: 0x{size:02x})",
        f"fd: 0x{int(chunks['small']['fd']):02x}",
        f"bk: 0x{int(chunks['small']['bk']):02x}",
        "",
    ]

    size = int(
        chunks["large"][
            (
                "mchunk_size"
                if "mchunk_size" in (f.name for f in chunks["large"].type.fields())
                else "size"
            )
        ]
    )
    real_size = size & (0xFFFFFFFFFFFFFFF - 0b111)
    expected["large"] = [
        "Free chunk (largebins) | PREV_INUSE",
        f"Addr: {int(chunks['large'].address):#x}",
        f"Size: 0x{real_size:02x} (with flag bits: 0x{size:02x})",
        f"fd: 0x{int(chunks['large']['fd']):02x}",
        f"bk: 0x{int(chunks['large']['bk']):02x}",
        f"fd_nextsize: 0x{int(chunks['large']['fd_nextsize']):02x}",
        f"bk_nextsize: 0x{int(chunks['large']['bk_nextsize']):02x}",
        "",
    ]

    size = int(
        chunks["unsorted"][
            (
                "mchunk_size"
                if "mchunk_size" in (f.name for f in chunks["unsorted"].type.fields())
                else "size"
            )
        ]
    )
    real_size = size & (0xFFFFFFFFFFFFFFF - 0b111)
    expected["unsorted"] = [
        "Free chunk (unsortedbin) | PREV_INUSE",
        f"Addr: {int(chunks['unsorted'].address):#x}",
        f"Size: 0x{real_size:02x} (with flag bits: 0x{size:02x})",
        f"fd: 0x{int(chunks['unsorted']['fd']):02x}",
        f"bk: 0x{int(chunks['unsorted']['bk']):02x}",
        "",
    ]

    return expected


@pwndbg_test
async def test_malloc_chunk_command(ctrl: Controller) -> None:
    import pwndbg
    import pwndbg.aglib.heap
    import pwndbg.aglib.memory
    import pwndbg.aglib.symbol

    await launch_to(ctrl, HEAP_MALLOC_CHUNK, "break_here")

    chunks = {}
    results = {}
    chunk_types = ["allocated", "tcache", "fast", "small", "large", "unsorted"]
    for name in chunk_types:
        chunks[name] = pwndbg.aglib.memory.get_typed_pointer_value(
            pwndbg.aglib.heap.current.malloc_chunk,
            pwndbg.aglib.symbol.lookup_symbol_value(f"{name}_chunk"),
        )
        results[name] = (await ctrl.execute_and_capture(f"malloc-chunk {name}_chunk")).splitlines()

    expected = generate_expected_malloc_chunk_output(chunks)

    for name in chunk_types:
        assert results[name] == expected[name]

    await ctrl.cont()

    # Print main thread's chunk from another thread
    assert pwndbg.dbg.selected_thread().index() == 2
    results["large"] = (await ctrl.execute_and_capture("malloc-chunk large_chunk")).splitlines()
    expected = generate_expected_malloc_chunk_output(chunks)
    assert results["large"] == expected["large"]

    await ctrl.cont()

    # Test some non-main-arena chunks
    for name in chunk_types:
        chunks[name] = pwndbg.aglib.memory.get_typed_pointer_value(
            pwndbg.aglib.heap.current.malloc_chunk,
            pwndbg.aglib.symbol.lookup_symbol_value(f"{name}_chunk"),
        )
        results[name] = (await ctrl.execute_and_capture(f"malloc-chunk {name}_chunk")).splitlines()

    expected = generate_expected_malloc_chunk_output(chunks)
    expected["allocated"][0] += " | NON_MAIN_ARENA"
    expected["tcache"][0] += " | NON_MAIN_ARENA"
    expected["fast"][0] += " | NON_MAIN_ARENA"

    for name in chunk_types:
        assert results[name] == expected[name]

    # Print another thread's chunk from the main thread
    await ctrl.select_thread(1)
    assert pwndbg.dbg.selected_thread().index() == 1
    results["large"] = (await ctrl.execute_and_capture("malloc-chunk large_chunk")).splitlines()
    assert results["large"] == expected["large"]


@pwndbg_test
async def test_malloc_chunk_command_heuristic(ctrl: Controller) -> None:
    import pwndbg
    import pwndbg.aglib.heap
    import pwndbg.aglib.symbol

    await ctrl.launch(HEAP_MALLOC_CHUNK)
    await ctrl.execute("set resolve-heap-via-heuristic force")
    break_at_sym("break_here")
    await ctrl.cont()

    chunks = {}
    results = {}
    chunk_types = ["allocated", "tcache", "fast", "small", "large", "unsorted"]
    for name in chunk_types:
        chunks[name] = pwndbg.aglib.heap.current.malloc_chunk(
            pwndbg.aglib.symbol.lookup_symbol_value(f"{name}_chunk")
        )
        results[name] = (await ctrl.execute_and_capture(f"malloc-chunk {name}_chunk")).splitlines()

    expected = generate_expected_malloc_chunk_output(chunks)

    for name in chunk_types:
        assert results[name] == expected[name]

    await ctrl.cont()

    # Print main thread's chunk from another thread
    assert pwndbg.dbg.selected_thread().index() == 2
    results["large"] = (await ctrl.execute_and_capture("malloc-chunk large_chunk")).splitlines()
    expected = generate_expected_malloc_chunk_output(chunks)
    assert results["large"] == expected["large"]

    await ctrl.cont()

    # Test some non-main-arena chunks
    for name in chunk_types:
        chunks[name] = pwndbg.aglib.heap.current.malloc_chunk(
            pwndbg.aglib.symbol.lookup_symbol_value(f"{name}_chunk")
        )
        results[name] = (await ctrl.execute_and_capture(f"malloc-chunk {name}_chunk")).splitlines()

    expected = generate_expected_malloc_chunk_output(chunks)
    expected["allocated"][0] += " | NON_MAIN_ARENA"
    expected["tcache"][0] += " | NON_MAIN_ARENA"
    expected["fast"][0] += " | NON_MAIN_ARENA"

    for name in chunk_types:
        assert results[name] == expected[name]

    # Print another thread's chunk from the main thread
    await ctrl.select_thread(1)
    assert pwndbg.dbg.selected_thread().index() == 1
    results["large"] = (await ctrl.execute_and_capture("malloc-chunk large_chunk")).splitlines()
    assert results["large"] == expected["large"]


@pwndbg_test
async def test_malloc_chunk_dump_command(ctrl: Controller) -> None:
    import pwndbg.aglib.heap
    import pwndbg.aglib.memory
    import pwndbg.aglib.symbol

    await launch_to(ctrl, HEAP_MALLOC_CHUNK_DUMP, "break_here")

    chunk = pwndbg.aglib.memory.get_typed_pointer_value(
        pwndbg.aglib.heap.current.malloc_chunk,
        pwndbg.aglib.symbol.lookup_symbol_value("test_chunk"),
    )
    chunk_addr = chunk.address

    malloc_chunk = await ctrl.execute_and_capture(f"malloc-chunk {int(chunk_addr):#x} -d")

    size = int(
        chunk[("mchunk_size" if "mchunk_size" in (f.name for f in chunk.type.fields()) else "size")]
    )

    real_size = size & (0xFFFFFFFFFFFFFFF - 0b111)

    chunk_addr = int(chunk.address)
    expected = [
        "Allocated chunk | PREV_INUSE",
        f"Addr: 0x{chunk_addr:x}",
        f"Size: 0x{real_size:02x} (with flag bits: 0x{size:02x})",
        "",
        "hexdump",
        f"+0000 0x{chunk_addr:x}  00 00 00 00 00 00 00 00  31 00 00 00 00 00 00 00  │........│1.......│",
        f"+0010 0x{chunk_addr+0x10:x}  54 68 69 73 20 69 73 20  61 20 74 65 73 74 20 73  │This.is.│a.test.s│",
        f"+0020 0x{chunk_addr+0x20:x}  74 72 69 6e 67 00 00 00  00 00 00 00 00 00 00 00  │tring...│........│",
        f"+0030 0x{chunk_addr+0x30:x}  00 00 00 00 00 00 00 00                           │........│        │",
    ]

    # now just compare the output
    assert malloc_chunk.splitlines() == expected


class mock_for_heuristic:
    def __init__(self, mock_symbols=[], mock_all=False):
        import pwndbg

        self.mock_symbols = (
            mock_symbols  # every symbol's address in the list will be mocked to `None`
        )
        self.mock_all = mock_all  # all symbols will be mocked to `None`
        # Save `selected_inferior` before mocking
        self.saved_func = pwndbg.dbg.selected_inferior

    def __enter__(self):
        import pwndbg

        def mock_lookup_symbol(original):
            def _mock(symbol, *args, **kwargs):
                if self.mock_all:
                    return None
                for s in self.mock_symbols:
                    if s == symbol:
                        return None
                return original(symbol, *args, **kwargs)

            return _mock

        def mock_interior(original):
            def _mock(*args, **kwargs):
                inst = original(*args, **kwargs)
                inst.lookup_symbol = mock_lookup_symbol(inst.lookup_symbol)
                return inst

            return _mock

        # Mock `symbol_address_from_name` from `selected_inferior`
        pwndbg.dbg.selected_inferior = mock_interior(pwndbg.dbg.selected_inferior)

    def __exit__(self, exc_type, exc_value, traceback):
        import pwndbg

        # Restore `selected_inferior`
        pwndbg.dbg.selected_inferior = self.saved_func


@pwndbg_test
async def test_main_arena_heuristic(ctrl: Controller) -> None:
    import pwndbg.aglib.heap
    import pwndbg.aglib.symbol
    import pwndbg.aglib.typeinfo

    await ctrl.launch(HEAP_MALLOC_CHUNK)
    await ctrl.execute("set resolve-heap-via-heuristic force")
    break_at_sym("break_here")
    await ctrl.cont()

    # Use the debug symbol to get the address of `main_arena`
    main_arena_addr_via_debug_symbol = pwndbg.aglib.symbol.lookup_symbol_addr(
        "main_arena", prefer_static=True
    )

    # Check if we can get the address of `main_arena` from debug symbols and the struct of `main_arena` is correct
    assert pwndbg.aglib.heap.current.main_arena is not None
    # Check the address of `main_arena` is correct
    assert pwndbg.aglib.heap.current.main_arena.address == main_arena_addr_via_debug_symbol
    # Check the struct size is correct
    assert (
        pwndbg.aglib.heap.current.main_arena._gdbValue.type.sizeof
        == pwndbg.aglib.typeinfo.lookup_types("struct malloc_state").sizeof
    )
    pwndbg.aglib.heap.current = type(pwndbg.aglib.heap.current)()  # Reset the heap object of pwndbg

    # Check if we can get the address of `main_arena` by parsing the .data section of the ELF of libc
    with mock_for_heuristic(["main_arena"]):
        assert pwndbg.aglib.heap.current.main_arena is not None
        # Check the address of `main_arena` is correct
        assert pwndbg.aglib.heap.current.main_arena.address == main_arena_addr_via_debug_symbol


@pwndbg_test
async def test_mp_heuristic(ctrl: Controller) -> None:
    import pwndbg.aglib.heap
    import pwndbg.aglib.symbol
    import pwndbg.aglib.typeinfo

    await ctrl.launch(HEAP_MALLOC_CHUNK)
    await ctrl.execute("set resolve-heap-via-heuristic force")
    break_at_sym("break_here")
    await ctrl.cont()

    # Use the debug symbol to get the address of `mp_`
    mp_addr_via_debug_symbol = pwndbg.aglib.symbol.lookup_symbol_addr("mp_", prefer_static=True)

    # Check if we can get the address of `mp_` from debug symbols and the struct of `mp_` is correct
    assert pwndbg.aglib.heap.current.mp is not None
    # Check the address of `main_arena` is correct
    assert pwndbg.aglib.heap.current.mp.address == mp_addr_via_debug_symbol
    # Check the struct size is correct
    assert (
        pwndbg.aglib.heap.current.mp.type.sizeof
        == pwndbg.aglib.typeinfo.lookup_types("struct malloc_par").sizeof
    )
    pwndbg.aglib.heap.current = type(pwndbg.aglib.heap.current)()  # Reset the heap object of pwndbg

    # Check if we can get the address of `mp_` by parsing the .data section of the ELF of libc
    with mock_for_heuristic(["mp_"]):
        assert pwndbg.aglib.heap.current.mp is not None
        # Check the address of `mp_` is correct
        assert pwndbg.aglib.heap.current.mp.address == mp_addr_via_debug_symbol


@pytest.mark.parametrize(
    "is_multi_threaded", [False, True], ids=["single-threaded", "multi-threaded"]
)
@pwndbg_test
async def test_thread_cache_heuristic(ctrl: Controller, is_multi_threaded: bool) -> None:
    import pwndbg
    import pwndbg.aglib.heap
    import pwndbg.aglib.memory
    import pwndbg.aglib.symbol
    import pwndbg.aglib.typeinfo

    # TODO: Support other architectures or different libc versions
    await ctrl.launch(HEAP_MALLOC_CHUNK)
    await ctrl.execute("set resolve-heap-via-heuristic force")
    break_at_sym("break_here")
    await ctrl.cont()
    if is_multi_threaded:
        await ctrl.cont()
        assert pwndbg.dbg.selected_thread().index() == 2

    # Use the debug symbol to find the address of `thread_cache`
    tcache_addr_via_debug_symbol = pwndbg.aglib.symbol.lookup_symbol_addr(
        "tcache", prefer_static=True
    )
    thread_cache_addr_via_debug_symbol = pwndbg.aglib.memory.u(tcache_addr_via_debug_symbol)

    # Check if we can get the address of `thread_cache` from debug symbols and the struct of `thread_cache` is correct
    assert pwndbg.aglib.heap.current.thread_cache is not None
    # Check the address of `thread_cache` is correct
    assert pwndbg.aglib.heap.current.thread_cache.address == thread_cache_addr_via_debug_symbol
    # Check the struct size is correct
    assert (
        pwndbg.aglib.heap.current.thread_cache.type.sizeof
        == pwndbg.aglib.typeinfo.lookup_types("struct tcache_perthread_struct").sizeof
    )
    pwndbg.aglib.heap.current = type(pwndbg.aglib.heap.current)()  # Reset the heap object of pwndbg

    # Check if we can get the address of `tcache` by using the first chunk or by brute force
    with mock_for_heuristic(["tcache"]):
        # Check if we can find tcache by brute force
        pwndbg.aglib.heap.current.prompt_for_brute_force_thread_cache_permission = lambda: True
        assert pwndbg.aglib.heap.current.thread_cache.address == thread_cache_addr_via_debug_symbol
        pwndbg.aglib.heap.current = type(
            pwndbg.aglib.heap.current
        )()  # Reset the heap object of pwndbg
        # Check if we can find tcache by using the first chunk
        # # Note: This will NOT work when can NOT find the heap boundaries or the the arena is been shared
        pwndbg.aglib.heap.current.prompt_for_brute_force_thread_cache_permission = lambda: False
        assert pwndbg.aglib.heap.current.thread_cache.address == thread_cache_addr_via_debug_symbol


@pytest.mark.parametrize(
    "is_multi_threaded", [False, True], ids=["single-threaded", "multi-threaded"]
)
@pwndbg_test
async def test_thread_arena_heuristic(ctrl: Controller, is_multi_threaded: bool) -> None:
    import pwndbg
    import pwndbg.aglib.heap
    import pwndbg.aglib.memory
    import pwndbg.aglib.symbol

    # TODO: Support other architectures or different libc versions
    await ctrl.launch(HEAP_MALLOC_CHUNK)
    await ctrl.execute("set resolve-heap-via-heuristic force")
    break_at_sym("break_here")
    await ctrl.cont()

    if is_multi_threaded:
        await ctrl.cont()
        assert pwndbg.dbg.selected_thread().index() == 2

    # Use the debug symbol to find the value of `thread_arena`
    thread_arena_via_debug_symbol = pwndbg.aglib.symbol.lookup_symbol_addr(
        "thread_arena", prefer_static=True
    )
    assert thread_arena_via_debug_symbol is not None
    thread_arena_via_debug_symbol = pwndbg.aglib.memory.u(thread_arena_via_debug_symbol)
    assert thread_arena_via_debug_symbol > 0

    # Check if we can get the address of `thread_arena` from debug symbols and the value of `thread_arena` is correct
    assert pwndbg.aglib.heap.current.thread_arena is not None
    # Check the address of `thread_arena` is correct
    assert pwndbg.aglib.heap.current.thread_arena.address == thread_arena_via_debug_symbol
    pwndbg.aglib.heap.current = type(pwndbg.aglib.heap.current)()  # Reset the heap object of pwndbg

    # Check if we can use brute-force to find the `thread_arena` when multi-threaded, and if we can use the `main_arena` as the `thread_arena` when single-threaded
    with mock_for_heuristic(["thread_arena"]):
        # mock the prompt to avoid input
        pwndbg.aglib.heap.current.prompt_for_brute_force_thread_arena_permission = lambda: True
        assert pwndbg.aglib.heap.current.thread_arena is not None
        # Check the value of `thread_arena` is correct
        assert pwndbg.aglib.heap.current.thread_arena.address == thread_arena_via_debug_symbol


@pwndbg_test
async def test_global_max_fast_heuristic(ctrl: Controller) -> None:
    import pwndbg.aglib.heap

    # TODO: Support other architectures or different libc versions
    await ctrl.launch(HEAP_MALLOC_CHUNK)
    await ctrl.execute("set resolve-heap-via-heuristic force")
    break_at_sym("break_here")
    await ctrl.cont()

    # Use the debug symbol to find the address of `global_max_fast`
    global_max_fast_addr_via_debug_symbol = pwndbg.aglib.symbol.lookup_symbol_addr(
        "global_max_fast", prefer_static=True
    )
    assert global_max_fast_addr_via_debug_symbol is not None

    # Check if we can get the address of `global_max_fast` from debug symbols and the value of `global_max_fast` is correct
    assert pwndbg.aglib.heap.current.global_max_fast is not None
    # Check the address of `global_max_fast` is correct
    assert pwndbg.aglib.heap.current._global_max_fast_addr == global_max_fast_addr_via_debug_symbol
    pwndbg.aglib.heap.current = type(pwndbg.aglib.heap.current)()  # Reset the heap object of pwndbg

    # Check if we can return the default value even if we can NOT find the address of `global_max_fast`
    with mock_for_heuristic(["global_max_fast"]):
        assert pwndbg.aglib.heap.current.global_max_fast == pwndbg.aglib.memory.u(
            global_max_fast_addr_via_debug_symbol
        )


@pytest.mark.parametrize(
    "is_multi_threaded", [False, True], ids=["single-threaded", "multi-threaded"]
)
@pwndbg_test
async def test_heuristic_fail_gracefully(ctrl: Controller, is_multi_threaded: bool) -> None:
    import pwndbg.aglib.heap
    from pwndbg.aglib.heap.ptmalloc import SymbolUnresolvableError

    # TODO: Support other architectures or different libc versions
    await ctrl.launch(HEAP_MALLOC_CHUNK)
    await ctrl.execute("set resolve-heap-via-heuristic force")
    break_at_sym("break_here")
    await ctrl.cont()
    if is_multi_threaded:
        await ctrl.cont()
        assert pwndbg.dbg.selected_thread().index() == 2

    def _test_heuristic_fail_gracefully(name):
        try:
            getattr(pwndbg.aglib.heap.current, name)
        except SymbolUnresolvableError as e:
            # That's the only exception we expect
            assert e.symbol  # we should show what symbol we failed to resolve

    # Mock all address and mess up the memory
    with mock_for_heuristic(mock_all=True):
        # mock the prompt to avoid input
        pwndbg.aglib.heap.current.prompt_for_brute_force_thread_arena_permission = lambda: False
        pwndbg.aglib.heap.current.prompt_for_brute_force_thread_cache_permission = lambda: False
        _test_heuristic_fail_gracefully("main_arena")
        _test_heuristic_fail_gracefully("mp")
        _test_heuristic_fail_gracefully("global_max_fast")
        _test_heuristic_fail_gracefully("thread_cache")
        _test_heuristic_fail_gracefully("thread_arena")


##
# Jemalloc Tests
##
HEAP_JEMALLOC_EXTENT_INFO = get_binary("heap_jemalloc_extent_info.out")
HEAP_JEMALLOC_HEAP = get_binary("heap_jemalloc_heap.out")
re_match_valid_address = r"0x7ffff[0-9a-fA-F]{6,9}"


@pwndbg_test
async def test_jemalloc_find_extent(ctrl: Controller) -> None:
    await launch_to(ctrl, HEAP_JEMALLOC_EXTENT_INFO, "break_here")

    # run jemalloc extent_info command
    result = (await ctrl.execute_and_capture("jemalloc-find-extent ptr")).splitlines()

    expected_output = [
        "Jemalloc find extent",
        "This command was tested only for jemalloc 5.3.0 and does not support lower versions",
        "",
        r"Pointer Address: " + re_match_valid_address,
        r"Extent Address: " + re_match_valid_address,
        "",
        r"Allocated Address: " + re_match_valid_address,
        r"Extent Address: " + re_match_valid_address,
        "Size: 0x1000",
        "Small class: True",
    ]

    expected_idx = 0
    for i in range(len(result)):
        if expected_idx == len(expected_output):
            break
        if re.match(expected_output[expected_idx], result[i]) is not None:
            expected_idx += 1
    assert expected_idx == len(expected_output)


@pwndbg_test
async def test_jemalloc_extent_info(ctrl: Controller) -> None:
    await launch_to(ctrl, HEAP_JEMALLOC_EXTENT_INFO, "break_here")

    find_extent_results = (await ctrl.execute_and_capture("jemalloc-find-extent ptr")).splitlines()
    extent_address = None
    for line in find_extent_results:
        if "Extent Address:" in line:
            extent_address = int(line.split(" ")[-1], 16)
    if extent_address is None:
        raise ValueError("Could not find extent address")
    # run jemalloc extent_info command
    result = (await ctrl.execute_and_capture(f"jemalloc-extent-info {extent_address}")).splitlines()

    expected_output = [
        "Jemalloc extent info",
        "This command was tested only for jemalloc 5.3.0 and does not support lower versions",
        "",
        r"Allocated Address: " + re_match_valid_address,
        r"Extent Address: " + re_match_valid_address,
        "Size: 0x1000",
        "Small class: True",
    ]

    expected_idx = 0
    for i in range(len(result)):
        if expected_idx == len(expected_output):
            break
        if re.match(expected_output[expected_idx], result[i]) is not None:
            expected_idx += 1
    assert expected_idx == len(expected_output)


@pwndbg_test
async def test_jemalloc_heap(ctrl: Controller) -> None:
    await launch_to(ctrl, HEAP_JEMALLOC_HEAP, "break_here")

    # run jemalloc extent_info command
    result = (await ctrl.execute_and_capture("jemalloc-heap")).splitlines()

    expected_output = [
        "Jemalloc heap",
        "This command was tested only for jemalloc 5.3.0 and does not support lower versions",
    ]

    # Extent sizes different depending on the system built (it would seem), so only check for the 0x8000 size,
    # since it seems consistent. The output of an extent implies the rest of the command is working
    expected_output += [
        "",
        "Allocated Address: " + re_match_valid_address,
        r"Extent Address: " + re_match_valid_address,
        "Size: 0x8000",
        "Small class: False",
    ]

    expected_idx = 0
    for i in range(len(result)):
        if expected_idx == len(expected_output):
            break
        if re.match(expected_output[expected_idx], result[i]) is not None:
            expected_idx += 1
    assert expected_idx == len(expected_output)
