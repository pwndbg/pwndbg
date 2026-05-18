from __future__ import annotations

import re
from typing import Any

import pytest

from ....host import Controller
from . import break_at_sym
from . import get_binary
from . import launch_to
from . import pwndbg_test

HEAP_MALLOC_CHUNK = get_binary("heap_malloc_chunk.native.out")
HEAP_MALLOC_CHUNK_DUMP = get_binary("heap_malloc_chunk_dump.native.out")
HEAP_GLIBC2_43 = get_binary("heap_glibc2.43.native.out")

ADDR_RE = re.compile(r"^Addr: (0x[0-9a-f]+)$")


def extract_chunk_addrs(output: str) -> list[int]:
    chunk_addrs: list[int] = []
    for line in output.splitlines():
        match = ADDR_RE.match(line)
        if match:
            chunk_addrs.append(int(match.group(1), 16))
    return chunk_addrs


def generate_expected_malloc_chunk_output(chunks: dict[str, Any]) -> dict[str, Any]:
    import pwndbg.aglib.heap
    from pwndbg.aglib.heap.ptmalloc import GlibcMemoryAllocator

    assert isinstance(pwndbg.aglib.heap.current, GlibcMemoryAllocator)

    expected = {}

    def read_chunk_real_size(chunk_type: str) -> tuple[int, int]:
        size = int(
            chunks[chunk_type][
                (
                    "mchunk_size"
                    if "mchunk_size" in (f.name for f in chunks[chunk_type].type.fields())
                    else "size"
                )
            ]
        )
        return size, size & (0xFFFFFFFFFFFFFFF - 0b111)

    size, real_size = read_chunk_real_size("allocated")
    expected["allocated"] = [
        "Allocated chunk | PREV_INUSE",
        f"Addr: {int(chunks['allocated'].address):#x}",
        f"Size: 0x{real_size:02x} (with flag bits: 0x{size:02x})",
        "",
    ]

    size, real_size = read_chunk_real_size("tcache")
    expected["tcache"] = [
        f"Free chunk ({'tcachebins' if pwndbg.aglib.heap.current.has_tcache else 'fastbins'}) | PREV_INUSE",
        f"Addr: {int(chunks['tcache'].address):#x}",
        f"Size: 0x{real_size:02x} (with flag bits: 0x{size:02x})",
        f"fd: 0x{int(chunks['tcache']['fd']):02x}",
        "",
    ]

    if "fast" in chunks:
        size, real_size = read_chunk_real_size("fast")
        expected["fast"] = [
            f"Free chunk ({'fastbins'}) | PREV_INUSE",
            f"Addr: {int(chunks['fast'].address):#x}",
            f"Size: 0x{real_size:02x} (with flag bits: 0x{size:02x})",
            f"fd: 0x{int(chunks['fast']['fd']):02x}",
            "",
        ]

    size, real_size = read_chunk_real_size("small")
    expected["small"] = [
        "Free chunk (smallbins) | PREV_INUSE",
        f"Addr: {int(chunks['small'].address):#x}",
        f"Size: 0x{real_size:02x} (with flag bits: 0x{size:02x})",
        f"fd: 0x{int(chunks['small']['fd']):02x}",
        f"bk: 0x{int(chunks['small']['bk']):02x}",
        "",
    ]

    size, real_size = read_chunk_real_size("large")
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

    size, real_size = read_chunk_real_size("unsorted")
    expected["unsorted"] = [
        "Free chunk (unsortedbin) | PREV_INUSE",
        f"Addr: {int(chunks['unsorted'].address):#x}",
        f"Size: 0x{real_size:02x} (with flag bits: 0x{size:02x})",
        f"fd: 0x{int(chunks['unsorted']['fd']):02x}",
        f"bk: 0x{int(chunks['unsorted']['bk']):02x}",
        "",
    ]

    if "tcache_large" in chunks:
        size, real_size = read_chunk_real_size("tcache_large")
        expected["tcache_large"] = [
            "Free chunk (tcachebins large) | PREV_INUSE",
            f"Addr: {int(chunks['tcache_large'].address):#x}",
            f"Size: 0x{real_size:02x} (with flag bits: 0x{size:02x})",
            f"fd: 0x{int(chunks['tcache_large']['fd']):02x}",
            "",
        ]

    return expected


@pwndbg_test
async def test_heap_command_count(ctrl: Controller) -> None:
    import pwndbg.aglib

    await launch_to(ctrl, HEAP_MALLOC_CHUNK, "break_here")
    if pwndbg.aglib.arch.name != "x86-64":
        pytest.skip("TODO multiarch")

    count_output = await ctrl.execute_and_capture("heap allocated_chunk --count 2")
    count_addrs = extract_chunk_addrs(count_output)
    assert len(count_addrs) == 2


@pwndbg_test
async def test_heap_command_range_and_count(ctrl: Controller) -> None:
    import pwndbg.aglib
    import pwndbg.aglib.symbol
    from pwndbg.aglib.heap.ptmalloc import Chunk

    await launch_to(ctrl, HEAP_MALLOC_CHUNK, "break_here")
    if pwndbg.aglib.arch.name != "x86-64":
        pytest.skip("TODO multiarch")

    chunk_start_addr = pwndbg.aglib.symbol.lookup_symbol_value("allocated_chunk")
    assert chunk_start_addr is not None

    first_chunk = Chunk(chunk_start_addr)
    second_chunk = first_chunk.next_chunk()
    assert second_chunk is not None
    third_chunk = second_chunk.next_chunk()
    assert third_chunk is not None
    fourth_chunk = third_chunk.next_chunk()
    assert fourth_chunk is not None

    range_start = first_chunk.address
    range_end = third_chunk.address

    range_output = await ctrl.execute_and_capture(f"heap {range_start:#x} {range_end:#x}")
    range_addrs = extract_chunk_addrs(range_output)

    assert range_addrs == [first_chunk.address, second_chunk.address, third_chunk.address]
    assert all(addr <= range_end for addr in range_addrs)
    assert fourth_chunk.address not in range_addrs

    range_count_output = await ctrl.execute_and_capture(
        f"heap {range_start:#x} {fourth_chunk.address:#x} --count 2"
    )
    range_count_addrs = extract_chunk_addrs(range_count_output)

    assert range_count_addrs == [first_chunk.address, second_chunk.address]

    invalid_range_output = await ctrl.execute_and_capture(f"heap {range_start:#x} {range_start:#x}")
    assert "`addr_end` must be greater than `addr_start`." in invalid_range_output


async def resolve_malloc_chunks(ctrl: Controller, heuristic: bool, chunk_types: list[str]) -> None:
    import pwndbg.aglib
    import pwndbg.aglib.heap
    import pwndbg.aglib.memory
    import pwndbg.aglib.symbol
    import pwndbg.dbg_mod
    from pwndbg.aglib.heap.ptmalloc import GlibcMemoryAllocator

    assert isinstance(pwndbg.aglib.heap.current, GlibcMemoryAllocator)

    chunks = {}
    results = {}
    malloc_chunk = pwndbg.aglib.heap.current.malloc_chunk
    if heuristic:
        assert malloc_chunk is not None
    else:
        assert isinstance(malloc_chunk, pwndbg.dbg_mod.Type)
    for name in chunk_types:
        chunk_addr = pwndbg.aglib.symbol.lookup_symbol_value(f"{name}_chunk")
        assert chunk_addr is not None
        if heuristic:
            chunks[name] = malloc_chunk(chunk_addr)
        else:
            chunks[name] = pwndbg.aglib.memory.get_typed_pointer_value(
                malloc_chunk,
                chunk_addr,
            )
        results[name] = (await ctrl.execute_and_capture(f"malloc-chunk {name}_chunk")).splitlines()

    expected = generate_expected_malloc_chunk_output(chunks)

    for name in chunk_types:
        assert results[name] == expected[name]

    await ctrl.cont()

    # Print main thread's chunk from another thread
    thread = pwndbg.dbg.selected_thread()
    assert thread is not None
    assert thread.index() == 2
    results["large"] = (await ctrl.execute_and_capture("malloc-chunk large_chunk")).splitlines()
    expected = generate_expected_malloc_chunk_output(chunks)
    assert results["large"] == expected["large"]

    await ctrl.cont()

    # Test some non-main-arena chunks
    for name in chunk_types:
        chunk_addr = pwndbg.aglib.symbol.lookup_symbol_value(f"{name}_chunk")
        assert chunk_addr is not None
        if heuristic:
            chunks[name] = malloc_chunk(chunk_addr)
        else:
            chunks[name] = pwndbg.aglib.memory.get_typed_pointer_value(
                malloc_chunk,
                chunk_addr,
            )
        results[name] = (await ctrl.execute_and_capture(f"malloc-chunk {name}_chunk")).splitlines()

    expected = generate_expected_malloc_chunk_output(chunks)
    expected["allocated"][0] += " | NON_MAIN_ARENA"
    expected["tcache"][0] += " | NON_MAIN_ARENA"
    if "tcache_large" in expected:
        expected["tcache_large"][0] += " | NON_MAIN_ARENA"
    if "fast" in expected:
        expected["fast"][0] += " | NON_MAIN_ARENA"

    for name in chunk_types:
        assert results[name] == expected[name]

    # Print another thread's chunk from the main thread
    await ctrl.select_thread(1)
    thread = pwndbg.dbg.selected_thread()
    assert thread is not None
    assert thread.index() == 1
    results["large"] = (await ctrl.execute_and_capture("malloc-chunk large_chunk")).splitlines()
    assert results["large"] == expected["large"]


@pwndbg_test
async def test_malloc_chunk_command(ctrl: Controller) -> None:
    import pwndbg.aglib
    import pwndbg.libc

    await launch_to(ctrl, HEAP_MALLOC_CHUNK, "break_here")
    if pwndbg.aglib.arch.name != "x86-64":
        pytest.skip("TODO multiarch")

    if pwndbg.libc.version() >= (2, 43):
        pytest.skip("Test is not applicable above glibc 2.43")

    await resolve_malloc_chunks(
        ctrl,
        False,
        ["allocated", "tcache", "fast", "small", "large", "unsorted"],
    )


@pwndbg_test
async def test_malloc_chunk_command_heuristic(ctrl: Controller) -> None:
    import pwndbg.aglib
    import pwndbg.libc

    await ctrl.launch(HEAP_MALLOC_CHUNK)
    if pwndbg.aglib.arch.name != "x86-64":
        pytest.skip("TODO multiarch")

    await ctrl.execute("set resolve-heap-via-heuristic force")
    break_at_sym("break_here")
    await ctrl.cont()

    if pwndbg.libc.version() >= (2, 43):
        pytest.skip("Test is not applicable above glibc 2.43")

    await resolve_malloc_chunks(
        ctrl,
        True,
        ["allocated", "tcache", "fast", "small", "large", "unsorted"],
    )


@pwndbg_test
async def test_malloc_chunk_2_43(ctrl: Controller) -> None:
    import pwndbg.aglib
    import pwndbg.libc

    await ctrl.launch(HEAP_GLIBC2_43, env={"GLIBC_TUNABLES": "glibc.malloc.tcache_max=0x1000"})
    if pwndbg.aglib.arch.name != "x86-64":
        pytest.skip("TODO multiarch")

    break_at_sym("break_here")
    await ctrl.cont()

    if pwndbg.libc.version() < (2, 43):
        pytest.skip("Test is not applicable below glibc 2.43")

    await resolve_malloc_chunks(
        ctrl,
        False,
        ["allocated", "tcache", "tcache_large", "small", "large", "unsorted"],
    )


@pwndbg_test
async def test_malloc_chunk_2_43_heuristic(ctrl: Controller) -> None:
    import pwndbg.aglib
    import pwndbg.libc

    await ctrl.launch(HEAP_GLIBC2_43, env={"GLIBC_TUNABLES": "glibc.malloc.tcache_max=0x1000"})
    if pwndbg.aglib.arch.name != "x86-64":
        pytest.skip("TODO multiarch")

    await ctrl.execute("set resolve-heap-via-heuristic force")
    break_at_sym("break_here")
    await ctrl.cont()

    if pwndbg.libc.version() < (2, 43):
        pytest.skip("Test is not applicable below glibc 2.43")

    await resolve_malloc_chunks(
        ctrl,
        True,
        ["allocated", "tcache", "tcache_large", "small", "large", "unsorted"],
    )


@pwndbg_test
async def test_malloc_chunk_dump_command(ctrl: Controller) -> None:
    import pwndbg.aglib
    import pwndbg.aglib.heap
    import pwndbg.aglib.memory
    import pwndbg.aglib.symbol
    from pwndbg.aglib.heap.ptmalloc import GlibcMemoryAllocator

    await launch_to(ctrl, HEAP_MALLOC_CHUNK_DUMP, "break_here")

    assert isinstance(pwndbg.aglib.heap.current, GlibcMemoryAllocator)

    if pwndbg.aglib.arch.name != "x86-64":
        pytest.skip("TODO multiarch")

    malloc_chunk = pwndbg.aglib.heap.current.malloc_chunk
    assert malloc_chunk is not None
    test_chunk_addr = pwndbg.aglib.symbol.lookup_symbol_value("test_chunk")
    assert test_chunk_addr is not None
    chunk = pwndbg.aglib.memory.get_typed_pointer_value(
        malloc_chunk,
        test_chunk_addr,
    )
    chunk_addr = chunk.address
    assert chunk_addr is not None

    malloc_chunk = await ctrl.execute_and_capture(f"malloc-chunk {int(chunk_addr):#x} -d")

    size = int(
        chunk[("mchunk_size" if "mchunk_size" in (f.name for f in chunk.type.fields()) else "size")]
    )

    real_size = size & (0xFFFFFFFFFFFFFFF - 0b111)

    assert chunk.address is not None
    chunk_addr = int(chunk.address)
    expected = [
        "Allocated chunk | PREV_INUSE",
        f"Addr: 0x{chunk_addr:x}",
        f"Size: 0x{real_size:02x} (with flag bits: 0x{size:02x})",
        "",
        "hexdump",
        f"+0000 0x{chunk_addr:x}  00 00 00 00 00 00 00 00  31 00 00 00 00 00 00 00  │........│1.......│",
        f"+0010 0x{chunk_addr + 0x10:x}  54 68 69 73 20 69 73 20  61 20 74 65 73 74 20 73  │This.is.│a.test.s│",
        f"+0020 0x{chunk_addr + 0x20:x}  74 72 69 6e 67 00 00 00  00 00 00 00 00 00 00 00  │tring...│........│",
        f"+0030 0x{chunk_addr + 0x30:x}  00 00 00 00 00 00 00 00                           │........│        │",
    ]

    # now just compare the output
    assert malloc_chunk.splitlines() == expected


class mock_for_heuristic:
    def __init__(self, mock_symbols: list[str] | None = None, mock_all: bool = False) -> None:
        """
        Arguments:
            mock_symbols: Every symbol's address in the list will be mocked to `None`
            mock_all: All symbols will be mocked to `None`.

        """
        import pwndbg

        if mock_all:
            assert mock_symbols is None

        self.mock_symbols: list[str] | None = mock_symbols
        self.mock_all: bool = mock_all
        # Save `selected_inferior` before mocking
        self.saved_func = pwndbg.dbg.selected_inferior

    def __enter__(self) -> None:
        import pwndbg

        def mock_lookup_symbol(original):
            def _mock(symbol, *args, **kwargs):
                if self.mock_all:
                    return None
                assert self.mock_symbols
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

    def __exit__(self, exc_type, exc_value, traceback) -> None:
        import pwndbg

        # Restore `selected_inferior`
        pwndbg.dbg.selected_inferior = self.saved_func


@pwndbg_test
async def test_main_arena_heuristic(ctrl: Controller) -> None:
    import pwndbg.aglib.heap
    import pwndbg.aglib.symbol
    import pwndbg.aglib.typeinfo
    from pwndbg.aglib.heap.ptmalloc import GlibcMemoryAllocator

    await ctrl.launch(HEAP_MALLOC_CHUNK)
    await ctrl.execute("set resolve-heap-via-heuristic force")
    break_at_sym("break_here")
    await ctrl.cont()

    assert isinstance(pwndbg.aglib.heap.current, GlibcMemoryAllocator)

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
    assert isinstance(pwndbg.aglib.heap.current, GlibcMemoryAllocator)

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
    from pwndbg.aglib.heap.ptmalloc import GlibcMemoryAllocator

    await ctrl.launch(HEAP_MALLOC_CHUNK)
    await ctrl.execute("set resolve-heap-via-heuristic force")
    break_at_sym("break_here")
    await ctrl.cont()

    assert isinstance(pwndbg.aglib.heap.current, GlibcMemoryAllocator)

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
    assert isinstance(pwndbg.aglib.heap.current, GlibcMemoryAllocator)

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
    import pwndbg.aglib
    import pwndbg.aglib.heap
    import pwndbg.aglib.memory
    import pwndbg.aglib.symbol
    import pwndbg.aglib.typeinfo
    from pwndbg.aglib.heap.ptmalloc import GlibcMemoryAllocator

    # TODO: Support other architectures or different libc versions
    await ctrl.launch(HEAP_MALLOC_CHUNK)
    if pwndbg.aglib.arch.name != "x86-64":
        pytest.skip("TODO multiarch")

    assert isinstance(pwndbg.aglib.heap.current, GlibcMemoryAllocator)

    await ctrl.execute("set resolve-heap-via-heuristic force")
    break_at_sym("break_here")
    await ctrl.cont()
    if is_multi_threaded:
        await ctrl.cont()
        thread = pwndbg.dbg.selected_thread()
        assert thread is not None and thread.index() == 2

    # Use the debug symbol to find the address of `thread_cache`
    tcache_addr_via_debug_symbol = pwndbg.aglib.symbol.lookup_symbol_addr(
        "tcache", prefer_static=True
    )
    assert tcache_addr_via_debug_symbol is not None
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
    assert isinstance(pwndbg.aglib.heap.current, GlibcMemoryAllocator)

    # Check if we can get the address of `tcache` by using the first chunk or by brute force
    with mock_for_heuristic(["tcache"]):
        # Check if we can find tcache by brute force
        pwndbg.aglib.heap.current.prompt_for_brute_force_thread_cache_permission = lambda: True  # type: ignore[attr-defined]
        thread_cache = pwndbg.aglib.heap.current.thread_cache
        assert thread_cache is not None
        assert thread_cache.address == thread_cache_addr_via_debug_symbol
        pwndbg.aglib.heap.current = type(
            pwndbg.aglib.heap.current
        )()  # Reset the heap object of pwndbg
        assert isinstance(pwndbg.aglib.heap.current, GlibcMemoryAllocator)
        # Check if we can find tcache by using the first chunk
        # # Note: This will NOT work when can NOT find the heap boundaries or the the arena is been shared
        pwndbg.aglib.heap.current.prompt_for_brute_force_thread_cache_permission = lambda: False  # type: ignore[attr-defined]
        thread_cache = pwndbg.aglib.heap.current.thread_cache
        assert (
            thread_cache is not None and thread_cache.address == thread_cache_addr_via_debug_symbol
        )


@pytest.mark.parametrize(
    "is_multi_threaded", [False, True], ids=["single-threaded", "multi-threaded"]
)
@pwndbg_test
async def test_thread_arena_heuristic(ctrl: Controller, is_multi_threaded: bool) -> None:
    import pwndbg.aglib
    import pwndbg.aglib.heap
    import pwndbg.aglib.memory
    import pwndbg.aglib.symbol
    from pwndbg.aglib.heap.ptmalloc import GlibcMemoryAllocator

    # TODO: Support other architectures or different libc versions
    await ctrl.launch(HEAP_MALLOC_CHUNK)
    if pwndbg.aglib.arch.name != "x86-64":
        pytest.skip("TODO multiarch")

    assert isinstance(pwndbg.aglib.heap.current, GlibcMemoryAllocator)

    await ctrl.execute("set resolve-heap-via-heuristic force")
    break_at_sym("break_here")
    await ctrl.cont()

    if is_multi_threaded:
        await ctrl.cont()
        thread = pwndbg.dbg.selected_thread()
        assert thread is not None and thread.index() == 2

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
    assert isinstance(pwndbg.aglib.heap.current, GlibcMemoryAllocator)

    # Check if we can use brute-force to find the `thread_arena` when multi-threaded, and if we can use the `main_arena` as the `thread_arena` when single-threaded
    with mock_for_heuristic(["thread_arena"]):
        # mock the prompt to avoid input
        pwndbg.aglib.heap.current.prompt_for_brute_force_thread_arena_permission = lambda: True  # type: ignore[attr-defined]
        assert pwndbg.aglib.heap.current.thread_arena is not None
        # Check the value of `thread_arena` is correct
        assert pwndbg.aglib.heap.current.thread_arena.address == thread_arena_via_debug_symbol


@pwndbg_test
async def test_global_max_fast_heuristic(ctrl: Controller) -> None:
    import pwndbg.aglib
    import pwndbg.aglib.heap
    import pwndbg.aglib.memory
    import pwndbg.aglib.symbol
    import pwndbg.libc
    from pwndbg.aglib.heap.ptmalloc import GlibcMemoryAllocator

    # TODO: Support other architectures or different libc versions
    await ctrl.launch(HEAP_MALLOC_CHUNK)
    if pwndbg.aglib.arch.name != "x86-64":
        pytest.skip("TODO multiarch")

    assert isinstance(pwndbg.aglib.heap.current, GlibcMemoryAllocator)

    await ctrl.execute("set resolve-heap-via-heuristic force")

    break_at_sym("break_here")
    await ctrl.cont()

    if pwndbg.libc.version() >= (2, 43):
        pytest.skip("Fastbin is removed after glibc 2.43")

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
    assert isinstance(pwndbg.aglib.heap.current, GlibcMemoryAllocator)

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
    from pwndbg.aglib.heap.ptmalloc import GlibcMemoryAllocator
    from pwndbg.lib import SymbolNotRecoveredError

    # TODO: Support other architectures or different libc versions
    await ctrl.launch(HEAP_MALLOC_CHUNK)
    await ctrl.execute("set resolve-heap-via-heuristic force")
    break_at_sym("break_here")
    await ctrl.cont()
    if is_multi_threaded:
        await ctrl.cont()
        thread = pwndbg.dbg.selected_thread()
        assert thread is not None and thread.index() == 2

    assert isinstance(pwndbg.aglib.heap.current, GlibcMemoryAllocator)

    def _test_heuristic_fail_gracefully(name):
        try:
            getattr(pwndbg.aglib.heap.current, name)
        except SymbolNotRecoveredError as e:
            # That's the only exception we expect
            assert e.name  # we should show what symbol we failed to resolve

    # Mock all address and mess up the memory
    with mock_for_heuristic(mock_all=True):
        # mock the prompt to avoid input
        pwndbg.aglib.heap.current.prompt_for_brute_force_thread_arena_permission = lambda: False  # type: ignore[attr-defined]
        pwndbg.aglib.heap.current.prompt_for_brute_force_thread_cache_permission = lambda: False  # type: ignore[attr-defined]
        _test_heuristic_fail_gracefully("main_arena")
        _test_heuristic_fail_gracefully("mp")
        _test_heuristic_fail_gracefully("global_max_fast")
        _test_heuristic_fail_gracefully("thread_cache")
        _test_heuristic_fail_gracefully("thread_arena")
