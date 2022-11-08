import gdb

import pwndbg
import pwndbg.gdblib.arch
import pwndbg.gdblib.memory
import pwndbg.gdblib.symbol
import pwndbg.gdblib.typeinfo
import pwndbg.glibc
import pwndbg.heap
import tests
from pwndbg.heap.ptmalloc import SymbolUnresolvableError

HEAP_MALLOC_CHUNK = tests.binaries.get("heap_malloc_chunk.out")


def generate_expected_malloc_chunk_output(chunks):
    expected = {}
    expected["allocated"] = [
        "Allocated chunk | PREV_INUSE",
        f"Addr: {chunks['allocated'].address}",
        f"Size: 0x{int(chunks['allocated']['mchunk_size' if 'mchunk_size' in (f.name for f in chunks['allocated'].type.fields()) else 'size']):02x}",
        "",
    ]

    expected["tcache"] = [
        f"Free chunk ({'tcachebins' if pwndbg.heap.current.has_tcache else 'fastbins'}) | PREV_INUSE",
        f"Addr: {chunks['tcache'].address}",
        f"Size: 0x{int(chunks['tcache']['mchunk_size' if 'mchunk_size' in (f.name for f in chunks['tcache'].type.fields()) else 'size']):02x}",
        f"fd: 0x{int(chunks['tcache']['fd']):02x}",
        "",
    ]

    expected["fast"] = [
        "Free chunk (fastbins) | PREV_INUSE",
        f"Addr: {chunks['fast'].address}",
        f"Size: 0x{int(chunks['fast']['mchunk_size' if 'mchunk_size' in (f.name for f in chunks['fast'].type.fields()) else 'size']):02x}",
        f"fd: 0x{int(chunks['fast']['fd']):02x}",
        "",
    ]

    expected["small"] = [
        "Free chunk (smallbins) | PREV_INUSE",
        f"Addr: {chunks['small'].address}",
        f"Size: 0x{int(chunks['small']['mchunk_size' if 'mchunk_size' in (f.name for f in chunks['small'].type.fields()) else 'size']):02x}",
        f"fd: 0x{int(chunks['small']['fd']):02x}",
        f"bk: 0x{int(chunks['small']['bk']):02x}",
        "",
    ]

    expected["large"] = [
        "Free chunk (largebins) | PREV_INUSE",
        f"Addr: {chunks['large'].address}",
        f"Size: 0x{int(chunks['large']['mchunk_size' if 'mchunk_size' in (f.name for f in chunks['large'].type.fields()) else 'size']):02x}",
        f"fd: 0x{int(chunks['large']['fd']):02x}",
        f"bk: 0x{int(chunks['large']['bk']):02x}",
        f"fd_nextsize: 0x{int(chunks['large']['fd_nextsize']):02x}",
        f"bk_nextsize: 0x{int(chunks['large']['bk_nextsize']):02x}",
        "",
    ]

    expected["unsorted"] = [
        "Free chunk (unsortedbin) | PREV_INUSE",
        f"Addr: {chunks['unsorted'].address}",
        f"Size: 0x{int(chunks['unsorted']['mchunk_size' if 'mchunk_size' in (f.name for f in chunks['unsorted'].type.fields()) else 'size']):02x}",
        f"fd: 0x{int(chunks['unsorted']['fd']):02x}",
        f"bk: 0x{int(chunks['unsorted']['bk']):02x}",
        "",
    ]

    return expected


def test_malloc_chunk_command(start_binary):
    start_binary(HEAP_MALLOC_CHUNK)
    gdb.execute("break break_here")
    gdb.execute("continue")

    chunks = {}
    results = {}
    chunk_types = ["allocated", "tcache", "fast", "small", "large", "unsorted"]
    for name in chunk_types:
        chunks[name] = pwndbg.gdblib.memory.poi(
            pwndbg.heap.current.malloc_chunk, gdb.lookup_symbol(f"{name}_chunk")[0].value()
        )
        results[name] = gdb.execute(f"malloc_chunk {name}_chunk", to_string=True).splitlines()

    expected = generate_expected_malloc_chunk_output(chunks)

    for name in chunk_types:
        assert results[name] == expected[name]

    gdb.execute("continue")

    # Print main thread's chunk from another thread
    assert gdb.selected_thread().num == 2
    results["large"] = gdb.execute("malloc_chunk large_chunk", to_string=True).splitlines()
    expected = generate_expected_malloc_chunk_output(chunks)
    assert results["large"] == expected["large"]

    gdb.execute("continue")

    # Test some non-main-arena chunks
    for name in chunk_types:
        chunks[name] = pwndbg.gdblib.memory.poi(
            pwndbg.heap.current.malloc_chunk, gdb.lookup_symbol(f"{name}_chunk")[0].value()
        )
        results[name] = gdb.execute(f"malloc_chunk {name}_chunk", to_string=True).splitlines()

    expected = generate_expected_malloc_chunk_output(chunks)
    expected["allocated"][0] += " | NON_MAIN_ARENA"
    expected["tcache"][0] += " | NON_MAIN_ARENA"
    expected["fast"][0] += " | NON_MAIN_ARENA"

    for name in chunk_types:
        assert results[name] == expected[name]

    # Print another thread's chunk from the main thread
    gdb.execute("thread 1")
    assert gdb.selected_thread().num == 1
    results["large"] = gdb.execute("malloc_chunk large_chunk", to_string=True).splitlines()
    assert results["large"] == expected["large"]


def test_malloc_chunk_command_heuristic(start_binary):
    start_binary(HEAP_MALLOC_CHUNK)
    gdb.execute("set resolve-heap-via-heuristic on")
    gdb.execute("break break_here")
    gdb.execute("continue")

    chunks = {}
    results = {}
    chunk_types = ["allocated", "tcache", "fast", "small", "large", "unsorted"]
    for name in chunk_types:
        chunks[name] = pwndbg.heap.current.malloc_chunk(
            gdb.lookup_symbol(f"{name}_chunk")[0].value()
        )
        results[name] = gdb.execute(f"malloc_chunk {name}_chunk", to_string=True).splitlines()

    expected = generate_expected_malloc_chunk_output(chunks)

    for name in chunk_types:
        assert results[name] == expected[name]

    gdb.execute("continue")

    # Print main thread's chunk from another thread
    assert gdb.selected_thread().num == 2
    results["large"] = gdb.execute("malloc_chunk large_chunk", to_string=True).splitlines()
    expected = generate_expected_malloc_chunk_output(chunks)
    assert results["large"] == expected["large"]

    gdb.execute("continue")

    # Test some non-main-arena chunks
    for name in chunk_types:
        chunks[name] = pwndbg.heap.current.malloc_chunk(
            gdb.lookup_symbol(f"{name}_chunk")[0].value()
        )
        results[name] = gdb.execute(f"malloc_chunk {name}_chunk", to_string=True).splitlines()

    expected = generate_expected_malloc_chunk_output(chunks)
    expected["allocated"][0] += " | NON_MAIN_ARENA"
    expected["tcache"][0] += " | NON_MAIN_ARENA"
    expected["fast"][0] += " | NON_MAIN_ARENA"

    for name in chunk_types:
        assert results[name] == expected[name]

    # Print another thread's chunk from the main thread
    gdb.execute("thread 1")
    assert gdb.selected_thread().num == 1
    results["large"] = gdb.execute("malloc_chunk large_chunk", to_string=True).splitlines()
    assert results["large"] == expected["large"]


class mock_for_heuristic:
    def __init__(self, mock_symbols=[], mock_all=False, mess_up_memory=False):
        self.mock_symbols = (
            mock_symbols  # every symbol's address in the list will be mocked to `None`
        )
        self.mock_all = mock_all  # all symbols will be mocked to `None`
        # Save `pwndbg.gdblib.symbol.address` and `pwndbg.gdblib.symbol.static_linkage_symbol_address` before mocking
        self.saved_address_func = pwndbg.gdblib.symbol.address
        self.saved_static_linkage_symbol_address_func = (
            pwndbg.gdblib.symbol.static_linkage_symbol_address
        )
        # We mess up the memory in the page of the symbols, to make sure that the heuristic will not succeed by parsing the memory
        self.mess_up_memory = mess_up_memory
        if mess_up_memory:
            # Save all the memory before we mess it up
            self.page = pwndbg.heap.current.possible_page_of_symbols
            self.saved_memory = pwndbg.gdblib.memory.read(self.page.vaddr, self.page.memsz)

    def __enter__(self):
        def mock(original):
            def _mock(symbol, *args, **kwargs):
                if self.mock_all:
                    return None
                for s in self.mock_symbols:
                    if s == symbol:
                        return None
                return original(symbol, *args, **kwargs)

            return _mock

        # Mock `pwndbg.gdblib.symbol.address` and `pwndbg.gdblib.symbol.static_linkage_symbol_address`
        pwndbg.gdblib.symbol.address = mock(pwndbg.gdblib.symbol.address)
        pwndbg.gdblib.symbol.static_linkage_symbol_address = mock(
            pwndbg.gdblib.symbol.static_linkage_symbol_address
        )
        if self.mess_up_memory:
            # Fill the page with `0xff`
            pwndbg.gdblib.memory.write(self.page.vaddr, b"\xff" * self.page.memsz)

    def __exit__(self, exc_type, exc_value, traceback):
        # Restore `pwndbg.gdblib.symbol.address` and `pwndbg.gdblib.symbol.static_linkage_symbol_address`
        pwndbg.gdblib.symbol.address = self.saved_address_func
        pwndbg.gdblib.symbol.static_linkage_symbol_address = (
            self.saved_static_linkage_symbol_address_func
        )
        if self.mess_up_memory:
            # Restore the memory
            pwndbg.gdblib.memory.write(self.page.vaddr, self.saved_memory)


def test_main_arena_heuristic(start_binary):
    start_binary(HEAP_MALLOC_CHUNK)
    gdb.execute("set resolve-heap-via-heuristic on")
    gdb.execute("break break_here")
    gdb.execute("continue")

    # Use the debug symbol to get the address of `main_arena`
    main_arena_addr_via_debug_symbol = pwndbg.gdblib.symbol.static_linkage_symbol_address(
        "main_arena"
    ) or pwndbg.gdblib.symbol.address("main_arena")

    # Level 1: We check we can get the address of `main_arena` from debug symbols and the struct of `main_arena` is correct
    assert pwndbg.heap.current.main_arena is not None
    # Check the address of `main_arena` is correct
    assert pwndbg.heap.current.main_arena.address == main_arena_addr_via_debug_symbol
    # Check the struct size is correct
    assert (
        pwndbg.heap.current.main_arena._gdbValue.type.sizeof
        == pwndbg.gdblib.typeinfo.lookup_types("struct malloc_state").sizeof
    )
    pwndbg.heap.current = type(pwndbg.heap.current)()  # Reset the heap object of pwndbg

    # Level 2.1: We check we can get the address of `main_arena` by parsing the assembly code of `malloc_trim`
    with mock_for_heuristic(["main_arena"], mess_up_memory=True):
        assert pwndbg.heap.current.main_arena is not None
        # Check the address of `main_arena` is correct
        assert pwndbg.heap.current.main_arena.address == main_arena_addr_via_debug_symbol
    pwndbg.heap.current = type(pwndbg.heap.current)()  # Reset the heap object of pwndbg

    # Level 2.2: No `__malloc_hook` this time, because it's possible to find `main_arena` by some magic about it
    with mock_for_heuristic(["main_arena", "__malloc_hook"], mess_up_memory=True):
        assert pwndbg.heap.current.main_arena is not None
        # Check the address of `main_arena` is correct
        assert pwndbg.heap.current.main_arena.address == main_arena_addr_via_debug_symbol
    pwndbg.heap.current = type(pwndbg.heap.current)()  # Reset the heap object of pwndbg

    # Level 3: We check we can get the address of `main_arena` by parsing the memory
    with mock_for_heuristic(mock_all=True):
        # Check the address of `main_arena` is correct
        assert pwndbg.heap.current.main_arena.address == main_arena_addr_via_debug_symbol


def test_mp_heuristic(start_binary):
    start_binary(HEAP_MALLOC_CHUNK)
    gdb.execute("set resolve-heap-via-heuristic on")
    gdb.execute("break break_here")
    gdb.execute("continue")

    # Use the debug symbol to get the address of `mp_`
    mp_addr_via_debug_symbol = pwndbg.gdblib.symbol.static_linkage_symbol_address(
        "mp_"
    ) or pwndbg.gdblib.symbol.address("mp_")

    # Level 1: We check we can get the address of `mp_` from debug symbols and the struct of `mp_` is correct
    assert pwndbg.heap.current.mp is not None
    # Check the address of `main_arena` is correct
    assert pwndbg.heap.current.mp.address == mp_addr_via_debug_symbol
    # Check the struct size is correct
    assert (
        pwndbg.heap.current.mp.type.sizeof
        == pwndbg.gdblib.typeinfo.lookup_types("struct malloc_par").sizeof
    )
    pwndbg.heap.current = type(pwndbg.heap.current)()  # Reset the heap object of pwndbg

    # Level 2: We check we can get the address of `mp_` by parsing the assembly code of `__libc_free`
    with mock_for_heuristic(["mp_"], mess_up_memory=True):
        assert pwndbg.heap.current.mp is not None
        # Check the address of `mp_` is correct
        assert pwndbg.heap.current.mp.address == mp_addr_via_debug_symbol
    pwndbg.heap.current = type(pwndbg.heap.current)()  # Reset the heap object of pwndbg

    # Level 3: We check we can get the address of `mp_` by parsing the memory
    with mock_for_heuristic(mock_all=True):
        # Check the address of `mp_` is correct
        assert pwndbg.heap.current.mp.address == mp_addr_via_debug_symbol


def test_global_max_fast_heuristic(start_binary):
    # TODO: Support other architectures or different libc versions
    start_binary(HEAP_MALLOC_CHUNK)
    gdb.execute("set resolve-heap-via-heuristic on")
    gdb.execute("break break_here")
    gdb.execute("continue")

    # Use the debug symbol to find the address of `global_max_fast`
    global_max_fast_addr_via_debug_symbol = pwndbg.gdblib.symbol.static_linkage_symbol_address(
        "global_max_fast"
    ) or pwndbg.gdblib.symbol.address("global_max_fast")
    assert global_max_fast_addr_via_debug_symbol is not None

    # Level 1: We check we can get the address of `global_max_fast` from debug symbols and the value of `global_max_fast` is correct
    assert pwndbg.heap.current.global_max_fast is not None
    # Check the address of `global_max_fast` is correct
    assert pwndbg.heap.current._global_max_fast_addr == global_max_fast_addr_via_debug_symbol
    pwndbg.heap.current = type(pwndbg.heap.current)()  # Reset the heap object of pwndbg

    # Level 2: We check we can get the address of `global_max_fast` by parsing the assembly code of `__libc_free`
    # Mock the address of `global_max_fast` to None
    with mock_for_heuristic(["global_max_fast"]):
        # Use heuristic to find `global_max_fast`
        assert pwndbg.heap.current.global_max_fast is not None
        # Check the address of `global_max_fast` is correct
        assert pwndbg.heap.current._global_max_fast_addr == global_max_fast_addr_via_debug_symbol


def test_thread_cache_heuristic(start_binary):
    # TODO: Support other architectures or different libc versions
    start_binary(HEAP_MALLOC_CHUNK)
    gdb.execute("set resolve-heap-via-heuristic on")
    gdb.execute("break break_here")
    gdb.execute("continue")

    # Use the debug symbol to find the address of `thread_cache`
    tcache_addr_via_debug_symbol = pwndbg.gdblib.symbol.static_linkage_symbol_address(
        "tcache"
    ) or pwndbg.gdblib.symbol.address("tcache")
    thread_cache_addr_via_debug_symbol = pwndbg.gdblib.memory.u(tcache_addr_via_debug_symbol)

    # Level 1: We check we can get the address of `thread_cache` from debug symbols and the struct of `thread_cache` is correct
    assert pwndbg.heap.current.thread_cache is not None
    # Check the address of `thread_cache` is correct
    assert pwndbg.heap.current.thread_cache.address == thread_cache_addr_via_debug_symbol
    # Check the struct size is correct
    assert (
        pwndbg.heap.current.thread_cache.type.sizeof
        == pwndbg.gdblib.typeinfo.lookup_types("struct tcache_perthread_struct").sizeof
    )
    pwndbg.heap.current = type(pwndbg.heap.current)()  # Reset the heap object of pwndbg

    # Level 2: We check we can get the address of `thread_cache` by parsing the assembly code of `__libc_malloc`
    # TODO: Find a good way to check we scuessfully get the address of `thread_cache` by parsing the assembly code instead of using the first chunk of `thread_cache`
    # Note: This only useful when we can NOT find the heap boundaries and the the arena is been shared, it should not be a big problem in most of the cases

    # Level 3: We check we can get the address of `thread_cache` by using the first chunk
    # Note: This will NOT work when can NOT find the heap boundaries or the the arena is been shared
    with mock_for_heuristic(["tcache", "__libc_malloc"]):
        # Check the address of `thread_cache` is correct
        assert pwndbg.heap.current.thread_cache.address == thread_cache_addr_via_debug_symbol


def test_thread_arena_heuristic(start_binary):
    # TODO: Support other architectures or different libc versions
    start_binary(HEAP_MALLOC_CHUNK)
    gdb.execute("set resolve-heap-via-heuristic on")
    gdb.execute("break break_here")
    gdb.execute("continue")

    # Use the debug symbol to find the value of `thread_arena`
    thread_arena_via_debug_symbol = pwndbg.gdblib.symbol.static_linkage_symbol_address(
        "thread_arena"
    ) or pwndbg.gdblib.symbol.address("thread_arena")
    assert thread_arena_via_debug_symbol is not None
    thread_arena_via_debug_symbol = pwndbg.gdblib.memory.u(thread_arena_via_debug_symbol)
    assert thread_arena_via_debug_symbol > 0

    # Level 1: We check we can get the address of `thread_arena` from debug symbols and the value of `thread_arena` is correct
    assert pwndbg.heap.current.thread_arena is not None
    # Check the address of `thread_arena` is correct
    assert pwndbg.heap.current.thread_arena.address == thread_arena_via_debug_symbol
    pwndbg.heap.current = type(pwndbg.heap.current)()  # Reset the heap object of pwndbg

    # Level 2: We check we can get the address of `thread_arena` by parsing the assembly code of `__libc_calloc`
    # Mock the address of `thread_arena` to None
    with mock_for_heuristic(["thread_arena"]):
        assert pwndbg.gdblib.symbol.address("thread_arena") is None
        # Check the value of `thread_arena` is correct
        assert pwndbg.heap.current.thread_arena.address == thread_arena_via_debug_symbol


def test_heuristic_fail_gracefully(start_binary):
    # TODO: Support other architectures or different libc versions
    start_binary(HEAP_MALLOC_CHUNK)
    gdb.execute("set resolve-heap-via-heuristic on")
    gdb.execute("break break_here")
    gdb.execute("continue")

    def _test_heuristic_fail_gracefully(name):
        try:
            getattr(pwndbg.heap.current, name)
            raise AssertionError(
                "The heuristic for pwndbg.heap.current.%s should fail with SymbolUnresolvableError"
                % name
            )
        except SymbolUnresolvableError:
            # That's the only exception we expect
            pass

    # Mock all address and mess up the memory
    with mock_for_heuristic(mock_all=True, mess_up_memory=True):
        _test_heuristic_fail_gracefully("main_arena")
        _test_heuristic_fail_gracefully("mp")
        _test_heuristic_fail_gracefully("global_max_fast")
        _test_heuristic_fail_gracefully("thread_cache")
        _test_heuristic_fail_gracefully("thread_arena")
