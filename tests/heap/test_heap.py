import gdb

import pwndbg
import tests

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
        f"Free chunk ({'tcache' if pwndbg.heap.current.has_tcache else 'fastbins'}) | PREV_INUSE",
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
    results["large"] = gdb.execute("malloc_chunk large_chunk", to_string=True).splitlines()
    assert results["large"] == expected["large"]
