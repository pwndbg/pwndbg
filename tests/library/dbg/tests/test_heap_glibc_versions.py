from __future__ import annotations

from pathlib import Path

import pytest

from ....host import Controller
from . import glibc_test_versions
from . import glibc_version_binaries
from . import glibc_version_params
from . import launch_to
from . import pwndbg_test

GLIBC_VERSIONS = glibc_test_versions()
assert GLIBC_VERSIONS, "no glibc versions parsed from Dockerfile.glibc-test-libs"


def version_tuple(ver: str) -> tuple[int, int]:
    parts = ver.split(".")
    return (int(parts[0]), int(parts[1]))


parametrize_malloc_chunk_versions = glibc_version_params(
    glibc_version_binaries("heap_malloc_chunk", include_system=False), with_version=True
)


@parametrize_malloc_chunk_versions
@pwndbg_test
async def test_heap_version_detection(ctrl: Controller, glibc_version: str, binary: Path) -> None:
    await ctrl.disable_debuginfod()
    await launch_to(ctrl, binary, "break_here")

    import pwndbg.aglib
    import pwndbg.libc

    if pwndbg.aglib.arch.name not in ("x86-64", "aarch64"):
        pytest.skip("glibc version tests are x86-64/aarch64 only")

    assert pwndbg.libc.which() == pwndbg.libc.LibcType.GLIBC
    detected = pwndbg.libc.version()
    expected = version_tuple(glibc_version)
    assert detected[:2] == expected, f"Expected glibc {expected}, detected {detected}"


@parametrize_malloc_chunk_versions
@pwndbg_test
async def test_heap_allocator_setup(ctrl: Controller, glibc_version: str, binary: Path) -> None:
    await ctrl.disable_debuginfod()
    await launch_to(ctrl, binary, "break_here")

    import pwndbg.aglib
    import pwndbg.aglib.heap
    from pwndbg.aglib.heap.ptmalloc import GlibcMemoryAllocator

    if pwndbg.aglib.arch.name not in ("x86-64", "aarch64"):
        pytest.skip("glibc version tests are x86-64/aarch64 only")

    allocator = pwndbg.aglib.heap.current
    assert isinstance(allocator, GlibcMemoryAllocator), (
        f"Expected GlibcMemoryAllocator, got {type(allocator)}"
    )

    assert allocator.has_tcache, f"glibc {glibc_version} should have tcache"
    assert allocator.main_arena is not None, f"main_arena should be found for glibc {glibc_version}"
    assert allocator.mp is not None, f"mp (malloc_par) should be found for glibc {glibc_version}"


@glibc_version_params(glibc_version_binaries("heap_bins", include_system=False), with_version=True)
@pwndbg_test
async def test_heap_bins_glibc_version(ctrl: Controller, glibc_version: str, binary: Path) -> None:
    import pwndbg.aglib
    import pwndbg.aglib.heap
    import pwndbg.aglib.memory
    import pwndbg.aglib.symbol
    from pwndbg.aglib.heap.ptmalloc import BinType
    from pwndbg.aglib.heap.ptmalloc import GlibcMemoryAllocator

    await ctrl.disable_debuginfod()
    await ctrl.launch(binary)

    if pwndbg.aglib.arch.name not in ("x86-64", "aarch64"):
        pytest.skip("glibc version tests are x86-64/aarch64 only")

    await ctrl.execute("set context-output /dev/null")
    await ctrl.execute("b breakpoint")
    await ctrl.cont()

    allocator = pwndbg.aglib.heap.current
    assert isinstance(allocator, GlibcMemoryAllocator)

    version = version_tuple(glibc_version)

    addr = pwndbg.aglib.symbol.lookup_symbol_addr("tcache_size")
    assert addr is not None
    tcache_size = allocator._request2size(pwndbg.aglib.memory.u64(addr))

    result = allocator.tcachebins()
    assert result is not None
    assert result.bin_type == BinType.TCACHE
    assert tcache_size in result.bins

    addr = pwndbg.aglib.symbol.lookup_symbol_addr("fastbin_size")
    assert addr is not None
    fastbin_size = allocator._request2size(pwndbg.aglib.memory.u64(addr))

    result = allocator.fastbins()
    if version >= (2, 43):
        assert result is None, f"glibc {glibc_version} should have no fastbins"
    else:
        assert result is not None
        assert result.bin_type == BinType.FAST
        assert fastbin_size in result.bins

    await ctrl.cont()

    result = allocator.tcachebins()
    assert result is not None
    assert tcache_size in result.bins

    await ctrl.cont()

    result = allocator.fastbins()
    if version < (2, 43):
        assert result is not None

    await ctrl.cont()

    result = allocator.unsortedbin()
    assert result is not None
    assert result.bin_type == BinType.UNSORTED

    if version >= (2, 41):
        assert len(result.bins["all"].fd_chain) <= 1
    else:
        assert len(result.bins["all"].fd_chain) >= 2

    await ctrl.cont()

    result = allocator.smallbins()
    assert result is not None
    assert result.bin_type == BinType.SMALL

    await ctrl.cont()

    result = allocator.largebins()
    assert result is not None
    assert result.bin_type == BinType.LARGE

    await ctrl.execute("bins")


@parametrize_malloc_chunk_versions
@pwndbg_test
async def test_heap_malloc_chunk_glibc_version(
    ctrl: Controller, glibc_version: str, binary: Path
) -> None:
    import pwndbg.aglib
    import pwndbg.aglib.heap
    import pwndbg.aglib.symbol
    from pwndbg.aglib.heap.ptmalloc import GlibcMemoryAllocator

    await ctrl.disable_debuginfod()
    await launch_to(ctrl, binary, "break_here")

    if pwndbg.aglib.arch.name not in ("x86-64", "aarch64"):
        pytest.skip("glibc version tests are x86-64/aarch64 only")

    allocator = pwndbg.aglib.heap.current
    assert isinstance(allocator, GlibcMemoryAllocator)

    malloc_chunk = allocator.malloc_chunk
    assert malloc_chunk is not None, (
        f"malloc_chunk type should be available for glibc {glibc_version}"
    )

    chunk_types = [
        "allocated_chunk",
        "tcache_chunk",
        "fast_chunk",
        "small_chunk",
        "large_chunk",
        "unsorted_chunk",
    ]
    for name in chunk_types:
        addr = pwndbg.aglib.symbol.lookup_symbol_value(name)
        if addr is None or addr == 0:
            continue
        result = await ctrl.execute_and_capture(f"malloc-chunk {name}")
        assert len(result) > 0, f"malloc-chunk {name} produced no output for glibc {glibc_version}"

        assert "chunk" in result.lower() or "Addr:" in result, (
            f"malloc-chunk {name} output doesn't look right for glibc {glibc_version}: {result[:200]}"
        )


@parametrize_malloc_chunk_versions
@pytest.mark.parametrize("use_heuristic", [False, True], ids=["debug-syms", "heuristic"])
@pwndbg_test
async def test_heap_heuristic_glibc_version(
    ctrl: Controller, glibc_version: str, binary: Path, use_heuristic: bool
) -> None:
    import pwndbg.aglib
    import pwndbg.aglib.heap
    from pwndbg.aglib.heap.ptmalloc import GlibcMemoryAllocator

    await ctrl.disable_debuginfod()
    await ctrl.launch(binary)

    if pwndbg.aglib.arch.name not in ("x86-64", "aarch64"):
        pytest.skip("glibc version tests are x86-64/aarch64 only")

    if use_heuristic:
        await ctrl.execute("set resolve-heap-via-heuristic force")

    await ctrl.execute("b break_here")
    await ctrl.cont()

    allocator = pwndbg.aglib.heap.current
    assert isinstance(allocator, GlibcMemoryAllocator), (
        f"Expected GlibcMemoryAllocator for glibc {glibc_version} "
        f"(heuristic={use_heuristic}), got {type(allocator)}"
    )

    main_arena = allocator.main_arena
    assert main_arena is not None, (
        f"main_arena not found for glibc {glibc_version} (heuristic={use_heuristic})"
    )

    result = await ctrl.execute_and_capture("heap")
    assert len(result) > 0, f"'heap' command produced no output for glibc {glibc_version}"


@glibc_version_params(
    glibc_version_binaries(
        "heap_malloc_chunk",
        suffix="-nodebug",
        include_system=False,
    ),
    {"2.42": "stripped glibc 2.42 heuristic can't recover main_arena"},
    with_version=True,
)
@pwndbg_test
async def test_heap_heuristic_nodebug_glibc_version(
    ctrl: Controller, glibc_version: str, binary: Path
) -> None:
    import pwndbg.aglib
    import pwndbg.aglib.heap
    import pwndbg.libc
    from pwndbg.aglib.heap.ptmalloc import GlibcMemoryAllocator

    await ctrl.disable_debuginfod()
    await ctrl.launch(binary)

    if pwndbg.aglib.arch.name not in ("x86-64", "aarch64"):
        pytest.skip("glibc version tests are x86-64/aarch64 only")

    await ctrl.execute("set resolve-heap-via-heuristic force")
    await ctrl.execute("b break_here")
    await ctrl.cont()

    assert pwndbg.libc.which() == pwndbg.libc.LibcType.GLIBC
    assert pwndbg.libc.has_debug_info() is False

    allocator = pwndbg.aglib.heap.current
    assert isinstance(allocator, GlibcMemoryAllocator)

    assert allocator.main_arena is not None

    assert pwndbg.libc.version()[:2] == version_tuple(glibc_version)

    result = await ctrl.execute_and_capture("heap")
    assert len(result) > 0
