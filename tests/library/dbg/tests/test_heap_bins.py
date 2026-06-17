from __future__ import annotations

import pytest

from ....host import Controller
from . import break_at_sym
from . import get_binary
from . import launch_to
from . import pwndbg_test

BINARY = get_binary("heap_bins.native.out")
GLIBC_2_43 = get_binary("heap_glibc2.43.native.out")


@pwndbg_test
async def test_heap_bins(ctrl: Controller) -> None:
    """
    Tests pwndbg.aglib.heap bins commands
    """
    import pwndbg
    import pwndbg.aglib.heap
    import pwndbg.aglib.memory
    import pwndbg.aglib.symbol
    import pwndbg.aglib.vmmap
    import pwndbg.libc
    from pwndbg.aglib.heap.ptmalloc import BinType
    from pwndbg.aglib.heap.ptmalloc import GlibcMemoryAllocator

    await ctrl.launch(BINARY)

    await ctrl.execute("set context-output /dev/null")
    await ctrl.execute("b breakpoint")
    await ctrl.cont()

    if pwndbg.libc.version() >= (2, 43):
        pytest.skip("Test is not applicable above glibc 2.43")

    assert isinstance(pwndbg.aglib.heap.current, GlibcMemoryAllocator)

    # check if all bins are empty at first
    allocator = pwndbg.aglib.heap.current
    assert allocator is not None

    addr = pwndbg.aglib.symbol.lookup_symbol_addr("tcache_size")
    assert addr is not None
    tcache_size = allocator._request2size(pwndbg.aglib.memory.u64(addr))
    addr = pwndbg.aglib.symbol.lookup_symbol_addr("tcache_count")
    assert addr is not None
    tcache_count = pwndbg.aglib.memory.u64(addr)
    addr = pwndbg.aglib.symbol.lookup_symbol_addr("fastbin_size")
    assert addr is not None
    fastbin_size = allocator._request2size(pwndbg.aglib.memory.u64(addr))
    addr = pwndbg.aglib.symbol.lookup_symbol_addr("fastbin_count")
    assert addr is not None
    fastbin_count = pwndbg.aglib.memory.u64(addr)
    addr = pwndbg.aglib.symbol.lookup_symbol_addr("smallbin_size")
    assert addr is not None
    smallbin_size = allocator._request2size(pwndbg.aglib.memory.u64(addr))
    addr = pwndbg.aglib.symbol.lookup_symbol_addr("smallbin_count")
    assert addr is not None
    smallbin_count = pwndbg.aglib.memory.u64(addr)
    addr = pwndbg.aglib.symbol.lookup_symbol_addr("largebin_size")
    assert addr is not None
    largebin_size = allocator._request2size(pwndbg.aglib.memory.u64(addr))
    addr = pwndbg.aglib.symbol.lookup_symbol_addr("largebin_count")
    assert addr is not None
    largebin_count = pwndbg.aglib.memory.u64(addr)

    result = allocator.tcachebins()
    assert result is not None
    assert result.bin_type == BinType.TCACHE
    assert tcache_size in result.bins
    assert result.bins[tcache_size].bk_chain is None and len(result.bins[tcache_size].fd_chain) == 1

    result = allocator.fastbins()
    assert result is not None
    assert result.bin_type == BinType.FAST
    assert fastbin_size in result.bins
    assert len(result.bins[fastbin_size].fd_chain) == 1

    result = allocator.unsortedbin()
    assert result is not None
    assert result.bin_type == BinType.UNSORTED
    assert len(result.bins["all"].fd_chain) == 1
    assert not result.bins["all"].is_corrupted

    result = allocator.smallbins()
    assert result is not None
    assert result.bin_type == BinType.SMALL
    assert smallbin_size in result.bins
    bk_chain = result.bins[smallbin_size].bk_chain
    assert (
        len(result.bins[smallbin_size].fd_chain) == 1
        and bk_chain is not None
        and len(bk_chain) == 1
    )
    assert not result.bins[smallbin_size].is_corrupted

    result = allocator.largebins()
    assert result is not None
    assert result.bin_type == BinType.LARGE
    largebin_size = list(result.bins.items())[allocator.largebin_index(largebin_size) - 64][0]
    assert largebin_size in result.bins
    bk_chain = result.bins[largebin_size].bk_chain
    assert len(result.bins[largebin_size].fd_chain) == 1 and len(bk_chain) == 1
    assert not result.bins[largebin_size].is_corrupted

    # check tcache
    await ctrl.cont()

    result = allocator.tcachebins()
    assert result is not None
    assert result.bin_type == BinType.TCACHE
    assert tcache_size in result.bins
    assert (
        result.bins[tcache_size].count == tcache_count
        and len(result.bins[tcache_size].fd_chain) == tcache_count + 1
    )
    for addr in result.bins[tcache_size].fd_chain[:-1]:
        assert pwndbg.aglib.vmmap.find(addr)

    # check fastbin
    await ctrl.cont()

    result = allocator.fastbins()
    assert result is not None
    assert result.bin_type == BinType.FAST
    assert (fastbin_size in result.bins) and (
        len(result.bins[fastbin_size].fd_chain) == fastbin_count + 1
    )
    for addr in result.bins[fastbin_size].fd_chain[:-1]:
        assert pwndbg.aglib.vmmap.find(addr)

    # check unsortedbin
    await ctrl.cont()

    result = allocator.unsortedbin()
    assert result is not None
    assert result.bin_type == BinType.UNSORTED
    bk_chain = result.bins["all"].bk_chain
    assert bk_chain is not None
    fd_chain_len = len(result.bins["all"].fd_chain)
    bk_chain_len = len(bk_chain)
    assert (
        (fd_chain_len == smallbin_count + 2 and bk_chain_len == smallbin_count + 2)
        # Since glibc 2.42, freed small-bin-sized chunks go directly to the smallbin instead of going
        # to the unsorted bin.
        or (fd_chain_len == 1 and bk_chain_len == 1)
    )
    assert not result.bins["all"].is_corrupted
    for addr in result.bins["all"].fd_chain[:-1]:
        assert pwndbg.aglib.vmmap.find(addr)
    for addr in bk_chain[:-1]:
        assert pwndbg.aglib.vmmap.find(addr)

    # check smallbins
    await ctrl.cont()

    result = allocator.smallbins()
    assert result is not None
    assert result.bin_type == "smallbins"
    bk_chain = result.bins[smallbin_size].bk_chain
    assert bk_chain is not None
    assert (
        len(result.bins[smallbin_size].fd_chain) == smallbin_count + 2
        and len(bk_chain) == smallbin_count + 2
    )
    assert not result.bins[smallbin_size].is_corrupted
    for addr in result.bins[smallbin_size].fd_chain[:-1]:
        assert pwndbg.aglib.vmmap.find(addr)
    for addr in bk_chain[:-1]:
        assert pwndbg.aglib.vmmap.find(addr)

    # check largebins
    await ctrl.cont()

    result = allocator.largebins()
    assert result is not None
    assert result.bin_type == BinType.LARGE
    bk_chain = result.bins[largebin_size].bk_chain
    assert bk_chain is not None
    assert (
        len(result.bins[largebin_size].fd_chain) == largebin_count + 2
        and len(bk_chain) == largebin_count + 2
    )
    assert not result.bins[largebin_size].is_corrupted
    for addr in result.bins[largebin_size].fd_chain[:-1]:
        assert pwndbg.aglib.vmmap.find(addr)
    for addr in bk_chain[:-1]:
        assert pwndbg.aglib.vmmap.find(addr)

    # check corrupted
    await ctrl.cont()
    result = allocator.smallbins()
    assert result is not None
    assert result.bin_type == BinType.SMALL
    assert result.bins[smallbin_size].is_corrupted

    result = allocator.largebins()
    assert result is not None
    assert result.bin_type == BinType.LARGE
    assert result.bins[largebin_size].is_corrupted

    await ctrl.execute("bins")


@pwndbg_test
async def test_heap_bins_2_43(ctrl: Controller) -> None:
    """
    Tests pwndbg.aglib.heap bins commands (Only for glibc 2.43+ targets)
    """
    import re

    import pwndbg
    import pwndbg.aglib.heap
    import pwndbg.aglib.vmmap
    import pwndbg.libc
    from pwndbg.aglib.heap.ptmalloc import BinType
    from pwndbg.aglib.heap.ptmalloc import GlibcMemoryAllocator

    await ctrl.launch(GLIBC_2_43, env={"GLIBC_TUNABLES": "glibc.malloc.tcache_max=0x1000"})

    break_at_sym("break_here")
    await ctrl.cont()

    if pwndbg.libc.version() < (2, 43):
        pytest.skip("Test is not applicable below glibc 2.43")

    assert isinstance(pwndbg.aglib.heap.current, GlibcMemoryAllocator)
    bin_pattern = re.compile(r"^([^ ]+)(?: \[ *(\d)+\])?:")

    # check if all bins are empty at first
    allocator = pwndbg.aglib.heap.current
    assert allocator is not None

    def verify_match(match: re.Match[str], bin_size: str, bin_count: int | None = None) -> None:
        groups = match.groups()
        assert len(groups) == 2
        assert groups[0] == bin_size
        if bin_count is None:
            assert groups[1] is None
        else:
            assert int(groups[1]) == bin_count

    result = (await ctrl.execute_and_capture("tcachebins")).splitlines()[1:]
    assert len(result) == 3
    matches = [bin_pattern.search(bin_str) for bin_str in result]
    verify_match(matches[0], "0x60", 1)
    verify_match(matches[1], "0x400-0x800", 1)
    verify_match(matches[2], "0x800-0x1000", 2)

    result = (await ctrl.execute_and_capture("smallbins")).splitlines()[1:]
    assert len(result) == 1
    matches = [bin_pattern.search(bin_str) for bin_str in result]
    verify_match(matches[0], "0x120")

    result = (await ctrl.execute_and_capture("largebins")).splitlines()[1:]
    assert len(result) == 1
    matches = [bin_pattern.search(bin_str) for bin_str in result]
    verify_match(matches[0], "0x500-0x530")

    result = (await ctrl.execute_and_capture("unsortedbin")).splitlines()[1:]
    assert len(result) == 1
    matches = [bin_pattern.search(bin_str) for bin_str in result]
    verify_match(matches[0], "all")

    result = allocator.tcachebins()
    assert result is not None
    assert result.bin_type == BinType.TCACHE
    bin = result.bins[0x60]
    assert bin.count == 1
    assert len(bin.fd_chain) == bin.count + 1
    assert pwndbg.aglib.vmmap.find(bin.fd_chain[0])
    assert bin.fd_chain[-1] == 0
    bin = result.bins[0x800]
    assert bin.count == 1
    assert len(bin.fd_chain) == bin.count + 1
    assert pwndbg.aglib.vmmap.find(bin.fd_chain[0])
    assert bin.fd_chain[-1] == 0
    bin = result.bins[0x1000]
    assert bin.count == 2
    assert len(bin.fd_chain) == bin.count + 1
    assert pwndbg.aglib.vmmap.find(bin.fd_chain[0])
    assert pwndbg.aglib.vmmap.find(bin.fd_chain[1])
    assert bin.fd_chain[-1] == 0

    result = allocator.smallbins()
    assert result is not None
    assert result.bin_type == BinType.SMALL
    bin = result.bins[0x120]
    assert len(bin.fd_chain) == len(bin.bk_chain) == 3
    assert pwndbg.aglib.vmmap.find(bin.fd_chain[0])

    result = allocator.largebins()
    assert result is not None
    assert result.bin_type == BinType.LARGE
    bin = result.bins[4]
    assert len(bin.fd_chain) == len(bin.bk_chain) == 3
    assert pwndbg.aglib.vmmap.find(bin.fd_chain[0])

    result = allocator.unsortedbin()
    assert result is not None
    assert result.bin_type == BinType.UNSORTED
    bin = result.bins["all"]
    assert len(bin.fd_chain) == len(bin.bk_chain) == 3
    assert pwndbg.aglib.vmmap.find(bin.fd_chain[0])


@pwndbg_test
async def test_largebins_size_range_64bit(ctrl: Controller) -> None:
    """
    Ensure the "largebins" command displays the correct largebin size ranges.
    This test targets 64-bit architectures.
    """
    await launch_to(ctrl, get_binary("initialized_heap.x86-64.out"), "break_here")

    command_output = (await ctrl.execute_and_capture("largebins --verbose")).splitlines()[1:]

    expected = [
        "0x400-0x430",
        "0x440-0x470",
        "0x480-0x4b0",
        "0x4c0-0x4f0",
        "0x500-0x530",
        "0x540-0x570",
        "0x580-0x5b0",
        "0x5c0-0x5f0",
        "0x600-0x630",
        "0x640-0x670",
        "0x680-0x6b0",
        "0x6c0-0x6f0",
        "0x700-0x730",
        "0x740-0x770",
        "0x780-0x7b0",
        "0x7c0-0x7f0",
        "0x800-0x830",
        "0x840-0x870",
        "0x880-0x8b0",
        "0x8c0-0x8f0",
        "0x900-0x930",
        "0x940-0x970",
        "0x980-0x9b0",
        "0x9c0-0x9f0",
        "0xa00-0xa30",
        "0xa40-0xa70",
        "0xa80-0xab0",
        "0xac0-0xaf0",
        "0xb00-0xb30",
        "0xb40-0xb70",
        "0xb80-0xbb0",
        "0xbc0-0xbf0",
        "0xc00-0xc30",
        "0xc40-0xdf0",
        "0xe00-0xff0",
        "0x1000-0x11f0",
        "0x1200-0x13f0",
        "0x1400-0x15f0",
        "0x1600-0x17f0",
        "0x1800-0x19f0",
        "0x1a00-0x1bf0",
        "0x1c00-0x1df0",
        "0x1e00-0x1ff0",
        "0x2000-0x21f0",
        "0x2200-0x23f0",
        "0x2400-0x25f0",
        "0x2600-0x27f0",
        "0x2800-0x29f0",
        "0x2a00-0x2ff0",
        "0x3000-0x3ff0",
        "0x4000-0x4ff0",
        "0x5000-0x5ff0",
        "0x6000-0x6ff0",
        "0x7000-0x7ff0",
        "0x8000-0x8ff0",
        "0x9000-0x9ff0",
        "0xa000-0xfff0",
        "0x10000-0x17ff0",
        "0x18000-0x1fff0",
        "0x20000-0x27ff0",
        "0x28000-0x3fff0",
        "0x40000-0x7fff0",
        "0x80000-∞",
    ]

    for bin_index, size_range in enumerate(command_output):
        assert size_range.split(":")[0] == expected[bin_index]


@pwndbg_test
async def test_largebins_size_range_32bit_big(ctrl: Controller) -> None:
    """
    Ensure the "largebins" command displays the correct largebin size ranges.
    This test targets 32-bit architectures with MALLOC_ALIGNMENT == 16.
    """
    await launch_to(ctrl, get_binary("initialized_heap_big.i386.out"), "break_here")

    command_output = (await ctrl.execute_and_capture("largebins --verbose")).splitlines()[1:]

    expected = [
        "0x3f0-0x3f0",
        "0x400-0x430",
        "0x440-0x470",
        "0x480-0x4b0",
        "0x4c0-0x4f0",
        "0x500-0x530",
        "0x540-0x570",
        "0x580-0x5b0",
        "0x5c0-0x5f0",
        "0x600-0x630",
        "0x640-0x670",
        "0x680-0x6b0",
        "0x6c0-0x6f0",
        "0x700-0x730",
        "0x740-0x770",
        "0x780-0x7b0",
        "0x7c0-0x7f0",
        "0x800-0x830",
        "0x840-0x870",
        "0x880-0x8b0",
        "0x8c0-0x8f0",
        "0x900-0x930",
        "0x940-0x970",
        "0x980-0x9b0",
        "0x9c0-0x9f0",
        "0xa00-0xa30",
        "0xa40-0xa70",
        "0xa80-0xab0",
        "0xac0-0xaf0",
        "0xb00-0xb30",
        "0xb40-0xb70",
        "0xb80-0xb70",  # Largebin 31 (bin 95) is unused, but its size is used to calculate the previous bin's maximum chunk size.
        "0xb80-0xbf0",
        "0xc00-0xdf0",
        "0xe00-0xff0",
        "0x1000-0x11f0",
        "0x1200-0x13f0",
        "0x1400-0x15f0",
        "0x1600-0x17f0",
        "0x1800-0x19f0",
        "0x1a00-0x1bf0",
        "0x1c00-0x1df0",
        "0x1e00-0x1ff0",
        "0x2000-0x21f0",
        "0x2200-0x23f0",
        "0x2400-0x25f0",
        "0x2600-0x27f0",
        "0x2800-0x29f0",
        "0x2a00-0x2ff0",
        "0x3000-0x3ff0",
        "0x4000-0x4ff0",
        "0x5000-0x5ff0",
        "0x6000-0x6ff0",
        "0x7000-0x7ff0",
        "0x8000-0x8ff0",
        "0x9000-0x9ff0",
        "0xa000-0xfff0",
        "0x10000-0x17ff0",
        "0x18000-0x1fff0",
        "0x20000-0x27ff0",
        "0x28000-0x3fff0",
        "0x40000-0x7fff0",
        "0x80000-∞",
    ]

    for bin_index, size_range in enumerate(command_output):
        assert size_range.split(":")[0] == expected[bin_index]


@pwndbg_test
async def test_smallbins_sizes_64bit(ctrl: Controller) -> None:
    """
    Ensure the "smallbins" command displays the correct smallbin sizes.
    This test targets 64-bit architectures.
    """
    await launch_to(ctrl, get_binary("initialized_heap.x86-64.out"), "break_here")

    command_output = (await ctrl.execute_and_capture("smallbins --verbose")).splitlines()[1:]

    expected = [
        "0x20",
        "0x30",
        "0x40",
        "0x50",
        "0x60",
        "0x70",
        "0x80",
        "0x90",
        "0xa0",
        "0xb0",
        "0xc0",
        "0xd0",
        "0xe0",
        "0xf0",
        "0x100",
        "0x110",
        "0x120",
        "0x130",
        "0x140",
        "0x150",
        "0x160",
        "0x170",
        "0x180",
        "0x190",
        "0x1a0",
        "0x1b0",
        "0x1c0",
        "0x1d0",
        "0x1e0",
        "0x1f0",
        "0x200",
        "0x210",
        "0x220",
        "0x230",
        "0x240",
        "0x250",
        "0x260",
        "0x270",
        "0x280",
        "0x290",
        "0x2a0",
        "0x2b0",
        "0x2c0",
        "0x2d0",
        "0x2e0",
        "0x2f0",
        "0x300",
        "0x310",
        "0x320",
        "0x330",
        "0x340",
        "0x350",
        "0x360",
        "0x370",
        "0x380",
        "0x390",
        "0x3a0",
        "0x3b0",
        "0x3c0",
        "0x3d0",
        "0x3e0",
        "0x3f0",
    ]

    for bin_index, bin_size in enumerate(command_output):
        assert bin_size.split(":")[0] == expected[bin_index]


@pwndbg_test
async def test_smallbins_sizes_32bit_big(ctrl: Controller) -> None:
    """
    Ensure the "smallbins" command displays the correct smallbin sizes.
    This test targets 32-bit architectures with MALLOC_ALIGNMENT == 16.
    """

    await launch_to(ctrl, get_binary("initialized_heap_big.i386.out"), "break_here")

    command_output = (await ctrl.execute_and_capture("smallbins --verbose")).splitlines()[1:]

    expected = [
        "0x10",
        "0x20",
        "0x30",
        "0x40",
        "0x50",
        "0x60",
        "0x70",
        "0x80",
        "0x90",
        "0xa0",
        "0xb0",
        "0xc0",
        "0xd0",
        "0xe0",
        "0xf0",
        "0x100",
        "0x110",
        "0x120",
        "0x130",
        "0x140",
        "0x150",
        "0x160",
        "0x170",
        "0x180",
        "0x190",
        "0x1a0",
        "0x1b0",
        "0x1c0",
        "0x1d0",
        "0x1e0",
        "0x1f0",
        "0x200",
        "0x210",
        "0x220",
        "0x230",
        "0x240",
        "0x250",
        "0x260",
        "0x270",
        "0x280",
        "0x290",
        "0x2a0",
        "0x2b0",
        "0x2c0",
        "0x2d0",
        "0x2e0",
        "0x2f0",
        "0x300",
        "0x310",
        "0x320",
        "0x330",
        "0x340",
        "0x350",
        "0x360",
        "0x370",
        "0x380",
        "0x390",
        "0x3a0",
        "0x3b0",
        "0x3c0",
        "0x3d0",
        "0x3e0",
    ]

    for bin_index, bin_size in enumerate(command_output):
        assert bin_size.split(":")[0] == expected[bin_index]


@pwndbg_test
async def test_heap_corruption_low_dereference(ctrl: Controller) -> None:
    """
    Tests that the bins corruption check doesn't report
    corrupted bins when heap-dereference-limit is less
    than the number of chunks in a bin.
    """

    await ctrl.execute("set context-output /dev/null")
    await launch_to(ctrl, BINARY, "breakpoint")

    await ctrl.cont()
    await ctrl.cont()
    await ctrl.cont()

    # unsorted bin now has 3 chunks

    await ctrl.execute("set heap-dereference-limit 1")

    bins_output = await ctrl.execute_and_capture("bins")
    assert "corrupted" not in bins_output
