import gdb

import pwndbg.gdblib.memory
import pwndbg.gdblib.symbol
import pwndbg.gdblib.vmmap
import pwndbg.heap
import tests
from pwndbg.heap.ptmalloc import BinType

BINARY = tests.binaries.get("heap_bins.out")


def test_heap_bins(start_binary):
    """
    Tests pwndbg heap bins commands
    """
    start_binary(BINARY)
    gdb.execute("set context-output /dev/null")
    gdb.execute("b breakpoint", to_string=True)

    # check if all bins are empty at first
    gdb.execute("continue")
    allocator = pwndbg.heap.current

    addr = pwndbg.gdblib.symbol.address("tcache_size")
    tcache_size = allocator._request2size(pwndbg.gdblib.memory.u64(addr))
    addr = pwndbg.gdblib.symbol.address("tcache_count")
    tcache_count = pwndbg.gdblib.memory.u64(addr)
    addr = pwndbg.gdblib.symbol.address("fastbin_size")
    fastbin_size = allocator._request2size(pwndbg.gdblib.memory.u64(addr))
    addr = pwndbg.gdblib.symbol.address("fastbin_count")
    fastbin_count = pwndbg.gdblib.memory.u64(addr)
    addr = pwndbg.gdblib.symbol.address("smallbin_size")
    smallbin_size = allocator._request2size(pwndbg.gdblib.memory.u64(addr))
    addr = pwndbg.gdblib.symbol.address("smallbin_count")
    smallbin_count = pwndbg.gdblib.memory.u64(addr)
    addr = pwndbg.gdblib.symbol.address("largebin_size")
    largebin_size = allocator._request2size(pwndbg.gdblib.memory.u64(addr))
    addr = pwndbg.gdblib.symbol.address("largebin_count")
    largebin_count = pwndbg.gdblib.memory.u64(addr)

    result = allocator.tcachebins()
    assert result.bin_type == BinType.TCACHE
    assert tcache_size in result.bins
    assert result.bins[tcache_size].bk_chain is None and len(result.bins[tcache_size].fd_chain) == 1

    result = allocator.fastbins()
    assert result.bin_type == BinType.FAST
    assert fastbin_size in result.bins
    assert len(result.bins[fastbin_size].fd_chain) == 1

    result = allocator.unsortedbin()
    assert result.bin_type == BinType.UNSORTED
    assert len(result.bins["all"].fd_chain) == 1
    assert not result.bins["all"].is_corrupted

    result = allocator.smallbins()
    assert result.bin_type == BinType.SMALL
    assert smallbin_size in result.bins
    assert (
        len(result.bins[smallbin_size].fd_chain) == 1
        and len(result.bins[smallbin_size].bk_chain) == 1
    )
    assert not result.bins[smallbin_size].is_corrupted

    result = allocator.largebins()
    assert result.bin_type == BinType.LARGE
    largebin_size = list(result.bins.items())[allocator.largebin_index(largebin_size) - 64][0]
    assert largebin_size in result.bins
    assert (
        len(result.bins[largebin_size].fd_chain) == 1
        and len(result.bins[largebin_size].bk_chain) == 1
    )
    assert not result.bins[largebin_size].is_corrupted

    # check tcache
    gdb.execute("continue")

    result = allocator.tcachebins()
    assert result.bin_type == BinType.TCACHE
    assert tcache_size in result.bins
    assert (
        result.bins[tcache_size].count == tcache_count
        and len(result.bins[tcache_size].fd_chain) == tcache_count + 1
    )
    for addr in result.bins[tcache_size].fd_chain[:-1]:
        assert pwndbg.gdblib.vmmap.find(addr)

    # check fastbin
    gdb.execute("continue")

    result = allocator.fastbins()
    assert result.bin_type == BinType.FAST
    assert (fastbin_size in result.bins) and (
        len(result.bins[fastbin_size].fd_chain) == fastbin_count + 1
    )
    for addr in result.bins[fastbin_size].fd_chain[:-1]:
        assert pwndbg.gdblib.vmmap.find(addr)

    # check unsortedbin
    gdb.execute("continue")

    result = allocator.unsortedbin()
    assert result.bin_type == BinType.UNSORTED
    assert (
        len(result.bins["all"].fd_chain) == smallbin_count + 2
        and len(result.bins["all"].bk_chain) == smallbin_count + 2
    )
    assert not result.bins["all"].is_corrupted
    for addr in result.bins["all"].fd_chain[:-1]:
        assert pwndbg.gdblib.vmmap.find(addr)
    for addr in result.bins["all"].bk_chain[:-1]:
        assert pwndbg.gdblib.vmmap.find(addr)

    # check smallbins
    gdb.execute("continue")

    result = allocator.smallbins()
    assert result.bin_type == "smallbins"
    assert (
        len(result.bins[smallbin_size].fd_chain) == smallbin_count + 2
        and len(result.bins[smallbin_size].bk_chain) == smallbin_count + 2
    )
    assert not result.bins[smallbin_size].is_corrupted
    for addr in result.bins[smallbin_size].fd_chain[:-1]:
        assert pwndbg.gdblib.vmmap.find(addr)
    for addr in result.bins[smallbin_size].bk_chain[:-1]:
        assert pwndbg.gdblib.vmmap.find(addr)

    # check largebins
    gdb.execute("continue")

    result = allocator.largebins()
    assert result.bin_type == BinType.LARGE
    assert (
        len(result.bins[largebin_size].fd_chain) == largebin_count + 2
        and len(result.bins[largebin_size].bk_chain) == largebin_count + 2
    )
    assert not result.bins[largebin_size].is_corrupted
    for addr in result.bins[largebin_size].fd_chain[:-1]:
        assert pwndbg.gdblib.vmmap.find(addr)
    for addr in result.bins[largebin_size].bk_chain[:-1]:
        assert pwndbg.gdblib.vmmap.find(addr)

    # check corrupted
    gdb.execute("continue")
    result = allocator.smallbins()
    assert result.bin_type == BinType.SMALL
    assert result.bins[smallbin_size].is_corrupted

    result = allocator.largebins()
    assert result.bin_type == BinType.LARGE
    assert result.bins[largebin_size].is_corrupted

    gdb.execute("bins")
