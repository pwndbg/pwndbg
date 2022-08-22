import gdb

import pwndbg.heap
import pwndbg.memory
import pwndbg.symbol
import pwndbg.vmmap
import tests

BINARY = tests.binaries.get('heap_bins.out')


def test_heap_bins(start_binary):
    """
    Tests pwndbg heap bins commands
    """
    start_binary(BINARY)
    gdb.execute('set context-output /dev/null')
    gdb.execute('b breakpoint', to_string=True)

    # check if all bins are empty at first
    gdb.execute('continue')
    allocator = pwndbg.heap.current

    addr = pwndbg.symbol.address("tcache_size")
    tcache_size = allocator._request2size(pwndbg.memory.u64(addr))
    addr = pwndbg.symbol.address("tcache_count")
    tcache_count = pwndbg.memory.u64(addr)
    addr = pwndbg.symbol.address("fastbin_size")
    fastbin_size = allocator._request2size(pwndbg.memory.u64(addr))
    addr = pwndbg.symbol.address("fastbin_count")
    fastbin_count = pwndbg.memory.u64(addr)
    addr = pwndbg.symbol.address("smallbin_size")
    smallbin_size = allocator._request2size(pwndbg.memory.u64(addr))
    addr = pwndbg.symbol.address("smallbin_count")
    smallbin_count = pwndbg.memory.u64(addr)
    addr = pwndbg.symbol.address("largebin_size")
    largebin_size = allocator._request2size(pwndbg.memory.u64(addr))
    addr = pwndbg.symbol.address("largebin_count")
    largebin_count = pwndbg.memory.u64(addr)

    result = allocator.tcachebins()
    assert result['type'] == 'tcachebins'
    assert tcache_size in result
    assert result[tcache_size][1] == 0 and len(result[tcache_size][0]) == 1

    result = allocator.fastbins()
    assert result['type'] == 'fastbins'
    assert fastbin_size in result
    assert len(result[fastbin_size]) == 1

    result = allocator.unsortedbin()
    assert result['type'] == 'unsortedbin'
    assert len(result['all'][0]) == 1
    assert not result['all'][2]

    result = allocator.smallbins()
    assert result['type'] == 'smallbins'
    assert smallbin_size in result
    assert len(result[smallbin_size][0]) == 1 and len(result[smallbin_size][1]) == 1
    assert not result[smallbin_size][2]

    result = allocator.largebins()
    assert result['type'] == 'largebins'
    largebin_size = list(result.items())[allocator.largebin_index(largebin_size) - 64][0]
    assert largebin_size in result
    assert len(result[largebin_size][0]) == 1 and len(result[largebin_size][1]) == 1
    assert not result[largebin_size][2]

    # check tcache
    gdb.execute('continue')

    result = allocator.tcachebins()
    assert result['type'] == 'tcachebins'
    assert tcache_size in result
    assert result[tcache_size][1] == tcache_count and len(result[tcache_size][0]) == tcache_count + 1
    for addr in result[tcache_size][0][:-1]:
        assert pwndbg.vmmap.find(addr)

    # check fastbin
    gdb.execute('continue')

    result = allocator.fastbins()
    assert result['type'] == 'fastbins'
    assert (fastbin_size in result) and (len(result[fastbin_size]) == fastbin_count + 1)
    for addr in result[fastbin_size][:-1]:
        assert pwndbg.vmmap.find(addr)

    # check unsortedbin
    gdb.execute('continue')

    result = allocator.unsortedbin()
    assert result['type'] == 'unsortedbin'
    assert len(result['all'][0]) == smallbin_count + 2 and len(result['all'][1]) == smallbin_count + 2
    assert not result['all'][2]
    for addr in result['all'][0][:-1]:
        assert pwndbg.vmmap.find(addr)
    for addr in result['all'][1][:-1]:
        assert pwndbg.vmmap.find(addr)

    # check smallbins
    gdb.execute('continue')

    result = allocator.smallbins()
    assert result['type'] == 'smallbins'
    assert len(result[smallbin_size][0]) == smallbin_count + 2 and len(result[smallbin_size][1]) == smallbin_count + 2
    assert not result[smallbin_size][2]
    for addr in result[smallbin_size][0][:-1]:
        assert pwndbg.vmmap.find(addr)
    for addr in result[smallbin_size][1][:-1]:
        assert pwndbg.vmmap.find(addr)

    # check largebins
    gdb.execute('continue')

    result = allocator.largebins()
    assert result['type'] == 'largebins'
    assert len(result[largebin_size][0]) == largebin_count + 2 and len(result[largebin_size][1]) == largebin_count + 2
    assert not result[largebin_size][2]
    for addr in result[largebin_size][0][:-1]:
        assert pwndbg.vmmap.find(addr)
    for addr in result[largebin_size][1][:-1]:
        assert pwndbg.vmmap.find(addr)

    # check corrupted
    gdb.execute('continue')
    result = allocator.smallbins()
    assert result['type'] == 'smallbins'
    assert result[smallbin_size][2]

    result = allocator.largebins()
    assert result['type'] == 'largebins'
    assert result[largebin_size][2]
