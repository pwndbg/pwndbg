from __future__ import print_function
import gdb

import pwndbg.vmmap
import pwndbg.commands
import pwndbg.symbol
import pwndbg.memory

from pwndbg.color import bold, yellow, red, underline

PREV_INUSE = 1
IS_MMAPED = 2
NON_MAIN_ARENA = 4

def get_main_arena(addr=None):
    if addr == None:
        main_arena = gdb.lookup_symbol('main_arena')[0].value()
    else:
        if isinstance(addr, (long, int)):
            addr = hex(addr)
        main_arena = gdb.parse_and_eval('(struct malloc_state)*' + addr)

    if main_arena == None:
        print(red('Symbol \'main_arena\' not found. Try installing libc ' \
                  'debugging symbols or specifying the main arena address ' \
                  'and try again'))

    return main_arena

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def heap(addr=None):
    main_arena = get_main_arena(addr)
    if main_arena == None:
        return

    heap_base = None
    for m in pwndbg.vmmap.get():
        if m.objfile == '[heap]':
            heap_base = m.vaddr

    if heap_base == None:
        print(red('Could not find the heap'))
        return

    top = main_arena['top']
    last_remainder = main_arena['last_remainder']

    print(bold('Top Chunk: ') + str(top))
    print(bold('Last Remainder: ') + str(last_remainder))
    print()

    # Print out all chunks on the heap
    # TODO: Add an option to only print out free/allocated chunks
    addr = heap_base
    while addr <= top:
        chunk = malloc_chunk(addr)
        size = int(chunk['size'])

        # Clear the bottom 3 bits
        size &= ~7
        addr += size

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def arena(addr=None):
    main_arena = get_main_arena(addr)
    if main_arena == None:
        return

    print(main_arena)

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def bins(addr=None):
    main_arena = get_main_arena(addr)
    if main_arena == None:
        return

    fastbins = main_arena['fastbinsY']
    bins = main_arena['bins']

    num_fastbins = int(fastbins.type.sizeof / fastbins.type.target().sizeof)
    num_bins = int(bins.type.sizeof / bins.type.target().sizeof)
    fd_field_offset = 16

    print(underline(yellow('Fastbins')))
    for i in range(num_fastbins):
        chain = pwndbg.chain.format(int(fastbins[i]), offset=fd_field_offset)
        print(bold(str(i)) + ': ' + chain)

    # TODO: Print other bins

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def top_chunk(addr=None):
    main_arena = get_main_arena(addr)
    if main_arena == None:
        return

    top = main_arena['top']
    print(top)

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def malloc_chunk(addr):
    if isinstance(addr, (long, int)):
        addr = hex(addr)

    gdb.lookup_type('struct malloc_chunk')
    chunk = gdb.parse_and_eval('(struct malloc_chunk)*' + addr)
    size = int(chunk['size'])
    prev_inuse = (size & PREV_INUSE) == 1
    is_mmaped = (size & IS_MMAPED) == 1
    non_main_arena = (size & NON_MAIN_ARENA) == 1

    header = bold(addr)
    if prev_inuse:
        header += yellow(' PREV_INUSE')
    if is_mmaped:
        header += yellow(' IS_MMAPED')
    if non_main_arena:
        header += yellow(' NON_MAIN_ARENA')
    print(header)
    print(chunk)

    return chunk
