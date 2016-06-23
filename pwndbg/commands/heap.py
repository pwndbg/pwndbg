#!/usr/bin/env python
from __future__ import print_function
from __future__ import unicode_literals

import six

import gdb
import pwndbg.commands
from pwndbg.color import bold
from pwndbg.color import red
from pwndbg.color import underline
from pwndbg.color import yellow

PREV_INUSE = 1
IS_MMAPED = 2
NON_MAIN_ARENA = 4

def value_from_type(type_name, addr):
    gdb_type = pwndbg.typeinfo.load(type_name)
    return gdb.Value(addr).cast(gdb_type.pointer()).dereference()

def get_main_arena(addr=None):
    if addr == None:
        main_arena = gdb.lookup_symbol('main_arena')[0].value()
    else:
        main_arena = value_from_type('struct malloc_state', addr)

    if main_arena == None:
        print(red('Symbol \'main_arena\' not found. Try installing libc ' \
                  'debugging symbols or specifying the main arena address ' \
                  'and try again'))

    return main_arena

def get_heap_bounds():
    page = None
    for m in pwndbg.vmmap.get():
        if m.objfile == '[heap]':
            page = m
            break

    if m != None:
        return (m.vaddr, m.vaddr + m.memsz)
    else:
        return (None, None)

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def heap(addr=None):
    """
    Prints out all chunks in the main_arena, or the arena specified by `addr`.
    """
    main_arena = get_main_arena(addr)
    if main_arena == None:
        return

    heap_base = get_heap_bounds()[0]
    if heap_base == None:
        print(red('Could not find the heap'))
        return

    top = main_arena['top']
    last_remainder = main_arena['last_remainder']

    print(bold('Top Chunk: ') + pwndbg.color.get(top))
    print(bold('Last Remainder: ') + pwndbg.color.get(last_remainder))
    print()

    # Print out all chunks on the heap
    # TODO: Add an option to print out only free or allocated chunks
    addr = heap_base
    while addr <= top:
        chunk = malloc_chunk(addr)
        size = int(chunk['size'])

        # Clear the bottom 3 bits
        size &= ~7
        addr += size

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def arena(addr=None):
    """
    Prints out the main arena or the arena at the specified by address.
    """
    main_arena = get_main_arena(addr)
    if main_arena == None:
        return

    print(main_arena)

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def bins(addr=None):
    """
    Prints out the contents of the fastbins of the main arena or the arena
    at the specified address.
    """
    main_arena = get_main_arena(addr)
    if main_arena == None:
        return

    fastbins = main_arena['fastbinsY']
    bins = main_arena['bins']

    size_t_size = pwndbg.typeinfo.load('size_t').sizeof
    num_fastbins = int(fastbins.type.sizeof / fastbins.type.target().sizeof)
    num_bins = int(bins.type.sizeof / bins.type.target().sizeof)
    fd_field_offset = 2 * size_t_size

    print(underline(yellow('fastbins')))
    for i in range(num_fastbins):
        size = 2 * size_t_size * (i + 1)
        chain = pwndbg.chain.format(int(fastbins[i]), offset=fd_field_offset)
        print((bold(size) + ': ').ljust(13) + chain)

    # TODO: Print other bins

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def top_chunk(addr=None):
    """
    Prints out the address of the top chunk of the main arena, or of the arena
    at the specified address.
    """
    main_arena = get_main_arena(addr)
    if main_arena == None:
        heap_start, heap_end = get_heap_bounds()
        if heap_start == None:
            print(red('Could not find the heap'))
            return

        # If we don't know where the main_arena struct is, just iterate
        # through all the heap objects until we hit the last one
        last_addr = None
        addr = heap_start
        while addr < heap_end:
            chunk = value_from_type('struct malloc_chunk', addr)
            size = int(chunk['size'])

            # Clear the bottom 3 bits
            size &= ~7

            last_addr = addr
            addr += size
        address = last_addr
    else:
        address = main_arena['top']

    return malloc_chunk(address)

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def malloc_chunk(addr):
    """
    Prints out the malloc_chunk at the specified address.
    """
    if not isinstance(addr, six.integer_types):
        addr = int(addr)

    chunk = value_from_type('struct malloc_chunk', addr)
    size = int(chunk['size'])
    prev_inuse = (size & PREV_INUSE) == 1
    is_mmaped = (size & IS_MMAPED) == 1
    non_main_arena = (size & NON_MAIN_ARENA) == 1

    header = pwndbg.color.get(addr)
    if prev_inuse:
        header += yellow(' PREV_INUSE')
    if is_mmaped:
        header += yellow(' IS_MMAPED')
    if non_main_arena:
        header += yellow(' NON_MAIN_ARENA')
    print(header)
    print(chunk)

    return chunk
