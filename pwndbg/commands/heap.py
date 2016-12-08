#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import gdb
import six

import pwndbg.color.memory as M
import pwndbg.commands
from pwndbg.color import bold
from pwndbg.color import red
from pwndbg.color import underline
from pwndbg.color import yellow

def value_from_type(type_name, addr):
    gdb_type = pwndbg.typeinfo.load(type_name)
    return gdb.Value(addr).cast(gdb_type.pointer()).dereference()

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def heap(addr=None):
    """
    Prints out all chunks in the main_arena, or the arena specified by `addr`.
    """
    main_heap   = pwndbg.heap.get_heap()
    main_arena  = main_heap.get_arena()

    if main_arena == None:
        return

    heap_base = main_heap.get_bounds()[0]
    print(heap_base)
    if heap_base == None:
        print(red('Could not find the heap'))
        return

    top = main_arena['top']
    last_remainder = main_arena['last_remainder']

    print(bold('Top Chunk: ') + M.get(top))
    print(bold('Last Remainder: ') + M.get(last_remainder))
    print()

    # Print out all chunks on the heap
    # TODO: Add an option to print out only free or allocated chunks
    addr = heap_base
    while addr <= top:
        chunk = malloc_chunk(addr)
        size = int(chunk['size'])

        # Clear the bottom 3 bits
        size &= ~7
        if size == 0:
            break
        addr += size

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def arena(addr=None):
    """
    Prints out the main arena or the arena at the specified by address.
    """
    main_heap   = pwndbg.heap.get_heap()
    main_arena  = main_heap.get_arena(addr)

    if main_arena == None:
        return

    print(main_arena)

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def mp():
    """
    Prints out the mp_ structure from glibc
    """
    main_heap   = pwndbg.heap.get_heap()

    print(main_heap.mp)

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def bins(addr=None):
    """
    Prints out the contents of the fastbins of the main arena or the arena
    at the specified address.
    """
    main_heap   = pwndbg.heap.get_heap()
    main_arena  = main_heap.get_arena(addr)
    if main_arena == None:
        return

    fastbins = main_arena['fastbinsY']
    bins = main_arena['bins']

    size_t_size = pwndbg.typeinfo.load('size_t').sizeof
    num_fastbins = 7
    num_bins = int(bins.type.sizeof / bins.type.target().sizeof)
    fd_field_offset = 2 * size_t_size

    print(underline(yellow('fastbins')))
    size = 2 * size_t_size
    for i in range(num_fastbins):
        size += 2 * size_t_size
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
    main_heap   = pwndbg.heap.get_heap()
    main_arena  = main_heap.get_arena(addr)

    if main_arena == None:
        heap_start, heap_end = main_heap.get_bounds()
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
    main_heap = pwndbg.heap.get_heap()

    if not isinstance(addr, six.integer_types):
        addr = int(addr)

    chunk = value_from_type('struct malloc_chunk', addr)
    size = int(chunk['size'])

    prev_inuse, is_mmapped, non_main_arena = main_heap.chunk_flags(size)

    header = M.get(addr)
    if prev_inuse:
        header += yellow(' PREV_INUSE')
    if is_mmapped:
        header += yellow(' IS_MMAPED')
    if non_main_arena:
        header += yellow(' NON_MAIN_ARENA')
    print(header)
    print(chunk)

    return chunk

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def bins(addr=None):
    """
    Prints out the contents of the fastbins of the main arena or the arena
    at the specified address.
    """
    fastbins(addr)
    unsortedbin(addr)
    smallbins(addr)
    largebins(addr)

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def fastbins(addr=None, verbose=True):
    """
    Prints out the contents of the fastbins of the main arena or the arena
    at the specified address.
    """
    main_heap = pwndbg.heap.get_heap()
    fastbins  = main_heap.fastbins(addr)

    formatted_bins = main_heap.format_bin(fastbins, verbose)

    print(underline(yellow('fastbins')))
    for node in formatted_bins:
        print(node)

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def unsortedbin(addr=None, verbose=True):
    """
    Prints out the contents of the unsorted bin of the main arena or the
    arena at the specified address.
    """
    main_heap   = pwndbg.heap.get_heap()
    unsortedbin = main_heap.unsortedbin(addr)

    formatted_bins = main_heap.format_bin(unsortedbin, verbose)

    print(underline(yellow('unsortedbin')))
    for node in formatted_bins:
        print(node)

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def smallbins(addr=None, verbose=False):
    """
    Prints out the contents of the small bin of the main arena or the arena
    at the specified address.
    """
    main_heap = pwndbg.heap.get_heap()
    smallbins = main_heap.smallbins(addr)

    formatted_bins = main_heap.format_bin(smallbins, verbose)

    print(underline(yellow('smallbins')))
    for node in formatted_bins:
        print(node)

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def largebins(addr=None, verbose=False):
    """
    Prints out the contents of the large bin of the main arena or the arena
    at the specified address.
    """
    main_heap = pwndbg.heap.get_heap()
    largebins = main_heap.largebins(addr)

    formatted_bins = main_heap.format_bin(largebins, verbose)

    print(underline(yellow('largebins')))
    for node in formatted_bins:
        print(node)
