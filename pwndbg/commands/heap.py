#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import struct

import gdb
import six

import pwndbg.color.memory as M
import pwndbg.commands
import pwndbg.typeinfo
from pwndbg.color import bold
from pwndbg.color import red
from pwndbg.color import underline
from pwndbg.color import yellow


def read_chunk(addr):
    # in old versions of glibc, `mchunk_[prev_]size` was simply called `[prev_]size`
    # to support both versions, we change the new names to the old ones here so that
    # the rest of the code can deal with uniform names
    renames = {
        "mchunk_size": "size",
        "mchunk_prev_size": "prev_size",
    }
    val = pwndbg.typeinfo.read_gdbvalue("struct malloc_chunk", addr)
    return dict({ renames.get(key, key): int(val[key]) for key in val.type.keys() }, value=val)


def format_bin(bins, verbose=False):
    main_heap = pwndbg.heap.current
    fd_offset = main_heap.chunk_key_offset('fd')

    result = []
    for size in bins:
        chain = bins[size]

        if not verbose and chain == [0]:
            continue

        formatted_chain = pwndbg.chain.format(chain, offset=fd_offset)

        if isinstance(size, int):
            size = hex(size)

        result.append((bold(size) + ': ').ljust(13) + formatted_chain)

    if not result:
        result.append(bold('empty'))

    return result

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def heap(addr=None):
    """
    Prints out all chunks in the main_arena, or the arena specified by `addr`.
    """
    main_heap   = pwndbg.heap.current
    main_arena  = main_heap.get_arena(addr)

    if main_arena == None:
        return

    heap_base = main_heap.get_bounds()[0]
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
    main_heap   = pwndbg.heap.current
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
    main_heap   = pwndbg.heap.current

    print(main_heap.mp)

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def top_chunk(addr=None):
    """
    Prints out the address of the top chunk of the main arena, or of the arena
    at the specified address.
    """
    main_heap   = pwndbg.heap.current
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
            chunk = read_chunk(addr)
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
    main_heap = pwndbg.heap.current

    if not isinstance(addr, six.integer_types):
        addr = int(addr)

    chunk = read_chunk(addr)
    size = int(chunk['size'])
    actual_size = size & ~7
    fastbins = main_heap.fastbins()

    prev_inuse, is_mmapped, non_main_arena = main_heap.chunk_flags(size)

    header = M.get(addr)
    if prev_inuse:
        if actual_size in fastbins:
            header += yellow(' FASTBIN')
        else:
            header += yellow(' PREV_INUSE')
    if is_mmapped:
        header += yellow(' IS_MMAPED')
    if non_main_arena:
        header += yellow(' NON_MAIN_ARENA')
    print(header, chunk["value"])

    return chunk

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def bins(addr=None):
    """
    Prints out the contents of the fastbins, unsortedbin, smallbins, and largebins from the
    main_arena or the specified address.
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
    main_heap = pwndbg.heap.current
    fastbins  = main_heap.fastbins(addr)

    if fastbins == None:
        return

    formatted_bins = format_bin(fastbins, verbose)

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
    main_heap   = pwndbg.heap.current
    unsortedbin = main_heap.unsortedbin(addr)

    if unsortedbin == None:
        return

    formatted_bins = format_bin(unsortedbin, verbose)

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
    main_heap = pwndbg.heap.current
    smallbins = main_heap.smallbins(addr)

    if smallbins == None:
        return

    formatted_bins = format_bin(smallbins, verbose)

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
    main_heap = pwndbg.heap.current
    largebins = main_heap.largebins(addr)

    if largebins == None:
        return

    formatted_bins = format_bin(largebins, verbose)

    print(underline(yellow('largebins')))
    for node in formatted_bins:
        print(node)

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def find_fake_fast(addr, size):
    """
    Finds candidate fake fast chunks that will overlap with the specified
    address. Used for fastbin dups and house of spirit
    """
    main_heap = pwndbg.heap.current

    fastbin  = main_heap.fastbin_index(int(size))
    max_fast = main_heap.global_max_fast
    start    = int(addr) - int(max_fast)
    mem      = pwndbg.memory.read(start, max_fast, partial=True)

    fmt = {
        'little': '<',
        'big': '>'
    }[pwndbg.arch.endian] + {
        4: 'I',
        8: 'Q'
    }[pwndbg.arch.ptrsize]

    print(red("FAKE CHUNKS"))
    for offset in range(max_fast - pwndbg.arch.ptrsize):
        candidate = mem[offset:offset + pwndbg.arch.ptrsize]
        if len(candidate) == pwndbg.arch.ptrsize:
            value = struct.unpack(fmt, candidate)[0]

            if main_heap.fastbin_index(value) == fastbin:
                malloc_chunk(start+offset-pwndbg.arch.ptrsize)
