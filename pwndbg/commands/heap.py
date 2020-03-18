#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import struct

import gdb
import six

import pwndbg.color.context as C
import pwndbg.color.memory as M
import pwndbg.commands
import pwndbg.typeinfo
from pwndbg.color import generateColorFunction
from pwndbg.color import message


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


def format_bin(bins, verbose=False, offset=None):
    main_heap = pwndbg.heap.current
    if offset is None:
        offset = main_heap.chunk_key_offset('fd')

    result = []
    bins_type = bins.pop('type')

    for size in bins:
        b = bins[size]
        count, is_chain_corrupted = None, False

        # fastbins consists of only single linked list
        if bins_type == 'fastbins':
            chain_fd = b
        # tcachebins consists of single linked list and entries count
        elif bins_type == 'tcachebins':
            chain_fd, count = b
        # normal bins consists of double linked list and may be corrupted (we can detect corruption)
        else:  # normal bin
            chain_fd, chain_bk, is_chain_corrupted = b

        if not verbose and (chain_fd == [0] and not count) and not is_chain_corrupted:
            continue

        if bins_type == 'tcachebins':
            limit = 8
            if count <= 7:
                limit = count + 1
            formatted_chain = pwndbg.chain.format(chain_fd[0], offset=offset, limit=limit)
        else:
            formatted_chain = pwndbg.chain.format(chain_fd[0], offset=offset)


        if isinstance(size, int):
            size = hex(size)

        if is_chain_corrupted:
            line = message.hint(size) + message.error(' [corrupted]') + '\n'
            line += message.hint('FD: ') + formatted_chain + '\n'
            line += message.hint('BK: ') + pwndbg.chain.format(chain_bk[0], offset=main_heap.chunk_key_offset('bk'))
        else:
            if count is not None:
                line = (message.hint(size) + message.hint(' [%3d]' % count) + ': ').ljust(13)
            else:
                line = (message.hint(size) + ': ').ljust(13)
            line += formatted_chain

        result.append(line)

    if not result:
        result.append(message.hint('empty'))

    return result


parser = argparse.ArgumentParser()
parser.description = "Prints out chunks starting from the address specified by `addr`."
parser.add_argument("addr", nargs="?", type=int, default=None, help="The address of the heap.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithLibcDebugSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def heap(addr=None):
    """
    Prints out chunks starting from the address specified by `addr`.
    """
    main_heap  = pwndbg.heap.current
    main_arena = main_heap.main_arena
    if main_arena is None:
        return

    page = main_heap.get_heap_boundaries(addr)
    if addr is None:
        addr = page.vaddr

    # Print out all chunks on the heap
    # TODO: Add an option to print out only free or allocated chunks

    # Check if there is an alignment at the start of the heap
    size_t = pwndbg.arch.ptrsize
    first_chunk_size = pwndbg.arch.unpack(pwndbg.memory.read(addr + size_t, size_t))
    if first_chunk_size == 0:
        addr += size_t * 2  # Skip the alignment
    while addr < page.vaddr + page.memsz:
        chunk = malloc_chunk(addr)  # Prints the chunk
        size = int(chunk['size'])
        # Clear the bottom 3 bits
        size &= ~7
        if size == 0:
            break
        addr += size
parser = argparse.ArgumentParser()
parser.description = "Prints out the main arena or the arena at the specified by address."
parser.add_argument("addr", nargs="?", type=int, default=None, help="The address of the arena.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithLibcDebugSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def arena(addr=None):
    """
    Prints out the main arena or the arena at the specified by address.
    """
    main_heap   = pwndbg.heap.current
    main_arena  = main_heap.get_arena(addr)

    if main_arena is None:
        return

    print(main_arena)


parser = argparse.ArgumentParser()
parser.description = "Prints out allocated arenas."
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithLibcDebugSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def arenas():
    """
    Prints out allocated arenas.
    """
    heap = pwndbg.heap.current
    for ar in heap.arenas:
        print(ar)


parser = argparse.ArgumentParser()
parser.description = "Print malloc thread cache info."
parser.add_argument("addr", nargs="?", type=int, default=None, help="The address of the tcache.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithLibcDebugSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def tcache(addr=None):
    """
    Prints out the thread cache.

    Glibc 2.26 malloc introduced per-thread chunk cache. This command prints
    out per-thread control structure of the cache.
    """
    main_heap = pwndbg.heap.current
    tcache = main_heap.get_tcache(addr)

    if tcache is None:
        return

    print(tcache)


parser = argparse.ArgumentParser()
parser.description = "Prints out the mp_ structure from glibc."
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithLibcDebugSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def mp():
    """
    Prints out the mp_ structure from glibc
    """
    main_heap   = pwndbg.heap.current

    print(main_heap.mp)


parser = argparse.ArgumentParser()
parser.description = "Prints out the address of the top chunk of the main arena, or of the arena at the specified address."
parser.add_argument("addr", nargs="?", type=int, default=None, help="The address of the arena.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithLibcDebugSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def top_chunk(addr=None):
    """
    Prints out the address of the top chunk of the main arena, or of the arena
    at the specified address.
    """
    main_heap   = pwndbg.heap.current
    main_arena  = main_heap.get_arena(addr)
    address = main_arena['top']

    return malloc_chunk(address)


parser = argparse.ArgumentParser()
parser.description = "Prints out the malloc_chunk at the specified address."
parser.add_argument("addr", nargs="?", type=int, default=None, help="The address of the chunk.")
parser.add_argument("fake", nargs="?", type=bool, default=False, help="If the chunk is a fake chunk.")#TODO describe this better
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithLibcDebugSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def malloc_chunk(addr,fake=False):
    """
    Prints out the malloc_chunk at the specified address.
    """
    main_heap = pwndbg.heap.current

    if not isinstance(addr, six.integer_types):
        addr = int(addr)

    chunk = read_chunk(addr)
    size = int(chunk['size'])
    actual_size = size & ~7
    prev_inuse, is_mmapped, non_main_arena = main_heap.chunk_flags(size)
    arena = None
    if not fake and non_main_arena:
        arena = main_heap.get_heap(addr)['ar_ptr']

    fastbins = [] if fake else main_heap.fastbins(arena)
    header = M.get(addr)
    if fake:
        header += message.prompt(' FAKE')
    if prev_inuse:
        if actual_size in fastbins:
            header += message.hint(' FASTBIN')
        else:
            header += message.hint(' PREV_INUSE')
    if is_mmapped:
        header += message.hint(' IS_MMAPED')
    if non_main_arena:
        header += message.hint(' NON_MAIN_ARENA')
    print(header, chunk["value"])

    return chunk


parser = argparse.ArgumentParser()
parser.description = """
    Prints out the contents of the tcachebins, fastbins, unsortedbin, smallbins, and largebins from the
    main_arena or the specified address.
    """
parser.add_argument("addr", nargs="?", type=int, default=None, help="The address of the bins.") #TODO describe this better if necessary
parser.add_argument("tcache_addr", nargs="?", type=int, default=None, help="The address of the tcache.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithLibcDebugSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def bins(addr=None, tcache_addr=None):
    """
    Prints out the contents of the tcachebins, fastbins, unsortedbin, smallbins, and largebins from the
    main_arena or the specified address.
    """
    if pwndbg.heap.current.has_tcache():
        tcachebins(tcache_addr)
    fastbins(addr)
    unsortedbin(addr)
    smallbins(addr)
    largebins(addr)


parser = argparse.ArgumentParser()
parser.description = """
    Prints out the contents of the fastbins of the main arena or the arena
    at the specified address.
    """
parser.add_argument("addr", nargs="?", type=int, default=None, help="The address of the fastbins.")
parser.add_argument("verbose", nargs="?", type=bool, default=True, help="Whether to show more details or not.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithLibcDebugSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def fastbins(addr=None, verbose=True):
    """
    Prints out the contents of the fastbins of the main arena or the arena
    at the specified address.
    """
    main_heap = pwndbg.heap.current
    fastbins  = main_heap.fastbins(addr)

    if fastbins is None:
        return

    formatted_bins = format_bin(fastbins, verbose)

    print(C.banner('fastbins'))
    for node in formatted_bins:
        print(node)


parser = argparse.ArgumentParser()
parser.description = """
    Prints out the contents of the unsorted bin of the main arena or the
    arena at the specified address.
    """
parser.add_argument("addr", nargs="?", type=int, default=None, help="The address of the unsorted bin.")
parser.add_argument("verbose", nargs="?", type=bool, default=True, help="Whether to show more details or not.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithLibcDebugSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def unsortedbin(addr=None, verbose=True):
    """
    Prints out the contents of the unsorted bin of the main arena or the
    arena at the specified address.
    """
    main_heap   = pwndbg.heap.current
    unsortedbin = main_heap.unsortedbin(addr)

    if unsortedbin is None:
        return

    formatted_bins = format_bin(unsortedbin, verbose)

    print(C.banner('unsortedbin'))
    for node in formatted_bins:
        print(node)


parser = argparse.ArgumentParser()
parser.description = """
    Prints out the contents of the small bin of the main arena or the arena
    at the specified address.
    """
parser.add_argument("addr", nargs="?", type=int, default=None, help="The address of the smallbins.")
parser.add_argument("verbose", nargs="?", type=bool, default=False, help="Whether to show more details or not.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithLibcDebugSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def smallbins(addr=None, verbose=False):
    """
    Prints out the contents of the small bin of the main arena or the arena
    at the specified address.
    """
    main_heap = pwndbg.heap.current
    smallbins = main_heap.smallbins(addr)

    if smallbins is None:
        return

    formatted_bins = format_bin(smallbins, verbose)

    print(C.banner('smallbins'))
    for node in formatted_bins:
        print(node)


parser = argparse.ArgumentParser()
parser.description = """
    Prints out the contents of the large bin of the main arena or the arena
    at the specified address.
    """
parser.add_argument("addr", nargs="?", type=int, default=None, help="The address of the largebins.")
parser.add_argument("verbose", nargs="?", type=bool, default=False, help="Whether to show more details or not.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithLibcDebugSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def largebins(addr=None, verbose=False):
    """
    Prints out the contents of the large bin of the main arena or the arena
    at the specified address.
    """
    main_heap = pwndbg.heap.current
    largebins = main_heap.largebins(addr)

    if largebins is None:
        return

    formatted_bins = format_bin(largebins, verbose)

    print(C.banner('largebins'))
    for node in formatted_bins:
        print(node)


parser = argparse.ArgumentParser()
parser.description = """
    Prints out the contents of the bins in current thread tcache or in tcache
    at the specified address.
    """
parser.add_argument("addr", nargs="?", type=int, default=None, help="The address of the tcache bins.")
parser.add_argument("verbose", nargs="?", type=bool, default=False, help="Whether to show more details or not.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithLibcDebugSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def tcachebins(addr=None, verbose=False):
    """
    Prints out the contents of the bins in current thread tcache or in tcache
    at the specified address.
    """
    main_heap = pwndbg.heap.current
    tcachebins = main_heap.tcachebins(addr)

    if tcachebins is None:
        return

    formatted_bins = format_bin(tcachebins, verbose, offset = main_heap.tcache_next_offset)

    print(C.banner('tcachebins'))
    for node in formatted_bins:
        print(node)


parser = argparse.ArgumentParser()
parser.description = """
    Finds candidate fake fast chunks that will overlap with the specified
    address. Used for fastbin dups and house of spirit
    """
parser.add_argument("addr", type=int, help="The start address of a word size value you want to overlap.")
parser.add_argument("size", nargs="?", type=int, default=None, help="The size of fastbin you want to use.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithLibcDebugSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def find_fake_fast(addr, size=None):
    """
    Finds candidate fake fast chunks that will overlap with the specified
    address. Used for fastbin dups and house of spirit
    """
    psize = pwndbg.arch.ptrsize
    main_heap = pwndbg.heap.current
    align = main_heap.malloc_alignment
    min_fast = main_heap.min_chunk_size
    max_fast = main_heap.global_max_fast
    max_fastbin  = main_heap.fastbin_index(max_fast)
    start    = int(addr) - max_fast + psize
    mem      = pwndbg.memory.read(start, max_fast - psize, partial=True)

    fmt = {
        'little': '<',
        'big': '>'
    }[pwndbg.arch.endian] + {
        4: 'I',
        8: 'Q'
    }[psize]

    if size is None:
        sizes = range(min_fast, max_fast + 1, align)
    else:
        sizes = [size]

    print(C.banner("FAKE CHUNKS"))
    for size in sizes:
        fastbin  = main_heap.fastbin_index(size)
        for offset in range((max_fastbin - fastbin) * align, max_fast - align + 1):
            candidate = mem[offset : offset + psize]
            if len(candidate) == psize:
                value = struct.unpack(fmt, candidate)[0]
                if main_heap.fastbin_index(value) == fastbin:
                    malloc_chunk(start+offset-psize, fake=True)


vis_heap_chunks_parser = argparse.ArgumentParser(description='Visualize heap chunks at the specified address')
vis_heap_chunks_parser.add_argument('count', type=lambda n:max(int(n, 0),1), nargs='?', default=10, help='Number of chunks to visualize')
vis_heap_chunks_parser.add_argument('address', help='Start address', nargs='?', default=None)
vis_heap_chunks_parser.add_argument('--naive', '-n', help='Attempt to keep printing beyond the top chunk', action='store_true', default=False)

@pwndbg.commands.ArgparsedCommand(vis_heap_chunks_parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithLibcDebugSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def vis_heap_chunks(address=None, count=None, naive=None):
    main_heap = pwndbg.heap.current
    heap_region = main_heap.get_heap_boundaries(address)
    main_arena = main_heap.get_arena_for_chunk(address) if address else main_heap.main_arena

    top_chunk = main_arena['top']
    ptr_size = main_heap.size_sz

    # Build a list of addresses that delimit each chunk.
    chunk_delims = []
    cursor = int(address) if address else heap_region.start

    for _ in range(count + 1):
        # Don't read beyond the heap mapping if --naive or corrupted heap.
        if cursor not in heap_region:
            chunk_delims.append(heap_region.end)
            break

        size_field = pwndbg.memory.u(cursor + ptr_size)
        real_size = size_field & ~main_heap.malloc_align_mask
        prev_inuse = main_heap.chunk_flags(size_field)[0]

        # Don't repeatedly operate on the same address (e.g. chunk size of 0).
        if cursor in chunk_delims or cursor + ptr_size in chunk_delims:
            break

        if prev_inuse:
            chunk_delims.append(cursor + ptr_size)
        else:
            chunk_delims.append(cursor)

        if (cursor == top_chunk and not naive) or (cursor == heap_region.end - ptr_size*2):
            chunk_delims.append(cursor + ptr_size*2)
            break

        cursor += real_size

    # Build the output buffer, changing color at each chunk delimiter.
    # TODO: maybe print free chunks in bold or underlined
    color_funcs = [
        generateColorFunction("yellow"),
        generateColorFunction("cyan"),
        generateColorFunction("purple"),
        generateColorFunction("green"),
        generateColorFunction("blue"),
    ]

    bin_collections = [
        pwndbg.heap.current.fastbins(None),
        pwndbg.heap.current.unsortedbin(None),
        pwndbg.heap.current.smallbins(None),
        pwndbg.heap.current.largebins(None),
        ]
    if pwndbg.heap.current.has_tcache():
        bin_collections.insert(0, pwndbg.heap.current.tcachebins(None))

    printed = 0
    out = ''
    asc = ''
    labels = []
    cursor = int(address) if address else heap_region.start

    for c, stop in enumerate(chunk_delims):
        color_func = color_funcs[c % len(color_funcs)]

        while cursor != stop:
            if printed % 2 == 0:
                out += "\n0x%x" % cursor

            cell = pwndbg.memory.u(cursor)
            cell_hex = '\t0x{:0{n}x}'.format(cell, n=ptr_size*2)

            out += color_func(cell_hex)
            printed += 1

            labels.extend(bin_labels(cursor, bin_collections))
            if cursor == top_chunk:
                labels.append('Top chunk')

            asc += bin_ascii(pwndbg.memory.read(cursor, ptr_size))
            if printed % 2 == 0:
                out += '\t' + color_func(asc) + ('\t <-- ' + ', '.join(labels) if len(labels) else '')
                asc = ''
                labels = []

            cursor += ptr_size

    print(out)

def bin_ascii(bs):
    from string import printable
    valid_chars = list(map(ord, set(printable) - set('\t\r\n')))
    return ''.join(chr(c) if c in valid_chars else '.'for c in bs)

def bin_labels(addr, collections):
    labels = []
    for bins in collections:
        bins_type = bins.get('type', None)
        if not bins_type:
            continue

        for size in filter(lambda x: x != 'type', bins.keys()):
            b = bins[size]
            if isinstance(size, int):
                size = hex(size)
            count = '/{:d}'.format(b[1]) if bins_type == 'tcachebins' else None
            chunks = bin_addrs(b, bins_type)
            for chunk_addr in chunks:
                if addr == chunk_addr:
                    labels.append('{:s}[{:s}][{:d}{}]'.format(bins_type, size, chunks.index(addr), count or ''))

    return labels

def bin_addrs(b, bins_type):
    addrs = []
    if bins_type == 'fastbins':
        return b
    # tcachebins consists of single linked list and entries count
    elif bins_type == 'tcachebins':
        addrs, _ = b
    # normal bins consists of double linked list and may be corrupted (we can detect corruption)
    else:  # normal bin
        addrs, _, _ = b
    return addrs
