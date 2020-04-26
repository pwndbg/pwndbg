#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import ctypes
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
        if not chunk:
            print(message.error('Bad chunk at address 0x{:x}'.format(addr)))
            break

        size = int(chunk['size'])
        if size < 0:
            print(message.notice('Negative chunk size, breaking'))
            break
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
    if not fastbins:
        fastbins = []

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

    first_chunk = heap_region.start
    top_chunk = main_arena['top']
    ptr_size = main_heap.size_sz

    # Check if there is an alignment at the start of the heap
    first_chunk_size = pwndbg.arch.unpack(pwndbg.memory.read(first_chunk + ptr_size, ptr_size))
    if first_chunk_size == 0:
        first_chunk += ptr_size * 2

    # Build a list of addresses that delimit each chunk.
    chunk_delims = []
    cursor = int(address) if address else first_chunk

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
    cursor = int(address) if address else first_chunk

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


try_free_parser = argparse.ArgumentParser(description='Check what would happen if free was called with given address')
try_free_parser.add_argument('addr', nargs='?', help='Address passed to free')
@pwndbg.commands.ArgparsedCommand(try_free_parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWhenHeapIsInitialized
def try_free(addr):
    addr = int(addr)

    # check hook
    free_hook = pwndbg.symbol.address('__free_hook')
    if free_hook is not None:
        if pwndbg.memory.pvoid(free_hook) != 0:
            message.success('__libc_free: will execute __free_hook')

    # free(0) has no effect
    if addr == 0:
        message.success('__libc_free: addr is 0, nothing to do')
        return

    # constants
    current_heap = pwndbg.heap.current
    arena = current_heap.get_arena()
    arena_addr = int(arena.address)

    aligned_lsb = current_heap.malloc_align_mask.bit_length()
    size_sz = current_heap.size_sz
    malloc_alignment = current_heap.malloc_alignment
    malloc_align_mask = current_heap.malloc_align_mask
    chunk_minsize = current_heap.minsize

    ptr_size = pwndbg.arch.ptrsize

    def unsigned_size(size):
        # read_chunk()['size'] is signed in pwndbg ;/
        # there may be better way to handle that
        if ptr_size < 8:
            return ctypes.c_uint32(size).value
        x = ctypes.c_uint64(size).value
        return x

    def chunksize(chunk_size):
        # maybe move this to ptmalloc.py
        return chunk_size & (~7)

    # mem2chunk
    addr -= 2 * size_sz

    # try to get the chunk
    try:
        chunk = read_chunk(addr)
    except gdb.MemoryError as e:
        print(message.error('Can\'t read chunk at address 0x{:x}, memory error'.format(addr)))
        return

    chunk_size = unsigned_size(chunk['size'])
    chunk_size_unmasked = chunksize(chunk_size)
    _, is_mmapped, _ = current_heap.chunk_flags(chunk_size)

    if is_mmapped:
        print(message.notice('__libc_free: Doing munmap_chunk'))
        return

    found_error = False

    # chunk doesn't overlap memory
    print(message.notice('General checks'))
    max_mem = (1 << (ptr_size*8)) - 1
    if addr + chunk_size >= max_mem:
        err = 'free(): invalid pointer -> &chunk + chunk->size > max memory\n'
        err += '    0x{:x} + 0x{:x} > 0x{:x}'
        err = err.format(addr, chunk_size, max_mem)
        print(message.error(err))
        found_error = True

    # chunk address is aligned
    addr_tmp = addr
    if malloc_alignment != 2 * size_sz:
        addr_tmp = addr + 2 * size_sz

    if addr_tmp & malloc_align_mask != 0:
        err = 'free(): invalid pointer -> misaligned chunk\n'
        err += '    LSB of 0x{:x} are 0b{}, should be 0b{}'
        if addr_tmp != addr:
            err += ' (0x{:x} was added to the address)'.format(2*size_sz)
        err = err.format(addr_tmp, bin(addr_tmp)[-aligned_lsb:], '0'*aligned_lsb)
        print(message.error(err))
        found_error = True

    # chunk's size is big enough
    if chunk_size_unmasked < chunk_minsize:
        err = 'free(): invalid size -> chunk\'s size smaller than MINSIZE\n'
        err += '    size is 0x{:x}, MINSIZE is 0x{:x}'
        err = err.format(chunk_size_unmasked, chunk_minsize)
        print(message.error(err))
        found_error = True

    # chunk's size is aligned
    if chunk_size_unmasked & malloc_align_mask != 0:
        err = 'free(): invalid size -> chunk\'s size is not aligned\n'
        err += '    LSB of size 0x{:x} are 0b{}, should be 0b{}'
        err = err.format(chunk_size_unmasked, bin(chunk_size_unmasked)[-aligned_lsb:], '0'*aligned_lsb)
        print(message.error(err))
        found_error = True

    if found_error:
        return

    # tcache
    if current_heap.has_tcache():
        tc_idx = (chunk_size_unmasked - chunk_minsize + malloc_alignment - 1) // malloc_alignment
        if tc_idx < current_heap.mp['tcache_bins']:
            print(message.notice('Tcache checks'))
            e = addr + 2*size_sz
            e += current_heap.tcache_entry.keys().index('key') * ptr_size
            e = pwndbg.memory.pvoid(e)
            tcache_addr = int(current_heap.thread_cache.address)
            if e == tcache_addr:
                # todo, actually do checks
                print(message.error('Will do checks for tcache double-free (memory_tcache_double_free)'))

            if int(current_heap.get_tcache()['counts'][tc_idx]) < int(current_heap.mp['tcache_count']):
                print(message.success('Using tcache_put'))

    # is fastbin
    if chunk_size_unmasked <= current_heap.global_max_fast:
        print(message.notice('Fastbin checks'))
        chunk_fastbin_idx = current_heap.fastbin_index(chunk_size_unmasked)
        fastbin_list = current_heap.fastbins(arena_addr)[(chunk_fastbin_idx+2)*(ptr_size*2)]

        try :
            next_chunk = read_chunk(addr + chunk_size_unmasked)
        except gdb.MemoryError as e:
            print(message.error('Can\'t read next chunk at address 0x{:x}, memory error'.format(chunk + chunk_size_unmasked)))
            return

        # next chunk's size is big enough and small enough
        next_chunk_size = unsigned_size(next_chunk['size'])
        if next_chunk_size <= 2*size_sz or chunksize(next_chunk_size) >= int(arena['system_mem']):
            err = 'free(): invalid next size (fast) -> next chunk\'s size not in [2*size_sz; av->system_mem]\n'
            err += '    next chunk\'s size is 0x{:x}, 2*size_sz is 0x{:x}, system_mem is 0x{:x}'
            err = err.format(next_chunk_size, 2*size_sz, int(arena['system_mem']))
            print(message.error(err))

        # chunk is not the same as the one on top of fastbin[idx]
        if int(fastbin_list[0]) == addr:
            err = 'double free or corruption (fasttop) -> chunk already is on top of fastbin list\n'
            err += '    fastbin idx == {}'
            err = err.format(chunk_fastbin_idx)
            print(message.error(err))

        # chunk's size is ~same as top chunk's size
        fastbin_top_chunk = int(fastbin_list[0])
        if fastbin_top_chunk != 0:
            try:
                fastbin_top_chunk = read_chunk(fastbin_top_chunk)
            except gdb.MemoryError as e:
                print(message.error('Can\'t read top fastbin chunk at address 0x{:x}, memory error'.format(fastbin_top_chunk)))
                return

            fastbin_top_chunk_size = chunksize(unsigned_size(fastbin_top_chunk['size']))
            if chunk_fastbin_idx != current_heap.fastbin_index(fastbin_top_chunk_size):
                err = 'invalid fastbin entry (free) -> chunk\'s size is not near top chunk\'s size\n'
                err += '    chunk\'s size == {}, idx == {}\n'
                err += '    top chunk\'s size == {}, idx == {}'
                err += '    if `have_lock` is false then the error is invalid'
                err = err.format(chunk['size'], chunk_fastbin_idx,
                    fastbin_top_chunk_size, current_heap.fastbin_index(fastbin_top_chunk_size))
                print(message.error(err))

    # is not mapped
    elif is_mmapped == 0:
        print(message.notice('Not mapped checks'))

        # chunks is not top chunk
        if addr == int(arena['top']):
            err = 'double free or corruption (top) -> chunk is top chunk'
            print(message.error(err))

        # next chunk is not beyond the boundaries of the arena
        NONCONTIGUOUS_BIT = 2
        top_chunk_addr = (int(arena['top']))
        top_chunk = read_chunk(top_chunk_addr)
        next_chunk_addr = addr + chunk_size_unmasked

        # todo: in libc, addition may overflow
        if (arena['flags'] & NONCONTIGUOUS_BIT == 0) and next_chunk_addr >= top_chunk_addr + chunksize(top_chunk['size']):
            err = 'double free or corruption (out) -> next chunk is beyond arena and arena is contiguous\n'
            err += 'next chunk at 0x{:x}, end of arena at 0x{:x}'
            err = err.format(next_chunk_addr, top_chunk_addr + chunksize(unsigned_size(top_chunk['size'])))
            print(message.error(err))

        # now we need to dereference chunk
        try :
            next_chunk = read_chunk(next_chunk_addr)
            next_chunk_size = chunksize(unsigned_size(next_chunk['size']))
        except (OverflowError, gdb.MemoryError) as e:
            print(message.error('Can\'t read next chunk at address 0x{:x}'.format(next_chunk_addr)))
            return

        # next chunk's P bit is set
        prev_inuse,_,_ = current_heap.chunk_flags(next_chunk['size'])
        if prev_inuse == 0:
            err = 'double free or corruption (!prev) -> next chunk\'s previous-in-use bit is 0\n'
            print(message.error(err))

        # next chunk's size is big enough and small enough
        if next_chunk_size <= 2*size_sz or next_chunk_size >= int(arena['system_mem']):
            err = 'free(): invalid next size (normal) -> next chunk\'s size not in [2*size_sz; system_mem]\n'
            err += 'next chunk\'s size is 0x{:x}, 2*size_sz is 0x{:x}, system_mem is 0x{:x}'
            err = err.format(next_chunk_size, 2*size_sz, int(arena['system_mem']))
            print(message.error(err))

        # consolidate backward
        prev_inuse,_,_ = current_heap.chunk_flags(chunk['size'])
        if prev_inuse == 0:
            print(message.notice('Backward consolidation'))
            prev_size = chunksize(unsigned_size(chunk['prev_size']))
            prev_chunk_addr = addr - prev_size

            try :
                prev_chunk = read_chunk(prev_chunk_addr)
                prev_chunk_size = chunksize(unsigned_size(prev_chunk['size']))
            except (OverflowError, gdb.MemoryError) as e:
                print(message.error('Can\'t read next chunk at address 0x{:x}'.format(prev_chunk_addr)))
                return

            if unsigned_size(prev_chunk['size']) != prev_size:
                err = 'corrupted size vs. prev_size while consolidating\n'
                err += 'prev_size field is 0x{:x}, prev chunk at 0x{:x}, prev chunk size is 0x{:x}'
                err = err.format(prev_size, prev_chunk_addr, unsigned_size(prev_chunk['size']))
                print(message.error(err))
            else:
                addr = prev_chunk_addr
                chunk_size += prev_size
                chunk_size_unmasked += prev_size
                try_unlink(addr)

        # consolidate forward
        if next_chunk_addr != top_chunk_addr:
            print(message.notice('Next chunk is not top chunk'))
            try :
                next_next_chunk_addr = next_chunk_addr + next_chunk_size
                next_next_chunk = read_chunk(next_next_chunk_addr)
            except (OverflowError, gdb.MemoryError) as e:
                print(message.error('Can\'t read next chunk at address 0x{:x}'.format(next_next_chunk_addr)))
                return
            
            prev_inuse,_,_ = current_heap.chunk_flags(next_next_chunk['size'])

            if prev_inuse == 0:
                print(message.notice('Forward consolidation'))
                try_unlink(next_chunk_addr)
                chunk_size += next_chunk_size
                chunk_size_unmasked += next_chunk_size
            else:
                print(message.notice('Clearing next chunk\'s P bit'))

            # unsorted bin fd->bk should be unsorted bean
            unsorted_addr = int(arena['bins']) - 2*ptr_size
            try:
                unsorted = read_chunk(unsorted_addr)
                try:
                    if read_chunk(unsorted['fd'])['bk'] != unsorted_addr:
                        err = 'free(): corrupted unsorted chunks -> unsorted_chunk->fd->bk != unsorted_chunk\n'
                        err += 'unsorted at 0x{:x}, unsorted->fd == 0x{:x}, unsorted->fd->bk == 0x{:x}'
                        err = err.format(unsorted_addr, unsorted['fd'], read_chunk(unsorted['fd'])['bk'])
                        print(message.error(err))
                except (OverflowError, gdb.MemoryError) as e:
                    print(message.error('Can\'t read chunk at 0x{:x}, it is unsorted bin fd'.format(unsorted['fd'])))
            except (OverflowError, gdb.MemoryError) as e:
                print(message.error('Can\'t read unsorted bin chunk at 0x{:x}'.format(unsorted_addr)))

        else:
            print(message.notice('Next chunk is top chunk'))
            chunk_size += next_chunk_size
            chunk_size_unmasked += next_chunk_size

        # todo: this may vary strongly
        FASTBIN_CONSOLIDATION_THRESHOLD = 65536
        if chunk_size_unmasked >= FASTBIN_CONSOLIDATION_THRESHOLD:
            print(message.notice('Doing malloc_consolidate and systrim/heap_trim'))

    #is mapped
    else:
        message.notice('Doing munmap_chunk')


def try_unlink(addr):
    pass

