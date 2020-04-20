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
    """Read a chunk's metadata."""
    # In GLIBC versions <= 2.24 the `mchunk_[prev_]size` field was named `[prev_]size`.
    # To support both versions, change the new names to the old ones here so that
    # the rest of the code can deal with uniform names.
    renames = {
        "mchunk_size": "size",
        "mchunk_prev_size": "prev_size",
    }
    val = pwndbg.typeinfo.read_gdbvalue("struct malloc_chunk", addr)
    return dict({ renames.get(key, key): int(val[key]) for key in val.type.keys() }, value=val)


def format_bin(bins, verbose=False, offset=None):
    allocator = pwndbg.heap.current
    if offset is None:
        offset = allocator.chunk_key_offset('fd')

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
            line += message.hint('BK: ') + pwndbg.chain.format(chain_bk[0], offset=allocator.chunk_key_offset('bk'))
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
parser.description = "Iteratively print chunks on a heap, default to the current thread's active heap."
parser.add_argument("addr", nargs="?", type=int, default=None, help="Address of the first chunk.")
parser.add_argument("-v", "--verbose", action="store_true", help="Print all chunk fields, even unused ones.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithLibcDebugSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def heap(addr=None, verbose=False):
    """Iteratively print chunks on a heap, default to the current thread's
    active heap.
    """
    allocator = pwndbg.heap.current
    heap_region = allocator.get_heap_boundaries(addr)
    arena = allocator.get_arena_for_chunk(addr) if addr else allocator.get_arena()

    top_chunk = arena['top']
    ptr_size = allocator.size_sz

    # Calculate where to start printing; if an address was supplied, use that,
    # if this heap belongs to the main arena, start at the beginning of the
    # heap's mapping, otherwise, compensate for the presence of a heap_info
    # struct and possibly an arena.
    if addr:
        cursor = int(addr)
    elif arena == allocator.main_arena:
        cursor = heap_region.start
    else:
        cursor = heap_region.start + allocator.heap_info.sizeof
        if pwndbg.vmmap.find(allocator.get_heap(heap_region.start)['ar_ptr']) == heap_region:
            # Round up to a 2-machine-word alignment after an arena to
            # compensate for the presence of the have_fastchunks variable
            # in GLIBC versions >= 2.27.
            cursor += (allocator.malloc_state.sizeof + ptr_size) & ~allocator.malloc_align_mask

    while cursor in heap_region:
        old_cursor = cursor
        size_field = pwndbg.memory.u(cursor + allocator.chunk_key_offset('size'))
        real_size = size_field & ~allocator.malloc_align_mask

        if cursor == top_chunk:
            out = message.off("Top chunk\n")
            out += "Addr: {}\nSize: 0x{:02x}".format(M.get(cursor), size_field)
            print(out)
            break

        fastbins = allocator.fastbins(arena.address)
        smallbins = allocator.smallbins(arena.address)
        largebins = allocator.largebins(arena.address)
        unsortedbin = allocator.unsortedbin(arena.address)
        if allocator.has_tcache():
            tcachebins = allocator.tcachebins(None)

        out = "Addr: {}\nSize: 0x{:02x}\n".format(M.get(cursor), size_field)

        if real_size in fastbins.keys() and cursor in fastbins[real_size]:
            out = message.on("Free chunk (fastbins)\n") + out
            if not verbose:
                out += message.system("fd: ") + "0x{:02x}\n".format(pwndbg.memory.u(cursor + allocator.chunk_key_offset('fd')))
        elif real_size in smallbins.keys() and cursor in bin_addrs(smallbins[real_size], "smallbins"):
            out = message.on("Free chunk (smallbins)\n") + out
            if not verbose:
                out += message.system("fd: ") + "0x{:02x}\n".format(pwndbg.memory.u(cursor + allocator.chunk_key_offset('fd')))
                out += message.system("bk: ") + "0x{:02x}\n".format(pwndbg.memory.u(cursor + allocator.chunk_key_offset('bk')))
        elif real_size >= list(largebins.items())[0][0] and cursor in bin_addrs(largebins[(list(largebins.items())[allocator.largebin_index(real_size) - 64][0])], "largebins"):
            out = message.on("Free chunk (largebins)\n") + out
            if not verbose:
                out += message.system("fd: ") + "0x{:02x}\n".format(pwndbg.memory.u(cursor + allocator.chunk_key_offset('fd')))
                out += message.system("bk: ") + "0x{:02x}\n".format(pwndbg.memory.u(cursor + allocator.chunk_key_offset('bk')))
                out += message.system("fd_nextsize: ") + "0x{:02x}\n".format(pwndbg.memory.u(cursor + allocator.chunk_key_offset('fd_nextsize')))
                out += message.system("bk_nextsize: ") + "0x{:02x}\n".format(pwndbg.memory.u(cursor + allocator.chunk_key_offset('bk_nextsize')))
        elif cursor in bin_addrs(unsortedbin['all'], "unsortedbin"):
            out = message.on("Free chunk (unsortedbin)\n") + out
            if not verbose:
                out += message.system("fd: ") + "0x{:02x}\n".format(pwndbg.memory.u(cursor + allocator.chunk_key_offset('fd')))
                out += message.system("bk: ") + "0x{:02x}\n".format(pwndbg.memory.u(cursor + allocator.chunk_key_offset('bk')))
        elif allocator.has_tcache() and real_size in tcachebins.keys() and cursor + ptr_size*2 in bin_addrs(tcachebins[real_size], "tcachebins"):
            out = message.on("Free chunk (tcache)\n") + out
            if not verbose:
                out += message.system("fd: ") + "0x{:02x}\n".format(pwndbg.memory.u(cursor + allocator.chunk_key_offset('fd')))
        else:
            out = message.hint("Allocated chunk\n") + out

        if verbose:
            out += message.system("fd: ") + "0x{:02x}\n".format(pwndbg.memory.u(cursor + allocator.chunk_key_offset('fd')))
            out += message.system("bk: ") + "0x{:02x}\n".format(pwndbg.memory.u(cursor + allocator.chunk_key_offset('bk')))
            out += message.system("fd_nextsize: ") + "0x{:02x}\n".format(pwndbg.memory.u(cursor + allocator.chunk_key_offset('fd_nextsize')))
            out += message.system("bk_nextsize: ") + "0x{:02x}\n".format(pwndbg.memory.u(cursor + allocator.chunk_key_offset('bk_nextsize')))

        print(out)
        cursor += real_size

        # Avoid an infinite loop when a chunk's size is 0.
        if cursor == old_cursor:
            break


parser = argparse.ArgumentParser()
parser.description = "Print the contents of an arena, default to the current thread's arena."
parser.add_argument("addr", nargs="?", type=int, default=None, help="Address of the arena.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithLibcDebugSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def arena(addr=None):
    """Print the contents of an arena, default to the current thread's arena."""
    allocator = pwndbg.heap.current
    arena = allocator.get_arena(addr)
    print(arena)


parser = argparse.ArgumentParser()
parser.description = "List this process's arenas."
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithLibcDebugSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def arenas():
    """Lists this process's arenas."""
    allocator = pwndbg.heap.current
    for ar in allocator.arenas:
        print(ar)


parser = argparse.ArgumentParser()
parser.description = "Print a thread's tcache contents, default to the current thread's tcache."
parser.add_argument("addr", nargs="?", type=int, default=None, help="Address of the tcache.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithLibcDebugSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
@pwndbg.commands.OnlyWithTcache
def tcache(addr=None):
    """Print a thread's tcache contents, default to the current thread's
    tcache.
    """
    allocator = pwndbg.heap.current
    tcache = allocator.get_tcache(addr)
    print(tcache)


parser = argparse.ArgumentParser()
parser.description = "Print the mp_ struct's contents."
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithLibcDebugSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def mp():
    """Print the mp_ struct's contents."""
    allocator = pwndbg.heap.current
    print(allocator.mp)


parser = argparse.ArgumentParser()
parser.description = "Print relevant information about an arena's top chunk, default to current thread's arena."
parser.add_argument("addr", nargs="?", type=int, default=None, help="Address of the arena.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithLibcDebugSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def top_chunk(addr=None):
    """Print relevant information about an arena's top chunk, default to the
    current thread's arena.
    """
    allocator = pwndbg.heap.current
    arena = allocator.get_arena(addr)
    address = arena['top']
    size = pwndbg.memory.u(int(address) + allocator.chunk_key_offset('size'))

    out = message.off("Top chunk\n") + "Addr: {}\nSize: 0x{:02x}".format(M.get(address), size)
    print(out)


parser = argparse.ArgumentParser()
parser.description = "Print a malloc_chunk struct's contents."
parser.add_argument("addr", nargs="?", type=int, default=None, help="Address of the chunk.")
parser.add_argument("fake", nargs="?", type=bool, default=False, help="Is this a fake chunk?")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithLibcDebugSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def malloc_chunk(addr,fake=False):
    """Print a malloc_chunk struct's contents."""
    allocator = pwndbg.heap.current

    if not isinstance(addr, six.integer_types):
        addr = int(addr)

    chunk = read_chunk(addr)
    size = int(chunk['size'])
    actual_size = size & ~7
    prev_inuse, is_mmapped, non_main_arena = allocator.chunk_flags(size)
    arena = None
    if not fake and non_main_arena:
        arena = allocator.get_heap(addr)['ar_ptr']

    fastbins = [] if fake else allocator.fastbins(arena)
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
parser.description = "Print the contents of all an arena's bins and a thread's tcache, default to the current thread's arena and tcache."
parser.add_argument("addr", nargs="?", type=int, default=None, help="Address of the arena.")
parser.add_argument("tcache_addr", nargs="?", type=int, default=None, help="Address of the tcache.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithLibcDebugSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def bins(addr=None, tcache_addr=None):
    """Print the contents of all an arena's bins and a thread's tcache,
    default to the current thread's arena and tcache.
    """
    if pwndbg.heap.current.has_tcache():
        tcachebins(tcache_addr)
    fastbins(addr)
    unsortedbin(addr)
    smallbins(addr)
    largebins(addr)


parser = argparse.ArgumentParser()
parser.description = "Print the contents of an arena's fastbins, default to the current thread's arena."
parser.add_argument("addr", nargs="?", type=int, default=None, help="Address of the arena.")
parser.add_argument("verbose", nargs="?", type=bool, default=True, help="Show extra detail.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithLibcDebugSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def fastbins(addr=None, verbose=True):
    """Print the contents of an arena's fastbins, default to the current
    thread's arena.
    """
    allocator = pwndbg.heap.current
    fastbins = allocator.fastbins(addr)

    if fastbins is None:
        return

    formatted_bins = format_bin(fastbins, verbose)

    print(C.banner('fastbins'))
    for node in formatted_bins:
        print(node)


parser = argparse.ArgumentParser()
parser.description = "Print the contents of an arena's unsortedbin, default to the current thread's arena."
parser.add_argument("addr", nargs="?", type=int, default=None, help="Address of the arena.")
parser.add_argument("verbose", nargs="?", type=bool, default=True, help="Show extra detail.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithLibcDebugSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def unsortedbin(addr=None, verbose=True):
    """Print the contents of an arena's unsortedbin, default to the current
    thread's arena.
    """
    allocator = pwndbg.heap.current
    unsortedbin = allocator.unsortedbin(addr)

    if unsortedbin is None:
        return

    formatted_bins = format_bin(unsortedbin, verbose)

    print(C.banner('unsortedbin'))
    for node in formatted_bins:
        print(node)


parser = argparse.ArgumentParser()
parser.description = "Print the contents of an arena's smallbins, default to the current thread's arena."
parser.add_argument("addr", nargs="?", type=int, default=None, help="Address of the arena.")
parser.add_argument("verbose", nargs="?", type=bool, default=False, help="Show extra detail.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithLibcDebugSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def smallbins(addr=None, verbose=False):
    """Print the contents of an arena's smallbins, default to the current
    thread's arena.
    """
    allocator = pwndbg.heap.current
    smallbins = allocator.smallbins(addr)

    if smallbins is None:
        return

    formatted_bins = format_bin(smallbins, verbose)

    print(C.banner('smallbins'))
    for node in formatted_bins:
        print(node)


parser = argparse.ArgumentParser()
parser.description = "Print the contents of an arena's largebins, default to the current thread's arena."
parser.add_argument("addr", nargs="?", type=int, default=None, help="Address of the arena.")
parser.add_argument("verbose", nargs="?", type=bool, default=False, help="Show extra detail.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithLibcDebugSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def largebins(addr=None, verbose=False):
    """Print the contents of an arena's largebins, default to the current
    thread's arena.
    """
    allocator = pwndbg.heap.current
    largebins = allocator.largebins(addr)

    if largebins is None:
        return

    formatted_bins = format_bin(largebins, verbose)

    print(C.banner('largebins'))
    for node in formatted_bins:
        print(node)


parser = argparse.ArgumentParser()
parser.description = "Print the contents of a tcache, default to the current thread's tcache."
parser.add_argument("addr", nargs="?", type=int, default=None, help="The address of the tcache bins.")
parser.add_argument("verbose", nargs="?", type=bool, default=False, help="Whether to show more details or not.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithLibcDebugSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
@pwndbg.commands.OnlyWithTcache
def tcachebins(addr=None, verbose=False):
    """Print the contents of a tcache, default to the current thread's tcache."""
    allocator = pwndbg.heap.current
    tcachebins = allocator.tcachebins(addr)

    if tcachebins is None:
        return

    formatted_bins = format_bin(tcachebins, verbose, offset = allocator.tcache_next_offset)

    print(C.banner('tcachebins'))
    for node in formatted_bins:
        print(node)


parser = argparse.ArgumentParser()
parser.description = "Find candidate fake fast chunks overlapping the specified address."
parser.add_argument("addr", type=int, help="Address of the word-sized value to overlap.")
parser.add_argument("size", nargs="?", type=int, default=None, help="Size of fake chunks to find.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithLibcDebugSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def find_fake_fast(addr, size=None):
    """Find candidate fake fast chunks overlapping the specified address."""
    psize = pwndbg.arch.ptrsize
    allocator = pwndbg.heap.current
    align = allocator.malloc_alignment
    min_fast = allocator.min_chunk_size
    max_fast = allocator.global_max_fast
    max_fastbin = allocator.fastbin_index(max_fast)
    start = int(addr) - max_fast + psize
    mem = pwndbg.memory.read(start, max_fast - psize, partial=True)

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
        fastbin  = allocator.fastbin_index(size)
        for offset in range((max_fastbin - fastbin) * align, max_fast - align + 1):
            candidate = mem[offset : offset + psize]
            if len(candidate) == psize:
                value = struct.unpack(fmt, candidate)[0]
                if allocator.fastbin_index(value) == fastbin:
                    malloc_chunk(start+offset-psize, fake=True)


parser = argparse.ArgumentParser()
parser.description = "Visualize chunks on a heap, default to the current arena's active heap."
parser.add_argument("count", nargs="?", type=lambda n:max(int(n, 0),1), default=10, help="Number of chunks to visualize.")
parser.add_argument("addr", nargs="?", default=None, help="Address of the first chunk.")
parser.add_argument("--naive", "-n", action="store_true", default=False, help="Attempt to keep printing beyond the top chunk.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithLibcDebugSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def vis_heap_chunks(addr=None, count=None, naive=None):
    """Visualize chunks on a heap, default to the current arena's active heap."""
    allocator = pwndbg.heap.current
    heap_region = allocator.get_heap_boundaries(addr)
    arena = allocator.get_arena_for_chunk(addr) if addr else allocator.get_arena()

    top_chunk = arena['top']
    ptr_size = allocator.size_sz

    # Build a list of addresses that delimit each chunk.
    chunk_delims = []
    if addr:
        cursor = int(addr)
    elif arena == allocator.main_arena:
        cursor = heap_region.start
    else:
        cursor = heap_region.start + allocator.heap_info.sizeof
        if pwndbg.vmmap.find(allocator.get_heap(heap_region.start)['ar_ptr']) == heap_region:
            # Round up to a 2-machine-word alignment after an arena to
            # compensate for the presence of the have_fastchunks variable
            # in GLIBC versions >= 2.27.
            cursor += (allocator.malloc_state.sizeof + ptr_size) & ~allocator.malloc_align_mask

    cursor_backup = cursor

    for _ in range(count + 1):
        # Don't read beyond the heap mapping if --naive or corrupted heap.
        if cursor not in heap_region:
            chunk_delims.append(heap_region.end)
            break

        size_field = pwndbg.memory.u(cursor + ptr_size)
        real_size = size_field & ~allocator.malloc_align_mask
        prev_inuse = allocator.chunk_flags(size_field)[0]

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
        allocator.fastbins(arena.address),
        allocator.unsortedbin(arena.address),
        allocator.smallbins(arena.address),
        allocator.largebins(arena.address),
        ]
    if allocator.has_tcache():
        # Only check for tcache entries belonging to the current thread,
        # it's difficult (impossible?) to find all the thread caches for a
        # specific heap.
        bin_collections.insert(0, allocator.tcachebins(None))

    printed = 0
    out = ''
    asc = ''
    labels = []
    cursor = cursor_backup

    for c, stop in enumerate(chunk_delims):
        color_func = color_funcs[c % len(color_funcs)]

        while cursor != stop:
            if printed % 2 == 0:
                out += "\n0x%x" % cursor

            cell = pwndbg.arch.unpack(pwndbg.memory.read(cursor, ptr_size))
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
    valid_chars = list(map(ord, set(printable) - set('\t\r\n\x0c')))
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
