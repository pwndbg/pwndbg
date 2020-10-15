#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse
import ctypes
import struct

import gdb

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
    return dict({ renames.get(key, key): int(val[key]) for key in val.type.keys() })


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
parser.add_argument("addr", nargs="?", type=int, default=None, help="Address of the first chunk (malloc_chunk struct start, prev_size field).")
parser.add_argument("-v", "--verbose", action="store_true", help="Print all chunk fields, even unused ones.")
parser.add_argument("-s", "--simple", action="store_true", help="Simply print malloc_chunk struct's contents.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithLibcDebugSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def heap(addr=None, verbose=False, simple=False):
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

    # i686 alignment heuristic
    first_chunk_size = pwndbg.arch.unpack(pwndbg.memory.read(cursor + ptr_size, ptr_size))
    if first_chunk_size == 0:
        cursor += ptr_size * 2

    while cursor in heap_region:
        malloc_chunk(cursor, verbose=verbose, simple=simple)

        if cursor == top_chunk:
            break

        size_field = pwndbg.memory.u(cursor + allocator.chunk_key_offset('size'))
        real_size = size_field & ~allocator.malloc_align_mask
        cursor += real_size

        # Avoid an infinite loop when a chunk's size is 0.
        if real_size == 0:
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
parser.description = "Print a chunk."
parser.add_argument("addr", type=int, help="Address of the chunk (malloc_chunk struct start, prev_size field).")
parser.add_argument("-f", "--fake", action="store_true", help="Is this a fake chunk?")
parser.add_argument("-v", "--verbose", action="store_true", help="Print all chunk fields, even unused ones.")
parser.add_argument("-s", "--simple", action="store_true", help="Simply print malloc_chunk struct's contents.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithLibcDebugSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def malloc_chunk(addr, fake=False, verbose=False, simple=False):
    """Print a malloc_chunk struct's contents."""
    # points to the real start of the chunk
    cursor = int(addr)

    allocator = pwndbg.heap.current
    ptr_size = allocator.size_sz

    size_field = pwndbg.memory.u(cursor + allocator.chunk_key_offset('size'))
    real_size = size_field & ~allocator.malloc_align_mask

    headers_to_print = []  # both state (free/allocated) and flags
    fields_to_print = set()  # in addition to addr and size
    out_fields = "Addr: {}\n".format(M.get(cursor))

    if fake:
        headers_to_print.append(message.on("Fake chunk"))
        verbose = True  # print all fields for fake chunks

    if simple:
        chunk = read_chunk(cursor)

        if not headers_to_print:
            headers_to_print.append(message.hint(M.get(cursor)))

        prev_inuse, is_mmapped, non_main_arena = allocator.chunk_flags(int(chunk['size']))
        if prev_inuse:
            headers_to_print.append(message.hint('PREV_INUSE'))
        if is_mmapped:
            headers_to_print.append(message.hint('IS_MMAPED'))
        if non_main_arena:
            headers_to_print.append(message.hint('NON_MAIN_ARENA'))

        print(' | '.join(headers_to_print))
        for key, val in chunk.items():
            print(message.system(key) + ": 0x{:02x}".format(int(val)))
        print('')
        return

    arena = allocator.get_arena_for_chunk(cursor)
    arena_address = None
    is_top = False
    if not fake and arena:
        arena_address = arena.address
        top_chunk = arena['top']
        if cursor == top_chunk:
            headers_to_print.append(message.off("Top chunk"))
            is_top = True

    if not is_top:
        fastbins = allocator.fastbins(arena_address) or {}
        smallbins = allocator.smallbins(arena_address) or {}
        largebins = allocator.largebins(arena_address) or {}
        unsortedbin = allocator.unsortedbin(arena_address) or {}
        if allocator.has_tcache():
            tcachebins = allocator.tcachebins(None)

        if real_size in fastbins.keys() and cursor in fastbins[real_size]:
            headers_to_print.append(message.on("Free chunk (fastbins)"))
            if not verbose:
                fields_to_print.add('fd')

        elif real_size in smallbins.keys() and cursor in bin_addrs(smallbins[real_size], "smallbins"):
            headers_to_print.append(message.on("Free chunk (smallbins)"))
            if not verbose:
                fields_to_print.update(['fd', 'bk'])

        elif real_size >= list(largebins.items())[0][0] and cursor in bin_addrs(largebins[(list(largebins.items())[allocator.largebin_index(real_size) - 64][0])], "largebins"):
            headers_to_print.append(message.on("Free chunk (largebins)"))
            if not verbose:
                fields_to_print.update(['fd', 'bk', 'fd_nextsize', 'bk_nextsize'])
        
        elif cursor in bin_addrs(unsortedbin['all'], "unsortedbin"):
            headers_to_print.append(message.on("Free chunk (unsortedbin)"))
            if not verbose:
                fields_to_print.update(['fd', 'bk'])

        elif allocator.has_tcache() and real_size in tcachebins.keys() and cursor + ptr_size*2 in bin_addrs(tcachebins[real_size], "tcachebins"):
            headers_to_print.append(message.on("Free chunk (tcache)"))
            if not verbose:
                fields_to_print.add('fd')

        else:
            headers_to_print.append(message.hint("Allocated chunk"))

    if verbose:
        fields_to_print.update(['prev_size', 'size', 'fd', 'bk', 'fd_nextsize', 'bk_nextsize'])
    else:
        out_fields += "Size: 0x{:02x}\n".format(size_field)

    prev_inuse, is_mmapped, non_main_arena = allocator.chunk_flags(size_field)
    if prev_inuse:
        headers_to_print.append(message.hint('PREV_INUSE'))
    if is_mmapped:
        headers_to_print.append(message.hint('IS_MMAPED'))
    if non_main_arena:
        headers_to_print.append(message.hint('NON_MAIN_ARENA'))

    fields_ordered = ['prev_size', 'size', 'fd', 'bk', 'fd_nextsize', 'bk_nextsize']
    for field_to_print in fields_ordered:
        if field_to_print in fields_to_print:
            out_fields += message.system(field_to_print) + ": 0x{:02x}\n".format(pwndbg.memory.u(cursor + allocator.chunk_key_offset(field_to_print)))

    print(' | '.join(headers_to_print) + "\n" + out_fields)


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
    if start < 0:
        print(message.warn('addr - global_max_fast is negative, if the max_fast is not corrupted, you gave wrong address'))
        start = 0  # TODO, maybe some better way to handle case when global_max_fast is overwritten with something large
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
        sizes = [int(size)]

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

    # Check if there is an alignment at the start of the heap, adjust if necessary.
    if not addr:
        first_chunk_size = pwndbg.arch.unpack(pwndbg.memory.read(cursor + ptr_size, ptr_size))
        if first_chunk_size == 0:
            cursor += ptr_size * 2

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
    allocator = pwndbg.heap.current
    arena = allocator.get_arena()

    aligned_lsb = allocator.malloc_align_mask.bit_length()
    size_sz = allocator.size_sz
    malloc_alignment = allocator.malloc_alignment
    malloc_align_mask = allocator.malloc_align_mask
    chunk_minsize = allocator.minsize

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

    def finalize(errors_found, returned_before_error):
        print('-'*10)
        if returned_before_error:
            print(message.success('Free should succeed!'))
        elif errors_found > 0:
            print(message.error('Errors found!'))
        else:
            print(message.success('All checks passed!'))


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
    _, is_mmapped, _ = allocator.chunk_flags(chunk_size)

    if is_mmapped:
        print(message.notice('__libc_free: Doing munmap_chunk'))
        return

    errors_found = False
    returned_before_error = False

    # chunk doesn't overlap memory
    print(message.notice('General checks'))
    max_mem = (1 << (ptr_size*8)) - 1
    if addr + chunk_size >= max_mem:
        err = 'free(): invalid pointer -> &chunk + chunk->size > max memory\n'
        err += '    0x{:x} + 0x{:x} > 0x{:x}'
        err = err.format(addr, chunk_size, max_mem)
        print(message.error(err))
        errors_found += 1

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
        errors_found += 1

    # chunk's size is big enough
    if chunk_size_unmasked < chunk_minsize:
        err = 'free(): invalid size -> chunk\'s size smaller than MINSIZE\n'
        err += '    size is 0x{:x}, MINSIZE is 0x{:x}'
        err = err.format(chunk_size_unmasked, chunk_minsize)
        print(message.error(err))
        errors_found += 1

    # chunk's size is aligned
    if chunk_size_unmasked & malloc_align_mask != 0:
        err = 'free(): invalid size -> chunk\'s size is not aligned\n'
        err += '    LSB of size 0x{:x} are 0b{}, should be 0b{}'
        err = err.format(chunk_size_unmasked, bin(chunk_size_unmasked)[-aligned_lsb:], '0'*aligned_lsb)
        print(message.error(err))
        errors_found += 1

    # tcache
    if allocator.has_tcache() and 'key' in allocator.tcache_entry.keys():
        tc_idx = (chunk_size_unmasked - chunk_minsize + malloc_alignment - 1) // malloc_alignment
        if tc_idx < allocator.mp['tcache_bins']:
            print(message.notice('Tcache checks'))
            e = addr + 2*size_sz
            e += allocator.tcache_entry.keys().index('key') * ptr_size
            e = pwndbg.memory.pvoid(e)
            tcache_addr = int(allocator.thread_cache.address)
            if e == tcache_addr:
                # todo, actually do checks
                print(message.error('Will do checks for tcache double-free (memory_tcache_double_free)'))
                errors_found += 1

            if int(allocator.get_tcache()['counts'][tc_idx]) < int(allocator.mp['tcache_count']):
                print(message.success('Using tcache_put'))
                if errors_found == 0:
                    returned_before_error = True

    if errors_found > 0:
        finalize(errors_found, returned_before_error)
        return

    # is fastbin
    if chunk_size_unmasked <= allocator.global_max_fast:
        print(message.notice('Fastbin checks'))
        chunk_fastbin_idx = allocator.fastbin_index(chunk_size_unmasked)
        fastbin_list = allocator.fastbins(int(arena.address))[(chunk_fastbin_idx+2)*(ptr_size*2)]

        try:
            next_chunk = read_chunk(addr + chunk_size_unmasked)
        except gdb.MemoryError as e:
            print(message.error('Can\'t read next chunk at address 0x{:x}, memory error'.format(chunk + chunk_size_unmasked)))
            finalize(errors_found, returned_before_error)
            return

        # next chunk's size is big enough and small enough
        next_chunk_size = unsigned_size(next_chunk['size'])
        if next_chunk_size <= 2*size_sz or chunksize(next_chunk_size) >= int(arena['system_mem']):
            err = 'free(): invalid next size (fast) -> next chunk\'s size not in [2*size_sz; av->system_mem]\n'
            err += '    next chunk\'s size is 0x{:x}, 2*size_sz is 0x{:x}, system_mem is 0x{:x}'
            err = err.format(next_chunk_size, 2*size_sz, int(arena['system_mem']))
            print(message.error(err))
            errors_found += 1

        # chunk is not the same as the one on top of fastbin[idx]
        if int(fastbin_list[0]) == addr:
            err = 'double free or corruption (fasttop) -> chunk already is on top of fastbin list\n'
            err += '    fastbin idx == {}'
            err = err.format(chunk_fastbin_idx)
            print(message.error(err))
            errors_found += 1

        # chunk's size is ~same as top chunk's size
        fastbin_top_chunk = int(fastbin_list[0])
        if fastbin_top_chunk != 0:
            try:
                fastbin_top_chunk = read_chunk(fastbin_top_chunk)
            except gdb.MemoryError as e:
                print(message.error('Can\'t read top fastbin chunk at address 0x{:x}, memory error'.format(fastbin_top_chunk)))
                finalize(errors_found, returned_before_error)
                return

            fastbin_top_chunk_size = chunksize(unsigned_size(fastbin_top_chunk['size']))
            if chunk_fastbin_idx != allocator.fastbin_index(fastbin_top_chunk_size):
                err = 'invalid fastbin entry (free) -> chunk\'s size is not near top chunk\'s size\n'
                err += '    chunk\'s size == {}, idx == {}\n'
                err += '    top chunk\'s size == {}, idx == {}'
                err += '    if `have_lock` is false then the error is invalid'
                err = err.format(chunk['size'], chunk_fastbin_idx,
                    fastbin_top_chunk_size, allocator.fastbin_index(fastbin_top_chunk_size))
                print(message.error(err))
                errors_found += 1

    # is not mapped
    elif is_mmapped == 0:
        print(message.notice('Not mapped checks'))

        # chunks is not top chunk
        if addr == int(arena['top']):
            err = 'double free or corruption (top) -> chunk is top chunk'
            print(message.error(err))
            errors_found += 1

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
            errors_found += 1

        # now we need to dereference chunk
        try :
            next_chunk = read_chunk(next_chunk_addr)
            next_chunk_size = chunksize(unsigned_size(next_chunk['size']))
        except (OverflowError, gdb.MemoryError) as e:
            print(message.error('Can\'t read next chunk at address 0x{:x}'.format(next_chunk_addr)))
            finalize(errors_found, returned_before_error)
            return

        # next chunk's P bit is set
        prev_inuse,_,_ = allocator.chunk_flags(next_chunk['size'])
        if prev_inuse == 0:
            err = 'double free or corruption (!prev) -> next chunk\'s previous-in-use bit is 0\n'
            print(message.error(err))
            errors_found += 1

        # next chunk's size is big enough and small enough
        if next_chunk_size <= 2*size_sz or next_chunk_size >= int(arena['system_mem']):
            err = 'free(): invalid next size (normal) -> next chunk\'s size not in [2*size_sz; system_mem]\n'
            err += 'next chunk\'s size is 0x{:x}, 2*size_sz is 0x{:x}, system_mem is 0x{:x}'
            err = err.format(next_chunk_size, 2*size_sz, int(arena['system_mem']))
            print(message.error(err))
            errors_found += 1

        # consolidate backward
        prev_inuse,_,_ = allocator.chunk_flags(chunk['size'])
        if prev_inuse == 0:
            print(message.notice('Backward consolidation'))
            prev_size = chunksize(unsigned_size(chunk['prev_size']))
            prev_chunk_addr = addr - prev_size

            try :
                prev_chunk = read_chunk(prev_chunk_addr)
                prev_chunk_size = chunksize(unsigned_size(prev_chunk['size']))
            except (OverflowError, gdb.MemoryError) as e:
                print(message.error('Can\'t read next chunk at address 0x{:x}'.format(prev_chunk_addr)))
                finalize(errors_found, returned_before_error)
                return

            if prev_chunk_size != prev_size:
                err = 'corrupted size vs. prev_size while consolidating\n'
                err += 'prev_size field is 0x{:x}, prev chunk at 0x{:x}, prev chunk size is 0x{:x}'
                err = err.format(prev_size, prev_chunk_addr, prev_chunk_size)
                print(message.error(err))
                errors_found += 1
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
                finalize(errors_found, returned_before_error)
                return
            
            prev_inuse,_,_ = allocator.chunk_flags(next_next_chunk['size'])
            if prev_inuse == 0:
                print(message.notice('Forward consolidation'))
                try_unlink(next_chunk_addr)
                chunk_size += next_chunk_size
                chunk_size_unmasked += next_chunk_size
            else:
                print(message.notice('Clearing next chunk\'s P bit'))

            # unsorted bin fd->bk should be unsorted bean
            unsorted_addr = int(arena['bins'][0])
            try:
                unsorted = read_chunk(unsorted_addr)
                try:
                    if read_chunk(unsorted['fd'])['bk'] != unsorted_addr:
                        err = 'free(): corrupted unsorted chunks -> unsorted_chunk->fd->bk != unsorted_chunk\n'
                        err += 'unsorted at 0x{:x}, unsorted->fd == 0x{:x}, unsorted->fd->bk == 0x{:x}'
                        err = err.format(unsorted_addr, unsorted['fd'], read_chunk(unsorted['fd'])['bk'])
                        print(message.error(err))
                        errors_found += 1
                except (OverflowError, gdb.MemoryError) as e:
                    print(message.error('Can\'t read chunk at 0x{:x}, it is unsorted bin fd'.format(unsorted['fd'])))
                    errors_found += 1
            except (OverflowError, gdb.MemoryError) as e:
                print(message.error('Can\'t read unsorted bin chunk at 0x{:x}'.format(unsorted_addr)))
                errors_found += 1

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

    finalize(errors_found, returned_before_error)


def try_unlink(addr):
    pass

