import argparse
import ctypes
import struct
from typing import Optional

import gdb

import pwndbg.color.context as C
import pwndbg.color.memory as M
import pwndbg.commands
import pwndbg.config
import pwndbg.glibc
import pwndbg.typeinfo
from pwndbg.color import generateColorFunction
from pwndbg.color import message
from pwndbg.color import underline
from pwndbg.commands.config import extend_value_with_default
from pwndbg.commands.config import get_config_parameters
from pwndbg.commands.config import print_row
from pwndbg.heap.ptmalloc import Bin
from pwndbg.heap.ptmalloc import Bins
from pwndbg.heap.ptmalloc import BinType
from pwndbg.heap.ptmalloc import read_chunk_from_gdb


def format_bin(bins: Bins, verbose=False, offset=None) -> list[str]:
    allocator = pwndbg.heap.current
    if offset is None:
        offset = allocator.chunk_key_offset('fd')

    result = []
    bins_type = bins.bin_type

    for size, b in bins.bins.items():
        if not verbose and (
            b.fd_chain == [0] and not b.count
        ) and not b.is_corrupted:
            continue

        safe_lnk = False
        if bins_type in [BinType.FAST, BinType.TCACHE]:
            safe_lnk = pwndbg.glibc.check_safe_linking()

        if bins_type == BinType.TCACHE:
            limit = min(8, b.count + 1)
        else:
            limit = pwndbg.chain.LIMIT

        formatted_chain = pwndbg.chain.format(
            b.fd_chain[0], limit=limit, offset=offset, safe_linking=safe_lnk
        )

        size_str = Bin.size_to_display_name(size)

        if b.is_corrupted:
            line = message.hint(size_str) + message.error(' [corrupted]') + '\n'
            line += message.hint('FD: ') + formatted_chain + '\n'
            line += message.hint('BK: ') + pwndbg.chain.format(
                b.bk_chain[0], offset=allocator.chunk_key_offset('bk')
            )
        else:
            line = message.hint(size_str)
            if b.count is not None:
                line += message.hint(' [%3d]' % b.count)

            line += ': '
            line.ljust(13)

            line += formatted_chain

        result.append(line)

    if not result:
        result.append(message.hint('empty'))

    return result


parser = argparse.ArgumentParser()
parser.description = "Iteratively print chunks on a heap, default to the current thread's active heap."
parser.add_argument(
    "addr",
    nargs="?",
    type=int,
    default=None,
    help=
    "Address of the first chunk (malloc_chunk struct start, prev_size field)."
)
parser.add_argument(
    "-v",
    "--verbose",
    action="store_true",
    help="Print all chunk fields, even unused ones."
)
parser.add_argument(
    "-s",
    "--simple",
    action="store_true",
    help="Simply print malloc_chunk struct's contents."
)
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithResolvedHeapSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def heap(addr: int = None, verbose=False, simple=False):
    """Iteratively print chunks on a heap, default to the current thread's
    active heap.
    """
    allocator = pwndbg.heap.current
    heap_region = allocator.get_heap_boundaries(addr)

    if addr:
        arena = allocator.get_arena_for_chunk(addr)
    else:
        arena = allocator.get_arena()

    ptr_size = allocator.size_sz

    # Store the heap base address in a GDB variable that can be used in other
    # GDB commands
    # TODO: See https://github.com/pwndbg/pwndbg/issues/1060
    gdb.execute('set $heap_base=0x{:x}'.format(heap_region.start))

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
        if pwndbg.vmmap.find(
            allocator.get_heap(heap_region.start)['ar_ptr']
        ) == heap_region:
            # Round up to a 2-machine-word alignment after an arena to
            # compensate for the presence of the have_fastchunks variable
            # in GLIBC versions >= 2.27.
            cursor += pwndbg.memory.align_down(
                allocator.malloc_state.sizeof + ptr_size,
                allocator.malloc_alignment
            )

    # In glibc 2.26, the malloc_alignment for i386 was hardcoded to 16 (instead
    # of 2*sizeof(size_t), which is 8). In order for the data to be aligned to
    # 16 bytes, the first chunk now needs to start offset 8 instead of offset 0

    # TODO: Can we just check if this is 32bit and >= glibc 2.26? This type of
    # check is confusing as is, and unnecessary in most cases
    first_chunk_size = pwndbg.arch.unpack(
        pwndbg.memory.read(cursor + ptr_size, ptr_size)
    )
    if first_chunk_size == 0:
        cursor += ptr_size * 2

    for chunk in allocator.chunks(cursor):
        malloc_chunk(chunk, verbose=verbose, simple=simple)


parser = argparse.ArgumentParser()
parser.description = "Print the contents of an arena, default to the current thread's arena."
parser.add_argument("addr", nargs="?", type=int, default=None, help="Address of the arena.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithResolvedHeapSyms
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
@pwndbg.commands.OnlyWithResolvedHeapSyms
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
@pwndbg.commands.OnlyWithResolvedHeapSyms
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
@pwndbg.commands.OnlyWithResolvedHeapSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def mp():
    """Print the mp_ struct's contents."""
    allocator = pwndbg.heap.current
    print(allocator.mp)


parser = argparse.ArgumentParser()
parser.description = "Print relevant information about an arena's top chunk, default to current thread's arena."
parser.add_argument(
    "addr", nargs="?", type=int, default=None, help="Address of the arena."
)
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithResolvedHeapSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def top_chunk(addr: Optional[int] = None):
    """Print relevant information about an arena's top chunk, default to the
    current thread's arena.
    """
    allocator = pwndbg.heap.current
    arena = allocator.get_arena(addr)
    address = arena['top']
    size = allocator.chunk_size_nomask(int(address))

    out = message.off("Top chunk\n") + "Addr: {}\nSize: 0x{:02x}".format(
        M.get(address), size
    )
    print(out)


def get_chunk_bin(addr: int) -> list[BinType]:
    # points to the real start of the chunk
    cursor = int(addr)

    allocator = pwndbg.heap.current
    size = allocator.chunk_size(cursor)

    arena = allocator.get_arena_for_chunk(addr)

    bins = [
        allocator.fastbins(arena.address),
        allocator.smallbins(arena.address),
        allocator.largebins(arena.address),
        allocator.unsortedbin(arena.address),
    ]

    if allocator.has_tcache():
        bins.append(allocator.tcachebins(None))

    # TODO: What if we were able to free a chunk of one size and get into a bin
    # of another size? Should we check every size?
    res = []
    for bin_ in bins:
        if bin_.contains_chunk(size, cursor):
            res.append(bin_.bin_type)

    if len(res) == 0:
        return [BinType.NOT_IN_BIN]
    else:
        return res


parser = argparse.ArgumentParser()
parser.description = "Print a chunk."
parser.add_argument(
    "addr",
    type=int,
    help="Address of the chunk (malloc_chunk struct start, prev_size field)."
)
parser.add_argument(
    "-f", "--fake", action="store_true", help="Is this a fake chunk?"
)
parser.add_argument(
    "-v",
    "--verbose",
    action="store_true",
    help="Print all chunk fields, even unused ones."
)
parser.add_argument(
    "-s",
    "--simple",
    action="store_true",
    help="Simply print malloc_chunk struct's contents."
)
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithResolvedHeapSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def malloc_chunk(addr: int, fake=False, verbose=False, simple=False):
    """Print a malloc_chunk struct's contents."""
    # points to the real start of the chunk
    cursor = int(addr)

    allocator = pwndbg.heap.current

    size_field = allocator.chunk_size_nomask(cursor)
    real_size = allocator.chunk_size(cursor)

    headers_to_print = []  # both state (free/allocated) and flags
    fields_to_print = set()  # in addition to addr and size

    prev_inuse, is_mmapped, non_main_arena = allocator.chunk_flags(size_field)
    if prev_inuse:
        headers_to_print.append(message.hint('PREV_INUSE'))
    if is_mmapped:
        headers_to_print.append(message.hint('IS_MMAPED'))
    if non_main_arena:
        headers_to_print.append(message.hint('NON_MAIN_ARENA'))

    if fake:
        headers_to_print.append(message.on('Fake chunk'))
        verbose = True  # print all fields for fake chunks

    if simple:
        chunk = read_chunk_from_gdb(cursor)

        # The address should be the first header
        headers_to_print.insert(0, message.hint(M.get(cursor)))

        print(' | '.join(headers_to_print))
        for key, val in chunk.items():
            print(message.system(key) + ': 0x{:02x}'.format(int(val)))
        print('')
        return

    arena = allocator.get_arena_for_chunk(cursor)
    arena_address = None
    is_top = False
    if not fake and arena:
        arena_address = arena.address
        top_chunk = arena['top']
        if cursor == top_chunk:
            headers_to_print.append(message.off('Top chunk'))
            is_top = True

    if not is_top:
        bin_types = get_chunk_bin(cursor)
        if BinType.NOT_IN_BIN in bin_types:
            headers_to_print.append(message.hint('Allocated chunk'))

        else:
            # TODO: Handle a chunk being in multiple bins
            bin_type = bin_types[0]
            headers_to_print.append(
                message.on('Free chunk ({})'.format('|'.join(bin_types)))
            )
            for bin_type in bin_types:
                fields_to_print.update(bin_type.valid_fields())


    out_fields = ['Addr: {}'.format(M.get(cursor))]
    fields_ordered = [
        'prev_size', 'size', 'fd', 'bk', 'fd_nextsize', 'bk_nextsize'
    ]
    if verbose:
        fields_to_print.update(fields_ordered)
    else:
        out_fields.append('Size: 0x{:02x}'.format(size_field))

    print(' | '.join(headers_to_print))
    for field_to_print in fields_ordered:
        if field_to_print in fields_to_print:
            field_val = pwndbg.memory.u(cursor + allocator.chunk_key_offset(field_to_print))
            out_fields.append(message.system(field_to_print) + ': 0x{:02x}'.format(field_val))

    print('\n'.join(out_fields))
    print('')


parser = argparse.ArgumentParser()
parser.description = "Print the contents of all an arena's bins and a thread's tcache, default to the current thread's arena and tcache."
parser.add_argument(
    "addr", nargs="?", type=int, default=None, help="Address of the arena."
)
parser.add_argument(
    "tcache_addr",
    nargs="?",
    type=int,
    default=None,
    help="Address of the tcache."
)
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithResolvedHeapSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def bins(addr: Optional[int] = None, tcache_addr: Optional[int] = None):
    """Print the contents of all an arena's bins and a thread's tcache,
    default to the current thread's arena and tcache.
    """
    if pwndbg.heap.current.has_tcache():
        tcachebins(tcache_addr)
    fastbins(addr)
    unsortedbin(addr)
    smallbins(addr)
    largebins(addr)


def print_bins(
    bin_type: BinType, addr: Optional[int] = None, verbose: bool = False
):
    allocator = pwndbg.heap.current
    offset = None

    # TODO: Abstract this away
    if bin_type == BinType.TCACHE:
        offset = allocator.tcache_next_offset
    else:
        offset = None

    bins = allocator.get_bins(bin_type, addr=addr)
    if bins is None:
        return

    formatted_bins = format_bin(bins, verbose, offset=offset)

    print(C.banner(bin_type.value))
    for node in formatted_bins:
        print(node)


parser = argparse.ArgumentParser()
parser.description = "Print the contents of an arena's fastbins, default to the current thread's arena."
parser.add_argument(
    "addr", nargs="?", type=int, default=None, help="Address of the arena."
)
parser.add_argument(
    "verbose", nargs="?", type=bool, default=True, help="Show extra detail."
)
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithResolvedHeapSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def fastbins(addr: Optional[int] = None, verbose=True):
    """Print the contents of an arena's fastbins, default to the current
    thread's arena.
    """
    print_bins(BinType.FAST, addr, verbose)


parser = argparse.ArgumentParser()
parser.description = "Print the contents of an arena's unsortedbin, default to the current thread's arena."
parser.add_argument(
    "addr", nargs="?", type=int, default=None, help="Address of the arena."
)
parser.add_argument(
    "verbose", nargs="?", type=bool, default=True, help="Show extra detail."
)
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithResolvedHeapSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def unsortedbin(addr: Optional[int] = None, verbose=True):
    """Print the contents of an arena's unsortedbin, default to the current
    thread's arena.
    """
    print_bins(BinType.UNSORTED, addr, verbose)


parser = argparse.ArgumentParser()
parser.description = "Print the contents of an arena's smallbins, default to the current thread's arena."
parser.add_argument(
    "addr", nargs="?", type=int, default=None, help="Address of the arena."
)
parser.add_argument(
    "verbose", nargs="?", type=bool, default=False, help="Show extra detail."
)
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithResolvedHeapSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def smallbins(addr: Optional[int] = None, verbose=False):
    """Print the contents of an arena's smallbins, default to the current
    thread's arena.
    """
    print_bins(BinType.SMALL, addr, verbose)


parser = argparse.ArgumentParser()
parser.description = "Print the contents of an arena's largebins, default to the current thread's arena."
parser.add_argument(
    "addr", nargs="?", type=int, default=None, help="Address of the arena."
)
parser.add_argument(
    "verbose", nargs="?", type=bool, default=False, help="Show extra detail."
)
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithResolvedHeapSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def largebins(addr: Optional[int] = None, verbose=False):
    """Print the contents of an arena's largebins, default to the current
    thread's arena.
    """
    print_bins(BinType.LARGE, addr, verbose)


parser = argparse.ArgumentParser()
parser.description = "Print the contents of a tcache, default to the current thread's tcache."
parser.add_argument(
    "addr",
    nargs="?",
    type=int,
    default=None,
    help="The address of the tcache bins."
)
parser.add_argument(
    "verbose",
    nargs="?",
    type=bool,
    default=False,
    help="Whether to show more details or not."
)
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithResolvedHeapSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
@pwndbg.commands.OnlyWithTcache
def tcachebins(addr: Optional[int] = None, verbose=False):
    """Print the contents of a tcache, default to the current thread's tcache."""
    print_bins(BinType.TCACHE, addr, verbose)


parser = argparse.ArgumentParser()
parser.description = "Find candidate fake fast chunks overlapping the specified address."
parser.add_argument("addr", type=int, help="Address of the word-sized value to overlap.")
parser.add_argument("size", nargs="?", type=int, default=None, help="Size of fake chunks to find.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithResolvedHeapSyms
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
parser.add_argument(
    "count",
    nargs="?",
    type=lambda n: max(int(n, 0), 1),
    default=10,
    help="Number of chunks to visualize."
)
parser.add_argument(
    "addr", nargs="?", default=None, help="Address of the first chunk."
)
parser.add_argument(
    "--naive",
    "-n",
    action="store_true",
    default=False,
    help="Attempt to keep printing beyond the top chunk."
)
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithResolvedHeapSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def vis_heap_chunks(addr: Optional[int] = None, count=None, naive=False):
    """Visualize chunks on a heap, default to the current arena's active heap."""
    allocator = pwndbg.heap.current
    heap_region = allocator.get_heap_boundaries(addr)
    arena = allocator.get_arena_for_chunk(addr
                                         ) if addr else allocator.get_arena()

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
        if pwndbg.vmmap.find(
            allocator.get_heap(heap_region.start)['ar_ptr']
        ) == heap_region:
            # Round up to a 2-machine-word alignment after an arena to
            # compensate for the presence of the have_fastchunks variable
            # in GLIBC versions >= 2.27.
            cursor += pwndbg.memory.align_down(
                allocator.malloc_state.sizeof + ptr_size,
                allocator.malloc_alignment
            )

    # Check if there is an alignment at the start of the heap, adjust if necessary.
    if not addr:
        first_chunk_size = pwndbg.arch.unpack(
            pwndbg.memory.read(cursor + ptr_size, ptr_size)
        )
        if first_chunk_size == 0:
            cursor += ptr_size * 2

    cursor_backup = cursor

    i = 0
    # TODO: This rewrite probably breaks --naive
    # TODO: If we do it like this, we should store the first chunk, not the next one
    for cursor in allocator.chunks(cursor):
        if i == 0:
            i += 1
            continue

        if i >= count:
            break

        i += 1

        next_chunk = allocator.next_chunk(cursor)
        if cursor == top_chunk:
            inuse = False
        else:
            inuse = allocator.prev_inuse(next_chunk)

        # TODO: Is this check still necessary?
        # Don't read beyond the heap mapping if --naive or corrupted heap.
        if cursor not in heap_region:
            chunk_delims.append((heap_region.end, inuse))
            break

        chunk_delims.append((cursor, inuse))

        # if (cursor == top_chunk
        #     and not naive) or (cursor == heap_region.end - ptr_size * 2):
        #     chunk_delims.append(cursor + ptr_size * 2)
        #     break

    # Build the output buffer, changing color at each chunk delimiter.
    color_funcs = [
        generateColorFunction('yellow'),
        generateColorFunction('cyan'),
        generateColorFunction('purple'),
        generateColorFunction('green'),
        generateColorFunction('blue'),
    ]

    printed = 0
    out = ''
    asc = ''
    labels = []

    cursor = cursor_backup

    for c, (stop, inuse) in enumerate(chunk_delims):
        if inuse:
            stop += ptr_size

        # TODO: Are we duplicating work with bin_labels?
        bin_type = get_chunk_bin(cursor)

        color_func = color_funcs[c % len(color_funcs)]

        while cursor != stop:
            if printed % 2 == 0:
                out += "\n0x%x" % cursor

            cell = pwndbg.arch.unpack(pwndbg.memory.read(cursor, ptr_size))
            cell_hex = '\t0x{:0{n}x}'.format(cell, n=ptr_size * 2)

            colored_text = color_func(cell_hex)
            if bin_type != BinType.NOT_IN_BIN:
                colored_text = underline(colored_text)
            out += colored_text
            printed += 1

            labels.extend(bin_labels(cursor, bin_type))
            if cursor == top_chunk:
                labels.append('Top chunk')

            asc += ''.join(
                c if c.isprintable() and c.isascii() else '.'
                for c in map(chr, pwndbg.memory.read(cursor, ptr_size))
            )
            if printed % 2 == 0:
                out += '\t' + color_func(asc) + (
                    '\t <-- ' + ', '.join(labels) if len(labels) else ''
                )
                asc = ''
                labels = []

            cursor += ptr_size

    print(out)


def bin_labels(addr: int, bin_type: BinType) -> list[str]:
    labels = []
    allocator = pwndbg.heap.current

    bins = allocator.get_bins(bin_type)
    if bins is None:
        return []

    for size, b in bins.bins.items():
        size_str = Bin.size_to_display_name(size)

        if b.contains_chunk(addr):
            count = ''
            if bins.bin_type == BinType.TCACHE:
                count = '/{:d}'.format(b.count)

            labels.append(
                '{:s}[{:s}][{:d}{:s}]'.format(
                    bins.bin_type.value, size_str, b.fd_chain.index(addr), count
                )
            )

    return labels


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
            print(message.success('__libc_free: will execute __free_hook'))

    # free(0) has no effect
    if addr == 0:
        print(message.success('__libc_free: addr is 0, nothing to do'))
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
        # read_chunk_from_gdb()['size'] is signed in pwndbg ;/
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
        chunk = read_chunk_from_gdb(addr)
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
            next_chunk = read_chunk_from_gdb(addr + chunk_size_unmasked)
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
                fastbin_top_chunk = read_chunk_from_gdb(fastbin_top_chunk)
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
        top_chunk = read_chunk_from_gdb(top_chunk_addr)
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
            next_chunk = read_chunk_from_gdb(next_chunk_addr)
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
                prev_chunk = read_chunk_from_gdb(prev_chunk_addr)
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
                next_next_chunk = read_chunk_from_gdb(next_next_chunk_addr)
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
                unsorted = read_chunk_from_gdb(unsorted_addr)
                try:
                    if read_chunk_from_gdb(unsorted['fd'])['bk'] != unsorted_addr:
                        err = 'free(): corrupted unsorted chunks -> unsorted_chunk->fd->bk != unsorted_chunk\n'
                        err += 'unsorted at 0x{:x}, unsorted->fd == 0x{:x}, unsorted->fd->bk == 0x{:x}'
                        err = err.format(unsorted_addr, unsorted['fd'], read_chunk_from_gdb(unsorted['fd'])['bk'])
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
        print(message.notice('Doing munmap_chunk'))

    finalize(errors_found, returned_before_error)


def try_unlink(addr):
    pass


parser = argparse.ArgumentParser(description='Shows heap related config. The list can be filtered.')
parser.add_argument('filter_pattern', type=str, nargs='?', default=None,
                    help='Filter to apply to config parameters names/descriptions')
@pwndbg.commands.ArgparsedCommand(parser)
def heap_config(filter_pattern):
    values = get_config_parameters('heap', filter_pattern)

    if not values:
        print(message.hint('No config parameter found with filter "{}"'.format(filter_pattern)))
        return

    longest_optname = max(map(len, [v.optname for v in values]))
    longest_value = max(map(len, [extend_value_with_default(repr(v.value), repr(v.default)) for v in values]))

    header = print_row('Name', 'Value', 'Def', 'Documentation', longest_optname, longest_value)
    print('-' * (len(header)))

    for v in sorted(values):
        print_row(v.optname, repr(v.value), repr(v.default), v.docstring, longest_optname, longest_value)

    print(message.hint('You can set config variable with `set <config-var> <value>`'))
    print(message.hint('Some config(e.g. main_arena) will only working when resolve-heap-via-heuristic is `True`'))
