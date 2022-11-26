import argparse
import ctypes

import gdb

import pwndbg.color.context as C
import pwndbg.color.memory as M
import pwndbg.commands
import pwndbg.gdblib.config
import pwndbg.gdblib.typeinfo
import pwndbg.glibc
import pwndbg.lib.heap.helpers
from pwndbg.color import generateColorFunction
from pwndbg.color import message
from pwndbg.commands.config import display_config
from pwndbg.heap.ptmalloc import Arena
from pwndbg.heap.ptmalloc import Bins
from pwndbg.heap.ptmalloc import BinType
from pwndbg.heap.ptmalloc import Chunk
from pwndbg.heap.ptmalloc import Heap


def read_chunk(addr):
    """Read a chunk's metadata."""
    # In GLIBC versions <= 2.24 the `mchunk_[prev_]size` field was named `[prev_]size`.
    # To support both versions, change the new names to the old ones here so that
    # the rest of the code can deal with uniform names.
    renames = {
        "mchunk_size": "size",
        "mchunk_prev_size": "prev_size",
    }
    if not pwndbg.gdblib.config.resolve_heap_via_heuristic:
        val = pwndbg.gdblib.typeinfo.read_gdbvalue("struct malloc_chunk", addr)
    else:
        val = pwndbg.heap.current.malloc_chunk(addr)
    return dict({renames.get(key, key): int(val[key]) for key in val.type.keys()})


def format_bin(bins: Bins, verbose=False, offset=None):
    allocator = pwndbg.heap.current
    if offset is None:
        offset = allocator.chunk_key_offset("fd")

    result = []
    bins_type = bins.bin_type

    for size in bins.bins:
        b = bins.bins[size]
        count, is_chain_corrupted = None, False
        safe_lnk = False

        # fastbins consists of only single linked list
        if bins_type == BinType.FAST:
            chain_fd = b.fd_chain
            safe_lnk = pwndbg.glibc.check_safe_linking()
        # tcachebins consists of single linked list and entries count
        elif bins_type == BinType.TCACHE:
            chain_fd = b.fd_chain
            count = b.count
            safe_lnk = pwndbg.glibc.check_safe_linking()
        # normal bins consists of double linked list and may be corrupted (we can detect corruption)
        else:  # normal bin
            chain_fd = b.fd_chain
            chain_bk = b.bk_chain
            is_chain_corrupted = b.is_corrupted

        if not verbose and (chain_fd == [0] and not count) and not is_chain_corrupted:
            continue

        if bins_type == BinType.TCACHE:
            limit = 8
            if count <= 7:
                limit = count + 1
            formatted_chain = pwndbg.chain.format(
                chain_fd[0], offset=offset, limit=limit, safe_linking=safe_lnk
            )
        else:
            formatted_chain = pwndbg.chain.format(chain_fd[0], offset=offset, safe_linking=safe_lnk)

        if isinstance(size, int):
            size = hex(size)

        if is_chain_corrupted:
            line = message.hint(size) + message.error(" [corrupted]") + "\n"
            line += message.hint("FD: ") + formatted_chain + "\n"
            line += message.hint("BK: ") + pwndbg.chain.format(
                chain_bk[0], offset=allocator.chunk_key_offset("bk")
            )
        else:
            if count is not None:
                line = (message.hint(size) + message.hint(" [%3d]" % count) + ": ").ljust(13)
            else:
                line = (message.hint(size) + ": ").ljust(13)
            line += formatted_chain

        result.append(line)

    if not result:
        result.append(message.hint("empty"))

    return result


parser = argparse.ArgumentParser()
parser.description = (
    "Iteratively print chunks on a heap, default to the current thread's active heap."
)
parser.add_argument(
    "addr",
    nargs="?",
    type=int,
    default=None,
    help="Address of the first chunk (malloc_chunk struct start, prev_size field).",
)
parser.add_argument(
    "-v", "--verbose", action="store_true", help="Print all chunk fields, even unused ones."
)
parser.add_argument(
    "-s", "--simple", action="store_true", help="Simply print malloc_chunk struct's contents."
)


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithResolvedHeapSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def heap(addr=None, verbose=False, simple=False):
    """Iteratively print chunks on a heap, default to the current thread's
    active heap.
    """
    allocator = pwndbg.heap.current

    if addr is not None:
        chunk = Chunk(addr)
        while chunk is not None:
            malloc_chunk(chunk.address)
            chunk = chunk.next_chunk()
    else:
        arena = allocator.thread_arena
        h = arena.active_heap

        for chunk in h:
            malloc_chunk(chunk.address)


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

    if addr is not None:
        arena = Arena(addr)
    else:
        arena = allocator.thread_arena

    print(arena._gdbValue)  # Breaks encapsulation, find a better way.


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
parser.description = (
    "Print relevant information about an arena's top chunk, default to current thread's arena."
)
parser.add_argument("addr", nargs="?", type=int, default=None, help="Address of the arena.")


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithResolvedHeapSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def top_chunk(addr=None):
    """Print relevant information about an arena's top chunk, default to the
    current thread's arena.
    """
    allocator = pwndbg.heap.current

    if addr is not None:
        arena = Arena(addr)
    else:
        arena = allocator.thread_arena

    malloc_chunk(arena.top)


parser = argparse.ArgumentParser()
parser.description = "Print a chunk."
parser.add_argument(
    "addr", type=int, help="Address of the chunk (malloc_chunk struct start, prev_size field)."
)
parser.add_argument("-f", "--fake", action="store_true", help="Is this a fake chunk?")
parser.add_argument(
    "-v", "--verbose", action="store_true", help="Print all chunk fields, even unused ones."
)
parser.add_argument(
    "-s", "--simple", action="store_true", help="Simply print malloc_chunk struct's contents."
)


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithResolvedHeapSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def malloc_chunk(addr, fake=False, verbose=False, simple=False):
    """Print a malloc_chunk struct's contents."""
    allocator = pwndbg.heap.current

    chunk = Chunk(addr)

    headers_to_print = []  # both state (free/allocated) and flags
    fields_to_print = set()  # in addition to addr and size
    out_fields = "Addr: {}\n".format(M.get(chunk.address))

    if fake:
        headers_to_print.append(message.on("Fake chunk"))
        verbose = True  # print all fields for fake chunks

    if simple:
        if not headers_to_print:
            headers_to_print.append(message.hint(M.get(chunk.address)))

        out_fields = ""
        verbose = True
    else:
        arena = chunk.arena
        if not fake and arena:
            if chunk.is_top_chunk:
                headers_to_print.append(message.off("Top chunk"))

        if not chunk.is_top_chunk and arena:

            bins_list = [
                allocator.fastbins(arena.address) or {},
                allocator.smallbins(arena.address) or {},
                allocator.largebins(arena.address) or {},
                allocator.unsortedbin(arena.address) or {},
            ]
            if allocator.has_tcache():
                bins_list.append(allocator.tcachebins(None))
            no_match = True
            for bins in bins_list:
                if bins.contains_chunk(chunk.real_size, chunk.address):
                    no_match = False
                    headers_to_print.append(message.on("Free chunk ({})".format(bins.bin_type)))
                    if not verbose:
                        fields_to_print.update(bins.bin_type.valid_fields())
            if no_match:
                headers_to_print.append(message.hint("Allocated chunk"))

    if verbose:
        fields_to_print.update(["prev_size", "size", "fd", "bk", "fd_nextsize", "bk_nextsize"])
    else:
        out_fields += "Size: 0x{:02x}\n".format(chunk.size)

    prev_inuse, is_mmapped, non_main_arena = allocator.chunk_flags(chunk.size)
    if prev_inuse:
        headers_to_print.append(message.hint("PREV_INUSE"))
    if is_mmapped:
        headers_to_print.append(message.hint("IS_MMAPED"))
    if non_main_arena:
        headers_to_print.append(message.hint("NON_MAIN_ARENA"))

    fields_ordered = ["prev_size", "size", "fd", "bk", "fd_nextsize", "bk_nextsize"]
    for field_to_print in fields_ordered:
        if field_to_print in fields_to_print:
            out_fields += message.system(field_to_print) + ": 0x{:02x}\n".format(
                getattr(chunk, field_to_print)
            )

    print(" | ".join(headers_to_print) + "\n" + out_fields)


parser = argparse.ArgumentParser()
parser.description = "Print the contents of all an arena's bins and a thread's tcache, default to the current thread's arena and tcache."
parser.add_argument("addr", nargs="?", type=int, default=None, help="Address of the arena.")
parser.add_argument("tcache_addr", nargs="?", type=int, default=None, help="Address of the tcache.")


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithResolvedHeapSyms
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
parser.description = (
    "Print the contents of an arena's fastbins, default to the current thread's arena."
)
parser.add_argument("addr", nargs="?", type=int, default=None, help="Address of the arena.")
parser.add_argument("verbose", nargs="?", type=bool, default=True, help="Show extra detail.")


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithResolvedHeapSyms
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

    print(C.banner("fastbins"))
    for node in formatted_bins:
        print(node)


parser = argparse.ArgumentParser()
parser.description = (
    "Print the contents of an arena's unsortedbin, default to the current thread's arena."
)
parser.add_argument("addr", nargs="?", type=int, default=None, help="Address of the arena.")
parser.add_argument("verbose", nargs="?", type=bool, default=True, help="Show extra detail.")


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithResolvedHeapSyms
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

    print(C.banner("unsortedbin"))
    for node in formatted_bins:
        print(node)


parser = argparse.ArgumentParser()
parser.description = (
    "Print the contents of an arena's smallbins, default to the current thread's arena."
)
parser.add_argument("addr", nargs="?", type=int, default=None, help="Address of the arena.")
parser.add_argument("verbose", nargs="?", type=bool, default=False, help="Show extra detail.")


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithResolvedHeapSyms
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

    print(C.banner("smallbins"))
    for node in formatted_bins:
        print(node)


parser = argparse.ArgumentParser()
parser.description = (
    "Print the contents of an arena's largebins, default to the current thread's arena."
)
parser.add_argument("addr", nargs="?", type=int, default=None, help="Address of the arena.")
parser.add_argument("verbose", nargs="?", type=bool, default=False, help="Show extra detail.")


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithResolvedHeapSyms
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

    print(C.banner("largebins"))
    for node in formatted_bins:
        print(node)


parser = argparse.ArgumentParser()
parser.description = "Print the contents of a tcache, default to the current thread's tcache."
parser.add_argument(
    "addr", nargs="?", type=int, default=None, help="The address of the tcache bins."
)
parser.add_argument(
    "verbose", nargs="?", type=bool, default=False, help="Whether to show more details or not."
)


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithResolvedHeapSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
@pwndbg.commands.OnlyWithTcache
def tcachebins(addr=None, verbose=False):
    """Print the contents of a tcache, default to the current thread's tcache."""
    allocator = pwndbg.heap.current
    tcachebins = allocator.tcachebins(addr)

    if tcachebins is None:
        return

    formatted_bins = format_bin(tcachebins, verbose, offset=allocator.tcache_next_offset)

    print(C.banner("tcachebins"))
    for node in formatted_bins:
        print(node)


parser = argparse.ArgumentParser()
parser.description = "Find candidate fake fast or tcache chunks overlapping the specified address."
parser.add_argument("addr", type=int, help="Address of the word-sized value to overlap.")
parser.add_argument(
    "size", nargs="?", type=int, default=None, help="Maximum size of fake chunks to find."
)
parser.add_argument(
    "--align",
    "-a",
    action="store_true",
    default=False,
    help="Whether the fake chunk must be aligned to MALLOC_ALIGNMENT. This is required for tcache "
    + "chunks and for all chunks when Safe Linking is enabled",
)


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithResolvedHeapSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def find_fake_fast(addr, size=None, align=False):
    """Find candidate fake fast chunks overlapping the specified address."""
    psize = pwndbg.gdblib.arch.ptrsize
    allocator = pwndbg.heap.current
    malloc_alignment = allocator.malloc_alignment

    min_fast = allocator.min_chunk_size
    max_fast = allocator.global_max_fast
    max_fastbin = allocator.fastbin_index(max_fast)

    if size is None:
        size = max_fast
    elif size > addr:
        print(message.warn("Size of 0x%x is greater than the target address 0x%x", (size, addr)))
        size = addr
    elif size > max_fast:
        print(
            message.warn(
                "0x%x is greater than the global_max_fast value of 0x%x" % (size, max_fast)
            )
        )
    elif size < min_fast:
        print(
            message.warn(
                "0x%x is smaller than the minimum fastbin chunk size of 0x%x" % (size, min_fast)
            )
        )
        size = min_fast

    # Clear the flags
    size &= ~0xF

    start = int(addr) - size + psize

    if align:
        # If a chunk is aligned to MALLOC_ALIGNMENT, the size field should be at
        # offset `psize`. First we align up to a multiple of `psize`
        new_start = pwndbg.lib.memory.align_up(start, psize)

        # Then we make sure we're at a multiple of `psize` but not `psize*2` by
        # making sure the bottom nibble gets set to `psize`
        new_start |= psize

        # We should not have increased `start` by more than `psize*2 - 1` bytes
        distance = new_start - start
        assert distance < psize * 2

        # If we're starting at a higher address, we still only want to read
        # enough bytes to reach our target address
        size -= distance

        # Clear the flags
        size &= ~0xF

        start = new_start

    print(
        message.notice(
            "Searching for fastbin sizes up to 0x%x starting at 0x%x resulting in an overlap of 0x%x"
            % (size, start, addr)
        )
    )

    # Only consider `size - psize` bytes, since we're starting from after `prev_size`
    mem = pwndbg.gdblib.memory.read(start, size - psize, partial=True)

    fmt = {"little": "<", "big": ">"}[pwndbg.gdblib.arch.endian] + {4: "I", 8: "Q"}[psize]

    print(C.banner("FAKE CHUNKS"))
    step = malloc_alignment if align else 1
    for offset in pwndbg.lib.heap.helpers.find_fastbin_size(mem, size, step):
        malloc_chunk(start + offset, fake=True)


pwndbg.gdblib.config.add_param(
    "max-visualize-chunk-size",
    0,
    "max display size for heap chunks visualization (0 for display all)",
)

pwndbg.gdblib.config.add_param(
    "default-visualize-chunk-number",
    10,
    "the number of chunks to visualize (default is 10)",
)

parser = argparse.ArgumentParser()
parser.description = "Visualize chunks on a heap, default to the current arena's active heap."
parser.add_argument(
    "count",
    nargs="?",
    type=lambda n: max(int(n, 0), 1),
    default=pwndbg.gdblib.config.default_visualize_chunk_number,
    help="Number of chunks to visualize.",
)
parser.add_argument("addr", nargs="?", default=None, help="Address of the first chunk.")
parser.add_argument(
    "--naive",
    "-n",
    action="store_true",
    default=False,
    help="Attempt to keep printing beyond the top chunk.",
)
parser.add_argument(
    "--display_all",
    "-a",
    action="store_true",
    default=False,
    help="Display all the chunk contents (Ignore the `max-visualize-chunk-size` configuration).",
)


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithResolvedHeapSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
def vis_heap_chunks(addr=None, count=None, naive=None, display_all=None):
    """Visualize chunks on a heap, default to the current arena's active heap."""
    allocator = pwndbg.heap.current

    if addr is not None:
        cursor = int(addr)
        heap_region = Heap(cursor)
        arena = heap_region.arena
    else:
        arena = allocator.thread_arena
        heap_region = arena.active_heap
        cursor = heap_region.start

    ptr_size = allocator.size_sz

    # Build a list of addresses that delimit each chunk.
    chunk_delims = []
    cursor_backup = cursor
    chunk = Chunk(cursor)

    for _ in range(count + 1):
        # Don't read beyond the heap mapping if --naive or corrupted heap.
        if cursor not in heap_region:
            chunk_delims.append(heap_region.end)
            break

        # Don't repeatedly operate on the same address (e.g. chunk size of 0).
        if cursor in chunk_delims or cursor + ptr_size in chunk_delims:
            break

        if chunk.prev_inuse:
            chunk_delims.append(cursor + ptr_size)
        else:
            chunk_delims.append(cursor)

        if (chunk.is_top_chunk and not naive) or (cursor == heap_region.end - ptr_size * 2):
            chunk_delims.append(cursor + ptr_size * 2)
            break

        cursor += chunk.real_size
        chunk = Chunk(cursor)

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
    out = ""
    asc = ""
    labels = []

    cursor = cursor_backup
    chunk = Chunk(cursor)

    has_huge_chunk = False
    # round up to align with 4*ptr_size and get half
    half_max_size = (
        pwndbg.lib.memory.round_up(pwndbg.gdblib.config.max_visualize_chunk_size, ptr_size << 2)
        >> 1
    )

    for c, stop in enumerate(chunk_delims):
        color_func = color_funcs[c % len(color_funcs)]

        if stop - cursor > 0x10000:
            has_huge_chunk = True
        first_cut = True
        # round down to align with 2*ptr_size
        begin_addr = pwndbg.lib.memory.round_down(cursor, ptr_size << 1)
        end_addr = pwndbg.lib.memory.round_down(stop, ptr_size << 1)

        while cursor != stop:
            # skip the middle part of a huge chunk
            if (
                not display_all
                and half_max_size > 0
                and begin_addr + half_max_size <= cursor < end_addr - half_max_size
            ):
                if first_cut:
                    out += "\n" + "." * len(hex(cursor))
                    first_cut = False
                cursor += ptr_size
                continue

            if printed % 2 == 0:
                out += "\n0x%x" % cursor

            cell = pwndbg.gdblib.arch.unpack(pwndbg.gdblib.memory.read(cursor, ptr_size))
            cell_hex = "\t0x{:0{n}x}".format(cell, n=ptr_size * 2)

            out += color_func(cell_hex)
            printed += 1

            labels.extend(bin_labels(cursor, bin_collections))
            if cursor == arena.top:
                labels.append("Top chunk")

            asc += bin_ascii(pwndbg.gdblib.memory.read(cursor, ptr_size))
            if printed % 2 == 0:
                out += (
                    "\t" + color_func(asc) + ("\t <-- " + ", ".join(labels) if len(labels) else "")
                )
                asc = ""
                labels = []

            cursor += ptr_size

    print(out)

    if has_huge_chunk and pwndbg.gdblib.config.max_visualize_chunk_size == 0:
        print(
            message.warn(
                "You can try `set max-visualize-chunk-size 0x500` and re-run this command.\n"
            )
        )


def bin_ascii(bs):
    from string import printable

    valid_chars = list(map(ord, set(printable) - set("\t\r\n\x0c\x0b")))
    return "".join(chr(c) if c in valid_chars else "." for c in bs)


def bin_labels(addr, collections):
    labels = []
    for bins in collections:
        if not bins:
            continue
        bins_type = bins.bin_type

        for size in bins.bins.keys():
            b = bins.bins[size]
            if isinstance(size, int):
                size = hex(size)
            count = "/{:d}".format(b.count) if bins_type == BinType.TCACHE else None
            chunks = b.fd_chain
            for chunk_addr in chunks:
                if addr == chunk_addr:
                    labels.append(
                        "{:s}[{:s}][{:d}{}]".format(
                            bins_type, size, chunks.index(addr), count or ""
                        )
                    )

    return labels


try_free_parser = argparse.ArgumentParser(
    description="Check what would happen if free was called with given address"
)
try_free_parser.add_argument("addr", nargs="?", help="Address passed to free")


@pwndbg.commands.ArgparsedCommand(try_free_parser)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWhenHeapIsInitialized
def try_free(addr):
    addr = int(addr)

    # check hook
    free_hook = pwndbg.gdblib.symbol.address("__free_hook")
    if free_hook is not None:
        if pwndbg.gdblib.memory.pvoid(free_hook) != 0:
            print(message.success("__libc_free: will execute __free_hook"))

    # free(0) has no effect
    if addr == 0:
        print(message.success("__libc_free: addr is 0, nothing to do"))
        return

    # constants
    allocator = pwndbg.heap.current
    arena = allocator.thread_arena

    aligned_lsb = allocator.malloc_align_mask.bit_length()
    size_sz = allocator.size_sz
    malloc_alignment = allocator.malloc_alignment
    malloc_align_mask = allocator.malloc_align_mask
    chunk_minsize = allocator.minsize

    ptr_size = pwndbg.gdblib.arch.ptrsize

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
        print("-" * 10)
        if returned_before_error:
            print(message.success("Free should succeed!"))
        elif errors_found > 0:
            print(message.error("Errors found!"))
        else:
            print(message.success("All checks passed!"))

    # mem2chunk
    addr -= 2 * size_sz

    # try to get the chunk
    try:
        chunk = read_chunk(addr)
    except gdb.MemoryError as e:
        print(message.error("Can't read chunk at address 0x{:x}, memory error".format(addr)))
        return

    chunk_size = unsigned_size(chunk["size"])
    chunk_size_unmasked = chunksize(chunk_size)
    _, is_mmapped, _ = allocator.chunk_flags(chunk_size)

    if is_mmapped:
        print(message.notice("__libc_free: Doing munmap_chunk"))
        return

    errors_found = False
    returned_before_error = False

    # chunk doesn't overlap memory
    print(message.notice("General checks"))
    max_mem = (1 << (ptr_size * 8)) - 1
    if addr + chunk_size >= max_mem:
        err = "free(): invalid pointer -> &chunk + chunk->size > max memory\n"
        err += "    0x{:x} + 0x{:x} > 0x{:x}"
        err = err.format(addr, chunk_size, max_mem)
        print(message.error(err))
        errors_found += 1

    # chunk address is aligned
    addr_tmp = addr
    if malloc_alignment != 2 * size_sz:
        addr_tmp = addr + 2 * size_sz

    if addr_tmp & malloc_align_mask != 0:
        err = "free(): invalid pointer -> misaligned chunk\n"
        err += "    LSB of 0x{:x} are 0b{}, should be 0b{}"
        if addr_tmp != addr:
            err += " (0x{:x} was added to the address)".format(2 * size_sz)
        err = err.format(addr_tmp, bin(addr_tmp)[-aligned_lsb:], "0" * aligned_lsb)
        print(message.error(err))
        errors_found += 1

    # chunk's size is big enough
    if chunk_size_unmasked < chunk_minsize:
        err = "free(): invalid size -> chunk's size smaller than MINSIZE\n"
        err += "    size is 0x{:x}, MINSIZE is 0x{:x}"
        err = err.format(chunk_size_unmasked, chunk_minsize)
        print(message.error(err))
        errors_found += 1

    # chunk's size is aligned
    if chunk_size_unmasked & malloc_align_mask != 0:
        err = "free(): invalid size -> chunk's size is not aligned\n"
        err += "    LSB of size 0x{:x} are 0b{}, should be 0b{}"
        err = err.format(
            chunk_size_unmasked, bin(chunk_size_unmasked)[-aligned_lsb:], "0" * aligned_lsb
        )
        print(message.error(err))
        errors_found += 1

    # tcache
    if allocator.has_tcache() and "key" in allocator.tcache_entry.keys():
        tc_idx = (chunk_size_unmasked - chunk_minsize + malloc_alignment - 1) // malloc_alignment
        if tc_idx < allocator.mp["tcache_bins"]:
            print(message.notice("Tcache checks"))
            e = addr + 2 * size_sz
            e += allocator.tcache_entry.keys().index("key") * ptr_size
            e = pwndbg.gdblib.memory.pvoid(e)
            tcache_addr = int(allocator.thread_cache.address)
            if e == tcache_addr:
                # todo, actually do checks
                print(
                    message.error(
                        "Will do checks for tcache double-free (memory_tcache_double_free)"
                    )
                )
                errors_found += 1

            if int(allocator.get_tcache()["counts"][tc_idx]) < int(allocator.mp["tcache_count"]):
                print(message.success("Using tcache_put"))
                if errors_found == 0:
                    returned_before_error = True

    if errors_found > 0:
        finalize(errors_found, returned_before_error)
        return

    # is fastbin
    if chunk_size_unmasked <= allocator.global_max_fast:
        print(message.notice("Fastbin checks"))
        chunk_fastbin_idx = allocator.fastbin_index(chunk_size_unmasked)
        fastbin_list = (
            allocator.fastbins(arena.address)
            .bins[(chunk_fastbin_idx + 2) * (ptr_size * 2)]
            .fd_chain
        )

        try:
            next_chunk = read_chunk(addr + chunk_size_unmasked)
        except gdb.MemoryError as e:
            print(
                message.error(
                    "Can't read next chunk at address 0x{:x}, memory error".format(
                        chunk + chunk_size_unmasked
                    )
                )
            )
            finalize(errors_found, returned_before_error)
            return

        # next chunk's size is big enough and small enough
        next_chunk_size = unsigned_size(next_chunk["size"])
        if next_chunk_size <= 2 * size_sz or chunksize(next_chunk_size) >= arena.system_mem:
            err = "free(): invalid next size (fast) -> next chunk's size not in [2*size_sz; av->system_mem]\n"
            err += "    next chunk's size is 0x{:x}, 2*size_sz is 0x{:x}, system_mem is 0x{:x}"
            err = err.format(next_chunk_size, 2 * size_sz, arena.system_mem)
            print(message.error(err))
            errors_found += 1

        # chunk is not the same as the one on top of fastbin[idx]
        if int(fastbin_list[0]) == addr:
            err = "double free or corruption (fasttop) -> chunk already is on top of fastbin list\n"
            err += "    fastbin idx == {}"
            err = err.format(chunk_fastbin_idx)
            print(message.error(err))
            errors_found += 1

        # chunk's size is ~same as top chunk's size
        fastbin_top_chunk = int(fastbin_list[0])
        if fastbin_top_chunk != 0:
            try:
                fastbin_top_chunk = read_chunk(fastbin_top_chunk)
            except gdb.MemoryError as e:
                print(
                    message.error(
                        "Can't read top fastbin chunk at address 0x{:x}, memory error".format(
                            fastbin_top_chunk
                        )
                    )
                )
                finalize(errors_found, returned_before_error)
                return

            fastbin_top_chunk_size = chunksize(unsigned_size(fastbin_top_chunk["size"]))
            if chunk_fastbin_idx != allocator.fastbin_index(fastbin_top_chunk_size):
                err = "invalid fastbin entry (free) -> chunk's size is not near top chunk's size\n"
                err += "    chunk's size == {}, idx == {}\n"
                err += "    top chunk's size == {}, idx == {}"
                err += "    if `have_lock` is false then the error is invalid"
                err = err.format(
                    chunk["size"],
                    chunk_fastbin_idx,
                    fastbin_top_chunk_size,
                    allocator.fastbin_index(fastbin_top_chunk_size),
                )
                print(message.error(err))
                errors_found += 1

    # is not mapped
    elif is_mmapped == 0:
        print(message.notice("Not mapped checks"))

        # chunks is not top chunk
        if addr == arena.top:
            err = "double free or corruption (top) -> chunk is top chunk"
            print(message.error(err))
            errors_found += 1

        # next chunk is not beyond the boundaries of the arena
        NONCONTIGUOUS_BIT = 2
        top_chunk_addr = arena.top
        top_chunk = read_chunk(top_chunk_addr)
        next_chunk_addr = addr + chunk_size_unmasked

        # todo: in libc, addition may overflow
        if (arena.flags & NONCONTIGUOUS_BIT == 0) and next_chunk_addr >= top_chunk_addr + chunksize(
            top_chunk["size"]
        ):
            err = "double free or corruption (out) -> next chunk is beyond arena and arena is contiguous\n"
            err += "next chunk at 0x{:x}, end of arena at 0x{:x}"
            err = err.format(
                next_chunk_addr, top_chunk_addr + chunksize(unsigned_size(top_chunk["size"]))
            )
            print(message.error(err))
            errors_found += 1

        # now we need to dereference chunk
        try:
            next_chunk = read_chunk(next_chunk_addr)
            next_chunk_size = chunksize(unsigned_size(next_chunk["size"]))
        except (OverflowError, gdb.MemoryError) as e:
            print(message.error("Can't read next chunk at address 0x{:x}".format(next_chunk_addr)))
            finalize(errors_found, returned_before_error)
            return

        # next chunk's P bit is set
        prev_inuse, _, _ = allocator.chunk_flags(next_chunk["size"])
        if prev_inuse == 0:
            err = "double free or corruption (!prev) -> next chunk's previous-in-use bit is 0\n"
            print(message.error(err))
            errors_found += 1

        # next chunk's size is big enough and small enough
        if next_chunk_size <= 2 * size_sz or next_chunk_size >= arena.system_mem:
            err = "free(): invalid next size (normal) -> next chunk's size not in [2*size_sz; system_mem]\n"
            err += "next chunk's size is 0x{:x}, 2*size_sz is 0x{:x}, system_mem is 0x{:x}"
            err = err.format(next_chunk_size, 2 * size_sz, arena.system_mem)
            print(message.error(err))
            errors_found += 1

        # consolidate backward
        prev_inuse, _, _ = allocator.chunk_flags(chunk["size"])
        if prev_inuse == 0:
            print(message.notice("Backward consolidation"))
            prev_size = chunksize(unsigned_size(chunk["prev_size"]))
            prev_chunk_addr = addr - prev_size

            try:
                prev_chunk = read_chunk(prev_chunk_addr)
                prev_chunk_size = chunksize(unsigned_size(prev_chunk["size"]))
            except (OverflowError, gdb.MemoryError) as e:
                print(
                    message.error("Can't read next chunk at address 0x{:x}".format(prev_chunk_addr))
                )
                finalize(errors_found, returned_before_error)
                return

            if prev_chunk_size != prev_size:
                err = "corrupted size vs. prev_size while consolidating\n"
                err += "prev_size field is 0x{:x}, prev chunk at 0x{:x}, prev chunk size is 0x{:x}"
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
            print(message.notice("Next chunk is not top chunk"))
            try:
                next_next_chunk_addr = next_chunk_addr + next_chunk_size
                next_next_chunk = read_chunk(next_next_chunk_addr)
            except (OverflowError, gdb.MemoryError) as e:
                print(
                    message.error(
                        "Can't read next chunk at address 0x{:x}".format(next_next_chunk_addr)
                    )
                )
                finalize(errors_found, returned_before_error)
                return

            prev_inuse, _, _ = allocator.chunk_flags(next_next_chunk["size"])
            if prev_inuse == 0:
                print(message.notice("Forward consolidation"))
                try_unlink(next_chunk_addr)
                chunk_size += next_chunk_size
                chunk_size_unmasked += next_chunk_size
            else:
                print(message.notice("Clearing next chunk's P bit"))

            # unsorted bin fd->bk should be unsorted bean
            unsorted_addr = int(arena.bins[0])
            try:
                unsorted = read_chunk(unsorted_addr)
                try:
                    if read_chunk(unsorted["fd"])["bk"] != unsorted_addr:
                        err = "free(): corrupted unsorted chunks -> unsorted_chunk->fd->bk != unsorted_chunk\n"
                        err += (
                            "unsorted at 0x{:x}, unsorted->fd == 0x{:x}, unsorted->fd->bk == 0x{:x}"
                        )
                        err = err.format(
                            unsorted_addr, unsorted["fd"], read_chunk(unsorted["fd"])["bk"]
                        )
                        print(message.error(err))
                        errors_found += 1
                except (OverflowError, gdb.MemoryError) as e:
                    print(
                        message.error(
                            "Can't read chunk at 0x{:x}, it is unsorted bin fd".format(
                                unsorted["fd"]
                            )
                        )
                    )
                    errors_found += 1
            except (OverflowError, gdb.MemoryError) as e:
                print(
                    message.error("Can't read unsorted bin chunk at 0x{:x}".format(unsorted_addr))
                )
                errors_found += 1

        else:
            print(message.notice("Next chunk is top chunk"))
            chunk_size += next_chunk_size
            chunk_size_unmasked += next_chunk_size

        # todo: this may vary strongly
        FASTBIN_CONSOLIDATION_THRESHOLD = 65536
        if chunk_size_unmasked >= FASTBIN_CONSOLIDATION_THRESHOLD:
            print(message.notice("Doing malloc_consolidate and systrim/heap_trim"))

    # is mapped
    else:
        print(message.notice("Doing munmap_chunk"))

    finalize(errors_found, returned_before_error)


def try_unlink(addr):
    pass


parser = argparse.ArgumentParser(description="Shows heap related config. The list can be filtered.")
parser.add_argument(
    "filter_pattern",
    type=str,
    nargs="?",
    default=None,
    help="Filter to apply to config parameters names/descriptions",
)


@pwndbg.commands.ArgparsedCommand(parser)
def heap_config(filter_pattern):
    display_config(filter_pattern, "heap")

    print(
        message.hint(
            "Some config(e.g. main_arena) will only working when resolve-heap-via-heuristic is `True`"
        )
    )
