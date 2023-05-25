import argparse
import ctypes
from string import printable
from typing import Dict
from typing import List

import gdb
from tabulate import tabulate

import pwndbg.color.context as C
import pwndbg.color.memory as M
import pwndbg.commands
import pwndbg.gdblib.config
import pwndbg.gdblib.typeinfo
import pwndbg.glibc
import pwndbg.lib.heap.helpers
from pwndbg.color import generateColorFunction
from pwndbg.color import message
from pwndbg.commands import CommandCategory
from pwndbg.commands.config import display_config
from pwndbg.heap.ptmalloc import Arena
from pwndbg.heap.ptmalloc import Bins
from pwndbg.heap.ptmalloc import BinType
from pwndbg.heap.ptmalloc import Chunk
from pwndbg.heap.ptmalloc import DebugSymsHeap
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
    if isinstance(pwndbg.heap.current, DebugSymsHeap):
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
            if bins_type == BinType.LARGE:
                start_size, end_size = allocator.largebin_size_range_from_index(size)
                size = hex(start_size) + "-"
                if end_size != pwndbg.gdblib.arch.ptrmask:
                    size += hex(end_size)
                else:
                    size += "\u221e"  # Unicode "infinity"
            else:
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


def print_no_arena_found_error(tid=None) -> None:
    if tid is None:
        tid = pwndbg.gdblib.proc.thread_id
    print(
        message.notice(
            f"No arena found for thread {message.hint(tid)} (the thread hasn't performed any allocations)."
        )
    )


def print_no_tcache_bins_found_error(tid=None) -> None:
    if tid is None:
        tid = pwndbg.gdblib.proc.thread_id
    print(
        message.notice(
            f"No tcache bins found for thread {message.hint(tid)} (the thread hasn't performed any allocations)."
        )
    )


parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="""Iteratively print chunks on a heap.

Default to the current thread's active heap.""",
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


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.HEAP)
@pwndbg.commands.OnlyWithResolvedHeapSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
@pwndbg.commands.OnlyWhenUserspace
def heap(addr=None, verbose=False, simple=False) -> None:
    """Iteratively print chunks on a heap, default to the current thread's
    active heap.
    """
    allocator = pwndbg.heap.current

    if addr is not None:
        chunk = Chunk(addr)
        while chunk is not None:
            malloc_chunk(chunk.address, verbose=verbose, simple=simple)
            chunk = chunk.next_chunk()
    else:
        arena = allocator.thread_arena
        # arena might be None if the current thread doesn't allocate the arena
        if arena is None:
            print_no_arena_found_error()
            return
        h = arena.active_heap

        for chunk in h:
            malloc_chunk(chunk.address, verbose=verbose, simple=simple)


parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="""Print the contents of an arena.

Default to the current thread's arena.""",
)
parser.add_argument("addr", nargs="?", type=int, default=None, help="Address of the arena.")


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.HEAP)
@pwndbg.commands.OnlyWithResolvedHeapSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
@pwndbg.commands.OnlyWhenUserspace
def arena(addr=None) -> None:
    """Print the contents of an arena, default to the current thread's arena."""
    allocator = pwndbg.heap.current

    if addr is not None:
        arena = Arena(addr)
    else:
        arena = allocator.thread_arena
        tid = pwndbg.gdblib.proc.thread_id
        # arena might be None if the current thread doesn't allocate the arena
        if arena is None:
            print_no_arena_found_error(tid)
            return
        print(
            message.notice(
                f"Arena for thread {message.hint(tid)} is located at: {message.hint(hex(arena.address))}"
            )
        )

    print(arena._gdbValue)  # Breaks encapsulation, find a better way.


parser = argparse.ArgumentParser(description="List this process's arenas.")


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.HEAP)
@pwndbg.commands.OnlyWithResolvedHeapSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
@pwndbg.commands.OnlyWhenUserspace
def arenas() -> None:
    """Lists this process's arenas."""
    allocator = pwndbg.heap.current
    arenas = allocator.arenas

    table = []
    headers = [
        "arena type",
        "arena address",
        "heap address",
        "map start",
        "map end",
        "perm",
        "size",
        "offset",
        "file",
    ]

    for arena in arenas:
        arena_type, text_color = (
            ("main_arena", message.success)
            if arena.is_main_arena
            else ("non-main arena", message.hint)
        )
        first_heap = arena.heaps[0]

        row = [
            text_color(arena_type),
            text_color(hex(arena.address)),
            text_color(hex(first_heap.start)),
        ]

        for mapping_data in str(pwndbg.gdblib.vmmap.find(first_heap.start)).split():
            row.append(M.c.heap(mapping_data))

        table.append(row)

        for extra_heap in arena.heaps[1:]:
            row = [
                "",
                text_color("\u21b3"),  # Unicode "downwards arrow with tip rightwards"
                text_color(hex(extra_heap.start)),
            ]

            for mapping_data in str(pwndbg.gdblib.vmmap.find(extra_heap.start)).split():
                row.append(M.c.heap(mapping_data))

            table.append(row)

    print(tabulate(table, headers, stralign="right"))


parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="""Print a thread's tcache contents.

Default to the current thread's tcache.""",
)
parser.add_argument("addr", nargs="?", type=int, default=None, help="Address of the tcache.")


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.HEAP)
@pwndbg.commands.OnlyWithResolvedHeapSyms
@pwndbg.commands.OnlyWithTcache
@pwndbg.commands.OnlyWhenUserspace
def tcache(addr=None) -> None:
    """Print a thread's tcache contents, default to the current thread's
    tcache.
    """
    allocator = pwndbg.heap.current
    tcache = allocator.get_tcache(addr)
    # if the current thread doesn't allocate the arena, tcache will be NULL
    tid = pwndbg.gdblib.proc.thread_id
    if tcache:
        print(
            message.notice(
                f"tcache is pointing to: {message.hint(hex(tcache.address))} for thread {message.hint(tid)}"
            )
        )
    else:
        print_no_tcache_bins_found_error(tid)
    if tcache:
        print(tcache)


parser = argparse.ArgumentParser(description="Print the mp_ struct's contents.")


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.HEAP)
@pwndbg.commands.OnlyWithResolvedHeapSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
@pwndbg.commands.OnlyWhenUserspace
def mp() -> None:
    """Print the mp_ struct's contents."""
    allocator = pwndbg.heap.current
    print(message.notice("mp_ struct at: ") + message.hint(hex(allocator.mp.address)))
    print(allocator.mp)


parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="""Print relevant information about an arena's top chunk.

Default to current thread's arena.""",
)
parser.add_argument("addr", nargs="?", type=int, default=None, help="Address of the arena.")


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.HEAP)
@pwndbg.commands.OnlyWithResolvedHeapSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
@pwndbg.commands.OnlyWhenUserspace
def top_chunk(addr=None) -> None:
    """Print relevant information about an arena's top chunk, default to the
    current thread's arena.
    """
    allocator = pwndbg.heap.current

    if addr is not None:
        arena = Arena(addr)
    else:
        arena = allocator.thread_arena
        # arena might be None if the current thread doesn't allocate the arena
        if arena is None:
            print_no_arena_found_error()
            return

    malloc_chunk(arena.top)


parser = argparse.ArgumentParser(description="Print a chunk.")
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


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.HEAP)
@pwndbg.commands.OnlyWithResolvedHeapSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
@pwndbg.commands.OnlyWhenUserspace
def malloc_chunk(addr, fake=False, verbose=False, simple=False) -> None:
    """Print a malloc_chunk struct's contents."""
    allocator = pwndbg.heap.current

    chunk = Chunk(addr)

    headers_to_print = []  # both state (free/allocated) and flags
    fields_to_print = set()  # in addition to addr and size
    out_fields = f"Addr: {M.get(chunk.address)}\n"

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
                allocator.fastbins(arena.address),
                allocator.smallbins(arena.address),
                allocator.largebins(arena.address),
                allocator.unsortedbin(arena.address),
            ]
            if allocator.has_tcache():
                bins_list.append(allocator.tcachebins(None))

            bins_list = [x for x in bins_list if x is not None]
            no_match = True
            for bins in bins_list:
                if bins.contains_chunk(chunk.real_size, chunk.address):
                    no_match = False
                    headers_to_print.append(message.on(f"Free chunk ({bins.bin_type})"))
                    if not verbose:
                        fields_to_print.update(bins.bin_type.valid_fields())
            if no_match:
                headers_to_print.append(message.hint("Allocated chunk"))

    if verbose:
        fields_to_print.update(["prev_size", "size", "fd", "bk", "fd_nextsize", "bk_nextsize"])
    else:
        out_fields += f"Size: 0x{chunk.size:02x}\n"

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
            out_fields += (
                message.system(field_to_print) + f": 0x{getattr(chunk, field_to_print):02x}\n"
            )

    print(" | ".join(headers_to_print) + "\n" + out_fields)


parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="""Print the contents of all an arena's bins and a thread's tcache.

Default to the current thread's arena and tcache.""",
)
parser.add_argument("addr", nargs="?", type=int, default=None, help="Address of the arena.")
parser.add_argument("tcache_addr", nargs="?", type=int, default=None, help="Address of the tcache.")


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.HEAP)
@pwndbg.commands.OnlyWithResolvedHeapSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
@pwndbg.commands.OnlyWhenUserspace
def bins(addr=None, tcache_addr=None) -> None:
    """Print the contents of all an arena's bins and a thread's tcache,
    default to the current thread's arena and tcache.
    """
    if pwndbg.heap.current.has_tcache():
        if tcache_addr is None and pwndbg.heap.current.thread_cache is None:
            print_no_tcache_bins_found_error()
        else:
            tcachebins(tcache_addr)
    if addr is None and pwndbg.heap.current.thread_arena is None:
        print_no_arena_found_error()
        return
    fastbins(addr)
    unsortedbin(addr)
    smallbins(addr)
    largebins(addr)


parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="""Print the contents of an arena's fastbins.

Default to the current thread's arena.""",
)
parser.add_argument("addr", nargs="?", type=int, help="Address of the arena.")
parser.add_argument(
    "-v", "--verbose", action="store_true", help="Show all fastbins, including empty ones"
)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.HEAP)
@pwndbg.commands.OnlyWithResolvedHeapSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
@pwndbg.commands.OnlyWhenUserspace
def fastbins(addr=None, verbose=False) -> None:
    """Print the contents of an arena's fastbins, default to the current
    thread's arena.
    """
    allocator = pwndbg.heap.current
    fastbins = allocator.fastbins(addr)

    if fastbins is None:
        print_no_arena_found_error()
        return

    formatted_bins = format_bin(fastbins, verbose)

    print(C.banner("fastbins"))
    for node in formatted_bins:
        print(node)


parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="""Print the contents of an arena's unsortedbin.

Default to the current thread's arena.""",
)
parser.add_argument("addr", nargs="?", type=int, help="Address of the arena.")
parser.add_argument(
    "-v", "--verbose", action="store_true", help='Show the "all" bin even if it\'s empty'
)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.HEAP)
@pwndbg.commands.OnlyWithResolvedHeapSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
@pwndbg.commands.OnlyWhenUserspace
def unsortedbin(addr=None, verbose=False) -> None:
    """Print the contents of an arena's unsortedbin, default to the current
    thread's arena.
    """
    allocator = pwndbg.heap.current
    unsortedbin = allocator.unsortedbin(addr)

    if unsortedbin is None:
        print_no_arena_found_error()
        return

    formatted_bins = format_bin(unsortedbin, verbose)

    print(C.banner("unsortedbin"))
    for node in formatted_bins:
        print(node)


parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="""Print the contents of an arena's smallbins.

Default to the current thread's arena.""",
)
parser.add_argument("addr", nargs="?", type=int, help="Address of the arena.")
parser.add_argument(
    "-v", "--verbose", action="store_true", help="Show all smallbins, including empty ones"
)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.HEAP)
@pwndbg.commands.OnlyWithResolvedHeapSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
@pwndbg.commands.OnlyWhenUserspace
def smallbins(addr=None, verbose=False) -> None:
    """Print the contents of an arena's smallbins, default to the current
    thread's arena.
    """
    allocator = pwndbg.heap.current
    smallbins = allocator.smallbins(addr)

    if smallbins is None:
        print_no_arena_found_error()
        return

    formatted_bins = format_bin(smallbins, verbose)

    print(C.banner("smallbins"))
    for node in formatted_bins:
        print(node)


parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="""Print the contents of an arena's largebins.

Default to the current thread's arena.""",
)
parser.add_argument("addr", nargs="?", type=int, help="Address of the arena.")
parser.add_argument(
    "-v", "--verbose", action="store_true", help="Show all largebins, including empty ones"
)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.HEAP)
@pwndbg.commands.OnlyWithResolvedHeapSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
@pwndbg.commands.OnlyWhenUserspace
def largebins(addr=None, verbose=False) -> None:
    """Print the contents of an arena's largebins, default to the current
    thread's arena.
    """
    allocator = pwndbg.heap.current
    largebins = allocator.largebins(addr)

    if largebins is None:
        print_no_arena_found_error()
        return

    formatted_bins = format_bin(largebins, verbose)

    print(C.banner("largebins"))
    for node in formatted_bins:
        print(node)


parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="""Print the contents of a tcache.

Default to the current thread's tcache.""",
)
parser.add_argument("addr", nargs="?", type=int, help="The address of the tcache bins.")
parser.add_argument(
    "-v", "--verbose", action="store_true", help="Show all tcachebins, including empty ones"
)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.HEAP)
@pwndbg.commands.OnlyWithResolvedHeapSyms
@pwndbg.commands.OnlyWithTcache
@pwndbg.commands.OnlyWhenUserspace
def tcachebins(addr=None, verbose=False) -> None:
    """Print the contents of a tcache, default to the current thread's tcache."""
    allocator = pwndbg.heap.current
    tcachebins = allocator.tcachebins(addr)

    if tcachebins is None:
        print_no_tcache_bins_found_error()
        return

    formatted_bins = format_bin(tcachebins, verbose, offset=allocator.tcache_next_offset)

    print(C.banner("tcachebins"))
    for node in formatted_bins:
        print(node)


parser = argparse.ArgumentParser(
    description="Find candidate fake fast or tcache chunks overlapping the specified address."
)
parser.add_argument("target_address", type=int, help="Address of the word-sized value to overlap.")
parser.add_argument(
    "max_candidate_size",
    nargs="?",
    type=int,
    default=None,
    help="Maximum size of fake chunks to find.",
)
parser.add_argument(
    "--align",
    "-a",
    action="store_true",
    default=False,
    help="Whether the fake chunk must be aligned to MALLOC_ALIGNMENT. This is required for tcache "
    + "chunks and for all chunks when Safe Linking is enabled",
)
parser.add_argument(
    "--glibc-fastbin-bug",
    "-b",
    action="store_true",
    default=False,
    help="Does the GLIBC fastbin size field bug affect the candidate size field width?",
)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.HEAP)
@pwndbg.commands.OnlyWithResolvedHeapSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
@pwndbg.commands.OnlyWhenUserspace
def find_fake_fast(
    target_address, max_candidate_size=None, align=False, glibc_fastbin_bug=False
) -> None:
    """Find candidate fake fast chunks overlapping the specified address."""
    allocator = pwndbg.heap.current

    size_sz = allocator.size_sz
    min_chunk_size = allocator.min_chunk_size
    global_max_fast = allocator.global_max_fast
    size_field_width = gdb.lookup_type("unsigned int").sizeof if glibc_fastbin_bug else size_sz

    if max_candidate_size is None:
        max_candidate_size = global_max_fast
    else:
        max_candidate_size = int(max_candidate_size)
        if max_candidate_size > global_max_fast:
            print(
                message.warn(
                    f"Maximum candidate size {max_candidate_size:#04x} is greater than the global_max_fast value of {global_max_fast:#04x}"
                )
            )

    target_address = int(target_address)
    if max_candidate_size > target_address:
        print(
            message.warn(
                f"Maximum candidate size {max_candidate_size:#04x} is greater than the target address {target_address:#x}"
            )
        )
        print(message.warn(f"Using maximum candidate size of {target_address:#x}"))
        max_candidate_size = target_address
    elif max_candidate_size < min_chunk_size:
        print(
            message.warn(
                f"Maximum candidate size {max_candidate_size:#04x} is smaller than the minimum chunk size of {min_chunk_size:#04x}"
            )
        )
        print(message.warn(f"Using maximum candidate size of {min_chunk_size:#04x}"))
        max_candidate_size = min_chunk_size

    max_candidate_size &= ~(allocator.malloc_align_mask)

    search_start = target_address - max_candidate_size + size_sz
    search_end = target_address

    if pwndbg.gdblib.memory.peek(search_start) is None:
        search_start = pwndbg.lib.memory.page_size_align(search_start)
        if (
            search_start > (search_end - size_field_width)
            or pwndbg.gdblib.memory.peek(search_start) is None
        ):
            print(
                message.warn(
                    "No fake fast chunk candidates found; memory preceding target address is not readable"
                )
            )
            return None

    if align:
        search_start = pwndbg.lib.memory.align_up(search_start, size_sz)
        search_start |= size_sz

        if search_start > (search_end - size_field_width):
            print(
                message.warn(
                    "No fake fast chunk candidates found; alignment didn't leave enough space for a size field"
                )
            )
            return None

    print(
        message.notice(
            f"Searching for fastbin size fields up to {max_candidate_size:#04x}, starting at {search_start:#x} resulting in an overlap of {target_address:#x}"
        )
    )

    search_region = pwndbg.gdblib.memory.read(search_start, search_end - search_start, partial=True)

    print(C.banner("FAKE CHUNKS"))
    step = allocator.malloc_alignment if align else 1
    for i in range(0, len(search_region), step):
        candidate = search_region[i : i + size_field_width]

        if len(candidate) == size_field_width:
            size_field = pwndbg.gdblib.arch.unpack(candidate)
            size_field &= ~(allocator.malloc_align_mask)

            if size_field < min_chunk_size or size_field > max_candidate_size:
                continue

            candidate_address = search_start + i
            if (candidate_address + size_field) >= (target_address + size_sz):
                malloc_chunk(candidate_address - size_sz, fake=True)
        else:
            break


pwndbg.gdblib.config.add_param(
    "max-visualize-chunk-size",
    0,
    "max display size for heap chunks visualization (0 for display all)",
)

pwndbg.gdblib.config.add_param(
    "default-visualize-chunk-number",
    10,
    "default number of chunks to visualize (default is 10)",
)

parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="""Visualize chunks on a heap.

Default to the current arena's active heap.""",
)
group = parser.add_mutually_exclusive_group()
group.add_argument(
    "count",
    nargs="?",
    type=lambda n: max(int(n, 0), 1),
    default=pwndbg.gdblib.config.default_visualize_chunk_number,
    help="Number of chunks to visualize.",
)
parser.add_argument("addr", nargs="?", default=None, help="Address of the first chunk.")
parser.add_argument(
    "--beyond_top",
    "-b",
    action="store_true",
    default=False,
    help="Attempt to keep printing beyond the top chunk.",
)
parser.add_argument(
    "--no_truncate",
    "-n",
    action="store_true",
    default=False,
    help="Display all the chunk contents (Ignore the `max-visualize-chunk-size` configuration).",
)
group.add_argument(
    "--all_chunks",
    "-a",
    action="store_true",
    default=False,
    help=" Display all chunks (Ignore the default-visualize-chunk-number configuration).",
)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.HEAP)
@pwndbg.commands.OnlyWithResolvedHeapSyms
@pwndbg.commands.OnlyWhenHeapIsInitialized
@pwndbg.commands.OnlyWhenUserspace
def vis_heap_chunks(
    addr=None, count=None, beyond_top=None, no_truncate=None, all_chunks=None
) -> None:
    """Visualize chunks on a heap, default to the current arena's active heap."""
    allocator = pwndbg.heap.current

    if addr is not None:
        cursor = int(addr)
        heap_region = Heap(cursor)
        arena = heap_region.arena
    else:
        arena = allocator.thread_arena
        # arena might be None if the current thread doesn't allocate the arena
        if arena is None:
            print_no_arena_found_error()
            return
        heap_region = arena.active_heap
        cursor = heap_region.start

    ptr_size = allocator.size_sz

    # Build a list of addresses that delimit each chunk.
    chunk_delims = []
    cursor_backup = cursor
    chunk = Chunk(cursor)

    chunk_id = 0
    while True:
        if not all_chunks and chunk_id == count + 1:
            break

        # Don't read beyond the heap mapping if --beyond_top or corrupted heap.
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

        if (chunk.is_top_chunk and not beyond_top) or (cursor == heap_region.end - ptr_size * 2):
            chunk_delims.append(cursor + ptr_size * 2)
            break

        cursor += chunk.real_size
        chunk = Chunk(cursor)
        chunk_id += 1

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

    bin_labels_map: Dict[int, List[str]] = bin_labels_mapping(bin_collections)

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
                not no_truncate
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

            data = pwndbg.gdblib.memory.read(cursor, ptr_size)
            cell = pwndbg.gdblib.arch.unpack(data)
            cell_hex = f"\t0x{cell:0{ptr_size * 2}x}"

            out += color_func(cell_hex)
            printed += 1

            labels.extend(bin_labels_map.get(cursor, []))
            if cursor == arena.top:
                labels.append("Top chunk")

            asc += bin_ascii(data)
            if printed % 2 == 0:
                out += "\t" + color_func(asc) + ("\t <-- " + ", ".join(labels) if labels else "")
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


VALID_CHARS = list(map(ord, set(printable) - set("\t\r\n\x0c\x0b")))


def bin_ascii(bs):
    return "".join(chr(c) if c in VALID_CHARS else "." for c in bs)


def bin_labels_mapping(collections):
    """
    Returns all potential bin labels for all potential addresses
    We precompute all of them because doing this on demand was too slow and inefficient
    See #1675 for more details
    """
    labels_mapping: Dict[int, List[str]] = {}

    for bins in collections:
        if not bins:
            continue
        bins_type = bins.bin_type

        for size in bins.bins.keys():
            b = bins.bins[size]
            if isinstance(size, int):
                size = hex(size)
            count = f"/{b.count:d}" if bins_type == BinType.TCACHE else None
            chunks = b.fd_chain
            for chunk_addr in chunks:
                labels_mapping.setdefault(chunk_addr, []).append(
                    f"{bins_type:s}[{size:s}][{chunks.index(chunk_addr):d}{count or ''}]"
                )

    return labels_mapping


try_free_parser = argparse.ArgumentParser(
    description="Check what would happen if free was called with given address."
)
try_free_parser.add_argument("addr", nargs="?", help="Address passed to free")


@pwndbg.commands.ArgparsedCommand(try_free_parser, category=CommandCategory.HEAP)
@pwndbg.commands.OnlyWhenHeapIsInitialized
@pwndbg.commands.OnlyWhenUserspace
def try_free(addr) -> None:
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
    # arena might be None if the current thread doesn't allocate the arena
    if arena is None:
        print_no_arena_found_error()
        return

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

    def finalize(errors_found, returned_before_error) -> None:
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
        print(message.error(f"Can't read chunk at address 0x{addr:x}, memory error"))
        return

    chunk_size = unsigned_size(chunk["size"])
    chunk_size_unmasked = chunksize(chunk_size)
    _, is_mmapped, _ = allocator.chunk_flags(chunk_size)

    if is_mmapped:
        print(message.notice("__libc_free: Doing munmap_chunk"))
        return

    errors_found = 0
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
            err += f" (0x{2 * size_sz:x} was added to the address)"
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
            e = addr + 2 * size_sz  # type: ignore[misc]
            e += allocator.tcache_entry.keys().index("key") * ptr_size  # type: ignore[misc]
            e = pwndbg.gdblib.memory.pvoid(e)  # type: ignore[misc]
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
                    f"Can't read next chunk at address 0x{chunk + chunk_size_unmasked:x}, memory error"
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
                        f"Can't read top fastbin chunk at address 0x{fastbin_top_chunk:x}, memory error"
                    )
                )
                finalize(errors_found, returned_before_error)
                return

            fastbin_top_chunk_size = chunksize(unsigned_size(fastbin_top_chunk["size"]))  # type: ignore[index]
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
            print(message.error(f"Can't read next chunk at address 0x{next_chunk_addr:x}"))
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
                print(message.error(f"Can't read next chunk at address 0x{prev_chunk_addr:x}"))
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
                print(message.error(f"Can't read next chunk at address 0x{next_next_chunk_addr:x}"))
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
                            f"Can't read chunk at 0x{unsorted['fd']:x}, it is unsorted bin fd"
                        )
                    )
                    errors_found += 1
            except (OverflowError, gdb.MemoryError) as e:
                print(message.error(f"Can't read unsorted bin chunk at 0x{unsorted_addr:x}"))
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


def try_unlink(addr) -> None:
    pass


parser = argparse.ArgumentParser(description="Shows heap related configuration.")
parser.add_argument(
    "filter_pattern",
    type=str,
    nargs="?",
    default=None,
    help="Filter to apply to config parameters names/descriptions",
)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.HEAP)
def heap_config(filter_pattern) -> None:
    display_config(filter_pattern, "heap", has_file_command=False)

    print(
        message.hint(
            "Some config values (e.g. main_arena) will be used only when resolve-heap-via-heuristic is `auto` or `force`"
        )
    )
