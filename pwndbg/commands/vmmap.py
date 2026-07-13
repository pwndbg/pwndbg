"""
Command to print the virtual memory map a la /proc/self/maps.
"""

from __future__ import annotations

import argparse
import os.path

from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile

import pwndbg.aglib
import pwndbg.aglib.elf
import pwndbg.aglib.file
import pwndbg.aglib.vmmap
import pwndbg.aglib.vmmap_custom
import pwndbg.color.memory as mem_color
import pwndbg.commands
import pwndbg.dbg_mod
import pwndbg.lib.cache
import pwndbg.lib.memory
from pwndbg.color import cyan
from pwndbg.color import green
from pwndbg.color import message
from pwndbg.color import red
from pwndbg.commands import CommandCategory
from pwndbg.lib.memory import Page

integer_types = (int, pwndbg.dbg_mod.Value)


def pages_filter(gdbval_or_str):
    # returns a module filter
    if isinstance(gdbval_or_str, str):
        module_name = gdbval_or_str
        return lambda page: module_name in page.objfile

    # returns an address filter
    if isinstance(gdbval_or_str, integer_types):
        addr = gdbval_or_str
        return lambda page: addr in page

    raise argparse.ArgumentTypeError("Unknown vmmap argument type.")


def print_vmmap_table_header(prefix: str = "") -> None:
    """
    Prints the table header for the vmmap command.
    """
    prefer_relpaths = "on" if pwndbg.config.vmmap_prefer_relpaths else "off"
    width = 2 + 2 * pwndbg.aglib.arch.ptrsize
    print(
        f"{prefix}{'Start':>{width}} {'End':>{width}} {'Perm'} {'Size':>8} {'Offset':>7} "
        f"{'File'} (set vmmap-prefer-relpaths {prefer_relpaths})"
    )


def print_vmmap_gaps_table_header() -> None:
    """
    Prints the table header for the vmmap --gaps command.
    """
    header = (
        f"{'Start':>{2 + 2 * pwndbg.aglib.arch.ptrsize}} "
        f"{'End':>{2 + 2 * pwndbg.aglib.arch.ptrsize}} "
        f"{'Perm':>4} "
        f"{'Size':>8} "
        f"{'Note':>9} "
        f"{'Accumulated Size':>{2 + 2 * pwndbg.aglib.arch.ptrsize}}"
    )
    print(header)


def calculate_total_memory(pages: tuple[Page, ...]) -> None:
    total = 0
    for page in pages:
        total += page.memsz
    if total > 1024 * 1024:
        print(f"Total memory mapped: {total:#x} ({total // 1024 // 1024} MB)")
    else:
        print(f"Total memory mapped: {total:#x} ({total // 1024} KB)")


def gap_text(page: Page) -> str:
    # Strip out offset and objfile from stringified page
    display_text = " ".join(str(page).split(" ")[:-2])
    return display_text.rstrip()


def print_map(page: Page) -> None:
    print(green(gap_text(page)))


def print_adjacent_map(map_start: Page, map_end: Page) -> None:
    print(
        green(
            f"{gap_text(map_end)} {'ADJACENT':>9} {hex(map_end.end - map_start.start):>{2 + 2 * pwndbg.aglib.arch.ptrsize}}"
        )
    )


def print_guard(page: Page) -> None:
    print(cyan(f"{gap_text(page)} {'GUARD':>9} "))


def print_gap(current: Page, last_map: Page):
    print(
        red(
            " - " * int(51 / 3)
            + f" {'GAP':>9} {hex(current.start - last_map.end):>{2 + 2 * pwndbg.aglib.arch.ptrsize}}"
        )
    )


def print_vmmap_gaps(pages: tuple[Page, ...]) -> None:
    """
    Indicates the size of adjacent memory regions and unmapped gaps between them in process memory
    """
    cache_status = pwndbg.aglib.vmmap.cache_status_text()
    cache_suffix = message.hint(f" [{cache_status}]") if cache_status is not None else ""
    print(f"LEGEND: {green('MAPPED')} | {cyan('GUARD')} | {red('GAP')}{cache_suffix}")
    print_vmmap_gaps_table_header()

    last_map = None  # The last mapped region we looked at
    last_start = None  # The last starting region of a series of mapped regions

    for page in pages:
        if last_map:
            # If there was a gap print it, and also print the last adjacent map set length
            if last_map.end != page.start:
                if last_start and last_start != last_map:
                    print_adjacent_map(last_start, last_map)
                print_gap(page, last_map)

            # If this is a guard page, print the last map and the guard page
            elif page.is_guard:
                if last_start and last_start != last_map:
                    print_adjacent_map(last_start, last_map)
                print_guard(page)
                last_start = None
                last_map = page
                continue

            # If we are tracking an adjacent set, don't print the current one yet
            elif last_start:
                if last_start != last_map:
                    print_map(last_map)
                last_map = page
                continue

        print_map(page)
        last_start = page
        last_map = page
    calculate_total_memory(pages)


parser = argparse.ArgumentParser(
    description="""Print virtual memory map pages.

Unnamed mappings are named as [anon_%#x] where %#x is high part of their start address. This is useful for filtering with `vmmap` or `search` commands.

Known issues with vmmap:
For QEMU user targets, the QEMU's gdbstub does not provide memory maps information to GDB until [0] is finished & merged. We try to deal with it without parsing the QEMU process' /proc/$pid/maps file, but if our approach fails, we simply create a [0, 0xffff...] vmmap which is not great and may result in lack of proper colors or inability to search memory with the `search` command.

For QEMU kernel, we use gdb-pt-dump that parses page tables from the guest by reading /proc/$pid/mem of QEMU process. If this does not work for you, use `set kernel-vmmap-via-page-tables off` to refer to our old method of reading vmmap info from `monitor info mem` command exposed by QEMU. Note that the latter may be slower and will not give full vmmaps permission information.

For coredump debugging, GDB also lacks all vmmap info but we do our best to get it back by using the `info proc mappings` and `maintenance info sections` commands.

As a last resort, we sometimes try to explore the addresses in CPU registers and if they are readable by GDB, we determine their bounds and create an "<explored>" vmmap. However, this method is slow and is not used on each GDB stop.

Memory pages can also be added manually with the use of vmmap-add, vmmap-clear and vmmap-load commands. This may be useful for bare metal debugging.

[0] https://lore.kernel.org/all/20220221030910.3203063-1-dominik.b.czarnota@gmail.com/""",
)
parser.add_argument(
    "gdbval_or_str",
    type=pwndbg.commands.sloppy_gdb_parse,
    nargs="?",
    default=None,
    help="Address or module name filter",
)
parser.add_argument("-w", "--writable", action="store_true", help="Display writable maps only")
parser.add_argument("-x", "--executable", action="store_true", help="Display executable maps only")
parser.add_argument(
    "-s",
    "--expand-shared-cache",
    action="store_true",
    help="Expand all entries in the DYLD Shared Cache (Darwin only)",
)
parser.add_argument(
    "-A", "--lines-after", type=int, help="Number of pages to display after result", default=1
)
parser.add_argument(
    "-B", "--lines-before", type=int, help="Number of pages to display before result", default=1
)
parser.add_argument(
    "-C", "--context", type=int, help="Number of pages to display around the result"
)
parser.add_argument(
    "--gaps",
    action="store_true",
    help="Display unmapped memory gap information in the memory map.",
)
parser.add_argument(
    "--refresh",
    action="store_true",
    help=(
        "Drop the cached memory map (used by default on macOS) and re-fetch it. "
        "See the `vmmap-cache` config option."
    ),
)


@pwndbg.commands.Command(
    parser, aliases=["lm", "address", "vprot", "libs"], category=CommandCategory.MEMORY
)
@pwndbg.commands.OnlyWhenRunning
def vmmap(
    gdbval_or_str=None,
    writable=False,
    executable=False,
    lines_after=1,
    lines_before=1,
    context=None,
    gaps=False,
    expand_shared_cache=False,
    refresh=False,
) -> None:
    lookaround_lines_limit = 64

    # Implement a sane limit
    if context is not None:
        lines_after = lines_before = min(lookaround_lines_limit, context)
    else:
        lines_after = min(lookaround_lines_limit, lines_after)
        lines_before = min(lookaround_lines_limit, lines_before)

    if refresh:
        pwndbg.aglib.vmmap.clear_persistent_cache()

    # All displayed pages, including lines after and lines before
    vmmap = pwndbg.aglib.vmmap.get_memory_map()
    if pwndbg.aglib.qemu.is_qemu_kernel():
        # called here so to not impact kernel_vmmap
        pwndbg.aglib.kernel.vmmap.annotate(vmmap)
    total_pages = vmmap.ranges()

    cache_status = pwndbg.aglib.vmmap.cache_status_text()
    cache_suffix = message.hint(f" [{cache_status}]") if cache_status is not None else ""

    # Filtered memory pages, indicated by a backtrace arrow in results
    filtered_pages = []

    # Only filter when -A and -B arguments are valid
    if gdbval_or_str and lines_after >= 0 and lines_before >= 0:
        # Always expand shared cache on detailed output.
        expand_shared_cache = True

        # Find matching page in memory
        filtered_pages = list(filter(pages_filter(gdbval_or_str), total_pages))
        pages_to_display = []

        for matched_page in filtered_pages:
            # Append matched page
            matched_index = total_pages.index(matched_page)

            # Include number of pages preceeding the matched page
            for before_index in range(lines_before + 1):
                # Guard index, and only insert the page if it is not displayed yet
                if (
                    matched_index - before_index >= 0
                    and total_pages[matched_index - before_index] not in pages_to_display
                ):
                    pages_to_display.append(total_pages[matched_index - before_index])

            # Include number of pages proceeding the matched page
            for after_index in range(1, lines_after + 1):
                if (
                    matched_index + after_index < len(total_pages) - 1
                    and total_pages[matched_index + after_index] not in pages_to_display
                ):
                    pages_to_display.append(total_pages[matched_index + after_index])

        # Sort results by address
        total_pages = sorted(pages_to_display, key=lambda page: page.vaddr)

    if not total_pages:
        print("There are no mappings for specified address or module.")
        return

    if gaps:
        print_vmmap_gaps(tuple(total_pages))
        return

    # Determine prefix width for alignment when showing filtered results
    prefix_str = str(pwndbg.config.backtrace_prefix)
    empty_prefix = " " * len(prefix_str) if filtered_pages else None
    header_prefix = f"{empty_prefix} " if filtered_pages else ""

    print(mem_color.legend() + cache_suffix)
    print_vmmap_table_header(header_prefix)

    shared_cache_first = None
    shared_cache_last = None
    shared_cache_collapsed = 0

    def flush_shared_cache_info():
        nonlocal shared_cache_first
        nonlocal shared_cache_last
        if shared_cache_first is not None and shared_cache_last is not None:
            print(
                pwndbg.lib.memory.format_address(
                    shared_cache_first.start,
                    shared_cache_last.end - shared_cache_first.start,
                    "---p",
                    shared_cache_first.offset,
                    pwndbg.aglib.arch.ptrsize,
                    "[DYLD Shared Cache]",
                )
            )

            shared_cache_first = None
            shared_cache_last = None

    for page in total_pages:
        if (executable and not page.execute) or (writable and not page.write):
            continue

        # Omit ranges from the shared cache if requested.
        if page is not None and page.in_darwin_shared_cache and not expand_shared_cache:
            if shared_cache_first is None:
                shared_cache_first = page
            shared_cache_last = page
            shared_cache_collapsed += 1
            continue
        flush_shared_cache_info()

        backtrace_prefix = empty_prefix
        display_text = str(page)

        if page in filtered_pages:
            # If page was one of the original results, add an arrow for clarity
            backtrace_prefix = prefix_str

            # If the page is the only filtered page, insert offset
            if len(filtered_pages) == 1 and isinstance(gdbval_or_str, integer_types):
                display_text = str(page) + " +0x%x" % (int(gdbval_or_str) - page.vaddr)

        print(mem_color.get(page.vaddr, text=display_text, prefix=backtrace_prefix, page=page))

    flush_shared_cache_info()
    if shared_cache_collapsed > 0:
        print(
            f"[Omitted {shared_cache_collapsed} {'entry' if shared_cache_collapsed == 1 else 'entries'} from the DYLD Shared Cache in total, use '-s' to expand]"
        )
        shared_cache_collapsed = 0

    if vmmap.is_qemu():
        print(
            "\n[QEMU <8.1 target detected - vmmap result might not be accurate; see `help vmmap`]"
        )


parser = argparse.ArgumentParser(description="Add virtual memory map page.")
parser.add_argument("start", type=int, help="Starting virtual address")
parser.add_argument("size", type=int, help="Size of the address space, in bytes")
parser.add_argument(
    "flags",
    nargs="?",
    type=str,
    default="",
    help="Flags set by the ELF file (r - read, w - write, x - executable)",
)
parser.add_argument(
    "offset",
    type=int,
    nargs="?",
    default=0,
    help="Offset into the original ELF file that the data is loaded from",
)


@pwndbg.commands.Command(parser, category=CommandCategory.MEMORY)
@pwndbg.commands.OnlyWhenRunning
def vmmap_add(start: int, size: int, flags: str, offset: int) -> None:
    page_flags = {
        "r": pwndbg.aglib.elf.PF_R,
        "w": pwndbg.aglib.elf.PF_W,
        "x": pwndbg.aglib.elf.PF_X,
    }
    perm = 0
    for flag in flags:
        flag_val = page_flags.get(flag)
        if flag_val is None:
            print('Invalid page flag "%s"', flag)
            return
        perm |= flag_val

    page = pwndbg.lib.memory.Page(start, size, perm, offset, pwndbg.aglib.arch.ptrsize)
    pwndbg.aglib.vmmap_custom.add_custom_page(page)

    print(f"{page!r} added")


parser = argparse.ArgumentParser(description="Explore a page, trying to guess permissions.")
parser.add_argument(
    "address", type=pwndbg.commands.sloppy_gdb_parse, help="Address of the page to explore"
)


@pwndbg.commands.Command(parser, category=CommandCategory.MEMORY)
@pwndbg.commands.OnlyWhenRunning
def vmmap_explore(address: int) -> None:
    if not isinstance(address, int):
        print("Address is not a valid integer.")
        return

    old_value = pwndbg.config.auto_explore_pages.value
    pwndbg.config.auto_explore_pages.value = "yes"
    try:
        pwndbg.lib.cache.clear_function_cache(pwndbg.aglib.vmmap.find)
        page = pwndbg.aglib.vmmap.find(address)
    finally:
        pwndbg.config.auto_explore_pages.value = old_value

    if page is None:
        print("Exploration failed. Maybe the address isn't readable?")
        return

    print_vmmap_table_header()
    print(page)


@pwndbg.commands.Command(
    "Clear custom vmmap entries added by vmmap_add and vmmap_explore and reset caches.",
    category=CommandCategory.MEMORY,
)
@pwndbg.commands.OnlyWhenRunning
def vmmap_clear() -> None:
    pwndbg.aglib.vmmap_custom.clear_custom_page()


parser = argparse.ArgumentParser(description="Load virtual memory map pages from ELF file.")
parser.add_argument(
    "filename",
    nargs="?",
    type=str,
    help="ELF filename, by default uses current loaded filename.",
)


@pwndbg.commands.Command(parser, category=CommandCategory.MISC)
@pwndbg.commands.OnlyWhenRunning
def vmmap_load(filename) -> None:
    if filename is None:
        filename = pwndbg.aglib.file.get_proc_exe_file()

    print(f'Load "{filename}" ...')
    file_basename = os.path.basename(filename)

    # TODO: Add an argument to let use to choose loading the page information from sections or segments

    # Use section information to recover the segment information.
    # The entry point of bare metal environment is often at the first segment.
    # For example, assume the entry point is at 0x8000.
    # In most of case, link will create a segment and starts from 0x0.
    # This cause all values less than 0x8000 be considered as a valid pointer.
    pages = []
    with open(filename, "rb") as f:
        elffile = ELFFile(f)

        ptrsize: int = pwndbg.aglib.arch.ptrsize
        for section in elffile.iter_sections():
            vaddr = section["sh_addr"]
            memsz = section["sh_size"]
            sh_flags = section["sh_flags"]
            offset = section["sh_offset"]

            # Don't add the sections that aren't mapped into memory
            if not sh_flags & SH_FLAGS.SHF_ALLOC:
                continue

            # Guess the segment flags from section flags
            flags = pwndbg.aglib.elf.PF_R
            if sh_flags & SH_FLAGS.SHF_WRITE:
                flags |= pwndbg.aglib.elf.PF_W
            if sh_flags & SH_FLAGS.SHF_EXECINSTR:
                flags |= pwndbg.aglib.elf.PF_X

            page = pwndbg.lib.memory.Page(
                vaddr, memsz, flags, offset, ptrsize, f"[{section.name}]: {file_basename}"
            )
            pages.append(page)

    for page in pages:
        pwndbg.aglib.vmmap_custom.add_custom_page(page)
        print(f"{page!r} added")
