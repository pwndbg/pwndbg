"""
Command to print the virtual memory map a la /proc/self/maps.
"""

from __future__ import annotations

import argparse
from typing import Tuple

import gdb
from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile

import pwndbg.color.memory as M
import pwndbg.commands
import pwndbg.gdblib.elf
import pwndbg.gdblib.vmmap
from pwndbg.color import cyan
from pwndbg.color import green
from pwndbg.color import red
from pwndbg.commands import CommandCategory
from pwndbg.gdblib import gdb_version
from pwndbg.lib.memory import Page

integer_types = (int, gdb.Value)


def pages_filter(gdbval_or_str):
    # returns a module filter
    if isinstance(gdbval_or_str, str):
        module_name = gdbval_or_str
        return lambda page: module_name in page.objfile

    # returns an address filter
    elif isinstance(gdbval_or_str, integer_types):
        addr = gdbval_or_str
        return lambda page: addr in page

    else:
        raise argparse.ArgumentTypeError("Unknown vmmap argument type.")


def print_vmmap_table_header() -> None:
    """
    Prints the table header for the vmmap command.
    """
    print(
        f"{'Start':>{2 + 2 * pwndbg.gdblib.arch.ptrsize}} {'End':>{2 + 2 * pwndbg.gdblib.arch.ptrsize}} {'Perm'} {'Size':>8} {'Offset':>6} {'File'}"
    )


def print_vmmap_gaps_table_header() -> None:
    """
    Prints the table header for the vmmap --gaps command.
    """
    header = (
        f"{'Start':>{2 + 2 * pwndbg.gdblib.arch.ptrsize}} "
        f"{'End':>{2 + 2 * pwndbg.gdblib.arch.ptrsize}} "
        f"{'Perm':>4} "
        f"{'Size':>8} "
        f"{'Note':>9} "
        f"{'Accumulated Size':>{2 + 2 * pwndbg.gdblib.arch.ptrsize}}"
    )
    print(header)


def calculate_total_memory(pages: Tuple[Page, ...]) -> None:
    total = 0
    for page in pages:
        total += page.memsz
    if total > 1024 * 1024:
        print(f"Total memory mapped: {total:#x} ({total//1024//1024} MB)")
    else:
        print(f"Total memory mapped: {total:#x} ({total//1024} KB)")


def gap_text(page: Page) -> str:
    # Strip out offset and objfile from stringified page
    display_text = " ".join(str(page).split(" ")[:-2])
    return display_text.rstrip()


def print_map(page: Page) -> None:
    print(green(gap_text(page)))


def print_adjacent_map(map_start: Page, map_end: Page) -> None:
    print(
        green(
            f"{gap_text(map_end)} {'ADJACENT':>9} {hex(map_end.end - map_start.start):>{2 + 2 * pwndbg.gdblib.arch.ptrsize}}"
        )
    )


def print_guard(page: Page) -> None:
    print(cyan(f"{gap_text(page)} {'GUARD':>9} "))


def print_gap(current: Page, last_map: Page):
    print(
        red(
            " - " * int(51 / 3)
            + f" {'GAP':>9} {hex(current.start - last_map.end):>{2 + 2 * pwndbg.gdblib.arch.ptrsize}}"
        )
    )


def print_vmmap_gaps(pages: Tuple[Page, ...]) -> None:
    """
    Indicates the size of adjacent memory regions and unmapped gaps between them in process memory
    """
    print(f"LEGEND: {green('MAPPED')} | {cyan('GUARD')} | {red('GAP')}")
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
    formatter_class=argparse.RawTextHelpFormatter,
    description="""Print virtual memory map pages.

Unnamed mappings are named as [anon_%#x] where %#x is high part of their start address. This is useful for filtering with `vmmap` or `search` commands.

Known issues with vmmap:
For QEMU user targets, the QEMU's gdbstub does not provide memory maps information to GDB until [0] is finished & merged. We try to deal with it without parsing the QEMU process' /proc/$pid/maps file, but if our approach fails, we simply create a [0, 0xffff...] vmmap which is not great and may result in lack of proper colors or inability to search memory with the `search` command.

For QEMU kernel, we use gdb-pt-dump that parses page tables from the guest by reading /proc/$pid/mem of QEMU process. If this does not work for you, use `set kernel-vmmap-via-page-tables off` to refer to our old method of reading vmmap info from `monitor info mem` command exposed by QEMU. Note that the latter may be slower and will not give full vmmaps permission information.

For coredump debugging, GDB also lacks all vmmap info but we do our best to get it back by using the `info proc mappings` and `maintenance info sections` commands.

As a last resort, we sometimes try to explore the addresses in CPU registers and if they are readable by GDB, we determine their bounds and create an "<explored>" vmmap. However, this method is slow and is not used on each GDB stop.

Memory pages can also be added manually with the use of vmmap_add, vmmap_clear and vmmap_load commands. This may be useful for bare metal debugging.

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
    "-A", "--lines-after", type=int, help="Number of pages to display after result", default=1
)
parser.add_argument(
    "-B", "--lines-before", type=int, help="Number of pages to display before result", default=1
)
parser.add_argument(
    "--gaps",
    action="store_true",
    help="Display unmapped memory gap information in the memory map.",
)


@pwndbg.commands.ArgparsedCommand(
    parser, aliases=["lm", "address", "vprot", "libs"], category=CommandCategory.MEMORY
)
@pwndbg.commands.OnlyWhenRunning
def vmmap(
    gdbval_or_str=None, writable=False, executable=False, lines_after=1, lines_before=1, gaps=False
) -> None:
    lookaround_lines_limit = 64

    # Implement a sane limit
    lines_after = min(lookaround_lines_limit, lines_after)
    lines_before = min(lookaround_lines_limit, lines_before)

    # All displayed pages, including lines after and lines before
    total_pages = pwndbg.gdblib.vmmap.get()

    # Filtered memory pages, indicated by a backtrace arrow in results
    filtered_pages = []

    # Only filter when -A and -B arguments are valid
    if gdbval_or_str and lines_after >= 0 and lines_before >= 0:
        # Find matching page in memory
        filtered_pages = list(filter(pages_filter(gdbval_or_str), total_pages))
        pages_to_display = []

        for matched_page in filtered_pages:
            # Append matched page
            matched_index = total_pages.index(matched_page)

            # Include number of pages preceeding the matched page
            for before_index in range(0, lines_before + 1):
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
        print_vmmap_gaps(total_pages)
        return

    print(M.legend())
    print_vmmap_table_header()

    for page in total_pages:
        if (executable and not page.execute) or (writable and not page.write):
            continue

        backtrace_prefix = None
        display_text = str(page)

        if page in filtered_pages:
            # If page was one of the original results, add an arrow for clarity
            backtrace_prefix = str(pwndbg.gdblib.config.backtrace_prefix)

            # If the page is the only filtered page, insert offset
            if len(filtered_pages) == 1 and isinstance(gdbval_or_str, integer_types):
                display_text = str(page) + " +0x%x" % (int(gdbval_or_str) - page.vaddr)

        print(M.get(page.vaddr, text=display_text, prefix=backtrace_prefix))

    if pwndbg.gdblib.qemu.is_qemu() and not pwndbg.gdblib.qemu.exec_file_supported():
        print("\n[QEMU target detected - vmmap result might not be accurate; see `help vmmap`]")

    # Only GDB versions >=12 report permission info in info proc mappings. On older versions, we fallback on "rwx".
    # See https://github.com/bminor/binutils-gdb/commit/29ef4c0699e1b46d41ade00ae07a54f979ea21cc
    if pwndbg.gdblib.qemu.is_qemu_usermode() and gdb_version[0] < 12:
        print(
            "\n[GDB <12.1 detected - vmmap cannot fetch permission information, defaulting to rwx]"
        )


parser = argparse.ArgumentParser(description="Add virtual memory map page.")
parser.add_argument("start", help="Starting virtual address")
parser.add_argument("size", help="Size of the address space, in bytes")
parser.add_argument(
    "flags", nargs="?", type=str, default="", help="Flags set by the ELF file, see PF_X, PF_R, PF_W"
)
parser.add_argument(
    "offset",
    nargs="?",
    default=0,
    help="Offset into the original ELF file that the data is loaded from",
)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.MEMORY)
@pwndbg.commands.OnlyWhenRunning
def vmmap_add(start, size, flags, offset) -> None:
    page_flags = {
        "r": pwndbg.gdblib.elf.PF_R,
        "w": pwndbg.gdblib.elf.PF_W,
        "x": pwndbg.gdblib.elf.PF_X,
    }
    perm = 0
    for flag in flags:
        flag_val = page_flags.get(flag, None)
        if flag_val is None:
            print('Invalid page flag "%s"', flag)
            return
        perm |= flag_val

    page = pwndbg.lib.memory.Page(start, size, perm, offset)
    pwndbg.gdblib.vmmap.add_custom_page(page)

    print("%r added" % page)


@pwndbg.commands.ArgparsedCommand(
    "Clear the vmmap cache.", category=CommandCategory.MEMORY
)  # TODO is this accurate?
@pwndbg.commands.OnlyWhenRunning
def vmmap_clear() -> None:
    pwndbg.gdblib.vmmap.clear_custom_page()


parser = argparse.ArgumentParser(description="Load virtual memory map pages from ELF file.")
parser.add_argument(
    "filename", nargs="?", type=str, help="ELF filename, by default uses current loaded filename."
)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.MEMORY)
@pwndbg.commands.OnlyWhenRunning
def vmmap_load(filename) -> None:
    if filename is None:
        filename = pwndbg.gdblib.file.get_proc_exe_file()

    print(f'Load "{filename}" ...')

    # TODO: Add an argument to let use to choose loading the page information from sections or segments

    # Use section information to recover the segment information.
    # The entry point of bare metal environment is often at the first segment.
    # For example, assume the entry point is at 0x8000.
    # In most of case, link will create a segment and starts from 0x0.
    # This cause all values less than 0x8000 be considered as a valid pointer.
    pages = []
    with open(filename, "rb") as f:
        elffile = ELFFile(f)

        for section in elffile.iter_sections():
            vaddr = section["sh_addr"]
            memsz = section["sh_size"]
            sh_flags = section["sh_flags"]
            offset = section["sh_offset"]

            # Don't add the sections that aren't mapped into memory
            if not sh_flags & SH_FLAGS.SHF_ALLOC:
                continue

            # Guess the segment flags from section flags
            flags = pwndbg.gdblib.elf.PF_R
            if sh_flags & SH_FLAGS.SHF_WRITE:
                flags |= pwndbg.gdblib.elf.PF_W
            if sh_flags & SH_FLAGS.SHF_EXECINSTR:
                flags |= pwndbg.gdblib.elf.PF_X

            page = pwndbg.lib.memory.Page(vaddr, memsz, flags, offset, filename)
            pages.append(page)

    for page in pages:
        pwndbg.gdblib.vmmap.add_custom_page(page)
        print("%r added" % page)
