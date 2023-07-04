"""
Command to print the virtual memory map a la /proc/self/maps.
"""
import argparse

import gdb
from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile

import pwndbg.color.memory as M
import pwndbg.commands
import pwndbg.gdblib.elf
import pwndbg.gdblib.vmmap
from pwndbg.commands import CommandCategory

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


@pwndbg.commands.ArgparsedCommand(
    parser, aliases=["lm", "address", "vprot", "libs"], category=CommandCategory.MEMORY
)
@pwndbg.commands.OnlyWhenRunning
def vmmap(gdbval_or_str=None, writable=False, executable=False) -> None:
    pages = pwndbg.gdblib.vmmap.get()

    if gdbval_or_str:
        pages = list(filter(pages_filter(gdbval_or_str), pages))

    if not pages:
        print("There are no mappings for specified address or module.")
        return

    print(M.legend())
    print_vmmap_table_header()
    if len(pages) == 1 and isinstance(gdbval_or_str, integer_types):
        page = pages[0]
        print(M.get(page.vaddr, text=str(page) + " +0x%x" % (int(gdbval_or_str) - page.vaddr)))
    else:
        for page in pages:
            if (executable and not page.execute) or (writable and not page.write):
                continue
            print(M.get(page.vaddr, text=str(page)))

    if pwndbg.gdblib.qemu.is_qemu():
        print("\n[QEMU target detected - vmmap result might not be accurate; see `help vmmap`]")


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
