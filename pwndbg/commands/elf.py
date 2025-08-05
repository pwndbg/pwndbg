from __future__ import annotations

import argparse
from typing import List
from typing import Tuple

from elftools.elf.elffile import ELFFile

import pwndbg.aglib
import pwndbg.aglib.proc
import pwndbg.color.memory as M
import pwndbg.commands
from pwndbg.color import message
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    description="""Prints the section mappings contained in the ELF header.
If binary not start or use --no-rebase, the section permission based on section flags.
""",
)

parser.add_argument(
    "-R",
    "--no-rebase",
    help="Print the non-rebased section address. ",
    action="store_true",
    default=False,
    dest="no_rebase",
)


@pwndbg.commands.Command(
    parser,
    category=CommandCategory.LINUX,
    examples="""
elfsections
elfsections --no-rebase
""",
)
@pwndbg.commands.OnlyWithFile
def elfsections(no_rebase: bool) -> None:
    local_path = pwndbg.aglib.file.get_proc_exe_file()

    bin_base_addr = 0
    # Get the binary base address, for rebase the section address if we need.
    if pwndbg.aglib.proc.alive:
        bin_base_addr = pwndbg.aglib.proc.binary_base_addr

    __SH_WRITE = 1 << 0
    __SH_ALLOC = 1 << 1
    __SH_EXEC = 1 << 2

    with open(local_path, "rb") as f:
        elffile = ELFFile(f)
        sections = []
        for section in elffile.iter_sections():
            start = section["sh_addr"]
            privilege = section["sh_flags"]

            # Don't print sections that aren't mapped into memory
            # test in go sample: "gosample.x64/86", some sections have the address but don't have the SH_ALLOC flags
            if not (privilege & __SH_ALLOC):
                continue

            size = section["sh_size"]

            # rebase the address if we need
            if not no_rebase:
                start = bin_base_addr + start if start < bin_base_addr else start

            sections.append([start, start + size, size, section.name, privilege])

        sections.sort()

        # print legend
        print(M.legend())

        # table header
        print(f"{'Start':>18} {'End':>18} {'Perm':>8} {'Size':>10}  {'Name':<}")

        # if the binary is started, use the memory permission for the coloring
        if pwndbg.aglib.proc.alive and not no_rebase:
            for start, end, size, name, privilege in sections:
                page = pwndbg.aglib.vmmap.find(start)

                privilege_str = "R" if page.read else "-"
                privilege_str += "W" if page.write else "-"
                privilege_str += "X" if page.execute else "-"

                print(
                    M.get(
                        start,
                        text=f"{start:>#18x} {end:>#18x} {privilege_str:>8} {size:>#10x}  {name:<}",
                    )
                )
        else:
            # if the binary is not start, use the section flags for the coloring.
            for start, end, size, name, privilege in sections:
                color = M.c.rodata
                privilege_str = "R"

                if privilege & __SH_WRITE:
                    privilege_str += "W"
                    color = M.c.data
                else:
                    privilege_str += "-"

                if privilege & __SH_EXEC:
                    privilege_str += "X"
                    color = M.c.code
                else:
                    privilege_str += "-"

                print(color(f"{start:>#18x} {end:>#18x} {privilege_str:>8} {size:>#10x}  {name:<}"))


@pwndbg.commands.Command(
    "Prints any symbols found in the .got.plt section if it exists.",
    category=CommandCategory.LINUX,
)
@pwndbg.commands.OnlyWithFile
def gotplt() -> None:
    print_symbols_in_section(".got.plt", "@got.plt")


# These are all the section names associated with PLTs.
# .plt.sec and .plt.bnd are associated with control flow transfer integrity.
# These are derived from this list that GDB recognizes: https://github.com/bminor/binutils-gdb/blob/38d726a24c1a85abdb606e7ab6cefad17872aad7/bfd/elf64-x86-64.c#L5775-L5780
PLT_SECTION_NAMES = (".plt", ".plt.sec", ".plt.got", ".plt.bnd")

parser = argparse.ArgumentParser(
    description="Prints any symbols found in Procedure Linkage Table sections if any exist.",
)

parser.add_argument(
    "-a",
    "--all-symbols",
    help="Print all symbols, not just those that end in @plt",
    action="store_true",
    default=False,
)


@pwndbg.commands.Command(
    parser,
    category=CommandCategory.LINUX,
)
@pwndbg.commands.OnlyWithFile
def plt(all_symbols: bool = False) -> None:
    local_path = pwndbg.aglib.file.get_proc_exe_file()

    bin_base_addr = 0
    # If we started the binary and it has PIE, rebase it
    if pwndbg.aglib.proc.alive:
        bin_base_addr = pwndbg.aglib.proc.binary_base_addr

    # List of (Section name, start_addr, end_addr)
    sections_found: List[Tuple[str, int, int]] = []

    with open(local_path, "rb") as f:
        elffile = ELFFile(f)

        for section_name in PLT_SECTION_NAMES:
            section = elffile.get_section_by_name(section_name)

            if section:
                start: int = section["sh_addr"]
                size: int = section["sh_size"]

                if start is None:
                    continue

                end = start + size

                # Rebase the start and end addresses if needed
                if start < bin_base_addr:
                    start += bin_base_addr
                    end += bin_base_addr

                sections_found.append((section_name, start, end))

    # Sort by the start address so we print from lowest to highest
    sections_found.sort(key=lambda x: x[1])

    for section_name, start, end in sections_found:
        symbols = get_symbols_in_region(start, end, "" if all_symbols else "@plt")

        print(message.notice(f"Section {section_name} {start:#x} - {end:#x}:"))

        if not symbols:
            print(message.error(f"No symbols found in section {section_name}"))

        stuff: List[Tuple[int, str]] = []

        for symbol, addr in symbols:
            stuff.append((addr, symbol))
            print(hex(int(addr)) + ": " + symbol)

    if len(sections_found) == 0:
        print(message.error("No .plt.* sections found"))


def get_section_bounds(section_name: str):
    local_path = pwndbg.aglib.file.get_proc_exe_file()

    with open(local_path, "rb") as f:
        elffile = ELFFile(f)

        section = elffile.get_section_by_name(section_name)

        if not section:
            return (None, None)

        start = section["sh_addr"]
        size = section["sh_size"]
        return (start, start + size)


def print_symbols_in_section(section_name, filter_text="") -> None:
    start, end = get_section_bounds(section_name)

    if start is None:
        print(message.error(f"Could not find section {section_name}"))
        return

    # If we started the binary and it has PIE, rebase it
    if pwndbg.aglib.proc.alive:
        bin_base_addr = pwndbg.aglib.proc.binary_base_addr

        # Rebase the start and end addresses if needed
        if start < bin_base_addr:
            start += bin_base_addr
            end += bin_base_addr

    print(message.notice(f"Section {section_name} {start:#x}-{end:#x}:"))

    symbols = get_symbols_in_region(start, end, filter_text)

    if not symbols:
        print(message.error(f"No symbols found in section {section_name}"))

    for symbol, addr in symbols:
        print(hex(int(addr)) + ": " + symbol)


def get_symbols_in_region(start: int, end: int, filter_text="") -> List[Tuple[str, int]]:
    symbols: List[Tuple[str, int]] = []
    ptr_size = pwndbg.aglib.typeinfo.pvoid.sizeof
    addr = start
    while addr < end:
        name = pwndbg.aglib.symbol.resolve_addr(addr)
        if name and "+" not in name and filter_text in name:
            symbols.append((name, addr))
        addr += ptr_size

    return symbols
