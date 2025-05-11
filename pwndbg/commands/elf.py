from __future__ import annotations

from typing import List
from typing import Tuple

from elftools.elf.elffile import ELFFile

import pwndbg.commands
from pwndbg.color import message
from pwndbg.commands import CommandCategory


@pwndbg.commands.Command(
    "Prints the section mappings contained in the ELF header.", category=CommandCategory.LINUX
)
@pwndbg.commands.OnlyWithFile
def elfsections() -> None:
    local_path = pwndbg.aglib.file.get_proc_exe_file()

    with open(local_path, "rb") as f:
        elffile = ELFFile(f)
        sections = []
        for section in elffile.iter_sections():
            start = section["sh_addr"]

            # Don't print sections that aren't mapped into memory
            if start == 0:
                continue

            size = section["sh_size"]
            sections.append((start, start + size, section.name))

        sections.sort()

        for start, end, name in sections:
            print(f"{start:#x} - {end:#x} ", name)


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


@pwndbg.commands.Command(
    "Prints any symbols found in Procedure Linkage Table sections if any exist.",
    category=CommandCategory.LINUX,
)
@pwndbg.commands.OnlyWithFile
def plt() -> None:
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
        symbols = get_symbols_in_region(start, end, "@plt")

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
