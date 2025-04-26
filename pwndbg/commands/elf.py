from __future__ import annotations

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


@pwndbg.commands.Command(
    "Prints any symbols found in the .plt section if it exists.", category=CommandCategory.LINUX
)
@pwndbg.commands.OnlyWithFile
def plt() -> None:
    print_symbols_in_section(".plt", "@plt")


def get_section_bounds(section_name):
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


def get_symbols_in_region(start, end, filter_text=""):
    symbols = []
    ptr_size = pwndbg.aglib.typeinfo.pvoid.sizeof
    addr = start
    while addr < end:
        name = pwndbg.aglib.symbol.resolve_addr(addr)
        if name and "+" not in name and filter_text in name:
            symbols.append((name, addr))
        addr += ptr_size

    return symbols
