from elftools.elf.elffile import ELFFile

import pwndbg.commands
from pwndbg.color import message
from pwndbg.commands import CommandCategory


@pwndbg.commands.ArgparsedCommand(
    "Prints the section mappings contained in the ELF header.", category=CommandCategory.LINUX
)
@pwndbg.commands.OnlyWithFile
def elfsections() -> None:
    local_path = pwndbg.gdblib.file.get_proc_exe_file()

    with open(local_path, "rb") as f:
        elffile = ELFFile(f)
        sections = []
        for section in elffile.iter_sections():
            start = section["sh_offset"]
            end = start + section["sh_size"]
            vm_start = section["sh_addr"]
            vm_end = vm_start + section["sh_size"]
            perm = format_section_flags(section["sh_flags"])
            # Don't print sections that aren't mapped into memory
            if vm_start == 0:
                continue

            sections.append((section.name, start, end, vm_start, vm_end, perm))

        sections.sort()

        print("%-20s %-20s %-20s %-20s %-20s %-20s" % 
              ("Section Name", "File Offset Start", "File Offset End", 
               "VMMap Address Start", "VMMap Address End", "Permissions"))
        for name, start, end, vm_start, vm_end, perm in sections:
            print("%-20s %#-20x %#-20x %#-20x %#-20x %-20s" % 
                  (name, start, end, vm_start, vm_end, perm))


def format_section_flags(flags):
    res = ""
    if flags & 0x01:
        res += "X"
    else:
        res += "-"
    if flags & 0x02:
        res += "W"
    else:
        res += "-"
    if flags & 0x04:
        res += "R"
    else:
        res += "-"
    return res

@pwndbg.commands.ArgparsedCommand(
    "Prints any symbols found in the .got.plt section if it exists.",
    category=CommandCategory.LINUX,
)
@pwndbg.commands.OnlyWithFile
def gotplt() -> None:
    print_symbols_in_section(".got.plt", "@got.plt")


@pwndbg.commands.ArgparsedCommand(
    "Prints any symbols found in the .plt section if it exists.", category=CommandCategory.LINUX
)
@pwndbg.commands.OnlyWithFile
def plt() -> None:
    print_symbols_in_section(".plt", "@plt")


def get_section_bounds(section_name):
    local_path = pwndbg.gdblib.file.get_proc_exe_file()

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

    elf_header = pwndbg.gdblib.elf.exe()

    # If we started the binary and it has PIE, rebase it
    if pwndbg.gdblib.proc.alive:
        bin_base_addr = pwndbg.gdblib.proc.binary_base_addr

        # Rebase the start and end addresses if needed
        if start < bin_base_addr:
            start += bin_base_addr
            end += bin_base_addr

    print(message.notice(f"Section {section_name} {start:#x}-{end:#x}:"))

    symbols = get_symbols_in_region(start, end, filter_text)

    if not symbols:
        print(message.error("No symbols found in section %s" % section_name))

    for symbol, addr in symbols:
        print(hex(int(addr)) + ": " + symbol)


def get_symbols_in_region(start, end, filter_text=""):
    symbols = []
    ptr_size = pwndbg.gdblib.typeinfo.pvoid.sizeof
    addr = start
    while addr < end:
        name = pwndbg.gdblib.symbol.get(addr, gdb_only=True)
        if name != "" and "+" not in name and filter_text in name:
            symbols.append((name, addr))
        addr += ptr_size

    return symbols
