from __future__ import annotations

import argparse

import gdb
import pwnlib
from pwnlib import asm

import pwndbg.chain
import pwndbg.commands
import pwndbg.enhance
import pwndbg.gdblib.file
import pwndbg.gdblib.shellcode
import pwndbg.wrappers.checksec
import pwndbg.wrappers.readelf
from pwndbg.commands import CommandCategory
from pwndbg.lib.regs import reg_sets

parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="""
Calls the mmap syscall and prints its resulting address.

Note that the mmap syscall may fail for various reasons
(see `man mmap`) and, in case of failure, its return value
will not be a valid pointer.

Examples:
    mmap 0x0 4096 PROT_READ|PROT_WRITE|PROT_EXEC MAP_PRIVATE|MAP_ANONYMOUS -1 0
    mmap 0x0 4096 PROT_READ MAP_PRIVATE 10 0
""",
)
parser.add_argument(
    "addr", help="Address hint to be given to mmap.", type=pwndbg.commands.sloppy_gdb_parse
)
parser.add_argument(
    "length",
    help="Length of the mapping, in bytes. Needs " "to be greater than zero.",
    type=int,
)
parser.add_argument(
    "prot", help="Prot string as in mmap(2). Eg. " '"PROT_READ|PROT_EXEC".', type=str
)
parser.add_argument(
    "flags", help="Flags string as in mmap(2). Eg. " '"MAP_PRIVATE|MAP_ANONYMOUS".', type=str
)
parser.add_argument(
    "fd", 
    help="File descriptor of the file to be mapped, or -1 if using MAP_ANONYMOUS.",
    type=int
)
parser.add_argument(
    "offset",
    help="Offset from the start of the file, in bytes, if using file based mapping.",
    type=int
)


prot_dict = {
    "PROT_NONE": 0x0,
    "PROT_READ": 0x1,
    "PROT_WRITE": 0x2,
    "PROT_EXEC": 0x4,
}

flag_dict = {
    "MAP_SHARED": 0x1,
    "MAP_PRIVATE": 0x2,
    "MAP_SHARED_VALIDATE": 0x3,
    "MAP_FIXED": 0x10,
    "MAP_ANONYMOUS": 0x20,
}

def prot_str_to_val(protstr):
    """Heuristic to convert PROT_EXEC|PROT_WRITE to integer value."""
    prot_int = 0
    for k, v in prot_dict.items():
        if k in protstr:
            prot_int |= v
    return prot_int

def flag_str_to_val(flagstr):
    """Heuristic to convert MAP_SHARED|MAP_FIXED to integer value."""
    flag_int = 0
    for k, v in flag_dict.items():
        if k in flagstr:
            flag_int |= v
    return flag_int

@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.MEMORY)
@pwndbg.commands.OnlyWhenRunning
def mmap(addr, length, prot, flags, fd, offset) -> None:
    prot_int = prot_str_to_val(prot)
    flag_int = flag_str_to_val(flags)
    
    pointer = pwndbg.gdblib.shellcode.exec_syscall(
        "SYS_mmap",
        int(pwndbg.lib.memory.page_align(addr)),
        int(length),
        prot_int,
        flag_int,
        int(fd),
        int(offset)
    )

    print(f"mmap returned 0x{pointer:04x}")

