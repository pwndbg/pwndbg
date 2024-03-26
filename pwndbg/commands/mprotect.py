from __future__ import annotations

import argparse

import pwndbg.chain
import pwndbg.commands
import pwndbg.enhance
import pwndbg.gdblib.file
import pwndbg.gdblib.shellcode
import pwndbg.wrappers.checksec
import pwndbg.wrappers.readelf
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    formatter_class=argparse.RawTextHelpFormatter,
    description="""
Calls the mprotect syscall and prints its result value.

Note that the mprotect syscall may fail for various reasons
(see `man mprotect`) and a non-zero error return value
can be decoded with the `errno <value>` command.

Examples:
    mprotect $rsp 4096 PROT_READ|PROT_WRITE|PROT_EXEC
    mprotect some_symbol 0x1000 PROT_NONE
""",
)
parser.add_argument(
    "addr", help="Page-aligned address to all mprotect on.", type=pwndbg.commands.sloppy_gdb_parse
)
parser.add_argument(
    "length",
    help="Count of bytes to call mprotect on. Needs to be multiple of page size.",
    type=int,
)
parser.add_argument(
    "prot", help='Prot string as in mprotect(2). Eg. "PROT_READ|PROT_EXEC"', type=str
)

SYS_MPROTECT = 0x7D

prot_dict = {
    "PROT_NONE": 0x0,
    "PROT_READ": 0x1,
    "PROT_WRITE": 0x2,
    "PROT_EXEC": 0x4,
}


def prot_str_to_val(protstr):
    """Heuristic to convert PROT_EXEC|PROT_WRITE to integer value."""
    prot_int = 0
    for k, v in prot_dict.items():
        if k in protstr:
            prot_int |= v
    return prot_int


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.MEMORY)
@pwndbg.commands.OnlyWhenRunning
def mprotect(addr, length, prot) -> None:
    prot_int = prot_str_to_val(prot)

    ret = pwndbg.gdblib.shellcode.exec_syscall(
        "SYS_mprotect", int(pwndbg.lib.memory.page_align(addr)), int(length), int(prot_int)
    )
    print(f"mprotect returned {ret}")
