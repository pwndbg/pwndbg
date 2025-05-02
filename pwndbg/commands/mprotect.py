from __future__ import annotations

import argparse

import pwndbg.aglib.file
import pwndbg.aglib.shellcode
import pwndbg.chain
import pwndbg.commands
import pwndbg.enhance
import pwndbg.lib.memory
import pwndbg.wrappers.checksec
import pwndbg.wrappers.readelf
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    description="""
Calls the mprotect syscall and prints its result value.

Note that the mprotect syscall may fail for various reasons
(see `man mprotect`) and a non-zero error return value
can be decoded with the `errno <value>` command.

Examples:
    mprotect $rsp 4096 PROT_READ|PROT_WRITE|PROT_EXEC
    mprotect $rsp 4096 rwx
    mprotect $rsp 4096 7
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
    "prot", help='Prot string as in mprotect(2). Eg. "PROT_READ|PROT_EXEC", "rx", or "5"', type=str
)

SYS_MPROTECT = 0x7D

prot_dict = {
    "PROT_NONE": 0x0,
    "PROT_READ": 0x1,
    "PROT_WRITE": 0x2,
    "PROT_EXEC": 0x4,
}


def prot_str_to_val(protstr: str) -> int:
    """
    Converts a protection string to an integer. Formats include:
     - A positive integer, like 3
     - A combination of r, w, and x, like rw
     - A combination of PROT_READ, PROT_WRITE, and PROT_EXEC, like PROT_READ|PROT_WRITE
    """
    protstr = protstr.upper()
    if "PROT" in protstr:
        prot_int = 0
        for k, v in prot_dict.items():
            if k in protstr:
                prot_int |= v
        return prot_int
    elif all(x in "RWX" for x in protstr):
        prot_int = 0
        for c in protstr:
            if c == "R":
                prot_int |= 1
            elif c == "W":
                prot_int |= 2
            elif c == "X":
                prot_int |= 4
        return prot_int
    else:
        try:
            return int(protstr, 0)
        except ValueError:
            raise ValueError("Invalid protection string passed into mprotect")


def prot_val_to_str(protval: int) -> str:
    if protval == 0:
        return "PROT_NONE"
    ret = []
    for k, v in prot_dict.items():
        if protval & v:
            ret.append(k)
    return "|".join(ret)


@pwndbg.commands.Command(parser, category=CommandCategory.MEMORY)
@pwndbg.commands.OnlyWhenRunning
def mprotect(addr, length, prot) -> None:
    prot_int = prot_str_to_val(prot)
    orig_addr = int(addr)
    aligned = pwndbg.lib.memory.page_align(orig_addr)

    async def ctrl(ec: pwndbg.dbg_mod.ExecutionController):
        print(
            f"calling mprotect on address {aligned:#x} with protection {prot_int} ({prot_val_to_str(prot_int)})"
        )

        ret = await pwndbg.aglib.shellcode.exec_syscall(
            ec, "SYS_mprotect", aligned, int(length) + orig_addr - aligned, int(prot_int)
        )
        print(f"mprotect returned {ret}")

    pwndbg.dbg.selected_inferior().dispatch_execution_controller(ctrl)
