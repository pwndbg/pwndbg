from __future__ import annotations

import argparse

import pwndbg.aglib.shellcode
import pwndbg.aglib.vmmap
import pwndbg.commands
import pwndbg.dbg_mod
import pwndbg.lib.errnum
import pwndbg.lib.memory
from pwndbg.color import message
from pwndbg.commands import CommandCategory
from pwndbg.lib import mmap

parser = argparse.ArgumentParser(
    description="""
Calls the mprotect syscall and prints its result value.

Note that the mprotect syscall may fail for various reasons
(see `man mprotect`) and a non-zero error return value
can be decoded with the `errno <value>` command.
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
    "prot",
    help='Prot string as in mprotect(2). Eg. "PROT_READ|PROT_EXEC", "rx", or "5"',
    type=mmap.prot_from_string,
)

SYS_MPROTECT = 0x7D
SYSCALL = "SYS_mprotect"


@pwndbg.commands.Command(
    parser,
    category=CommandCategory.MEMORY,
    examples="""
mprotect $rsp 4096 PROT_READ|PROT_WRITE|PROT_EXEC
mprotect $rsp 4096 rwx
mprotect $rsp 4096 7
mprotect some_symbol 0x1000 PROT_NONE
""",
)
@pwndbg.commands.OnlyWhenRunning
def mprotect(addr, length, prot: int) -> None:
    orig_addr = int(addr)
    aligned = pwndbg.lib.memory.page_align(orig_addr)

    async def ctrl(ec: pwndbg.dbg_mod.ExecutionController):
        print(
            f"calling mprotect on address {aligned:#x} with protection {prot} ({mmap.prot_to_string(prot)})"
        )

        ret = await pwndbg.aglib.shellcode.exec_syscall(
            ec, SYSCALL, aligned, int(length) + orig_addr - aligned, prot
        )

        pwndbg.lib.errnum.handle_syscall_ret(SYSCALL, ret, pwndbg.aglib.arch.ptrbits)

        if pwndbg.aglib.vmmap.cache_status_text() is not None:
            print(
                message.warn(
                    "vmmap cache is on and was not cleared; "
                    "run `vmmap --refresh` to pick up the permission change."
                )
            )

    pwndbg.dbg.selected_inferior().dispatch_execution_controller(ctrl)
