from __future__ import annotations

import gdb

import pwndbg.chain
import pwndbg.commands
import pwndbg.gdblib.arch
import pwndbg.gdblib.regs
import pwndbg.gdblib.vmmap
from pwndbg.commands import CommandCategory


@pwndbg.commands.ArgparsedCommand(
    "Print out the stack addresses that contain return addresses.", category=CommandCategory.STACK
)
@pwndbg.commands.OnlyWhenRunning
def retaddr() -> None:
    sp = pwndbg.gdblib.regs.sp
    stack = pwndbg.gdblib.vmmap.find(sp)

    # Enumerate all return addresses
    frame = gdb.newest_frame()
    addresses = []
    while frame:
        addr = int(frame.pc())
        if pwndbg.gdblib.memory.is_readable_address(addr):
            addresses.append(addr)
        frame = frame.older()

    # Find all of them on the stack
    start = stack.vaddr
    stop = start + stack.memsz
    while addresses and start < sp < stop:
        value = pwndbg.gdblib.memory.u(sp)

        if value in addresses:
            index = addresses.index(value)
            del addresses[:index]
            print(pwndbg.chain.format(sp))

        sp += pwndbg.gdblib.arch.ptrsize
