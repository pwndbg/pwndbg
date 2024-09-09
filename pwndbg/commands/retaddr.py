from __future__ import annotations

import pwndbg.aglib.arch
import pwndbg.aglib.regs
import pwndbg.aglib.vmmap
import pwndbg.chain
import pwndbg.commands
from pwndbg.commands import CommandCategory


@pwndbg.commands.ArgparsedCommand(
    "Print out the stack addresses that contain return addresses.", category=CommandCategory.STACK
)
@pwndbg.commands.OnlyWhenRunning
def retaddr() -> None:
    addresses = pwndbg.aglib.stack.callstack()

    sp = pwndbg.aglib.regs.sp
    stack = pwndbg.aglib.vmmap.find(sp)

    # Find all return addresses on the stack
    start = stack.vaddr
    stop = start + stack.memsz
    while addresses and start < sp < stop:
        value = pwndbg.aglib.memory.u(sp)

        if value in addresses:
            index = addresses.index(value)
            del addresses[:index]
            print(pwndbg.chain.format(sp))

        sp += pwndbg.aglib.arch.ptrsize
