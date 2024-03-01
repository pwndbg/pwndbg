from __future__ import annotations

import pwndbg.chain
import pwndbg.commands
import pwndbg.gdblib.arch
import pwndbg.gdblib.regs
import pwndbg.gdblib.stack
import pwndbg.gdblib.vmmap
from pwndbg.commands import CommandCategory


@pwndbg.commands.ArgparsedCommand(
    "Print out the stack addresses that contain return addresses.", category=CommandCategory.STACK
)
@pwndbg.commands.OnlyWhenRunning
def retaddr() -> None:
    for _, retaddr in enumerate(pwndbg.gdblib.stack.yield_return_addresses()):
        print(pwndbg.chain.format(retaddr))
