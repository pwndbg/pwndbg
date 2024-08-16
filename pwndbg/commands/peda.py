from __future__ import annotations

import argparse

import gdb

import pwndbg.auxv
import pwndbg.commands
import pwndbg.commands.context
import pwndbg.commands.telescope
import pwndbg.gdblib.proc
from pwndbg.color import message
from pwndbg.commands import CommandCategory


@pwndbg.commands.ArgparsedCommand("Gets the current file.")
@pwndbg.commands.OnlyWhenRunning
def getfile() -> None:
    print(repr(pwndbg.auxv.get().AT_EXECFN))


parser = argparse.ArgumentParser(
    description="Continue execution until an address or function."
)
parser.add_argument("target", type=int, help="Location to stop execution at")


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.NEXT)
def xuntil(target) -> None:
    try:
        addr = target

        if not pwndbg.gdblib.memory.peek(addr):
            print(message.error("Invalid address %#x" % addr))
            return

        spec = "*%#x" % (addr)
    except (TypeError, ValueError):
        # The following gdb command will throw an error if the symbol is not defined.
        try:
            gdb.execute(f"info address {target}", to_string=True, from_tty=False)
        except gdb.error:
            print(message.error(f"Unable to resolve {target}"))
            return
        spec = target

    gdb.Breakpoint(spec, temporary=True)
    if pwndbg.gdblib.proc.alive:
        gdb.execute("continue", from_tty=False)
    else:
        gdb.execute("run", from_tty=False)


xinfo = pwndbg.commands.context.context
xprint = pwndbg.commands.telescope.telescope
