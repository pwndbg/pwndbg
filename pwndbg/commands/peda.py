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
parser.add_argument("target", type=int, help="Address or function to stop execution at")


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.NEXT)
def xuntil(target) -> None:
    running = pwndbg.gdblib.proc.alive
    if not running:
        print(message.notice("Process is not running. Starting process..."))
        gdb.execute("starti", from_tty=False, to_string=True)
        target = pwndbg.gdblib.functions.rebase(target)
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
    gdb.execute("continue", from_tty=False)


xinfo = pwndbg.commands.context.context
xprint = pwndbg.commands.telescope.telescope
