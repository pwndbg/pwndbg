from __future__ import annotations

import argparse

import gdb

import pwndbg.aglib.memory
import pwndbg.aglib.proc
import pwndbg.auxv
import pwndbg.commands
import pwndbg.commands.context
import pwndbg.commands.telescope
from pwndbg.color import message
from pwndbg.commands import CommandCategory


@pwndbg.commands.Command("Gets the current file.", category=CommandCategory.MISC)
@pwndbg.commands.OnlyWhenRunning
def getfile() -> None:
    print(repr(pwndbg.auxv.get().AT_EXECFN))


parser = argparse.ArgumentParser(description="Continue execution until an address or expression.")
parser.add_argument("target", type=int, help="Location to stop execution at")


@pwndbg.commands.Command(parser, category=CommandCategory.NEXT)
def xuntil(target) -> None:
    try:
        addr = target

        if not pwndbg.aglib.memory.peek(addr):
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
    if pwndbg.aglib.proc.alive:
        gdb.execute("continue", from_tty=False)
    else:
        gdb.execute("run", from_tty=False)
