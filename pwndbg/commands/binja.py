from __future__ import annotations

import gdb

import pwndbg.binja
import pwndbg.commands
import pwndbg.gdblib.events
import pwndbg.gdblib.functions
from pwndbg.commands import CommandCategory


@pwndbg.commands.ArgparsedCommand(
    "Synchronize Binary Ninja's cursor with GDB.",
    category=CommandCategory.INTEGRATIONS,
    command_name="bn-sync",
    aliases=["bns"],
)
@pwndbg.commands.OnlyWhenRunning
def bn_sync(*args) -> None:
    """
    Synchronize IDA's cursor with GDB
    """
    pc = int(gdb.selected_frame().pc())
    pwndbg.binja.navigate_to(pc)

@pwndbg.gdblib.functions.GdbFunction()
@pwndbg.binja.with_bn()
def bn_sym(name) -> int | None:
    """
    Lookup a symbol's address by name from Binary Ninja.
    """
    name = name.string()
    addr: int | None = pwndbg.binja._bn.get_symbol_addr(name)
    return addr
