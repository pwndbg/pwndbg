from __future__ import annotations

import gdb

import pwndbg.binja
import pwndbg.commands
import pwndbg.gdblib.events
from pwndbg.commands import CommandCategory


@pwndbg.commands.ArgparsedCommand(
    "Synchronize Binary Ninja's cursor with GDB.",
    category=CommandCategory.INTEGRATIONS,
    command_name="bn-sync",
    aliases=["bns"],
)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.binja.with_bn
def bn_sync(*args) -> None:
    """
    Synchronize IDA's cursor with GDB
    """
    try:
        pc = int(gdb.selected_frame().pc())
        pwndbg.binja.navigate_to(pc)
    except Exception:
        pass
