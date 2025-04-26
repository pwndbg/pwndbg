from __future__ import annotations

import pwndbg.aglib.regs
import pwndbg.commands
import pwndbg.integration.binja
from pwndbg.commands import CommandCategory


@pwndbg.commands.Command(
    "Synchronize Binary Ninja's cursor with GDB.",
    category=CommandCategory.INTEGRATIONS,
    command_name="bn-sync",
    aliases=["bns"],
)
@pwndbg.commands.OnlyWhenRunning
def bn_sync(*args) -> None:
    """
    Synchronize Binary Ninja's cursor with GDB
    """
    pwndbg.integration.binja.navigate_to(pwndbg.aglib.regs.pc)
