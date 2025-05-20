from __future__ import annotations

import pwndbg.aglib.proc
import pwndbg.aglib.regs
import pwndbg.commands
from pwndbg.commands import CommandCategory


@pwndbg.commands.Command(
    "Prints out the FS base address. See also $fsbase.", category=CommandCategory.REGISTER
)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.aglib.proc.OnlyWithArch(["i386", "x86-64"])
def fsbase() -> None:
    """
    Prints out the FS base address. See also $fsbase.
    """
    print(hex(int(pwndbg.aglib.regs.fsbase)))


@pwndbg.commands.Command(
    "Prints out the GS base address. See also $gsbase.", category=CommandCategory.REGISTER
)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.aglib.proc.OnlyWithArch(["i386", "x86-64"])
def gsbase() -> None:
    """
    Prints out the GS base address. See also $gsbase.
    """
    print(hex(int(pwndbg.aglib.regs.gsbase)))


# See pwndbg.gdblib.functions for the $fsbase() and $gsbase() definitions.
