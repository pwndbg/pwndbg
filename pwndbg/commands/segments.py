from __future__ import annotations

import gdb

import pwndbg.commands
import pwndbg.gdblib.regs
from pwndbg.commands import CommandCategory


class segment(gdb.Function):
    """Get the flat address of memory based off of the named segment register."""

    def __init__(self, name: str) -> None:
        super().__init__(name)
        self.name = name

    def invoke(self, arg: gdb.Value = gdb.Value(0), *args: gdb.Value) -> int:
        result = getattr(pwndbg.gdblib.regs, self.name)
        return result + int(arg)


# TODO/FIXME: This should be defined only for x86 and x86_64
segment("fsbase")
segment("gsbase")


@pwndbg.commands.ArgparsedCommand(
    "Prints out the FS base address. See also $fsbase.", category=CommandCategory.REGISTER
)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithArch(["i386", "x86-64"])
def fsbase() -> None:
    """
    Prints out the FS base address. See also $fsbase.
    """
    print(hex(int(pwndbg.gdblib.regs.fsbase)))


@pwndbg.commands.ArgparsedCommand(
    "Prints out the GS base address. See also $gsbase.", category=CommandCategory.REGISTER
)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWithArch(["i386", "x86-64"])
def gsbase() -> None:
    """
    Prints out the GS base address. See also $gsbase.
    """
    print(hex(int(pwndbg.gdblib.regs.gsbase)))
