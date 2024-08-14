from __future__ import annotations

import argparse

import gdb

import pwndbg.commands
import pwndbg.gdblib.arch
import pwndbg.gdblib.argv
import pwndbg.gdblib.typeinfo
from pwndbg.commands import CommandCategory


@pwndbg.commands.ArgparsedCommand(
    "Prints out the number of arguments.", category=CommandCategory.LINUX
)
@pwndbg.commands.OnlyWhenRunning
def argc() -> None:
    print(pwndbg.gdblib.argv.argc)


parser = argparse.ArgumentParser(description="Prints out the contents of argv.")
parser.add_argument(
    "i", nargs="?", type=int, default=None, help="Index of the argument to print out."
)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.LINUX)
@pwndbg.commands.OnlyWhenRunning
def argv(i=None) -> None:
    start = pwndbg.gdblib.argv.argv
    n = pwndbg.gdblib.argv.argc + 1

    if i is not None:
        n = 1
        start += (pwndbg.gdblib.arch.ptrsize) * i

    pwndbg.commands.telescope.telescope(start, n)


parser = argparse.ArgumentParser(description="Prints out the contents of the environment.")
parser.add_argument(
    "name", nargs="?", type=str, default=None, help="Name of the environment variable to see."
)


@pwndbg.commands.ArgparsedCommand(
    parser, aliases=["env", "environ"], category=CommandCategory.LINUX
)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWhenUserspace
def envp(name=None):
    """
    Prints out the contents of the environment.
    """
    if name is not None:
        gdb.execute(f'p $environ("{name}")')
        return

    start = pwndbg.gdblib.argv.envp
    n = pwndbg.gdblib.argv.envc + 1

    return pwndbg.commands.telescope.telescope(start, n)


class argv_function(gdb.Function):
    """
    Evaluate argv on the supplied value.
    """

    def __init__(self) -> None:
        super().__init__("argv")

    def invoke(self, number_value: gdb.Value = gdb.Value(0), *args: gdb.Value) -> gdb.Value:
        number = int(number_value)

        if number > pwndbg.gdblib.argv.argc:
            return gdb.Value(0)

        ppchar = pwndbg.gdblib.typeinfo.pchar.pointer()
        value = gdb.Value(pwndbg.gdblib.argv.argv)
        argv = value.cast(ppchar)
        return (argv + number).dereference()


argv_function()


class envp_function(gdb.Function):
    """
    Evaluate envp on the supplied value.
    """

    def __init__(self) -> None:
        super().__init__("envp")

    def invoke(self, number_value: gdb.Value = gdb.Value(0), *args: gdb.Value) -> gdb.Value:
        number = int(number_value)

        if number > pwndbg.gdblib.argv.envc:
            return pwndbg.gdblib.typeinfo.void.optimized_out()

        ppchar = pwndbg.gdblib.typeinfo.pchar.pointer()
        value = gdb.Value(pwndbg.gdblib.argv.envp)
        envp = value.cast(ppchar)
        return (envp + number).dereference()


envp_function()


class argc_function(gdb.Function):
    """
    Evaluates to argc.
    """

    def __init__(self) -> None:
        super().__init__("argc")

    def invoke(self, *args: gdb.Value) -> int:
        return pwndbg.gdblib.argv.argc


argc_function()


class environ_function(gdb.Function):
    """
    Evaluate getenv() on the supplied value.
    """

    def __init__(self) -> None:
        super().__init__("environ")

    def invoke(self, name_value: gdb.Value = gdb.Value(""), *args: gdb.Value) -> gdb.Value:
        name = name_value.string()
        if not name:
            raise gdb.GdbError("No environment variable name provided")
        name += "="
        ppchar = pwndbg.gdblib.typeinfo.pchar.pointer()
        value = gdb.Value(pwndbg.gdblib.argv.envp)
        envp = value.cast(ppchar)

        for i in range(pwndbg.gdblib.argv.envc):
            ptr = (envp + i).dereference()
            sz = ptr.string()
            if sz.startswith(name):
                return ptr

        return pwndbg.gdblib.typeinfo.void.optimized_out()


environ_function()
