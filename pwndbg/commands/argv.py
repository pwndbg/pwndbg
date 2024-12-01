from __future__ import annotations

import argparse

import gdb

import pwndbg.aglib.arch
import pwndbg.aglib.typeinfo
import pwndbg.commands
import pwndbg.commands.telescope
import pwndbg.gdblib.argv
from pwndbg.commands import CommandCategory


def dbg_value_to_gdb(d: pwndbg.dbg_mod.Value) -> gdb.Value:
    from pwndbg.dbg.gdb import GDBValue

    assert isinstance(d, GDBValue)
    return d.inner


def gdb_none_value() -> gdb.Value:
    return dbg_value_to_gdb(pwndbg.dbg.selected_inferior().create_value(0))


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
        start += (pwndbg.aglib.arch.ptrsize) * i

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
            return gdb_none_value()

        ppchar = pwndbg.aglib.typeinfo.pchar.pointer()
        argv = pwndbg.dbg.selected_inferior().create_value(pwndbg.gdblib.argv.argv, ppchar)
        return dbg_value_to_gdb((argv + number).dereference())


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
            return gdb_none_value()

        ppchar = pwndbg.aglib.typeinfo.pchar.pointer()
        envp = pwndbg.dbg.selected_inferior().create_value(pwndbg.gdblib.argv.envp, ppchar)
        return dbg_value_to_gdb((envp + number).dereference())


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
        ppchar = pwndbg.aglib.typeinfo.pchar.pointer()
        envp = pwndbg.dbg.selected_inferior().create_value(pwndbg.gdblib.argv.envp, ppchar)

        for i in range(pwndbg.gdblib.argv.envc):
            ptr = (envp + i).dereference()
            sz = ptr.string()
            if sz.startswith(name):
                return dbg_value_to_gdb(ptr)

        return gdb_none_value()


environ_function()
