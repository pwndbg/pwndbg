from __future__ import annotations

import argparse

import pwndbg.aglib.arch
import pwndbg.aglib.argv
import pwndbg.aglib.typeinfo
import pwndbg.commands
import pwndbg.commands.telescope
from pwndbg.commands import CommandCategory


@pwndbg.commands.ArgparsedCommand(
    "Prints out the number of arguments.", category=CommandCategory.LINUX
)
@pwndbg.commands.OnlyWhenRunning
def argc() -> None:
    print(pwndbg.aglib.argv.argc_numbers)


parser = argparse.ArgumentParser(description="Prints out the contents of argv.")
parser.add_argument(
    "i", nargs="?", type=int, default=None, help="Index of the argument to print out."
)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.LINUX)
@pwndbg.commands.OnlyWhenRunning
def argv(i=None) -> None:
    start = pwndbg.aglib.argv.argv_ptr
    n = pwndbg.aglib.argv.argc_numbers + 1

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
def envp(name: str = None):
    """
    Prints out the contents of the environment.
    """
    if name is not None:
        val = pwndbg.aglib.argv.environ(name)
        print(val.value_to_human_readable())
        return

    start = pwndbg.aglib.argv.envp_ptr
    n = pwndbg.aglib.argv.envc_numbers + 1

    pwndbg.commands.telescope.telescope(start, n)
