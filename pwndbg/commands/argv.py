from __future__ import annotations

import argparse

import pwndbg.aglib.arch
import pwndbg.aglib.argv
import pwndbg.aglib.typeinfo
import pwndbg.commands
import pwndbg.commands.telescope
from pwndbg.commands import CommandCategory


@pwndbg.commands.Command("Prints out the number of arguments.", category=CommandCategory.LINUX)
@pwndbg.commands.OnlyWhenRunning
def argc() -> None:
    print(pwndbg.aglib.argv.argc())


parser = argparse.ArgumentParser(description="Prints out the contents of argv.")
parser.add_argument(
    "i", nargs="?", type=int, default=None, help="Index of the argument to print out."
)


@pwndbg.commands.Command(parser, category=CommandCategory.LINUX)
@pwndbg.commands.OnlyWhenRunning
def argv(i: int = None) -> None:
    if i is not None:
        val = pwndbg.aglib.argv.argv(i)
        if val is None:
            print("Argv not found")
            return

        pwndbg.commands.telescope.telescope(int(val.address), 1)
        return

    start = int(pwndbg.aglib.argv.argv(0).address)
    n = pwndbg.aglib.argv.argc() + 1
    pwndbg.commands.telescope.telescope(start, n)


parser = argparse.ArgumentParser(description="Prints out the contents of the environment.")
parser.add_argument(
    "name", nargs="?", type=str, default=None, help="Name of the environment variable to see."
)


@pwndbg.commands.Command(parser, aliases=["env", "environ"], category=CommandCategory.LINUX)
@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.OnlyWhenUserspace
def envp(name: str = None):
    """
    Prints out the contents of the environment.
    """
    if name is not None:
        val = pwndbg.aglib.argv.environ(name)
        if val is None:
            print("Environ not found")
            return

        pwndbg.commands.telescope.telescope(int(val.address), 1)
        return

    start = int(pwndbg.aglib.argv.envp(0).address)
    n = pwndbg.aglib.argv.envc() + 1
    pwndbg.commands.telescope.telescope(start, n)
