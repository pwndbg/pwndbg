from __future__ import annotations

import argparse
from typing import List

import pwndbg.aglib.arch
import pwndbg.aglib.disasm.disassembly
import pwndbg.arguments
import pwndbg.chain
import pwndbg.commands
import pwndbg.commands.telescope
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    description="Prints determined arguments for call/syscall instruction."
)
parser.add_argument("-f", "--force", action="store_true", help="Force displaying of all arguments.")


@pwndbg.commands.Command(parser, aliases=["args"], category=CommandCategory.MISC)
@pwndbg.commands.OnlyWhenRunning
def dumpargs(force: bool = False) -> None:
    args = (not force and call_args()) or all_args()

    if args:
        print("\n".join(args))
    else:
        print("Couldn't resolve call arguments from registers.")
        print(
            f"Detected ABI: {pwndbg.aglib.arch.name} ({pwndbg.aglib.arch.ptrsize * 8} bit) either doesn't pass arguments through registers or is not implemented. Maybe they are passed on the stack?"
        )


def call_args() -> List[str]:
    """
    Returns list of resolved call argument strings for display.
    Attempts to resolve the target and determine the number of arguments.

    Return empty list if PC is not on a call or syscall instruction.
    """

    # Get arguments and add spacing
    return [
        f"        {arg}"
        for arg in pwndbg.arguments.format_args(pwndbg.aglib.disasm.disassembly.one())
    ]


def all_args() -> List[str]:
    """
    Returns list of all argument strings for display.
    """
    results: List[str] = []

    for name, value in pwndbg.arguments.arguments():
        results.append("%4s = %s" % (name, pwndbg.chain.format(value)))

    return results
