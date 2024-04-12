from __future__ import annotations

import argparse

import pwndbg.gdblib.nearpc
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(description="Disassemble near a specified address.")
parser.add_argument("pc", type=int, nargs="?", default=None, help="Address to disassemble near.")
parser.add_argument(
    "lines",
    type=int,
    nargs="?",
    default=None,
    help="Number of lines to show on either side of the address.",
)
parser.add_argument(
    "-e",
    "--emulate",
    action="store_true",
    help="Whether to emulate instructions to find the next ones or just linearly disassemble.",
)


@pwndbg.commands.ArgparsedCommand(parser, aliases=["pdisass", "u"], category=CommandCategory.DISASS)
@pwndbg.commands.OnlyWhenRunning
def nearpc(pc=None, lines=None, emulate=False) -> None:
    """
    Disassemble near a specified address.
    """
    repeat = False
    for command in pwndbg.commands.commands:
        if command.__module__ == "pwndbg.commands.nearpc" and command.repeat == True:
            repeat = True
            break

    print("\n".join(pwndbg.gdblib.nearpc.nearpc(pc, lines, emulate, repeat)))


parser = argparse.ArgumentParser(
    description="Like nearpc, but will emulate instructions from the current $PC forward."
)
parser.add_argument("pc", type=int, nargs="?", default=None, help="Address to emulate near.")
parser.add_argument(
    "lines",
    type=int,
    nargs="?",
    default=None,
    help="Number of lines to show on either side of the address.",
)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.DISASS)
@pwndbg.commands.OnlyWhenRunning
def emulate(pc=None, lines=None, emulate_=True) -> None:
    """
    Like nearpc, but will emulate instructions from the current $PC forward.
    """
    nearpc.repeat = emulate.repeat
    nearpc(pc, lines, emulate_)
