from __future__ import annotations

import argparse

import pwndbg.aglib.nearpc
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(description="Disassemble near a specified address.")
parser.add_argument(
    "pc",
    type=int,
    nargs="?",
    default=None,
    help="Address to disassemble near. If this is the only argument and the value provided is small enough, it is interpreted as lines instead.",
)
parser.add_argument(
    "lines",
    type=int,
    nargs="?",
    default=None,
    help="Number of lines to show on either side of the address.",
)
parser.add_argument(
    "--emulate",
    choices=["on", "off"],
    default="off",
    help="Enable or disable emulation.",
)


@pwndbg.commands.ArgparsedCommand(parser, aliases=["pdisass", "u"], category=CommandCategory.DISASS)
@pwndbg.commands.OnlyWhenRunning
def nearpc(pc=None, lines=None, emulate="off", use_cache=False, linear=True) -> None:
    """
    Disassemble near a specified address.
    """
    emulate_flag = emulate == "on"
    print(
        "\n".join(
            pwndbg.aglib.nearpc.nearpc(
                pc, lines, emulate_flag, nearpc.repeat, use_cache=use_cache, linear=linear
            )
        )
    )


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
    nearpc(pc, lines, emulate_, use_cache=True, linear=False)
