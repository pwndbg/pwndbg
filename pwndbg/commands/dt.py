from __future__ import annotations

import argparse

import pwndbg
import pwndbg.aglib.dt
from pwndbg.color import message
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    description="""
Dump out information on a type (e.g. ucontext_t).

Optionally overlay that information at an address.""",
)
parser.add_argument(
    "typename",
    type=str,
    help='The name of the structure being dumped. Use quotes if the type contains spaces (e.g. "struct malloc_state").',
)
parser.add_argument(
    "address", type=int, nargs="?", default=None, help="The address of the structure."
)


@pwndbg.commands.Command(parser, category=CommandCategory.MISC)
def dt(typename: str, address: int | None = None) -> None:
    """
    Dump out information on a type (e.g. ucontext_t).

    Optionally overlay that information at an address.
    """
    if address is not None and not pwndbg.aglib.memory.is_readable_address(address):
        print(message.error("The provided address is not readable."))
        return

    print(pwndbg.aglib.dt.dt(typename, addr=address))
