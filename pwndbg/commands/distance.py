import argparse

import pwndbg.commands
import pwndbg.gdblib.arch
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(description="Print the distance between the two arguments.")
parser.add_argument("a", type=int, help="The first address.")
parser.add_argument("b", type=int, help="The second address.")


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.MEMORY)
def distance(a, b) -> None:
    """Print the distance between the two arguments"""
    a = int(a) & pwndbg.gdblib.arch.ptrmask
    b = int(b) & pwndbg.gdblib.arch.ptrmask

    distance = b - a

    print(
        "%#x->%#x is %#x bytes (%#x words)"
        % (a, b, distance, distance // pwndbg.gdblib.arch.ptrsize)
    )
