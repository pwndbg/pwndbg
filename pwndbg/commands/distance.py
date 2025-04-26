from __future__ import annotations

import argparse

import pwndbg.aglib.arch
import pwndbg.color.memory as M
import pwndbg.commands
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    description="Print the distance between the two arguments, or print the offset to the address's page base."
)
parser.add_argument("a", type=int, help="The first address.")
parser.add_argument("b", nargs="?", default=None, type=int, help="The second address.")


@pwndbg.commands.Command(parser, category=CommandCategory.MEMORY)
def distance(a, b) -> None:
    """Print the distance between the two arguments"""

    if b is None:
        page = pwndbg.aglib.vmmap.find(a)

        if not page:
            print("%#x does not belong to a mapped page in memory" % (a))
        else:
            # a is a gdb.Value, explicitely convert to int
            distance = int(a) - page.vaddr

            display_text = "%#x->%#x is %#x bytes (%#x words)" % (
                page.vaddr,
                a,
                distance,
                distance // pwndbg.aglib.arch.ptrsize,
            )

            print(M.get(page.vaddr, text=display_text))
    else:
        a = int(a) & pwndbg.aglib.arch.ptrmask
        b = int(b) & pwndbg.aglib.arch.ptrmask

        distance = b - a

        print(
            "%#x->%#x is %#x bytes (%#x words)"
            % (a, b, distance, distance // pwndbg.aglib.arch.ptrsize)
        )
