from __future__ import annotations

import argparse

import pwndbg.color.memory as M
import pwndbg.commands
import pwndbg.gdblib.arch
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    description="Print the distance between the two arguments, or print the offset to the address's page base."
)
parser.add_argument("a", type=int, help="The first address.")
parser.add_argument("b", nargs="?", default=None, type=int, help="The second address.")


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.MEMORY)
def distance(a, b) -> None:
    """Print the distance between the two arguments"""

    if b is None:
        total_pages = pwndbg.gdblib.vmmap.get()

        if not total_pages:
            print("There are no memory pages in `vmmap`")
            return

        # Find the page the address belongs to
        for page in total_pages:
            if a >= page.vaddr and a < page.end:
                # a is a gdb.Value, explicitely convert to int
                distance = int(a) - page.vaddr

                display_text = "%#x->%#x is %#x bytes (%#x words)" % (
                    page.vaddr,
                    a,
                    distance,
                    distance // pwndbg.gdblib.arch.ptrsize,
                )

                print(M.get(page.vaddr, text=display_text))
                return

        print("%#x does not belong to a mapped page in memory" % (a))
    else:
        a = int(a) & pwndbg.gdblib.arch.ptrmask
        b = int(b) & pwndbg.gdblib.arch.ptrmask

        distance = b - a

        print(
            "%#x->%#x is %#x bytes (%#x words)"
            % (a, b, distance, distance // pwndbg.gdblib.arch.ptrsize)
        )
