from __future__ import annotations

import argparse

import pwndbg.aglib
import pwndbg.color.memory as mem_color
import pwndbg.commands
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    description="Print the distance between the two arguments, or print the offset to the address's page base."
)
parser.add_argument("a", type=pwndbg.commands.AddressExpr, help="The first address.")
parser.add_argument(
    "b", nargs="?", default=None, type=pwndbg.commands.AddressExpr, help="The second address."
)


@pwndbg.commands.Command(parser, category=CommandCategory.MEMORY)
def distance(a, b) -> None:
    """Print the distance between the two arguments"""

    if b is None:
        page = pwndbg.aglib.vmmap.find(a)

        if not page:
            print(f"{a:#x} does not belong to a mapped page in memory")
        else:
            # a is a gdb.Value, explicitely convert to int
            distance = int(a) - page.vaddr

            display_text = f"{page.vaddr:#x}->{a:#x} is {distance:#x} bytes ({distance // pwndbg.aglib.arch.ptrsize:#x} words)"

            print(mem_color.get(page.vaddr, text=display_text))
    else:
        a = int(a) & pwndbg.aglib.arch.ptrmask
        b = int(b) & pwndbg.aglib.arch.ptrmask

        distance = b - a

        print(
            f"{a:#x}->{b:#x} is {distance:#x} bytes ({distance // pwndbg.aglib.arch.ptrsize:#x} words)"
        )
