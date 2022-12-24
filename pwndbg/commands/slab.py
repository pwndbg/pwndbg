import argparse

from tabulate import tabulate

import pwndbg.commands
import pwndbg.gdblib.kernel.slab
from pwndbg.gdblib.kernel.slab import oo_objects
from pwndbg.gdblib.kernel.slab import oo_order

parser = argparse.ArgumentParser(description="Prints information about the SLUB allocator.")
parser.add_argument(
    "filter_",
    metavar="filter",
    type=str,
    nargs="?",
    help="Only show caches that contain the given filter string",
)


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
@pwndbg.commands.OnlyWhenPagingEnabled
def slab(filter_=None):
    results = []
    for cache in pwndbg.gdblib.kernel.slab.caches():
        name = pwndbg.gdblib.memory.string(cache["name"]).decode("ascii")
        if filter_ and filter_ not in name:
            continue
        order = oo_order(int(cache["oo"]["x"]))
        objects = oo_objects(int(cache["oo"]["x"]))
        results.append(
            [
                name,
                objects,
                int(cache["size"]),
                int(cache["object_size"]),
                int(cache["inuse"]),
                order,
            ]
        )

    print(tabulate(results, headers=["Name", "# Objects", "Size", "Obj Size", "# inuse", "order"]))
