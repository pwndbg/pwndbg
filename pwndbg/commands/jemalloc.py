from __future__ import annotations

import argparse

import pwndbg
import pwndbg.aglib.heap
import pwndbg.aglib.heap.jemalloc as jemalloc
import pwndbg.color.context as C
from pwndbg.color import message
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    description="Returns extent information for pointer address allocated by jemalloc"
)
parser.add_argument("addr", type=int, help="Address of the allocated memory location")


@pwndbg.commands.Command(parser, category=CommandCategory.JEMALLOC)
def jemalloc_find_extent(addr) -> None:
    print(C.banner("Jemalloc find extent"))
    print("This command was tested only for jemalloc 5.3.0 and does not support lower versions")
    print()

    addr = int(addr)

    try:
        rtree = jemalloc.RTree.get_rtree()
        extent = rtree.lookup_hard(addr)
        if extent is None:
            print(message.error("ERROR: Extent not found"))
            return
        # print pointer address first, then extent address then extent information
        print(f"Pointer Address: {hex(addr)}")
        print(f"Extent Address: {hex(extent.extent_address)}")
        print()

        jemalloc_extent_info(extent.extent_address, header=False)
    except pwndbg.dbg_mod.Error as e:
        print(message.error(f"ERROR: {e}"))
        return


parser = argparse.ArgumentParser(description="Prints extent information for the given address")
parser.add_argument("addr", type=int, help="Address of the extent metadata")
parser.add_argument(
    "-v", "--verbose", action="store_true", help="Print all chunk fields, even unused ones."
)


@pwndbg.commands.Command(parser, category=CommandCategory.JEMALLOC)
def jemalloc_extent_info(addr, verbose=False, header=True) -> bool:
    if header:
        print(C.banner("Jemalloc extent info"))
        print("This command was tested only for jemalloc 5.3.0 and does not support lower versions")
        print()

    try:
        extent = jemalloc.Extent(int(addr))

        print(f"Allocated Address: {hex(extent.allocated_address)}")
        print(f"Extent Address: {hex(extent.extent_address)}")

        print(f"Size: {hex(extent.size)}")
        print(f"Small class: {extent.has_slab}")

        print(f"State: {extent.state_name}")

        if verbose:
            for bit, val in extent.bitfields.items():
                print(bit, val)
    except pwndbg.dbg_mod.Error as e:
        print(message.error(f"ERROR: {e}"))
        return False
    return True


parser = argparse.ArgumentParser(description="Prints all extents information")


@pwndbg.commands.Command(parser, category=CommandCategory.JEMALLOC)
def jemalloc_heap() -> None:
    print(C.banner("Jemalloc heap"))
    print("This command was tested only for jemalloc 5.3.0 and does not support lower versions")
    print()

    try:
        rtree = jemalloc.RTree.get_rtree()
        extents = rtree.extents
        if len(extents) == 0:
            print(message.warn("No extents found"))
            return
        for extent in extents:
            # TODO: refactor so not create copies
            if not jemalloc_extent_info(extent.extent_address, header=False):
                return
            print()
    except pwndbg.dbg_mod.Error as e:
        print(message.error(f"ERROR: {e}"))
        return
