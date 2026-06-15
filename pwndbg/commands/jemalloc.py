from __future__ import annotations

import argparse

import pwndbg
import pwndbg.color.context as ctx_color
import pwndbg.commands
import pwndbg.dbg_mod
from pwndbg.aglib.heap import jemalloc
from pwndbg.color import message
from pwndbg.commands import CommandCategory


def jemalloc_find_extent(addr: int) -> None:
    print(ctx_color.banner("Jemalloc find extent"))
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


def jemalloc_extent_info(addr: int, verbose: bool = False, header: bool = True) -> bool:
    if header:
        print(ctx_color.banner("Jemalloc extent info"))
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


def jemalloc_heap() -> None:
    print(ctx_color.banner("Jemalloc heap"))
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


parser = argparse.ArgumentParser(description="Utility for inspecting the jemalloc allocator.")
subparsers = parser.add_subparsers(dest="command")
subparsers.required = True

heap_parser = subparsers.add_parser(
    "heap",
    description="Prints all extents information",
    help="Prints all extents information",
)

info_parser = subparsers.add_parser(
    "extent-info",
    description="Prints extent information for the given address",
    help="Prints extent information for the given address",
)
info_parser.add_argument("addr", type=int, help="Address of the extent metadata")
info_parser.add_argument(
    "-v",
    "--verbose",
    action="store_true",
    default=False,
    help="Print all chunk fields, even unused ones.",
)

find_parser = subparsers.add_parser(
    "find-extent",
    description="Returns extent information for pointer address allocated by jemalloc",
    help="Returns extent information for pointer address allocated by jemalloc",
)
find_parser.add_argument("addr", type=int, help="Address of the allocated memory location")


@pwndbg.commands.Command(parser, command_name="jemalloc", category=CommandCategory.ALLOCATORS)
def jemalloc_command(command: str, addr: int = -1, verbose: bool = False) -> None:
    match command:
        case "heap":
            jemalloc_heap()
        case "extent-info":
            assert addr != -1
            jemalloc_extent_info(addr, verbose)
        case "find-extent":
            assert addr != -1
            jemalloc_find_extent(addr)
