"""
Commands for dealing with Linux kernel SLAB memory allocator

Some of the code here was inspired from https://github.com/NeatMonster/slabdbg
"""
import argparse
import sys
from typing import Iterator, List, Union

import gdb
from tabulate import tabulate

import pwndbg.color as C
import pwndbg.color.message as M
import pwndbg.commands
import pwndbg.gdblib.kernel.slab
from pwndbg.commands import CommandCategory
from pwndbg.gdblib.kernel import kconfig, per_cpu
from pwndbg.gdblib.kernel.slab import oo_objects, oo_order

parser = argparse.ArgumentParser(description="Prints information about the SLUB allocator")
subparsers = parser.add_subparsers(dest="command")

# The command will still work on 3.6 and earlier, but the help won't be shown
# when no subcommand is provided
if (sys.version_info.major, sys.version_info.minor) >= (3, 7):
    subparsers.required = True


parser_list = subparsers.add_parser("list", prog="slab")
parser_list.add_argument(
    "filter_",
    metavar="filter",
    type=str,
    nargs="?",
    help="Only show caches that contain the given filter string",
)

# TODO: --cpu, --node, --partial, --active
parser_info = subparsers.add_parser("info", prog="slab")
parser_info.add_argument("names", metavar="name", type=str, nargs="+", help="")
parser_info.add_argument("-v", "--verbose", action="store_true", help="")


def swab(x):
    return int(
        ((x & 0x00000000000000FF) << 56)
        | ((x & 0x000000000000FF00) << 40)
        | ((x & 0x0000000000FF0000) << 24)
        | ((x & 0x00000000FF000000) << 8)
        | ((x & 0x000000FF00000000) >> 8)
        | ((x & 0x0000FF0000000000) >> 24)
        | ((x & 0x00FF000000000000) >> 40)
        | ((x & 0xFF00000000000000) >> 56)
    )


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
@pwndbg.commands.OnlyWhenPagingEnabled
def slab(command, filter_=None, names=None, verbose=False) -> None:
    if command == "list":
        slab_list(filter_)
    elif command == "info":
        for name in names:
            slab_info(name, verbose)


_flags = {
    "SLAB_DEBUG_FREE": 0x00000100,
    "SLAB_RED_ZONE": 0x00000400,
    "SLAB_POISON": 0x00000800,
    "SLAB_HWCACHE_ALIGN": 0x00002000,
    "SLAB_CACHE_DMA": 0x00004000,
    "SLAB_STORE_USER": 0x00010000,
    "SLAB_RECLAIM_ACCOUNT": 0x00020000,
    "SLAB_PANIC": 0x00040000,
    "SLAB_DESTROY_BY_RCU": 0x00080000,
    "SLAB_MEM_SPREAD": 0x00100000,
    "SLAB_TRACE": 0x00200000,
    "SLAB_DEBUG_OBJECTS": 0x00400000,
    "SLAB_NOLEAKTRACE": 0x00800000,
    "SLAB_NOTRACK": 0x01000000,
    "SLAB_FAILSLAB": 0x02000000,
}


def get_flags_list(flags: int):
    flags_list = []

    for flag_name, mask in _flags.items():
        if flags & mask:
            flags_list.append(flag_name)

    return flags_list


class IndentContextManager:
    def __init__(self) -> None:
        self.indent = 0

    def __enter__(self) -> None:
        self.indent += 1

    def __exit__(self, exc_type, exc_value, exc_tb) -> None:
        self.indent -= 1
        assert self.indent >= 0

    def print(self, *a, **kw) -> None:
        print("    " * self.indent, *a, **kw)


def walk_freelist(freelist, offset, random):
    while freelist:
        address = int(freelist)
        yield address
        freelist = pwndbg.gdblib.memory.pvoid(address + offset)
        if random:
            freelist ^= random ^ swab(address + offset)


def _yx(val: int) -> str:
    return C.yellow(hex(val))


def _rx(val: int) -> str:
    return C.red(hex(val))


def print_slab(
        slab: gdb.Value, cpu_cache: gdb.Value, slab_cache: gdb.Value, 
        indent, verbose: bool, is_partial: bool = False
) -> None:
    slab_address = int(slab.address)
    offset = int(slab_cache["offset"])
    random = int(slab_cache["random"]) if "SLAB_FREELIST_HARDENED" in kconfig() else 0
    address = pwndbg.gdblib.kernel.page_to_virt(slab_address)
    indent.print(f"- {C.green('Slab')} @ {_yx(address)} [{_rx(slab_address)}]:")
    with indent:
        if is_partial:
            freelists = [list(walk_freelist(slab["freelist"], offset, random))]
            inuse = slab["inuse"]
        else:
            # `freelist` is a generator, we need to evaluate it now and save the
            # result in case we want to print it later
            freelists = [
                list(walk_freelist(cpu_cache["freelist"], offset, random)),
                list(walk_freelist(slab["freelist"], offset, random)),
            ]

            # `inuse` will always equal `objects` for the active slab, so we
            # need to subtract the length of the freelist
            inuse = int(slab["inuse"]) - len(freelists[0])

        objects = int(slab["objects"])
        indent.print(f"{C.blue('In-Use')}: {inuse}/{objects}")

        indent.print(f"{C.blue('Frozen')}:", slab["frozen"])
        indent.print(f"{C.blue('Freelist')}:", _yx(int(slab["freelist"])))

        if verbose:
            with indent:
                size = int(slab_cache["size"])
                for address in range(address, address + objects * size, size):
                    if address in freelists[0]:
                        cur_freelist = freelists[0]
                    elif len(freelists) > 1 and address in freelists[1]:
                        cur_freelist = freelists[1]
                    else:
                        indent.print("-", hex(int(address)), "(in-use)")
                        continue
                    next_free_idx = cur_freelist.index(address) + 1
                    next_free = cur_freelist[next_free_idx] if len(cur_freelist) > next_free_idx else 0
                    indent.print("-", _yx(int(address)), f"(next: {next_free:#018x})")


def print_cpu_cache(
        cpu_cache: gdb.Value, slab_cache: gdb.Value, verbose: bool, indent
    ) -> None:
    indent.print(f"{C.green('Per-CPU Data')} @ {_yx(int(cpu_cache))}:")
    with indent:
        freelist = cpu_cache["freelist"]
        indent.print(f"{C.blue('Freelist')}:", _yx(int(freelist)))

        active_slab = cpu_cache["slab"]
        if active_slab:
            indent.print(f"{C.green('Active Slab')}:")
            with indent:
                print_slab(
                    active_slab.dereference(),
                    cpu_cache,
                    slab_cache,
                    indent,
                    verbose,
                    is_partial=False,
                )
        else:
            indent.print("Active Slab: (none)")

        partial_slab = cpu_cache["partial"]
        if partial_slab:
            # calculate approx obj count in half-full slabs (as done in kernel)
            # Note, this is a very bad approximation and could/should probably
            # be replaced by a more exact method or removed from pwndbg
            oo = oo_objects(slab_cache["oo"]["x"])
            slabs = int(partial_slab["slabs"])
            pobjects = (slabs * oo) // 2

            cpu_partial = int(slab_cache["cpu_partial"])
            indent.print(
                f"{C.green('Partial Slabs')} [{partial_slab['slabs']}] [PO: ~{pobjects}/{cpu_partial}]:"
            )
            while partial_slab:
                cur_slab = partial_slab.dereference()
                print_slab(
                    cur_slab, 
                    cpu_cache,
                    slab_cache,
                    indent,
                    verbose,
                    is_partial=True,
                )
                partial_slab = cur_slab["next"]
        else:
            indent.print("Partial Slabs: (none)")


def slab_info(name: str, verbose: bool) -> None:
    cache = pwndbg.gdblib.kernel.slab.get_cache(name)

    if cache is None:
        print(M.error(f"Cache {name} not found"))
        return

    indent = IndentContextManager()

    indent.print(f"{C.green('Slab Cache')} @ {_yx(int(cache))}")
    with indent:
        indent.print(f"{C.blue('Name')}:", cache["name"].string())
        flags_list = get_flags_list(int(cache["flags"]))
        if flags_list:
            indent.print(f"{C.blue('Flags')}: {' | '.join(flags_list)}")
        else:
            indent.print(f"{C.blue('Flags')}: (none)")

        indent.print(f"{C.blue('Offset')}:", int(cache["offset"]))
        indent.print(f"{C.blue('Size')}:", int(cache["size"]))
        indent.print(f"{C.blue('Align')}:", int(cache["align"]))
        indent.print(f"{C.blue('Object Size')}:", int(cache["object_size"]))

        # TODO: Handle multiple CPUs
        cpu_cache = per_cpu(cache["cpu_slab"])

        print_cpu_cache(cpu_cache, cache, verbose, indent)

        # TODO: print_node_cache


def slab_list(filter_) -> None:
    results = []
    for cache in pwndbg.gdblib.kernel.slab.caches():
        name = cache["name"].string()
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

