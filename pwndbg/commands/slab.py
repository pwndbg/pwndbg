"""
Commands for dealing with Linux kernel slab allocator. Currently, only SLUB is supported.

Some of the code here was inspired from https://github.com/NeatMonster/slabdbg
Some of the code here was inspired from https://github.com/osandov/drgn
"""

from __future__ import annotations

import argparse
import sys

from tabulate import tabulate

import pwndbg.aglib.kernel.slab
import pwndbg.aglib.memory
import pwndbg.color.message as M
import pwndbg.commands
from pwndbg.aglib.kernel.slab import CpuCache
from pwndbg.aglib.kernel.slab import NodeCache
from pwndbg.aglib.kernel.slab import Slab
from pwndbg.aglib.kernel.slab import find_containing_slab_cache
from pwndbg.commands import CommandCategory
from pwndbg.lib.exception import IndentContextManager

parser = argparse.ArgumentParser(description="Prints information about the slab allocator")
subparsers = parser.add_subparsers(dest="command")
parser.add_argument(
    "-c", "--cpu", type=cpu_limitcheck, dest="cpu", default=False, help="CPU to display"
)
parser.add_argument(
    "-p", "--partial", action="store_true", default=False, help="only displays partial lists"
)
parser.add_argument(
    "-a", "--active", action="store_true", default=False, help="only displays the active list"
)

# The command will still work on 3.6 and earlier, but the help won't be shown
# when no subcommand is provided
if (sys.version_info.major, sys.version_info.minor) >= (3, 7):
    subparsers.required = True


parser_list = subparsers.add_parser("list", prog="slab list")
parser_list.add_argument(
    "filter_",
    metavar="filter",
    type=str,
    default=None,
    nargs="?",
    help="Only show caches that contain the given filter string",
)

# TODO: --cpu, --node, --partial, --active
parser_info = subparsers.add_parser("info", prog="slab info")
parser_info.add_argument("names", metavar="name", type=str, default=None, nargs="+", help="")
parser_info.add_argument("-v", "--verbose", action="store_true", default=False, help="")

parser_contains = subparsers.add_parser("contains", prog="slab contains")
parser_contains.add_argument(
    "addresses", metavar="addr", type=str, default=None, nargs="+", help=""
)


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
@pwndbg.commands.OnlyWhenPagingEnabled
def slab(command, filter_, names, verbose, addresses, cpu, partial, active) -> None:
    if command == "list":
        slab_list(filter_)
    elif command == "info":
        for name in names:
            slab_info(name, verbose)
    elif command == "contains":
        for addr in addresses:
            slab_contains(addr)


def print_slab(slab: Slab, indent, verbose: bool) -> None:
    indent.print(
        f"- {indent.prefix('Slab')} @ {indent.addr_hex(slab.virt_address)} [{indent.aux_hex(slab.slab_address)}]:"
    )

    with indent:
        indent.print(f"{indent.prefix('In-Use')}: {slab.inuse}/{slab.object_count}")
        indent.print(f"{indent.prefix('Frozen')}: {slab.frozen}")
        indent.print(f"{indent.prefix('Freelist')}: {indent.addr_hex(int(slab.freelist))}")

        if verbose:
            with indent:
                free_objects = slab.free_objects
                for addr in slab.objects:
                    if addr not in free_objects:
                        indent.print(f"- {addr:#x} (in-use)")
                        continue
                    for freelist in slab.freelists:
                        next_free = freelist.find_next(addr)
                        if next_free:
                            indent.print(f"- {indent.addr_hex(addr)} (next: {next_free:#x})")
                            break
                    else:
                        indent.print(f"- {indent.addr_hex(addr)} (no next)")


def print_cpu_cache(cpu_cache: CpuCache, verbose: bool, indent) -> None:
    indent.print(
        f"{indent.prefix('kmem_cache_cpu')} @ {indent.addr_hex(cpu_cache.address)} [CPU {cpu_cache.cpu}]:"
    )
    with indent:
        indent.print(f"{indent.prefix('Freelist')}:", indent.addr_hex(int(cpu_cache.freelist)))

        active_slab = cpu_cache.active_slab
        if active_slab:
            indent.print(f"{indent.prefix('Active Slab')}:")
            with indent:
                print_slab(active_slab, indent, verbose)
        else:
            indent.print("Active Slab: (none)")

        partial_slabs = cpu_cache.partial_slabs
        if not partial_slabs:
            indent.print("Partial Slabs: (none)")
            return
        slabs = partial_slabs[0].slabs
        pobjects = partial_slabs[0].pobjects
        # the kernel checks cpu_partial_slabs to determine whether partial slabs are to be flushed
        # see: https://elixir.bootlin.com/linux/v6.13/source/mm/slub.c#L3209
        cpu_partial_slabs = partial_slabs[0].slab_cache.cpu_partial_slabs
        indent.print(
            f"{indent.prefix('Partial Slabs')} [nr_objs: {indent.aux_hex(pobjects)}] [nr_slabs/cpu_partial_slabs: {indent.aux_hex(slabs)}/{indent.aux_hex(cpu_partial_slabs)}]"
        )
        with indent:
            for partial_slab in partial_slabs:
                print_slab(partial_slab, indent, verbose)


def print_node_cache(node_cache: NodeCache, verbose: bool, indent) -> None:
    indent.print(
        f"{indent.prefix('kmem_cache_node')} @ {indent.addr_hex(node_cache.address)} [NUMA node {node_cache.node}]:"
    )
    with indent:
        partial_slabs = node_cache.partial_slabs
        if not partial_slabs:
            indent.print("Partial Slabs: (none)")
            return

        indent.print(
            f"{indent.prefix('Partial Slabs')} [nr_partial: {indent.aux_hex(len(partial_slabs))}]"
        )
        with indent:
            for slab in partial_slabs:
                print_slab(slab, indent, verbose)


def slab_info(name: str, verbose: bool) -> None:
    slab_cache = pwndbg.aglib.kernel.slab.get_cache(name)

    if slab_cache is None:
        print(M.error(f"Cache {name} not found"))
        return

    indent = IndentContextManager()

    indent.print(f"{indent.prefix('Slab Cache')} @ {indent.addr_hex(slab_cache.address)}")
    with indent:
        indent.print(f"{indent.prefix('Name')}: {slab_cache.name}")
        flags_list = slab_cache.flags
        if flags_list:
            indent.print(f"{indent.prefix('Flags')}: {' | '.join(flags_list)}")
        else:
            indent.print(f"{indent.prefix('Flags')}: (none)")

        indent.print(f"{indent.prefix('Offset')}: {slab_cache.offset}")
        indent.print(f"{indent.prefix('Size')}: {slab_cache.size}")
        indent.print(f"{indent.prefix('Align')}: {slab_cache.align}")
        indent.print(f"{indent.prefix('Object Size')}: {slab_cache.object_size}")

        for cpu_cache in slab_cache.cpu_caches:
            print_cpu_cache(cpu_cache, verbose, indent)

        for node_cache in slab_cache.node_caches:
            print_node_cache(node_cache, verbose, indent)


def slab_list(filter_) -> None:
    results = [
        [
            slab_cache.name,
            slab_cache.oo_objects,
            slab_cache.size,
            slab_cache.object_size,
            slab_cache.inuse,
            slab_cache.oo_order,
        ]
        for slab_cache in pwndbg.aglib.kernel.slab.caches()
        if not filter_ or filter_ in slab_cache.name
    ]

    print(tabulate(results, headers=["Name", "# Objects", "Size", "Obj Size", "# inuse", "order"]))


def slab_contains(address: str) -> None:
    """prints the slab_cache associated with the provided address"""

    try:
        parsed_addr = pwndbg.dbg.selected_frame().evaluate_expression(address)
    except pwndbg.dbg_mod.Error as e:
        print(M.error(f"Could not parse '{address}'"))
        print(M.error(f"Message: {e}"))
        return

    addr = int(pwndbg.aglib.memory.get_typed_pointer("void", parsed_addr))
    try:
        slab_cache = find_containing_slab_cache(addr)
        print(f"{addr:#x} @", M.hint(f"{slab_cache.name}"))
    except Exception:
        print(M.warn("address does not belong to a SLUB cache"))
