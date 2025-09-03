"""
Commands for dealing with Linux kernel slab allocator. Currently, only SLUB is supported.

Some of the code here was inspired from https://github.com/NeatMonster/slabdbg
Some of the code here was inspired from https://github.com/osandov/drgn
"""

from __future__ import annotations

import argparse
import sys

from tabulate import tabulate

import pwndbg
import pwndbg.aglib.kernel.slab
import pwndbg.aglib.kernel.symbol
import pwndbg.aglib.memory
import pwndbg.color.message as M
import pwndbg.commands
from pwndbg.aglib.kernel.slab import CpuCache
from pwndbg.aglib.kernel.slab import Freelist
from pwndbg.aglib.kernel.slab import NodeCache
from pwndbg.aglib.kernel.slab import Slab
from pwndbg.aglib.kernel.slab import find_containing_slab_cache
from pwndbg.commands import CommandCategory
from pwndbg.lib.exception import IndentContextManager

parser = argparse.ArgumentParser(
    description="Prints information about the linux kernel's slab allocator SLUB."
)
subparsers = parser.add_subparsers(dest="command")

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

parser_info = subparsers.add_parser("info", prog="slab info")
parser_info.add_argument("names", metavar="name", type=str, nargs="+", help="")
parser_info.add_argument("-v", "--verbose", action="store_true", help="")
parser_info.add_argument("-c", "--cpu", type=int, help="CPU to display")
parser_info.add_argument("-n", "--node", type=int, help="")
parser_info.add_argument(
    "-p", "--partial-only", action="store_true", help="only displays partial lists"
)
parser_info.add_argument(
    "-a", "--active-only", action="store_true", help="only displays the active list"
)

parser_contains = subparsers.add_parser("contains", prog="slab contains")
parser_contains.add_argument("addresses", metavar="addr", type=str, nargs="+", help="")


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSymbols
@pwndbg.commands.OnlyWhenPagingEnabled
def slab(
    command,
    filter_=None,
    names=None,
    verbose=False,
    addresses=None,
    cpu=None,
    node=None,
    partial_only=False,
    active_only=False,
) -> None:
    if not pwndbg.aglib.kernel.has_debug_info():
        pwndbg.aglib.kernel.slab.load_slab_typeinfo()
    if command == "list":
        slab_list(filter_)
    elif command == "info":
        partial, active = True, True
        if partial_only and active_only:
            print(M.warn("partial_only and active_only are both specified"))
            return
        if partial_only:
            active = False
        if active_only:
            partial = False
        for name in names:
            slab_info(name, verbose, cpu, node, active, partial)
    elif command == "contains":
        for addr in addresses:
            slab_contains(addr)


def print_slab(slab: Slab, indent, verbose: bool, cpu_freelist: Freelist = None) -> None:
    indent.print(
        f"- {indent.prefix('Slab')} @ {indent.addr_hex(slab.virt_address)} [{indent.aux_hex(slab.slab_address)}]:"
    )

    with indent:
        indent.print(f"{indent.prefix('In-Use')}: {slab.inuse}/{slab.object_count}")
        indent.print(f"{indent.prefix('Frozen')}: {slab.frozen}")
        indent.print(f"{indent.prefix('Freelist')}: {indent.addr_hex(int(slab.freelist))}")

        idx = 0
        indexes = {}
        freelist = slab.freelist
        for addr in freelist:
            if addr in indexes:
                break
            indexes[addr] = idx
            idx += 1
        if cpu_freelist is not None:
            for idx, addr in enumerate(cpu_freelist):
                if addr in indexes:
                    break
                indexes[addr] = idx

        if verbose:
            with indent:
                free_objects = slab.free_objects
                for addr in slab.objects:
                    prefix = f"- {indent.prefix('[0x--]')} {hex(addr)}"
                    if addr in indexes:
                        prefix = (
                            f"- {indent.prefix(f'[0x{indexes[addr]:02}]')} {indent.addr_hex(addr)}"
                        )
                    if addr not in free_objects:
                        indent.print(f"{prefix} (in-use)")
                        continue
                    next_free = freelist.find_next(addr)
                    if next_free:
                        indent.print(f"{prefix} (next: {indent.aux_hex(next_free)})")
                        continue
                    if cpu_freelist is not None:
                        next_free = cpu_freelist.find_next(addr)
                        if next_free:
                            indent.print(
                                f"{prefix} (next: {indent.aux_hex(next_free)}) [CPU cache]"
                            )
                            continue
                        if addr in cpu_freelist:
                            indent.print(f"{prefix} (no next) [CPU cache]")
                            continue
                    indent.print(f"{prefix} (no next)")


def print_cpu_cache(
    cpu_cache: CpuCache, verbose: bool, active: bool, partial: bool, indent
) -> None:
    indent.print(
        f"{indent.prefix('kmem_cache_cpu')} @ {indent.addr_hex(cpu_cache.address)} [CPU {cpu_cache.cpu}]:"
    )
    with indent:
        if active:
            indent.print(f"{indent.prefix('Freelist')}:", indent.addr_hex(int(cpu_cache.freelist)))
            active_slab = cpu_cache.active_slab
            if active_slab:
                indent.print(f"{indent.prefix('Active Slab')}:")
                with indent:
                    print_slab(active_slab, indent, verbose, cpu_cache.freelist)
            else:
                indent.print("Active Slab: (none)")

        if not partial:
            return
        partial_slabs = cpu_cache.partial_slabs
        if not partial_slabs:
            indent.print("Partial Slabs: (none)")
            return
        slabs = partial_slabs[0].slabs
        # the kernel checks cpu_partial_slabs to determine whether partial slabs are to be flushed
        # see: https://elixir.bootlin.com/linux/v6.13/source/mm/slub.c#L3209
        cpu_partial_slabs = partial_slabs[0].slab_cache.cpu_partial_slabs
        if cpu_partial_slabs is None:
            # legacy
            cpu_partial_slabs = partial_slabs[0].pobjects
        indent.print(
            f"{indent.prefix('Partial Slabs')} [nr_slabs/cpu_partial_slabs: {indent.aux_hex(slabs)}/{indent.aux_hex(cpu_partial_slabs)}]"
        )
        with indent:
            for partial_slab in partial_slabs:
                print_slab(partial_slab, indent, verbose)


def print_node_cache(node_cache: NodeCache, verbose: bool, indent) -> None:
    address, nr_partial, min_partial, node = (
        node_cache.address,
        node_cache.nr_partial,
        node_cache.min_partial,
        node_cache.node,
    )
    # https://elixir.bootlin.com/linux/v6.13/source/mm/slub.c#L3140
    indent.print(
        f"{indent.prefix('kmem_cache_node')} @ {indent.addr_hex(address)} [NUMA node {node}, nr_partial/min_partial: {indent.aux_hex(nr_partial)}/{indent.aux_hex(min_partial)}]:"
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


def slab_info(name: str, verbose: bool, cpu: int, node: int, active: bool, partial: bool) -> None:
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

        indent.print(f"{indent.prefix('Offset')}: {indent.aux_hex(slab_cache.offset)}")
        indent.print(f"{indent.prefix('Slab size')}: {indent.aux_hex(slab_cache.slab_size)}")
        indent.print(
            f"{indent.prefix('Size (including metadata)')}: {indent.aux_hex(slab_cache.size)}"
        )
        indent.print(f"{indent.prefix('Align')}: {indent.aux_hex(slab_cache.align)}")
        indent.print(f"{indent.prefix('Object Size')}: {indent.aux_hex(slab_cache.object_size)}")
        useroffset, usersize = slab_cache.useroffset, slab_cache.usersize
        if useroffset is not None and usersize is not None:
            indent.print(f"{indent.prefix('Usercopy region offset')}: {useroffset}")
            indent.print(f"{indent.prefix('Usercopy region size')}: {usersize}")

        for cpu_cache in slab_cache.cpu_caches:
            if cpu is not None and cpu_cache.cpu != cpu:
                continue
            print_cpu_cache(cpu_cache, verbose, active, partial, indent)

        if not partial:
            return

        for node_cache in slab_cache.node_caches:
            if node is not None and node != node_cache.node:
                continue
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

    addr = None
    try:
        addr = int(pwndbg.dbg.selected_frame().evaluate_expression(address))
    except pwndbg.dbg_mod.Error as e:
        print(M.error(f"Could not parse '{address}'"))
        print(M.error(f"Message: {e}"))
        return

    try:
        slab_cache = find_containing_slab_cache(addr)
        print(f"{addr:#x} @", M.hint(f"{slab_cache.name}"))
        slab = slab_cache.find_containing_slab(addr)
        if slab is None:
            print(M.warn("Did not finding containing slab."))
            return
        desc = "[something went wrong]"
        inuse = desc
        try:
            if addr in slab.free_objects:
                inuse = "free"
            elif addr in slab.objects:
                inuse = "in-use"
            if slab.is_cpu and not slab.is_partial:
                desc = f"[active, cpu {slab.cpu_cache.cpu}]"
            elif slab.is_cpu and slab.is_partial:
                desc = f"[partial, cpu {slab.cpu_cache.cpu}]"
            elif not slab.is_cpu and slab.is_partial:
                desc = f"[partial, node {slab.node_cache.node}]"
        except Exception:
            pass
        print("slab:", M.hint(f"{hex(slab.virt_address)}"), desc)
        print("status:", M.hint(inuse))
    except Exception as e:
        print(M.warn(f"address does not belong to a SLUB cache: {e}"))
