"""
Commands for dealing with Linux kernel slab allocator. Currently, only SLUB is supported.

Some of the code here was inspired from https://github.com/NeatMonster/slabdbg
Some of the code here was inspired from https://github.com/osandov/drgn
"""

from __future__ import annotations

import argparse
import sys
from types import TracebackType
from typing import Optional
from typing import Type

from tabulate import tabulate

import pwndbg.aglib.kernel.slab
import pwndbg.color as C
import pwndbg.color.message as M
import pwndbg.commands
from pwndbg.aglib.kernel.slab import CpuCache
from pwndbg.aglib.kernel.slab import NodeCache
from pwndbg.aglib.kernel.slab import Slab
from pwndbg.aglib.kernel.slab import find_containing_slab_cache
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(description="Prints information about the slab allocator")
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
    nargs="?",
    help="Only show caches that contain the given filter string",
)

# TODO: --cpu, --node, --partial, --active
parser_info = subparsers.add_parser("info", prog="slab info")
parser_info.add_argument("names", metavar="name", type=str, nargs="+", help="")
parser_info.add_argument("-v", "--verbose", action="store_true", help="")

parser_contains = subparsers.add_parser("contains", prog="slab contains")
parser_contains.add_argument("addresses", metavar="addr", type=str, nargs="+", help="")


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
@pwndbg.commands.OnlyWhenPagingEnabled
def slab(command, filter_=None, names=None, verbose=False, addresses=None) -> None:
    if command == "list":
        slab_list(filter_)
    elif command == "info":
        for name in names:
            slab_info(name, verbose)
    elif command == "contains":
        for addr in addresses:
            slab_contains(addr)


class IndentContextManager:
    def __init__(self) -> None:
        self.indent = 0

    def __enter__(self) -> None:
        self.indent += 1

    def __exit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_value: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> None:
        self.indent -= 1
        assert self.indent >= 0

    def print(self, *a, **kw) -> None:
        print("    " * self.indent, *a, **kw)


def _yx(val: int) -> str:
    return C.yellow(hex(val))


def _rx(val: int) -> str:
    return C.red(hex(val))


def print_slab(slab: Slab, indent, verbose: bool) -> None:
    indent.print(f"- {C.green('Slab')} @ {_yx(slab.virt_address)} [{_rx(slab.slab_address)}]:")

    with indent:
        indent.print(f"{C.blue('In-Use')}: {slab.inuse}/{slab.object_count}")
        indent.print(f"{C.blue('Frozen')}: {slab.frozen}")
        indent.print(f"{C.blue('Freelist')}: {_yx(int(slab.freelist))}")

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
                            indent.print(f"- {_yx(addr)} (next: {next_free:#x})")
                            break
                    else:
                        indent.print(f"- {_yx(addr)} (no next)")


def print_cpu_cache(cpu_cache: CpuCache, verbose: bool, indent) -> None:
    indent.print(f"{C.green('kmem_cache_cpu')} @ {_yx(cpu_cache.address)} [CPU {cpu_cache.cpu}]:")
    with indent:
        indent.print(f"{C.blue('Freelist')}:", _yx(int(cpu_cache.freelist)))

        active_slab = cpu_cache.active_slab
        if active_slab:
            indent.print(f"{C.green('Active Slab')}:")
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
        cpu_partial = partial_slabs[0].slab_cache.cpu_partial
        indent.print(f"{C.green('Partial Slabs')} [{slabs}] [PO: ~{pobjects}/{cpu_partial}]:")
        for partial_slab in partial_slabs:
            print_slab(partial_slab, indent, verbose)


def print_node_cache(node_cache: NodeCache, verbose: bool, indent) -> None:
    indent.print(
        f"{C.green('kmem_cache_node')} @ {_yx(node_cache.address)} [NUMA node {node_cache.node}]:"
    )
    with indent:
        partial_slabs = node_cache.partial_slabs
        if not partial_slabs:
            indent.print("Partial Slabs: (none)")
            return

        indent.print(f"{C.green('Partial Slabs')}:")
        for slab in partial_slabs:
            print_slab(slab, indent, verbose)


def slab_info(name: str, verbose: bool) -> None:
    slab_cache = pwndbg.aglib.kernel.slab.get_cache(name)

    if slab_cache is None:
        print(M.error(f"Cache {name} not found"))
        return

    indent = IndentContextManager()

    indent.print(f"{C.green('Slab Cache')} @ {_yx(slab_cache.address)}")
    with indent:
        indent.print(f"{C.blue('Name')}: {slab_cache.name}")
        flags_list = slab_cache.flags
        if flags_list:
            indent.print(f"{C.blue('Flags')}: {' | '.join(flags_list)}")
        else:
            indent.print(f"{C.blue('Flags')}: (none)")

        indent.print(f"{C.blue('Offset')}: {slab_cache.offset}")
        indent.print(f"{C.blue('Size')}: {slab_cache.size}")
        indent.print(f"{C.blue('Align')}: {slab_cache.align}")
        indent.print(f"{C.blue('Object Size')}: {slab_cache.object_size}")

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

    addr = int(parsed_addr)
    slab_cache = find_containing_slab_cache(addr)
    print(f"{addr:#x} @", M.hint(f"{slab_cache.name}"))
