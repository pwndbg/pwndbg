"""
Commands for dealing with Linux kernel slab allocator. Currently, only SLUB is supported.

Some of the code here was inspired from https://github.com/NeatMonster/slabdbg
Some of the code here was inspired from https://github.com/osandov/drgn
"""

from __future__ import annotations

import argparse

from tabulate import tabulate

import pwndbg
import pwndbg.aglib.kernel.slab
import pwndbg.aglib.memory
import pwndbg.color
import pwndbg.commands
import pwndbg.dbg_mod
from pwndbg.aglib.kernel.slab import CpuCache
from pwndbg.aglib.kernel.slab import Freelist
from pwndbg.aglib.kernel.slab import NodeCache
from pwndbg.aglib.kernel.slab import Slab
from pwndbg.aglib.kernel.slab import find_containing_slab_cache
from pwndbg.color import message
from pwndbg.commands import CommandCategory
from pwndbg.lib.exception import IndentContextManager

parser = argparse.ArgumentParser(
    description="Prints information about the linux kernel's slab allocator SLUB."
)
subparsers = parser.add_subparsers(dest="command")
subparsers.required = True


parser_list = subparsers.add_parser(
    "list",
    description="List SLUB caches filtered by name.",
    help="List SLUB caches filtered by name.",
)
parser_list.add_argument(
    "filter_",
    metavar="filter",
    type=str,
    default=None,
    nargs="?",
    help="Only show caches that contain the given filter string",
)

parser_info = subparsers.add_parser(
    "info", description="Dump information about a cache.", help="Dump information about a cache."
)
parser_info.add_argument("names", metavar="name", type=str, nargs="+", help="")
parser_info.add_argument("-v", "--verbose", action="store_true", help="")
parser_info.add_argument("-c", "--cpu", type=int, help="CPU to display")
parser_info.add_argument("-n", "--node", type=int, help="")
parser_info.add_argument("-p", "--partial", action="store_true", help="displays partial lists")
parser_info.add_argument("-a", "--active", action="store_true", help="displays the active list")

parser_contains = subparsers.add_parser(
    "contains", description="Get the cache for an address.", help="Get the cache for an address."
)
parser_contains.add_argument("addresses", metavar="addr", type=str, nargs="+", help="")


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelSymbols
@pwndbg.commands.OnlyWhenPagingEnabled
def slab(
    command: str,
    filter_: str | None = None,
    names: list[str] | None = None,
    verbose: bool = False,
    addresses: list[str] | None = None,
    cpu: int | None = None,
    node: int | None = None,
    partial: bool = False,
    active: bool = False,
) -> None:
    pwndbg.aglib.kernel.slab.recover_slab_typeinfo()
    if command == "list":
        slab_list(filter_)
    elif command == "info":
        assert names
        if not partial and not active:
            partial = active = True
        for name in names:
            slab_info(name, verbose, cpu, node, active, partial)
    elif command == "contains":
        assert addresses
        for addr in addresses:
            slab_contains(addr)


def emphasize(s):
    return pwndbg.color.underline(pwndbg.color.bold(pwndbg.color.red(s)))


indent = IndentContextManager()


def handle_next(curr: int, freelist: Freelist) -> str:
    next = freelist.find_next(curr)
    if next == 0:
        return "no next"
    desc = f"next: {indent.aux_hex(next)}"
    if not pwndbg.aglib.memory.is_kernel(next + freelist.offset):
        desc = emphasize("invalid address") + " " + desc
    elif freelist.cyclic is not None and freelist.cyclic == curr:
        desc = emphasize("cyclic list detected") + ", " + desc
    elif not freelist.slab or next not in freelist.slab:
        desc = emphasize("next is not within the slab") + ", " + desc
    elif not freelist.is_valid_obj(next):
        desc = emphasize("unaligned or out-of-range") + " " + desc
    return desc


def freelist_desc(freelist: Freelist) -> str:
    head = int(freelist)
    desc = None
    if head:
        if not pwndbg.aglib.memory.is_kernel(head):
            desc = "invalid address"
        elif not freelist.slab or head not in freelist.slab:
            desc = "not within the slab"
        elif not freelist.is_valid_obj(head):
            desc = "unaligned or out-of-range"
    return indent.addr_hex(head) + (f" [{emphasize(desc)}]" if desc else "")


def print_slab(slab: Slab, verbose: bool) -> None:
    indent.print(
        f"- {indent.prefix('Slab')} @ {indent.addr_hex(slab.slab_address)} [{indent.aux_hex(slab.virt_address)}]:"
    )

    with indent:
        indent.print(f"{indent.prefix('In-Use')}: {slab.inuse}/{slab.object_count}")
        indent.print(f"{indent.prefix('Frozen')}: {slab.frozen}")
        indent.print(f"{indent.prefix('Freelist')}: {freelist_desc(slab.freelist)}")

        cpu_freelist = slab.cpu_cache.freelist if slab.is_active else None
        indexes = {}
        freelist = slab.freelist
        for idx, addr in enumerate(freelist):
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
                    if addr not in free_objects:
                        indent.print(f"{prefix} (in-use)")
                        continue
                    index = indexes[addr]
                    if addr in indexes:
                        prefix = f"- {indent.prefix(f'[0x{index:02x}]')} {indent.addr_hex(addr)}"
                    desc = None
                    in_cpu_freelist = False
                    if addr in freelist:
                        desc = handle_next(addr, freelist)
                    elif cpu_freelist is not None and addr in cpu_freelist:
                        # need to traverse the list to catch potential freelist.cyclic
                        desc = handle_next(addr, cpu_freelist)
                        in_cpu_freelist = True
                    if desc is None:
                        desc = "something went wrong"
                    if in_cpu_freelist:
                        indent.print(f"{prefix} ({desc}) [CPU cache]")
                        continue
                    indent.print(f"{prefix} ({desc})")


def print_cpu_cache(cpu_cache: CpuCache, verbose: bool, active: bool, partial: bool) -> None:
    indent.print(
        f"{indent.prefix('kmem_cache_cpu')} @ {indent.addr_hex(cpu_cache.address)} [CPU {cpu_cache.cpu}]:"
    )
    with indent:
        if active:
            indent.print(f"{indent.prefix('Freelist')}:", freelist_desc(cpu_cache.freelist))
            active_slab = cpu_cache.active_slab
            if active_slab:
                indent.print(f"{indent.prefix('Active Slab')}:")
                with indent:
                    print_slab(active_slab, verbose)
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
                print_slab(partial_slab, verbose)


def print_node_cache(node_cache: NodeCache, verbose: bool) -> None:
    address, nr_partial, min_partial, node = (
        node_cache.address,
        node_cache.nr_partial,
        node_cache.min_partial,
        node_cache.node,
    )
    # https://elixir.bootlin.com/linux/v6.13/source/mm/slub.c#L3140
    indent.print(
        f"{indent.prefix('kmem_cache_node')} @ {indent.addr_hex(address)} [NUMA node {node}]:"
    )
    with indent:
        partial_slabs = node_cache.partial_slabs
        if not partial_slabs:
            indent.print("Partial Slabs: (none)")
            return

        indent.print(
            f"{indent.prefix('Partial Slabs')} [nr_partial/min_partial: {indent.aux_hex(nr_partial)}/{indent.aux_hex(min_partial)}]"
        )
        with indent:
            for slab in partial_slabs:
                print_slab(slab, verbose)


def slab_info(
    name: str, verbose: bool, cpu: int | None, node: int | None, active: bool, partial: bool
) -> None:
    slab_cache = pwndbg.aglib.kernel.slab.get_cache(name)

    if slab_cache is None:
        print(message.error(f"Cache {name} not found"))
        return

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
            print_cpu_cache(cpu_cache, verbose, active, partial)

        if not partial:
            return

        for node_cache in slab_cache.node_caches:
            if node is not None and node != node_cache.node:
                continue
            print_node_cache(node_cache, verbose)


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
        addr = int(pwndbg.dbg.selected_frame().evaluate_expression(address)) & ((1 << 64) - 1)
    except pwndbg.dbg_mod.Error as e:
        print(message.error(f"Could not parse '{address}'"))
        print(message.error(f"Message: {e}"))
        return

    try:
        base, slab_cache = find_containing_slab_cache(addr)
        assert base and slab_cache, "cannot find the kmem_cache the address belongs to."
        addr = base + ((addr - base) // slab_cache.size) * slab_cache.size
        indent.print(f"{addr:#x} @", message.hint(f"{slab_cache.name}"))
        inuse = f"[something went wrong: {hex(addr)}]"
        slab = slab_cache.find_containing_slab(addr)
        if slab:
            if addr in slab.free_objects:
                inuse = "free"
            elif addr in slab.objects:
                inuse = "in-use"
            if slab.is_active:
                location = f"active, cpu {slab.cpu_cache.cpu}"
            elif slab.is_cpu:
                location = f"partial, cpu {slab.cpu_cache.cpu}"
            else:
                location = f"partial, node {slab.node_cache.node}"
            if slab.inuse == slab.object_count:
                objcnt = "full"
            else:
                objcnt = f"{slab.inuse}/{slab.object_count} in-use"
            desc = f"[{location}, {objcnt}]"
        else:
            inuse = "in-use"
            desc = "[inactive, full]"
        indent.print("slab:", message.hint(f"{hex(base)}"), desc)
        indent.print("status:", message.hint(inuse))
    except Exception as e:
        print(message.warn(f"address does not belong to a SLUB cache: {e}"))
