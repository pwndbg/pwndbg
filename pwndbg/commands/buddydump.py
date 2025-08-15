from __future__ import annotations

import argparse
import logging
from dataclasses import dataclass
from typing import List
from typing import Tuple

import pwndbg
import pwndbg.aglib.kernel.buddydump
import pwndbg.aglib.kernel.symbol
import pwndbg.aglib.memory
import pwndbg.aglib.symbol
import pwndbg.commands
from pwndbg.aglib import kernel
from pwndbg.aglib.kernel import per_cpu
from pwndbg.aglib.kernel.macros import for_each_entry
from pwndbg.commands import CommandCategory
from pwndbg.lib.exception import IndentContextManager

log = logging.getLogger(__name__)


MAX_PG_FREE_LIST_STR_RESULT_CNT = 0x10
MAX_PG_FREE_LIST_CNT = 0x1000
NONE_TUPLE = (None, None)
# https://elixir.bootlin.com/linux/v6.13.12/source/include/linux/mmzone.h#L52
MIGRATE_PCPTYPES = 3


@dataclass
class ParsedBuddyArgs:
    # stores the input options
    zone: str | None
    order: int | None
    mtype: str | None
    cpu: int | None
    find: int | None


@dataclass
class CurrentBuddyParams:
    # stores the current properties of the freelist being/to be traversed
    # this is so that values can be cleanly passed around
    sections: List[Tuple[str, str]]
    indent: IndentContextManager
    zone: pwndbg.dbg_mod.Value | None
    order: int
    mtype: str | None
    freelists: pwndbg.dbg_mod.Value | None
    freelist: pwndbg.dbg_mod.Value | None
    nr_types: int | None
    found: bool


def cpu_limitcheck(cpu: str):
    if cpu is None:
        return None
    nr_cpus = pwndbg.aglib.kernel.nproc()
    if cpu.isdigit() and int(cpu) < nr_cpus:
        return int(cpu)
    raise argparse.ArgumentTypeError(
        f"The --cpu option takes in a number less than nr_cpu_ids ({nr_cpus})."
    )


parser = argparse.ArgumentParser(
    description="Displays metadata and freelists of the buddy allocator."
)
parser.add_argument(
    "-z",
    "--zone",
    type=str,
    dest="zone",
    default=None,
    help="Displays/searches lists only in the specified zone.",
)
parser.add_argument(
    "-o",
    "--order",
    type=int,
    dest="order",
    help="Displays/searches lists only with the specified order.",
)
parser.add_argument(
    "-m",
    "--mtype",
    type=str,
    dest="mtype",
    default=None,
    help="Displays/searches lists only with the specified mtype.",
)
parser.add_argument(
    "-p",
    "--pcp-only",
    action="store_true",
    dest="pcp_only",
    default=False,
    help="Displays/searches only PCP lists.",
)
parser.add_argument(
    "-c", "--cpu", type=cpu_limitcheck, dest="cpu", default=None, help="CPU nr for searching PCP."
)
parser.add_argument("-n", "--node", type=int, dest="node", default=0, help="")
parser.add_argument(
    "-f",
    "--find",
    type=int,
    dest="find",
    default=None,
    help="The address to find in page free lists.",
)


def static_str_arr(name: str) -> List[str]:
    arr = pwndbg.aglib.symbol.lookup_symbol(name).dereference()
    return [arr[i].string() for i in range(arr.type.array_len)]


def check_find(counter: int, physmap_addr: int, pba: ParsedBuddyArgs, cbp: CurrentBuddyParams):
    if counter < MAX_PG_FREE_LIST_STR_RESULT_CNT and pba.find is None:
        return True
    if pba.find is None:
        return False
    start = physmap_addr
    end = physmap_addr + 0x1000 * (1 << cbp.order)
    return pba.find >= start and pba.find < end


def traverse_pglist(
    pba: ParsedBuddyArgs, cbp: CurrentBuddyParams
) -> Tuple[List[Tuple[int, str]], int, List[str]]:
    freelist = cbp.freelist
    if freelist is None or int(freelist["next"]) == 0:
        return None, 0, None
    indent = cbp.indent
    seen_pages = set()
    results = []
    counter = 0
    msgs = []
    for e in for_each_entry(freelist, "struct page", "lru"):
        page = int(e)
        phys_addr = pwndbg.aglib.kernel.page_to_phys(page)
        physmap_addr = pwndbg.aglib.kernel.page_to_physmap(page)
        if check_find(counter, physmap_addr, pba, cbp):
            results.append(
                (
                    counter,
                    f"{indent.addr_hex(physmap_addr)} [page: {indent.aux_hex(page)}, phys: {indent.aux_hex(phys_addr)}]",
                )
            )
            cbp.found = True
        if counter == MAX_PG_FREE_LIST_STR_RESULT_CNT:
            msgs.append(f"{indent.prefix('... (truncated)')}")
            msgs.append(
                f"This doubly linked list reached size {indent.aux_hex(MAX_PG_FREE_LIST_STR_RESULT_CNT)}"
            )
        counter += 1
        if page in seen_pages:
            msgs.append(f"Cyclic doubly linked list detected: {results[-1]}")
            break
        seen_pages.add(page)
        if counter == MAX_PG_FREE_LIST_CNT:
            msgs.append(
                f"This doubly link list exceeds size {indent.aux_hex(MAX_PG_FREE_LIST_CNT)}"
            )
            break
    return results, counter, msgs


def print_section(section: Tuple[str, str], indent: IndentContextManager):
    prefix, desc = section
    if prefix is not None:
        title = indent.prefix(prefix)
        if desc is not None:
            title = f"{title} ({desc}):"
        indent.print(title)


def print_pglist(pba: ParsedBuddyArgs, cbp: CurrentBuddyParams):
    sections, indent = cbp.sections, cbp.indent
    if len(sections) != 3:
        log.warning(f"The number ({len(sections)}) of sections is not 2!")
        return
    results, counter, msgs = traverse_pglist(pba, cbp)
    if not results or len(results) == 0 or counter == 0:
        return
    print_section(sections[0], indent)
    sections[0] = NONE_TUPLE  # so that the header info is not reprinted
    with indent:
        print_section(sections[1], indent)
        sections[1] = NONE_TUPLE
        with indent:
            print_section(sections[2], indent)
            sections[2] = NONE_TUPLE
            with indent:
                indent.print(
                    f"- {indent.prefix(cbp.mtype)} (contains {indent.aux_hex(counter)} elements)"
                )
                with indent:
                    for i, result in results:
                        indent.print(indent.prefix(f"[0x{i:02x}] ") + result)
                    if msgs is not None:
                        for msg in msgs:
                            indent.print(msg)
                        print()


def print_mtypes(pba: ParsedBuddyArgs, cbp: CurrentBuddyParams):
    freelists, nr_types = cbp.freelists, cbp.nr_types
    mtypes = pwndbg.aglib.kernel.symbol.migratetype_names()
    if nr_types is None:
        nr_types = len(mtypes)
    for i in range(nr_types):
        cbp.mtype = mtypes[i]
        if pba.mtype is not None and cbp.mtype != pba.mtype:
            continue
        cbp.freelist = freelists[i]
        print_pglist(pba, cbp)


def print_pcp_set(pba: ParsedBuddyArgs, cbp: CurrentBuddyParams):
    pcp = None
    pcp_lists = None
    if cbp.zone.type.has_field("per_cpu_pageset"):
        pcp = per_cpu(cbp.zone["per_cpu_pageset"], pba.cpu)
        pcp_lists = pcp["lists"]
    elif cbp.zone.type.has_field("pageset"):
        pcp = per_cpu(cbp.zone["pageset"], pba.cpu)
        pcp_lists = pcp["pcp"]["lists"]
    cbp.sections[1] = ("per_cpu_pageset", None)
    if pcp is None or pcp_lists is None:
        log.warning("cannot find pcplist")
        return
    nr_pcp_lists = pwndbg.aglib.kernel.symbol.npcplist()
    for i in range(0, nr_pcp_lists, MIGRATE_PCPTYPES):
        # https://elixir.bootlin.com/linux/v6.13.12/source/include/linux/mmzone.h#L660
        order = i // MIGRATE_PCPTYPES
        if pba.order is not None and pba.order != order:
            continue
        cbp.freelists = pcp_lists[order * MIGRATE_PCPTYPES].address
        cbp.nr_types = MIGRATE_PCPTYPES
        if order == 4:
            # https://elixir.bootlin.com/linux/v6.13/source/arch/x86/include/asm/page_types.h#L20
            order = 21 - 12  # HPAGE_SHIFT - PAGE_SHIFT
            cbp.nr_types = nr_pcp_lists % MIGRATE_PCPTYPES
        cbp.sections[2] = (
            f"Order {order}",
            f"size: {cbp.indent.aux_hex(0x1000 * (1 << order))}",
        )
        cbp.order = order
        print_mtypes(pba, cbp)


def print_free_area(pba: ParsedBuddyArgs, cbp: CurrentBuddyParams):
    free_area = cbp.zone["free_area"]
    cbp.sections[1] = ("free_area", None)
    for order in range(free_area.type.array_len):
        if pba.order is not None and pba.order != order:
            continue
        cbp.freelists = free_area[order]["free_list"]
        nr_free = int(free_area[order]["nr_free"])
        cbp.sections[2] = (
            f"Order {order}",
            f"nr_free: {cbp.indent.aux_hex(nr_free)}, size: {cbp.indent.aux_hex(0x1000 * (1 << order))}",
        )
        cbp.order = order
        print_mtypes(pba, cbp)


def print_zones(pba: ParsedBuddyArgs, cbp: CurrentBuddyParams, zones, pcp_only):
    for i in range(pwndbg.aglib.kernel.symbol.nzones()):
        cbp.zone = zones[i]
        name = zones[i]["name"].string()
        if pba.zone is not None and pba.zone != name:
            continue
        cbp.sections[0] = (f"Zone {name}", None)
        print_pcp_set(pba, cbp)
        if not pcp_only:
            print_free_area(pba, cbp)


"""
Based off https://github.com/bata24/gef and https://elixir.bootlin.com/linux/v6.13/source

Simplified visualization from bata24/gef:

+-node_data[MAX_NUMNODES]-+
| *pglist_data (node 0)   |--+
| *pglist_data (node 1)   |  |
| *pglist_data (node 2)   |  |
| ...                     |  |
+-------------------------+  |
                             |
+----------------------------+
|
v
+-pglist_data------------------------------+
| node_zones[MAX_NR_ZONES]                 |
|   +-node_zones[0]----------------------+ |   +--->+-per_cpu_pages--------+
|   |  ...                               | |   |    | ...                  |
|   |  per_cpu_pageset                   |-----+    | lists[NR_PCP_LISTS]  |    +-page-----+
|   |  ...                               | |        |   +-lists[0]-------+ |    | flags    |
|   |  name                              | |        |   | next           |----->| lru.next |->..."
|   |  ...                               | |        |   | prev           | |    | lru.prev |
|   |  free_area[MAX_ORDER]              | |        |   +-lists[1]-------+ |    | ...      |
|   |    +-free_area[0]----------------+ | |        |   | ...            | |    +----------+
|   |    | free_list[MIGRATE_TYPES]    | | |        |   +----------------+ |
|   |    |   +-free_list[0]----------+ | | |        +----------------------+
|   |    |   | next                  |---------+
|   |    |   | prev                  | | | |   |
|   |    |   +-free_list[1]----------+ | | |   |    +-page-----+    +-page-----+    +-page-----+
|   |    |   | ...                   | | | |   |    | flags    |    | flags    |    | flags    |
|   |    |   +-----------------------+ | | |   +--->| lru.next |--->| lru.next |--->| lru.next |->..."
|   |    | nr_free                     | | |        | lru.prev |    | lru.prev |    | lru.prev |
|   |    +-free_area[1]----------------+ | |        | ...      |    | ...      |    | ...      |
|   |    | ...                         | | |        +----------+    +----------+    +----------+
|   |    +-----------------------------+ | |
|   +-node_zones[1]----------------------+ |
|   |  ...                               | |
|   +------------------------------------+ |
| ...                                      |
+------------------------------------------+
"""


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSymbols
@pwndbg.commands.OnlyWhenPagingEnabled
def buddydump(
    zone: str, pcp_only: bool, order: int, mtype: str, cpu: int, node: int, find: int
) -> None:
    node_data = pwndbg.aglib.kernel.node_data()
    if not node_data:
        log.warning("WARNING: Symbol 'node_data' not found")
        return
    if not pwndbg.aglib.kernel.has_debug_info():
        pwndbg.aglib.kernel.buddydump.load_buddydump_typeinfo()
        node_data = pwndbg.aglib.memory.get_typed_pointer("node_data_t", node_data)
    pba = ParsedBuddyArgs(zone, order, mtype, cpu, find)
    cbp = CurrentBuddyParams(
        [NONE_TUPLE] * 3, IndentContextManager(), None, None, None, None, None, None, False
    )
    for node_idx in range(kernel.num_numa_nodes()):
        if node is not None and node_idx != node:
            continue
        zones = None
        if "CONFIG_NUMA" in pwndbg.aglib.kernel.kconfig():
            # only display one node per invocation is probably sufficient under most use cases
            zones = node_data.dereference()[node_idx]["node_zones"]
        else:
            zones = node_data["node_zones"]
        print_zones(pba, cbp, zones, pcp_only)
    if not cbp.found:
        log.warning("No free pages with specified filters found.")
