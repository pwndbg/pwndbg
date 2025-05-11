from __future__ import annotations

import argparse
import logging
from dataclasses import dataclass
from typing import List
from typing import Tuple

import pwndbg
import pwndbg.aglib.memory
import pwndbg.aglib.symbol
import pwndbg.commands
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
    zone: pwndbg.dbg_mod.Value | None
    order: int | None
    mtype: str | None
    cpu: int | None
    sections: List[Tuple[str, str]]
    indent: IndentContextManager

def cpu_limitcheck(cpu: str):
    if cpu is None:
        return None
    nr_cpus = pwndbg.aglib.kernel.nproc()
    if cpu.isdigit() and int(cpu) < nr_cpus:
        return int(cpu)
    raise argparse.ArgumentTypeError(
        f"The --cpu option takes in a number less than nr_cpu_ids ({nr_cpus})."
    )


parser = argparse.ArgumentParser(description="Print Per-CPU page list.")
parser.add_argument(
    "-z",
    "--zone",
    type=str,
    dest="zone",
    choices=["DMA", "DMA32", "Normal", "HighMem", "Movable", "Device"],
    default=None,
    help="",
)
parser.add_argument("-o", "--order", type=int, dest="order", help="")
parser.add_argument(
    "-m",
    "--mtype",
    type=str,
    dest="mtype",
    choices=["Unmovable", "Movable", "Reclaimable", "HighAtomic", "CMA", "Isolate"],
    default=None,
    help="",
)
parser.add_argument("-p", "--pcp-only", action="store_true", dest="pcp_only", default=False, help="")
parser.add_argument("-c", "--cpu", type=cpu_limitcheck, dest="cpu", default=None)


def static_str_arr(name: str) -> List[str]:
    arr = pwndbg.aglib.symbol.lookup_symbol(name).dereference()
    return [arr[i].string() for i in range(len(arr))]


def traverse_pglist(
    free_list: pwndbg.dbg_mod.Value, indent: IndentContextManager
) -> Tuple[List[str], int, List[str]]:
    if free_list is None or int(free_list["next"]) == 0:
        return None, 0, None
    seen_pages = set()
    results = []
    counter = 0
    msgs = []
    for e in for_each_entry(free_list, "struct page", "lru"):
        page = int(e)
        if counter < MAX_PG_FREE_LIST_STR_RESULT_CNT:
            phys_addr = pwndbg.aglib.kernel.page_to_phys(page)
            physmap_addr = pwndbg.aglib.kernel.page_to_physmap(page)
            results.append(
                f"{indent.addr_hex(physmap_addr)} [page: {indent.aux_hex(page)}, phys: {indent.aux_hex(phys_addr)}]"
            )
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


def print_pglist(
    free_list: pwndbg.dbg_mod.Value,
    name: str | None,
    sections: List[Tuple[str, str]],
    indent: IndentContextManager,
):
    if len(sections) != 3:
        log.warning(f"The number ({len(sections)}) of sections is not 2!")
        return
    results, counter, msgs = traverse_pglist(free_list, indent)
    if not results or len(results) == 0 or counter == 0:
        return
    # this needs to be done after passing the previous if-statement buf before the first print within `with indent`
    print_section(sections[0], indent)
    sections[0] = NONE_TUPLE
    with indent:
        print_section(sections[1], indent)
        sections[1] = NONE_TUPLE
        with indent:
            print_section(sections[2], indent)
            sections[2] = NONE_TUPLE
            with indent:
                indent.print(
                    f"- {indent.prefix(name)} (contains {indent.aux_hex(counter)} elements)"
                )
                with indent:
                    for i, result in enumerate(results):
                        indent.print(indent.prefix(f"[0x{i:02x}] ") + result)
                    if msgs is not None:
                        for msg in msgs:
                            indent.print(msg)
                        print()


def print_mtypes(
    free_list: pwndbg.dbg_mod.Value,
    pba: ParsedBuddyArgs,
    nr_types: int | None = None,
):
    names = static_str_arr("migratetype_names")
    if nr_types is None:
        nr_types = len(names)
    for i in range(nr_types):
        name = names[i]
        if pba.mtype is not None and name != pba.mtype:
            continue
        print_pglist(free_list[i], name, pba.sections, pba.indent)


def print_pcp_set(pba: ParsedBuddyArgs):
    pcp = per_cpu(pba.zone["per_cpu_pageset"], pba.cpu)
    pba.sections[1] = ("per_cpu_pageset", f"number of pages {pba.indent.aux_hex(int(pcp["count"]))}")
    nr_pcp_lists = pwndbg.aglib.kernel.npcplist()
    pcp_lists = pcp["lists"]
    for i in range(0, nr_pcp_lists, MIGRATE_PCPTYPES):
        # https://elixir.bootlin.com/linux/v6.13.12/source/include/linux/mmzone.h#L660
        order = i // MIGRATE_PCPTYPES
        if pba.order is not None and pba.order != order:
            continue
        free_list = pcp_lists[order * MIGRATE_PCPTYPES].address
        nr_types = MIGRATE_PCPTYPES
        if order == MIGRATE_PCPTYPES + 1:
            order = 11 # THPs are 2MB
            nr_types = nr_pcp_lists % MIGRATE_PCPTYPES
        pba.sections[2] = (
            f"Order {order}",
            f"size: {pba.indent.aux_hex(0x1000 * (1 << order))}",
        )
        print_mtypes(free_list, pba, nr_types)


def print_free_area(pba: ParsedBuddyArgs):
    free_area = pba.zone["free_area"]
    pba.sections[1] = ("free_area", None)
    for order in range(len(free_area)):
        if pba.order is not None and pba.order != order:
            continue
        free_list = free_area[order]["free_list"]
        nr_free = int(free_area[order]["nr_free"])
        pba.sections[2] = (
            f"Order {order}",
            f"nr_free: {pba.indent.aux_hex(nr_free)}, size: {pba.indent.aux_hex(0x1000 * (1 << order))}",
        )
        print_mtypes(free_list, pba)


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
@pwndbg.commands.OnlyWhenPagingEnabled
def pcplist(zone: str, pcp_only: bool, order: int, mtype: str, cpu: int) -> None:
    node_data = pwndbg.aglib.symbol.lookup_symbol("node_data")
    if not node_data:
        log.warning("WARNING: Symbol 'node_data' not found")
        return
    pba = ParsedBuddyArgs(None, order, mtype, cpu, [NONE_TUPLE] * 3, IndentContextManager())
    # TODO: this command currently only supports one node which should be the common case
    zones = node_data.dereference()[0]["node_zones"]
    for i, name in enumerate(static_str_arr("zone_names")):
        if zone is not None and zone != name:
            continue
        pba.zone = zones[i]
        pba.sections[0] = (f"Zone {name}", None)
        print_pcp_set(pba)
        if not pcp_only:
            print_free_area(pba)
