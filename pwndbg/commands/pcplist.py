from __future__ import annotations

import argparse
import logging
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


def pcp_typecheck(pcp: str):
    str_opts = {"none", "only", "all"}
    nr_pcp_lists = pwndbg.aglib.kernel.npcplist()
    if pcp is None:
        return "all"  # default
    if pcp in str_opts:
        return pcp
    if pcp.isdigit() and int(pcp) < nr_pcp_lists:
        return pcp
    raise argparse.ArgumentTypeError(f"Only {str_opts} and numbers < {nr_pcp_lists} are allowed.")


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
parser.add_argument("-p", "--pcp", type=pcp_typecheck, dest="pcp", default="all", help="")
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
            msgs.append(
                f"Cyclic doubly linked list detected: {indent.addr_hex(physmap_addr)} [page: {indent.aux_hex(page)}, phys: {indent.aux_hex(phys_addr)}]"
            )
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
) -> bool:
    if len(sections) != 2:
        log.warning("The number of sections is not 2!")
        return False
    results, counter, msgs = traverse_pglist(free_list, indent)
    if not results or len(results) == 0 or counter == 0:
        return False
    # this needs to be done after passing the previous if-statement buf before the first print within `with indent`
    with indent:
        print_section(sections[0], indent)
        with indent:
            print_section(sections[1], indent)
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
    return True


def print_mtypes(
    free_list: pwndbg.dbg_mod.Value,
    sections: List[Tuple[str, str]],
    indent: IndentContextManager,
    mtype: str | None,
) -> bool:
    for i, name in enumerate(static_str_arr("migratetype_names")):
        if mtype is not None and name != mtype:
            continue
        _free_list = free_list[i]
        if print_pglist(_free_list, name, sections, indent):
            sections = [NONE_TUPLE, NONE_TUPLE]
    # returns if it succeeded or not
    return sections[0] == NONE_TUPLE and sections[1] == NONE_TUPLE


def print_pcp_lists(
    zone: pwndbg.dbg_mod.Value | None, indent: IndentContextManager, choice: str, cpu: int | None
):
    if choice == "none":
        return
    pcp = per_cpu(zone["per_cpu_pageset"], cpu)
    sections = [
        ("per_cpu_pageset", f"number of pages {indent.aux_hex(int(pcp["count"]))}"),
        NONE_TUPLE,
    ]
    for i in range(pwndbg.aglib.kernel.npcplist()):
        if choice.isdigit() and int(choice) != i:
            continue
        if print_pglist(pcp["lists"][i], f"PCP List {i}", sections, indent):
            sections[0] = NONE_TUPLE  # do not reprint section info multiple times


def print_free_area(
    zone: pwndbg.dbg_mod.Value | None,
    indent: IndentContextManager,
    order: int | None,
    mtype: str | None,
):
    free_area = zone["free_area"]
    sections: List[Tuple[str, str]] = [("free_area", None), NONE_TUPLE]
    for i in range(len(free_area)):
        if order is not None and i != order:
            continue
        free_list = free_area[i]["free_list"]
        nr_free = int(free_area[i]["nr_free"])
        sections[1] = (
            f"Order {i}",
            f"nr_free: {indent.aux_hex(nr_free)}, size: {indent.aux_hex(0x1000 * (2 ** i))}",
        )
        if print_mtypes(free_list, sections, indent, mtype):
            sections[0] = NONE_TUPLE  # do not reprint section info multiple times


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
@pwndbg.commands.OnlyWhenPagingEnabled
def pcplist(zone: str, pcp: str, order: int, mtype: str, cpu: int) -> None:
    indent = IndentContextManager()
    node_data = pwndbg.aglib.symbol.lookup_symbol("node_data")
    if not node_data:
        log.warning("WARNING: Symbol 'node_data' not found")
        return
    # TODO: this command currently only supports one node which should be the common case
    zones = node_data.dereference()[0]["node_zones"]
    for i, name in enumerate(static_str_arr("zone_names")):
        if zone is not None and zone != name:
            continue
        indent.print(indent.prefix(f"Zone {name}"))
        if mtype is None and order is None:
            print_pcp_lists(zones[i], indent, pcp, cpu)
        if pcp != "only" and not pcp.isdigit():
            print_free_area(zones[i], indent, order, mtype)
