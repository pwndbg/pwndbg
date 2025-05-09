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

parser = argparse.ArgumentParser(description="Print Per-CPU page list.")
parser.add_argument("zone", type=int, nargs="?", help="")
parser.add_argument(
    "-pcp", "--pcp-only", action="store_true", dest="pcp_only", help="Print only pcp lists."
)

MAX_PG_FREE_LIST_STR_RESULT_CNT = 0x10
MAX_PG_FREE_LIST_CNT = 0x1000
NONE_TUPLE = (None, None)


def array_size(t: pwndbg.dbg_mod.Value):
    return t.type.sizeof // t.type.target().sizeof


def static_str_arr(name: str) -> List[str]:
    results = []
    arr = pwndbg.aglib.symbol.lookup_symbol(name).dereference()
    sz = array_size(arr)
    for i in range(sz):
        results.append(arr[i].string())
    return results


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
    results, counter, msgs = traverse_pglist(free_list, indent)
    if not results or len(results) == 0 or counter == 0:
        return False
    # this needs to be done after passing the previous if-statement buf before the first print within `with indent`
    if len(sections) != 2:
        log.warning("The number of sections is not 2!")
        return False
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
    free_list: pwndbg.dbg_mod.Value, sections: List[Tuple[str, str]], indent: IndentContextManager
) -> bool:
    for i, name in enumerate(static_str_arr("migratetype_names")):
        _free_list = free_list[i]
        if print_pglist(_free_list, name, sections, indent):
            sections = [NONE_TUPLE, NONE_TUPLE]
    return len(sections) == 0


def print_pcp_lists(zone: pwndbg.dbg_mod.Value | None, indent: IndentContextManager):
    pcp = per_cpu(zone["per_cpu_pageset"])
    sections = [
        ("per_cpu_pageset", f"number of pages {indent.aux_hex(int(pcp["count"]))}"),
        NONE_TUPLE,
    ]
    pcp_lists = pcp["lists"]
    for i in range(array_size(pcp_lists)):
        if print_pglist(pcp_lists[i], f"PCP List {i}", sections, indent):
            sections[0] = NONE_TUPLE  # do not reprint section info multiple times


def print_free_area(zone: pwndbg.dbg_mod.Value | None, indent: IndentContextManager):
    free_area = zone["free_area"]
    sections: List[Tuple[str, str]] = [("free_area", None), NONE_TUPLE]
    for order in range(array_size(free_area)):
        free_list = free_area[order]["free_list"]
        nr_free = int(free_area[order]["nr_free"])
        order_desc = (
            f"Order {order}",
            f"nr_free: {indent.aux_hex(nr_free)}, size: {indent.aux_hex(0x1000 * (2 ** order))}",
        )
        sections[1] = order_desc
        if print_mtypes(free_list, sections, indent):
            sections[0] = NONE_TUPLE  # do not reprint section info multiple times


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
@pwndbg.commands.OnlyWhenPagingEnabled
def pcplist(zone: int = None, pcp_only: bool = False) -> None:
    indent = IndentContextManager()
    node_data = pwndbg.aglib.symbol.lookup_symbol("node_data")
    if not node_data:
        log.warning("WARNING: Symbol 'node_data' not found")
        return
    # TODO: this command currently only supports one node which should be the common case
    zones = node_data.dereference()[0]["node_zones"]
    for i, name in enumerate(static_str_arr("zone_names")):
        indent.print(indent.prefix(f"Zone {name}"))
        print_pcp_lists(zones[i], indent)
        if not pcp_only:
            print_free_area(zones[i], indent)
