from __future__ import annotations

import argparse
import logging

import pwndbg
import pwndbg.aglib.memory
import pwndbg.aglib.symbol
import pwndbg.commands
from pwndbg.aglib.kernel import per_cpu
from pwndbg.aglib.kernel.macros import for_each_entry
from pwndbg.commands import CommandCategory

log = logging.getLogger(__name__)

parser = argparse.ArgumentParser(description="Print Per-CPU page list")

parser.add_argument("zone", type=int, nargs="?", help="")
# parser.add_argument("list_num", type=int, help="")


def print_zone(zone: int, list_num=None) -> None:
    contig_value = pwndbg.aglib.symbol.lookup_symbol("contig_page_data")
    if not contig_value:
        print("WARNING: Symbol 'contig_page_data' not found")
        return

    print(f"Zone {zone}")
    contig_value = contig_value.dereference()
    pageset_addr = per_cpu(contig_value["node_zones"][zone]["pageset"])
    pageset = pwndbg.aglib.memory.get_typed_pointer_value("struct per_cpu_pageset", pageset_addr)
    pcp = pageset["pcp"]
    print("count: ", int(pcp["count"]))
    print("high: ", int(pcp["high"]))
    print("")
    for i in range(4):
        print(f"pcp.lists[{i}]:")

        count = 0
        for e in for_each_entry(pcp["lists"][i], "struct page", "lru"):
            count += 1
            print(e.value_to_human_readable())

        if count == 0:
            print("EMPTY")
        else:
            print(f"{count} entries")

        print("")


@pwndbg.commands.Command(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
@pwndbg.commands.OnlyWhenPagingEnabled
def pcplist(zone: int = None, list_num: int = None) -> None:
    log.warning("This command is a work in progress and may not work as expected.")
    if zone:
        print_zone(zone, list_num)
    else:
        for i in range(3):
            print_zone(i)
