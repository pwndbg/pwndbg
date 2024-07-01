from __future__ import annotations

import argparse

import gdb

import pwndbg.commands
import pwndbg.gdblib.memory
from pwndbg.commands import CommandCategory
from pwndbg.gdblib.kernel import per_cpu
from pwndbg.gdblib.kernel.macros import for_each_entry

parser = argparse.ArgumentParser(description="Print Per-CPU page list")

parser.add_argument("zone", type=int, nargs="?", help="")
# parser.add_argument("list_num", type=int, help="")


def print_zone(zone, list_num=None) -> None:
    print(f"Zone {zone}")
    pageset_addr = per_cpu(
        gdb.lookup_global_symbol("contig_page_data").value()["node_zones"][zone]["pageset"]
    )
    pageset = pwndbg.gdblib.memory.get_typed_pointer_value(
        gdb.lookup_type("struct per_cpu_pageset"), pageset_addr
    )
    pcp = pageset["pcp"]
    print("count: ", pcp["count"])
    print("high: ", pcp["high"])
    print("")
    for i in range(4):
        print(f"pcp.lists[{i}]:")

        count = 0
        for e in for_each_entry(pcp["lists"][i], "struct page", "lru"):
            count += 1
            print(e)

        if count == 0:
            print("EMPTY")
        else:
            print(f"{count} entries")

        print("")


@pwndbg.commands.ArgparsedCommand(parser, category=CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSyms
@pwndbg.commands.OnlyWhenPagingEnabled
def pcplist(zone=None, list_num=None) -> None:
    if zone:
        print_zone(zone, list_num)
    else:
        for i in range(3):
            print_zone(i)
