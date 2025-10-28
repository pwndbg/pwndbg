from __future__ import annotations

import argparse
from dataclasses import dataclass
from typing import List

import pwndbg.aglib.regs
import pwndbg.aglib.symbol
import pwndbg.arguments
import pwndbg.color as C
import pwndbg.color.message as M
import pwndbg.commands
from pwndbg.dbg import BreakpointLocation

parser = argparse.ArgumentParser(
    description="Tracing kernel memory (SLUB and buddy) allocations and deallocations."
)
parser.add_argument(
    "-s", "--trace-slab", action="store_true", help="enable slab (de)allocation tracing"
)
parser.add_argument(
    "-b", "--trace-buddy", action="store_true", help="enable buddy (de)allocation tracing"
)
parser.add_argument("-v", "--verbose", action="store_true", help="print backtraces")
parser.add_argument("-c", "--command", type=str, default="n", help="command to step through")


@dataclass
class KtraceMemAux:
    bt: List[str] = None
    order: int = None


def _format_slab_output(is_free: bool, objaddr: int):
    if objaddr == 0:
        return
    if is_free:
        prefix = C.red("[SLAB FREE]")
    else:
        prefix = C.green("[SLAB ALLOC]")
    try:
        cache = pwndbg.aglib.kernel.slab.find_containing_slab_cache(objaddr)
        addr = C.blue(hex(objaddr))
        print(f"{prefix} {C.blue(cache.name)} obj @ {addr}")
    except Exception:
        print(M.warn(f"{prefix} invalid SLUB object @ {objaddr}"))


def _format_page_output(is_free: bool, page: int, order: int):
    if is_free:
        prefix = C.red("[PAGE FREE]")
    else:
        prefix = C.green("[PAGE ALLOC]")
    prefix += C.blue(f" order-{order}")
    physmap = pwndbg.aglib.kernel.page_to_virt(page)
    desc = f"{C.blue(hex(page))} (physmap: {C.red(hex(physmap))})"
    print(f"{prefix} page @ {desc}")


class KmemTracepoints:
    def __init__(self):
        # try to capture the lowest possible level of exported functions in the (de)alloc chain
        # for example __alloc_pages_bulk calls __alloc_pages and only __alloc_pages is included
        # lists might not be complete
        # try to resolve all names, if does not exist, means it is not exported for that version
        kmalloc_names = (
            "__kmalloc",
            "__kmalloc_node",
            "__kmalloc_node_track_caller",
            "__kmalloc_track_caller",
            "__krealloc",
            "kmalloc_order",
            "kmalloc_order_trace",
            "kmem_cache_alloc",
            "kmem_cache_alloc_node",
            "kmem_cache_alloc_node_trace",
            "kmem_cache_alloc_trace",
            "kmem_cache_alloc_lru",
            "krealloc",
            "kmalloc_node_trace",
            "kmalloc_trace",
            "__kmalloc_node_noprof",
            "__kmalloc_noprof",
            "kmalloc_node_trace_noprof",
            "kmalloc_node_track_caller_noprof",
            "kmalloc_trace_noprof",
            "kmem_cache_alloc_lru_noprof",
            "kmem_cache_alloc_node_noprof",
            "kmem_cache_alloc_noprof",
            "krealloc_noprof",
            "__kmalloc_node_track_caller_noprof",
            "__kmalloc_cache_node_noprof",
            "__kmalloc_cache_noprof",
        )
        self.kallocs = KmemTracepoints.resolve_names(kmalloc_names)
        kfree_names = ("kfree",)
        self.kfrees = KmemTracepoints.resolve_names(kfree_names)
        palloc_names = (  # all of those functions have the 2nd arg == order
            "__alloc_frozen_pages_noprof",
            "__alloc_pages",
            "__alloc_pages_nodemask",
            "alloc_pages_noprof",
        )
        self.pallocs = KmemTracepoints.resolve_names(palloc_names)
        pfree_names = (  # page *, order
            "__free_pages",
        )
        self.pfrees = KmemTracepoints.resolve_names(pfree_names)
        self.sps = []
        # auxiliary data that serves different purposes depending on the stop point
        self.aux = KtraceMemAux()
        self.slab_tracepoints_enabled = True
        self.buddy_tracepoints_enabled = True

    @staticmethod
    def resolve_names(names):
        result = []
        for name in names:
            addr = pwndbg.aglib.symbol.lookup_symbol_addr(name)
            if addr is None:
                continue
            result.append(addr)
        return result

    @staticmethod
    def _kalloc_handler() -> bool:
        objaddr = pwndbg.aglib.regs.read_reg_uncached(pwndbg.aglib.regs.retval)
        _format_slab_output(False, objaddr)
        return False

    @staticmethod
    def kalloc_handler(sp: pwndbg.dbg_mod.StopPoint) -> bool:
        pwndbg.dbg.selected_inferior().trace_ret(KmemTracepoints._kalloc_handler, True)
        return False

    @staticmethod
    def kfree_handler(sp: pwndbg.dbg_mod.StopPoint) -> bool:
        objaddr = pwndbg.arguments.argument(0)
        _format_slab_output(True, objaddr)
        return False

    @staticmethod
    def _palloc_handler() -> bool:
        self = get_kmem_tracepoints()
        page = pwndbg.aglib.regs.read_reg_uncached(pwndbg.aglib.regs.retval)
        order = self.aux.order
        _format_page_output(False, page, order)
        return False

    @staticmethod
    def palloc_handler(sp: pwndbg.dbg_mod.StopPoint) -> bool:
        self = get_kmem_tracepoints()
        order = pwndbg.arguments.argument(1)
        pwndbg.dbg.selected_inferior().trace_ret(KmemTracepoints._palloc_handler, True)
        self.aux.order = order
        return False

    @staticmethod
    def pfree_handler(sp: pwndbg.dbg_mod.StopPoint) -> bool:
        page = pwndbg.arguments.argument(0)
        order = pwndbg.arguments.argument(1)
        _format_page_output(True, page, order)
        return False

    def register_breakpoints(self):
        inf = pwndbg.dbg.selected_inferior()
        for kalloc in self.kallocs:
            bp = BreakpointLocation(kalloc)
            sp = inf.break_at(bp, KmemTracepoints.kalloc_handler, internal=True)
            self.sps.append(sp)
        for kfree in self.kfrees:
            bp = BreakpointLocation(kfree)
            sp = inf.break_at(bp, KmemTracepoints.kfree_handler, internal=True)
            self.sps.append(sp)
        for palloc in self.pallocs:
            bp = BreakpointLocation(palloc)
            sp = inf.break_at(bp, KmemTracepoints.palloc_handler, internal=True)
            self.sps.append(sp)
        for pfree in self.pfrees:
            bp = BreakpointLocation(pfree)
            sp = inf.break_at(bp, KmemTracepoints.pfree_handler, internal=True)
            self.sps.append(sp)

    def remove_breakpoints(self):
        for sp in self.sps:
            sp.remove()
        self.sps = []


@pwndbg.lib.cache.cache_until("objfile")
def get_kmem_tracepoints():
    return KmemTracepoints()


@pwndbg.commands.Command(parser, category=pwndbg.commands.CommandCategory.KERNEL)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelDebugSymbols
@pwndbg.commands.OnlyWhenPagingEnabled
def kmem_trace(trace_slab: bool, trace_buddy: bool, verbose: bool, command: str):
    tps = get_kmem_tracepoints()
    tps.slab_tracepoints_enabled = trace_slab
    tps.buddy_tracepoints_enabled = trace_buddy
    tps.register_breakpoints()
    ret = pwndbg.dbg.selected_inferior().runcmd(command)
    out = ""
    for line in ret.splitlines():
        if "[SLAB" in line or "[PAGE" in line:
            out += line + "\n"
    print(out)
    tps.remove_breakpoints()
