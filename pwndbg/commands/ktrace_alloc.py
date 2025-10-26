from __future__ import annotations

import re
from typing import Callable

import pwndbg.aglib.regs
import pwndbg.aglib.symbol
import pwndbg.arguments
import pwndbg.color.message as M
from pwndbg.dbg import BreakpointLocation


class KtraceMemPoints:
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
        self.kallocs = KtraceMemPoints.resolve_names(kmalloc_names)
        kfree_names = ("kfree",)
        self.kfrees = KtraceMemPoints.resolve_names(kfree_names)
        palloc_names = (  # all of those functions have the 2nd arg == order
            "__alloc_frozen_pages_noprof",
            "__alloc_pages",
            "__alloc_pages_nodemask",
        )
        self.pallocs = KtraceMemPoints.resolve_names(palloc_names)
        pfree_names = (  # page *, order
            "__free_pages",
        )
        self.pfrees = KtraceMemPoints.resolve_names(pfree_names)
        self.sps = []

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
    def kalloc_handler(sp: pwndbg.dbg_mod.StopPoint) -> bool:
        objaddr = KtraceMemPoints.trace_retval()
        try:
            cache = pwndbg.aglib.kernel.slab.find_containing_slab_cache(objaddr)
            print(f"[SLUB ALLOC] {cache.name} obj @ {hex(objaddr)}")
        except Exception:
            print(M.warn(f"[SLUB ALLOC] invalid SLUB object @ {hex(objaddr)}"))
            return True
        return False

    @staticmethod
    def kfree_handler(sp: pwndbg.dbg_mod.StopPoint) -> bool:
        objaddr = pwndbg.arguments.argument(0)
        if objaddr == 0:
            return False
        try:
            cache = pwndbg.aglib.kernel.slab.find_containing_slab_cache(objaddr)
            print(f"[SLUB FREE] {cache.name} obj @ {hex(objaddr)}")
        except Exception:
            print(M.warn(f"[SLUB FREE] invalid SLUB object @ {hex(objaddr)}"))
        return False

    @staticmethod
    def palloc_handler(sp: pwndbg.dbg_mod.StopPoint) -> bool:
        page = KtraceMemPoints.trace_retval()
        order = pwndbg.arguments.argument(1)
        print(f"[PAGE ALLOC] order-{order} page @ {hex(page)}")
        return False

    @staticmethod
    def pfree_handler(sp: pwndbg.dbg_mod.StopPoint) -> bool:
        page = pwndbg.arguments.argument(0)
        order = pwndbg.arguments.argument(1)
        print(f"[PAGE FREE] order-{order} page @ {hex(page)}")
        return False

    @staticmethod
    def trace_retval():
        bt = pwndbg.commands.context.context_backtrace()
        pattern = re.compile(r"0x[0-9a-f]+")
        retaddr = pattern.search(bt[1]).group(0)
        if not retaddr:
            return
        retaddr = int(retaddr, 16)
        pwndbg.dbg.selected_inferior().dispatch_execution_controller(
            pwndbg.aglib.next.break_next_ret
        )
        retval = pwndbg.aglib.regs.read_reg_uncached(pwndbg.aglib.regs.retval)
        return retval

    def register_breakpoints(self):
        inf = pwndbg.dbg.selected_inferior()
        for kalloc in self.kallocs:
            bp = BreakpointLocation(kalloc)
            sp = inf.break_at(bp, KtraceMemPoints.kalloc_handler, internal=True)
            self.sps.append(sp)
        for kfree in self.kfrees:
            bp = BreakpointLocation(kfree)
            sp = inf.break_at(bp, KtraceMemPoints.kfree_handler, internal=True)
            self.sps.append(sp)
        for palloc in self.pallocs:
            bp = BreakpointLocation(palloc)
            sp = inf.break_at(bp, KtraceMemPoints.palloc_handler, internal=True)
            self.sps.append(sp)
        for pfree in self.pfrees:
            bp = BreakpointLocation(pfree)
            sp = inf.break_at(bp, KtraceMemPoints.pfree_handler, internal=True)
            self.sps.append(sp)

    def remove_breakpoints(self):
        for sp in self.sps:
            sp.remove()
        self.sps = []


@pwndbg.lib.cache.cache_until("objfile")
def get_kmem_tracepoints():
    return KtraceMemPoints()
