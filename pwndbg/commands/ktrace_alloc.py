from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Callable
from typing import List

import pwndbg.aglib.regs
import pwndbg.aglib.symbol
import pwndbg.arguments
import pwndbg.color.message as M
from pwndbg.dbg import BreakpointLocation


@dataclass
class KtraceMemAux:
    bt: List[str] = None
    order: int = None


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
            "alloc_pages_noprof",
        )
        self.pallocs = KtraceMemPoints.resolve_names(palloc_names)
        pfree_names = (  # page *, order
            "__free_pages",
        )
        self.pfrees = KtraceMemPoints.resolve_names(pfree_names)
        self.sps = []
        # auxiliary data that serves different purposes depending on the stop point
        self.aux = KtraceMemAux()

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
        try:
            cache = pwndbg.aglib.kernel.slab.find_containing_slab_cache(objaddr)
            print(f"[SLUB ALLOC] {cache.name} obj @ {hex(objaddr)}")
        except Exception:
            print(M.warn(f"[SLUB ALLOC] invalid SLUB object @ {hex(objaddr)}"))
        return False

    @staticmethod
    def kalloc_handler(sp: pwndbg.dbg_mod.StopPoint) -> bool:
        pwndbg.dbg.selected_inferior().trace_ret(KtraceMemPoints._kalloc_handler, True)
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
    def _palloc_handler() -> bool:
        self = get_kmem_tracepoints()
        page = pwndbg.aglib.regs.read_reg_uncached(pwndbg.aglib.regs.retval)
        order = self.aux.order
        print(f"[PAGE ALLOC] order-{order} page @ {hex(page)}")
        return False

    @staticmethod
    def palloc_handler(sp: pwndbg.dbg_mod.StopPoint) -> bool:
        self = get_kmem_tracepoints()
        order = pwndbg.arguments.argument(1)
        pwndbg.dbg.selected_inferior().trace_ret(KtraceMemPoints._palloc_handler, True)
        self.aux.order = order
        return False

    @staticmethod
    def pfree_handler(sp: pwndbg.dbg_mod.StopPoint) -> bool:
        page = pwndbg.arguments.argument(0)
        order = pwndbg.arguments.argument(1)
        print(f"[PAGE FREE] order-{order} page @ {hex(page)}")
        return False

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
