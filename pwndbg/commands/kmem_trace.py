from __future__ import annotations

import argparse
import threading
from typing import Any

import pwndbg.aglib
import pwndbg.aglib.kernel
import pwndbg.aglib.kernel.slab
import pwndbg.aglib.symbol
import pwndbg.arguments
import pwndbg.commands.context
import pwndbg.dbg_mod
import pwndbg.lib.cache
from pwndbg import color
from pwndbg.color import message
from pwndbg.dbg_mod import BreakpointLocation
from pwndbg.dbg_mod import DebuggerType

parser = argparse.ArgumentParser(
    description="""
Trace kernel memory (SLUB and buddy) allocations and frees.

This command will execute `next` in the debugger, and print out all (de)allocations that happen until
the command finishes. As such this makes most sense to call when the PC is on a function call instruction.
Only (de)allocations triggered by the current function are considered (rather than other threads etc).

If neither `-s` nor `-b` are passed, both allocators are traced.
    """,
)
parser.add_argument(
    "-s", "--trace-slab", action="store_true", help="do only slab allocator tracing"
)
parser.add_argument(
    "-b", "--trace-buddy", action="store_true", help="do only buddy allocator tracing"
)
parser.add_argument("-v", "--verbose", action="store_true", help="print backtraces")
parser.add_argument(
    "-c",
    "--command",
    type=str,
    default="next",
    help="trace during the execution of this command",
)
parser.add_argument(
    "--all",
    action="store_true",
    help="display ALL memory allocations/frees regardless if they are triggered by the current function.",
)


class KmemTracepointsData:
    def __init__(self, verbose: bool, trace_all: bool) -> None:
        self.results: list[str] = []
        self.order = 0
        self.mutex = threading.RLock()
        self.verbose = verbose
        self.curr = None  # None means tracing all
        if not trace_all:
            # current frame only accounting for jumps
            if inf := pwndbg.dbg.selected_frame():
                if parent := inf.parent():
                    pc = parent.pc()
                    if symbol_name := pwndbg.aglib.symbol.resolve_addr(pc):
                        self.curr = symbol_name.split("+")[0]

            if self.curr is None:
                print(message.warn("Couldn't locate frame properly. Tracing --all."))

    def add_result(self, result: str) -> None:
        if not result:
            return
        with self.mutex:
            bt = pwndbg.commands.context.context_backtrace(False)
            if not self.curr or any(self.curr in line for line in bt):
                self.results.append(result)
                if self.verbose:
                    self.results += bt

    def _format_kmem_tracepoint_output(
        self, prefix: str, name: str, type: str, addr: int | None
    ) -> str:
        prefix = prefix.ljust(12, " ")
        if "FREE" in prefix:
            prefix = color.red(prefix)
        else:
            prefix = color.green(prefix)
        name = color.blue(name.ljust(20, " "))
        type = type.ljust(4, " ")
        return f"{prefix} {name} {type} @ {color.blue(hex(addr) if addr else str(addr))}"

    def format_slab_kmem_tracepoint_output(self, is_free: bool, objaddr: int | None) -> None:
        if is_free:
            prefix = "[SLAB FREE]"
        else:
            prefix = "[SLAB ALLOC]"
        cache = None
        if objaddr:
            _, cache = pwndbg.aglib.kernel.slab.find_containing_slab_cache(objaddr)
        result = message.warn(
            f"{prefix} invalid SLUB object @ {hex(objaddr) if objaddr else objaddr}"
        )

        if cache is not None:
            result = self._format_kmem_tracepoint_output(prefix, cache.name, "obj", objaddr)
        self.add_result(result)

    def format_page_kmem_tracepoint_output(
        self, is_free: bool, page: int | None, order: int
    ) -> None:
        if is_free:
            prefix = "[PAGE FREE]"
        else:
            prefix = "[PAGE ALLOC]"
        name = f"order-{order}"
        result = self._format_kmem_tracepoint_output(prefix, name, "page", page)
        if page is not None:
            physmap = pwndbg.aglib.kernel.page_to_virt(page)
            result += f" (physmap: {color.red(hex(physmap))})"
        self.add_result(result)


class KmemTracepoints:
    # exceptions to the default processing of (de)alloc funcs
    # the tuple is interpreted on a handler basis
    # e.g. `"kmem_cache_free": (1,)` means the second argument of kmem_cache_free is the address of freed object
    EXCEPTIONS: dict[str, tuple[Any, ...]] = {"kmem_cache_free": (1,)}

    def __init__(self) -> None:
        # try to capture the lowest possible level of exported functions in the (de)alloc chain
        # for example __alloc_pages_bulk calls __alloc_pages and only __alloc_pages is included
        # lists might not be complete
        # try to resolve all names, if does not exist, means it is not exported for that version
        # for the alloc functions, only the return value matters
        kmalloc_names = (  # (trys to) include all slab alloc functions for all v5.x and v6.x
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
        self.kallocs = self.resolve_names(kmalloc_names)
        kfree_names = (
            "kfree",
            "kfree_nolock",
            "kmem_cache_free",
        )
        self.kfrees = self.resolve_names(kfree_names)
        palloc_names = (  # all of those functions have the 2nd arg == order
            "__alloc_frozen_pages_noprof",
            "__alloc_pages",
            "__alloc_pages_nodemask",
            "alloc_pages_noprof",
        )
        self.pallocs = self.resolve_names(palloc_names)
        pfree_names = (  # page *, order
            "__free_pages",
        )
        self.pfrees = self.resolve_names(pfree_names)
        self.sps: list[pwndbg.dbg_mod.StopPoint] = []
        self.slab_tracepoints_enabled = True
        self.buddy_tracepoints_enabled = True

    def resolve_names(self, names: tuple[str, ...]) -> list[int]:
        result = []
        for name in names:
            addr = pwndbg.aglib.symbol.lookup_symbol_addr(name)
            if addr is None:
                continue
            result.append(addr)
        return result

    @staticmethod
    def _kalloc_handler() -> bool:
        assert pwndbg.aglib.regs.retval

        self = get_kmem_tracepoints()
        objaddr = pwndbg.aglib.regs.read_reg_uncached(pwndbg.aglib.regs.retval)
        self.data.format_slab_kmem_tracepoint_output(False, objaddr)
        return False

    @staticmethod
    def kalloc_handler(sp: pwndbg.dbg_mod.StopPoint) -> bool:
        pwndbg.dbg.selected_inferior().trace_ret(KmemTracepoints._kalloc_handler, True)
        return False

    @staticmethod
    def kfree_handler(sp: pwndbg.dbg_mod.StopPoint) -> bool:
        self = get_kmem_tracepoints()
        arg: int = 0
        if symbol_name := pwndbg.aglib.symbol.resolve_addr(pwndbg.aglib.regs.pc):
            symbol_name = symbol_name.split("+")[0]
            if symbol_name in KmemTracepoints.EXCEPTIONS:
                arg = KmemTracepoints.EXCEPTIONS[symbol_name][0]
        objaddr = pwndbg.arguments.argument(arg)
        self.data.format_slab_kmem_tracepoint_output(True, objaddr)
        return False

    @staticmethod
    def _palloc_handler() -> bool:
        assert pwndbg.aglib.regs.retval

        self = get_kmem_tracepoints()
        page = pwndbg.aglib.regs.read_reg_uncached(pwndbg.aglib.regs.retval)
        order = self.data.order
        self.data.format_page_kmem_tracepoint_output(False, page, order)
        return False

    @staticmethod
    def palloc_handler(sp: pwndbg.dbg_mod.StopPoint) -> bool:
        self = get_kmem_tracepoints()
        order = pwndbg.arguments.argument(1)
        pwndbg.dbg.selected_inferior().trace_ret(KmemTracepoints._palloc_handler, True)
        self.data.order = order
        return False

    @staticmethod
    def pfree_handler(sp: pwndbg.dbg_mod.StopPoint) -> bool:
        self = get_kmem_tracepoints()
        page = pwndbg.arguments.argument(0)
        order = pwndbg.arguments.argument(1)
        self.data.format_page_kmem_tracepoint_output(True, page, order)
        return False

    def register_breakpoints(self, verbose: bool, trace_all: bool) -> None:
        inf = pwndbg.dbg.selected_inferior()
        self.data = KmemTracepointsData(verbose, trace_all)
        self.data.results = []
        if self.slab_tracepoints_enabled:
            for kalloc in self.kallocs:
                bp = BreakpointLocation(kalloc)
                sp = inf.break_at(bp, KmemTracepoints.kalloc_handler, internal=True)
                self.sps.append(sp)
            for kfree in self.kfrees:
                bp = BreakpointLocation(kfree)
                sp = inf.break_at(bp, KmemTracepoints.kfree_handler, internal=True)
                self.sps.append(sp)
        if self.buddy_tracepoints_enabled:
            for palloc in self.pallocs:
                bp = BreakpointLocation(palloc)
                sp = inf.break_at(bp, KmemTracepoints.palloc_handler, internal=True)
                self.sps.append(sp)
            for pfree in self.pfrees:
                bp = BreakpointLocation(pfree)
                sp = inf.break_at(bp, KmemTracepoints.pfree_handler, internal=True)
                self.sps.append(sp)

    def remove_breakpoints(self) -> None:
        for sp in self.sps:
            sp.remove()
        self.sps = []
        self.slab_tracepoints_enabled = True
        self.buddy_tracepoints_enabled = True


@pwndbg.lib.cache.cache_until("objfile")
def get_kmem_tracepoints() -> KmemTracepoints:
    return KmemTracepoints()


@pwndbg.commands.Command(
    parser,
    category=pwndbg.commands.CommandCategory.KERNEL,
    notes="""
The `--all` flag may be helpful if you also want to trace frees scheduled with rcu or if the traced command
steps out of the current function. You may also find `-c finish` and `-c continue` useful.
""",
    # FIXME: The -c option
    #     default="next",
    # is not portable.
    only_debuggers={DebuggerType.GDB, DebuggerType.LLDB},
)
@pwndbg.commands.OnlyWhenQemuKernel
@pwndbg.commands.OnlyWithKernelSymbols
@pwndbg.commands.OnlyWhenPagingEnabled
def kmem_trace(trace_slab: bool, trace_buddy: bool, verbose: bool, command: str, all: bool) -> None:
    if pwndbg.aglib.regs.retval is None:
        print(
            message.error(
                "kmem-trace is not available on this architecture because the return value register is not defined."
            )
        )
        return

    tps = get_kmem_tracepoints()

    if not trace_slab and not trace_buddy:
        trace_slab = trace_buddy = True
    tps.slab_tracepoints_enabled = trace_slab
    tps.buddy_tracepoints_enabled = trace_buddy
    # We intentionally do not check `if trace_slab and trace_buddy` to allow for
    # commandline ergonomics.

    tps.register_breakpoints(verbose, all)
    print(message.success("Finished registering tracepoints."))

    old_val = pwndbg.config.context_backtrace_lines.value
    pwndbg.config.context_backtrace_lines.value = 1000  # enable full backtrace

    try:
        pwndbg.dbg.selected_inferior().runcmd(command)
    except Exception as e:
        tps.data.results.append(
            message.warn(f"running command `{command}` with kmem-trace failed with error: {str(e)}")
        )

    pwndbg.config.context_backtrace_lines.value = old_val  # restore
    pwndbg.commands.context.context()

    tps.remove_breakpoints()

    print("\n".join(tps.data.results))
    pwndbg.dbg.ctx_suspend_once()
