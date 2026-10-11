from __future__ import annotations

import functools
import re
from collections.abc import Callable
from typing import Any

from typing_extensions import ParamSpec

import pwndbg.aglib.disasm.disassembly
import pwndbg.aglib.kernel
import pwndbg.aglib.kernel.ktask
import pwndbg.aglib.symbol

P = ParamSpec("P")


NeedLookup = -1


def kernel_symbol(
    prefer_symbol: bool = True, symbol_name: str | None = None
) -> Callable[[Callable[P, int | None]], Callable[P, int | None]]:
    """
    Marks a kernel symbol lookup function.
    This decorator should be used exclusively for ArchSymbols (and its subclasses).

    Arguments:
        prefer_symbol: if true, this decorator will try to resolve the actual symbol address with lookup_symbol first.
        symbol_name: the actual name of the symbol, if different from the function name.

    The return value of the wrapped function will be returnedif the value is of type `int | None`.
    If NeedLookup is returned, further lookup is needed.

    Returns:
        The address of the symbol if the symbol was resolved, else None is returned.
    """

    def decorator(f: Callable[P, int | None]) -> Callable[P, int | None]:
        @functools.wraps(f)
        def func(*args: P.args, **kwargs: P.kwargs) -> int | None:
            self = args[0]
            result = f(*args, **kwargs)
            if result != NeedLookup:
                return result
            result = None
            if prefer_symbol:
                result = pwndbg.aglib.symbol.lookup_symbol_addr(symbol_name or f.__name__)
            if result is None:
                # we use heuristics if the symbol could not be resolved by lookup_symbol
                if (field_name := f"{f.__name__}_heuristic_func") and hasattr(self, field_name):
                    heuristic_func_name: str = getattr(self, field_name)
                    if pwndbg.aglib.symbol.lookup_symbol(heuristic_func_name):
                        arch_heuristic_handle: Callable[[], int | None] = getattr(
                            self, f"_{f.__name__}"
                        )
                        result = arch_heuristic_handle()
            if result is None and not prefer_symbol:
                result = pwndbg.aglib.symbol.lookup_symbol_addr(symbol_name or f.__name__)
            return result

        return func

    return decorator


class ArchSymbols:
    def __init__(self) -> None:
        krelease = pwndbg.aglib.kernel.krelease()
        self.node_data_heuristic_func = "first_online_pgdat"
        self.slab_caches_heuristic_func = "slab_next"
        self.per_cpu_offset_heuristic_func = "nr_iowait_cpu"
        self.modules_heuristic_func = "find_module_all"
        self.db_list_heuristic_func = (
            "dma_buf_file_release" if not krelease or krelease >= (5, 10) else "dma_buf_release"
        )
        self.prog_idr_heuristic_func = "bpf_prog_free_id"
        self.map_idr_heuristic_func = "bpf_map_free_id"
        self.current_task_heuristic_func = "common_cpu_up"

    def disass(self, name: str) -> str | None:
        sym = pwndbg.aglib.symbol.lookup_symbol(name)
        if sym is None:
            return None
        addr = int(sym)
        disass = []
        while (symname := pwndbg.aglib.symbol.resolve_addr(addr)) and symname.split("+")[0] == name:
            instr = pwndbg.aglib.disasm.disassembly.get_one_instruction(addr, enhance=False)
            if instr is None:
                break
            disass.append(hex(addr) + " " + instr.asm_string)
            addr = instr.next
        return "\n".join(disass)

    def regex(self, s: str, pattern: str, nth: int) -> re.Match[Any] | None:
        p = re.compile(pattern)
        if nth == 0:
            return p.search(s)
        matches = list(p.finditer(s))
        if nth < len(matches):
            return matches[nth]
        return None

    @property
    @kernel_symbol()
    def node_data(self) -> int:
        if "CONFIG_NUMA" not in pwndbg.aglib.kernel.kconfig_mod.kconfig():
            addr = pwndbg.aglib.symbol.lookup_symbol_addr("contig_page_data")
            if addr:
                return addr
        return NeedLookup

    @property
    @kernel_symbol()
    def slab_caches(self) -> int:
        return NeedLookup

    @property
    @kernel_symbol(symbol_name="__per_cpu_offset")
    def per_cpu_offset(self) -> int:
        return NeedLookup

    @property
    @kernel_symbol()
    def modules(self) -> int:
        return NeedLookup

    @property
    @kernel_symbol()
    def db_list(self) -> int | None:
        krelease = pwndbg.aglib.kernel.krelease()
        if not krelease or krelease >= (6, 10):
            debugfs_list = pwndbg.aglib.symbol.lookup_symbol_addr("debugfs_list")
            # TODO: fallback not supported for >= v6.10, should look at dma_buf_debug_show later if needed
            # though the symbol should exist if the function symbol exist
            return debugfs_list
        return NeedLookup

    @property
    @kernel_symbol()
    def map_idr(self) -> int:
        return NeedLookup

    @property
    @kernel_symbol()
    def prog_idr(self) -> int:
        return NeedLookup

    # using symbols usually yield incorrect results
    @property
    @kernel_symbol(prefer_symbol=False)
    def current_task(self) -> int:
        return NeedLookup

    @property
    @kernel_symbol()
    def init_task(self) -> int:
        return NeedLookup

    def _node_data(self) -> int | None:
        raise NotImplementedError()

    def _slab_caches(self) -> int | None:
        raise NotImplementedError()

    def _per_cpu_offset(self) -> int | None:
        raise NotImplementedError()

    def _modules(self) -> int | None:
        raise NotImplementedError()

    def _db_list(self) -> int | None:
        raise NotImplementedError()

    def _map_idr(self) -> int | None:
        raise NotImplementedError()

    def _prog_idr(self) -> int | None:
        raise NotImplementedError()

    def _current_task(self) -> int | None:
        raise NotImplementedError()

    def _init_task(self) -> int | None:
        return pwndbg.aglib.kernel.ktask.INIT_TASK
