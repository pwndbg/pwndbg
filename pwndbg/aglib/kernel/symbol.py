from __future__ import annotations

import functools
import re
from collections.abc import Callable
from typing import Any

from typing_extensions import ParamSpec

import pwndbg.aglib.disasm.disassembly
import pwndbg.aglib.kernel
import pwndbg.aglib.kernel.ktask
import pwndbg.aglib.memory
import pwndbg.aglib.qemu
import pwndbg.aglib.symbol
import pwndbg.aglib.typeinfo
import pwndbg.dbg_mod
import pwndbg.lib.cache

#########################################
# helpers
#
#########################################
POSSIBLE_ZONE_NAMES = (
    "DMA",
    "DMA32",
    "Normal",
    "HighMem",
    "Movable",
    "Device",
)


@pwndbg.lib.cache.cache_until("objfile")
def migratetype_names() -> tuple[str, ...]:
    names = [
        "Unmovable",
        "Movable",
        "Reclaimable",
        "HighAtomic",
    ]
    kconfig = pwndbg.aglib.kernel.kconfig()
    if "CONFIG_CMA" in kconfig:
        names.append("CMA")
    if "CONFIG_MEMORY_ISOLATION" in kconfig:
        names.append("Isolate")
    return tuple(names)


# try getting value of a symbol as an unsigned integer
def try_usymbol(name: str, size: int | None = None) -> int | None:
    if not pwndbg.aglib.kernel.has_debug_symbols():
        return None
    try:
        if pwndbg.aglib.kernel.has_debug_info():
            return pwndbg.aglib.symbol.lookup_symbol_value(name)

        symbol = pwndbg.aglib.symbol.lookup_symbol_addr(name)
        if symbol is None:
            return None

        if size is None:
            size = pwndbg.aglib.arch.ptrbits

        if size == 8:
            return pwndbg.aglib.memory.u(symbol)
        if size == 16:
            return pwndbg.aglib.memory.u16(symbol)
        if size == 32:
            return pwndbg.aglib.memory.u32(symbol)

        return pwndbg.aglib.memory.u64(symbol)
    except Exception:
        # for kpti
        return None


@pwndbg.aglib.kernel.requires_debug_symbols("zone_names", default=4)
def nzones() -> int:
    _zone_names = pwndbg.aglib.symbol.lookup_symbol_addr("zone_names")
    for i in range(len(POSSIBLE_ZONE_NAMES) + 1):
        char_ptr = pwndbg.aglib.memory.u64(_zone_names + i * 8)
        if pwndbg.aglib.memory.string(char_ptr).decode() not in POSSIBLE_ZONE_NAMES:
            return i
    assert False, "cannot determine the number of zones"


def nmtypes() -> int:
    return len(migratetype_names())


def node_data_pointer() -> pwndbg.dbg_mod.Value | None:
    addr = pwndbg.aglib.kernel.node_data()
    if addr is None:
        return None
    node_data = pwndbg.aglib.memory.get_typed_pointer("struct pglist_data", addr)
    if "CONFIG_NUMA" in pwndbg.aglib.kernel.kconfig():
        return node_data.cast(node_data.type.pointer())
    return node_data


def get_one_node_data() -> pwndbg.dbg_mod.Value | None:
    node_data = node_data_pointer()
    if not node_data or "CONFIG_NUMA" not in pwndbg.aglib.kernel.kconfig():
        return node_data
    return node_data.dereference()


def npcplist() -> int:
    """returns NR_PCP_LISTS (https://elixir.bootlin.com/linux/v6.13/source/include/linux/mmzone.h#L671)"""
    if not pwndbg.aglib.kernel.has_debug_info():
        if pwndbg.aglib.kernel.krelease() < (5, 14):
            return 3
        return 12
    node_data0 = get_one_node_data()
    zone = node_data0[0]["node_zones"][0]
    # index 0 should always exist
    if zone.type.has_field("per_cpu_pageset"):
        lists = zone["per_cpu_pageset"]["lists"]
        return lists.type.array_len
    if zone.type.has_field("pageset"):
        lists = zone["pageset"]["pcp"]["lists"]
        return lists.type.array_len
    return 0


def kversion_cint(kversion: tuple[int, ...] | None = None) -> int | None:
    if kversion is None:
        kversion = pwndbg.aglib.kernel.krelease()
    if kversion is None or len(kversion) != 3:
        return None
    x, y, z = kversion
    return ((x) * 65536) + ((y) * 256) + (z)


#########################################
# common structurs
#
#########################################
COMMON_TYPES = """
#include <stdint.h>
#include <stddef.h>
#include <linux/version.h>
typedef unsigned char u8;
typedef char s8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef long long s64;
typedef unsigned long u64;
#define bool int
#if UINTPTR_MAX == 0xffffffff
    typedef int16_t arch_word_t;
#else
    typedef int32_t arch_word_t;
#endif
typedef struct {
    unsigned int val;
} kuid_t;
typedef struct {
    unsigned int val;
} kgid_t;
typedef int pid_t;
typedef struct {
    int counter;
} atomic_t;
typedef struct refcount_struct {
	atomic_t refs;
} refcount_t;
typedef struct {
	unsigned long f;
} memdesc_flags_t;

struct list_head {
    struct list_head *next, *prev;
};
struct hlist_node {
	struct hlist_node *next, **pprev;
};
struct kmem_cache;
enum pageflags {
	PG_locked,		/* Page is locked. Don't touch. */
	PG_writeback,		/* Page is under writeback */
	PG_referenced,
	PG_uptodate,
	PG_dirty,
	PG_lru,
	PG_head,		/* Must be in bit 6 */
	PG_waiters,		/* Page has waiters, check its waitqueue. Must be bit #7 and in the same byte as "PG_locked" */
	PG_active,
	PG_workingset,
	PG_owner_priv_1,	/* Owner use. If pagecache, fs may use */
	PG_owner_2,		/* Owner use. If pagecache, fs may use */
	PG_arch_1,
	PG_reserved,
	PG_private,		/* If pagecache, has fs-private data */
	PG_private_2,		/* If pagecache, has fs aux data */
	PG_reclaim,		/* To be reclaimed asap */
	PG_swapbacked,		/* Page is backed by RAM/swap */
	PG_unevictable,		/* Page is "unevictable"  */
	PG_dropbehind,		/* drop pages on IO completion */
};
#define POINTER_SIZE (sizeof(void *))
"""


@pwndbg.aglib.kernel.typeinfo_recovery("struct page", requires_kversion=True)
def recover_page_typeinfo() -> str:
    defs = []
    for config in (
        "CONFIG_MEMCG",
        "CONFIG_KASAN",
    ):
        if config in pwndbg.aglib.kernel.kconfig():
            defs.append(config)
    result = f"#define KVERSION {kversion_cint()}\n"
    result += "\n".join(f"#define {s}" for s in defs)
    result += COMMON_TYPES
    result += """
    struct page { // just a simplied page struct with relevant fields
#if KVERSION < KERNEL_VERSION(6, 18, 0)
        unsigned long flags;
#else
        memdesc_flags_t flags;
#endif
        union {
            struct {
                union {
                    struct {
                        union {
                            struct list_head lru;
                            struct list_head buddy_list;
                            struct list_head pcp_list;
                        };
                    };
                    struct {	/* Tail pages of compound page */
                        unsigned long compound_head;	/* Bit zero is set */
                    };
                };
            };
#if KVERSION < KERNEL_VERSION(5, 17, 0)
            struct {	/* slab, slob and slub */
                union {
                    struct list_head slab_list;
                    struct {	/* Partial pages */
                        struct page *next;
                        arch_word_t pages;	/* Nr of pages left */
#if KVERSION < KERNEL_VERSION(5, 16, 0)
                        arch_word_t pobjects;	/* Approximate count */
#endif
                    };
                };
                struct kmem_cache *slab_cache; /* not slob */
                /* Double-word boundary */
                void *freelist;		/* first free object */
                union {
                    void *s_mem;	/* slab: first object */
                    unsigned long counters;		/* SLUB */
                    struct {			/* SLUB */
                        unsigned inuse:16;
                        unsigned objects:15;
                        unsigned frozen:1;
                    };
                };
            };
#endif
            char _pad[0x28]; // the rest are not relavent to this project but needs to be 0x28 bytes
        };
        union {
            atomic_t _mapcount;
            unsigned int page_type;
        };
        atomic_t _refcount;
#ifdef CONFIG_MEMCG
        unsigned long memcg_data;
#endif
#if defined(WANT_PAGE_VIRTUAL) /* never set for x86 and arm */
        void *virtual;
#endif /* WANT_PAGE_VIRTUAL */
#ifdef LAST_CPUPID_NOT_IN_PAGE_FLAGS /* TODO: seems never got set for all the kernel builds I have worked with */
#if KVERSION >= KERNEL_VERSION(6, 7, 0)
        int _last_cpupid;
#endif
#endif
#if defined(CONFIG_KASAN) && KVERSION >= KERNEL_VERSION(6, 1, 0)
        struct page *kmsan_shadow;
        struct page *kmsan_origin;
#endif
#ifdef LAST_CPUPID_NOT_IN_PAGE_FLAGS
#if KVERSION < KERNEL_VERSION(6, 7, 0)
        int _last_cpupid;
#endif
#endif
    };
    """
    return result


P = ParamSpec("P")


class NeedLookup:
    pass


def kernel_symbol_func(
    prefer_symbol: bool = True, symbol_name: str | None = None
) -> Callable[[Callable[P, int | None | type[NeedLookup]]], Callable[P, int | None]]:
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

    def decorator(f: Callable[P, int | None | type[NeedLookup]]) -> Callable[P, int | None]:
        @functools.wraps(f)
        def func(*args: P.args, **kwargs: P.kwargs) -> int | None:
            self = args[0]
            result = f(*args, **kwargs)
            if isinstance(result, int | None):
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

    @kernel_symbol_func()
    def node_data(self) -> int | type[NeedLookup]:
        if "CONFIG_NUMA" not in pwndbg.aglib.kernel.kconfig():
            addr = pwndbg.aglib.symbol.lookup_symbol_addr("contig_page_data")
            if addr:
                return addr
        return NeedLookup

    @kernel_symbol_func()
    def slab_caches(self) -> type[NeedLookup]:
        return NeedLookup

    @kernel_symbol_func(symbol_name="__per_cpu_offset")
    def per_cpu_offset(self) -> type[NeedLookup]:
        return NeedLookup

    @kernel_symbol_func()
    def modules(self) -> type[NeedLookup]:
        return NeedLookup

    @kernel_symbol_func()
    def db_list(self) -> int | None | type[NeedLookup]:
        krelease = pwndbg.aglib.kernel.krelease()
        if not krelease or krelease >= (6, 10):
            debugfs_list = pwndbg.aglib.symbol.lookup_symbol_addr("debugfs_list")
            # TODO: fallback not supported for >= v6.10, should look at dma_buf_debug_show later if needed
            # though the symbol should exist if the function symbol exist
            return debugfs_list
        return NeedLookup

    @kernel_symbol_func()
    def map_idr(self) -> type[NeedLookup]:
        return NeedLookup

    @kernel_symbol_func()
    def prog_idr(self) -> type[NeedLookup]:
        return NeedLookup

    # using symbols usually yield incorrect results
    @kernel_symbol_func(prefer_symbol=False)
    def current_task(self) -> type[NeedLookup]:
        return NeedLookup

    @kernel_symbol_func()
    def init_task(self) -> type[NeedLookup]:
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


class x86_64Symbols(ArchSymbols):
    # op ... [... +/- (0x...)]
    # if negative, the `-0x...`` is a kernel address displayed as a negative number
    # returns the first 0x... as an int if exists
    def qword_op_reg_memoff(
        self, disass: str, op: str, sign: str = "-", nth: int = 0
    ) -> int | None:
        result = self.regex(disass, rf"{op}.*\[.*{re.escape(sign)}\s(0x[0-9a-f]+)\]", nth)
        if result is not None:
            if sign == "-":
                return (1 << 64) - int(result.group(1), 16)
            return int(result.group(1), 16)
        return None

    # op [... +/- (0x...)] ...
    # if negative, the `-0x...`` is a kernel address displayed as a negative number
    # returns the first 0x... as an int if exists
    def dword_op_memoff_reg(
        self, disass: str, op: str, first: bool = True, nth: int = 0
    ) -> int | None:
        r = rf"{op}.*\[.*([+-])\s(0x[0-9a-f]{{1,8}})\]\s*,"
        if not first:
            r = rf"{op}.*,\s*\[.*([+-])\s(0x[0-9a-f]{{1,8}})\]"
        result = self.regex(disass, r, nth)
        if result is None:
            return None
        value = int(result.group(2), 16)
        return (1 << 64) - value if result.group(1) == "-" else value

    # mov reg, <kernel address as a constant>
    def qword_mov_reg_const(self, disass: str, nth: int = 0) -> int | None:
        result = self.regex(disass, r"mov.*(0x[0-9a-f]{16})", nth)
        if result is not None:
            return int(result.group(1), 16)
        return None

    def dword_mov_reg_const(self, disass: str, nth: int = 0) -> int | None:
        result = self.regex(disass, r"mov.*(0x[0-9a-f]{1,8})\b(?!\])", nth)
        if result is not None:
            return int(result.group(1), 16)
        return None

    def qword_mov_reg_ripoff(self, disass: str, nth: int = 0) -> int | None:
        result = self.regex(
            " ".join(disass.splitlines()),
            r"mov.*\[rip\s([\+\-]\s0x[0-9a-f]+)\]\s(0x[0-9a-f]{16})",
            nth,
        )
        if result is not None:
            return int(result.group(1).replace(" ", ""), 16) + int(result.group(2), 16)
        return None

    def _node_data(self) -> int | None:
        disass = self.disass(self.node_data_heuristic_func)
        if not disass:
            return None
        if (result := self.qword_op_reg_memoff(disass, op="mov", sign="-")) is not None:
            return result
        return self.qword_mov_reg_const(disass)

    def _slab_caches(self) -> int | None:
        disass = self.disass(self.slab_caches_heuristic_func)
        if not disass:
            return None
        return self.qword_mov_reg_const(disass)

    def _per_cpu_offset(self) -> int | None:
        disass = self.disass(self.per_cpu_offset_heuristic_func)
        if not disass:
            return None
        if (result := self.qword_op_reg_memoff(disass, op="add", sign="-")) is not None:
            return result
        if (result := self.qword_mov_reg_const(disass)) is not None:
            return result
        return self.qword_mov_reg_ripoff(disass)

    def _modules(self) -> int | None:
        disass = self.disass(self.modules_heuristic_func)
        if not disass:
            return None
        return self.qword_mov_reg_ripoff(disass)

    def _db_list(self) -> int | None:
        offset = 0x10  # offset of the lock
        disass = self.disass(self.db_list_heuristic_func)
        if not disass:
            return None
        if (result := self.qword_mov_reg_const(disass)) is not None:
            return result - offset
        return None

    def _map_idr(self) -> int | None:
        disass = self.disass(self.map_idr_heuristic_func)
        if not disass:
            return None
        if (result := self.qword_mov_reg_const(disass, nth=1)) is not None:
            return result
        return self.qword_mov_reg_const(disass)

    def _prog_idr(self) -> int | None:
        disass = self.disass(self.prog_idr_heuristic_func)
        if not disass:
            return None
        if (result := self.qword_mov_reg_const(disass, nth=1)) is not None:
            return result
        return self.qword_mov_reg_const(disass)

    def _current_task(self) -> int | None:
        disass = self.disass(self.current_task_heuristic_func)
        if not disass:
            return None
        if (result := self.dword_mov_reg_const(disass)) is not None:
            return result
        if (result := self.qword_mov_reg_const(disass)) is not None:
            return result
        return self.dword_op_memoff_reg(disass, "mov", True)


class Aarch64Symbols(ArchSymbols):
    # adrp x?, <kernel address>
    # add x?, x?, #0x...
    def qword_adrp_add_const(self, disass: str, nth: int = 0) -> int | None:
        prev = ""
        for line in disass.splitlines():
            if "adrp" in prev and "add" in line:
                result = self.regex(prev, r"\,\s*0x([0-9a-f]+)", nth=0)
                tmp = None
                if result is not None:
                    tmp = int(result.group(1), 16)
                result = self.regex(line, r"#0x([0-9a-f]+)", nth=0)
                if result is not None and tmp is not None:
                    if nth == 0:
                        return tmp + int(result.group(1), 16)
                    nth -= 1
            prev = line
        return None

    def _node_data(self) -> int | None:
        disass = self.disass(self.node_data_heuristic_func)
        if not disass:
            return None
        return self.qword_adrp_add_const(disass)

    def _slab_caches(self) -> int | None:
        disass = self.disass(self.slab_caches_heuristic_func)
        if not disass:
            return None
        result = self.qword_adrp_add_const(disass)
        if result:
            return result
        # adrp x<num>, 0x....
        # ...
        # add x<num>, x<num>, #0x...
        # ...
        # add x1, x<num>, #0x...
        pattern = re.compile(
            r"adrp\s+x(\d+),\s+0x([0-9a-fA-F]+).*?\n"
            r".*?add\s+x\1,\s+x\1,\s+#0x([0-9a-fA-F]+).*?\n"
            r".*?add\s+x1,\s+x\1,\s+#0x([0-9a-fA-F]+)",
            re.DOTALL,
        )
        m = pattern.search(disass)
        if m is None:
            return None
        return sum(int(m.group(i), 16) for i in [2, 3, 4])

    def _per_cpu_offset(self) -> int | None:
        disass = self.disass(self.per_cpu_offset_heuristic_func)
        if not disass:
            return None
        return self.qword_adrp_add_const(disass)

    def _modules(self) -> int | None:
        disass = self.disass(self.modules_heuristic_func)
        if not disass:
            return None
        # adrp x<num>, 0x....
        # ...
        # add x<num>, x<num>, #0x...
        # ...
        # ldr x?, [x<num>, #0x]!...
        pattern = re.compile(
            r"adrp\s+x(\d+),\s+0x([0-9a-fA-F]+).*?\n"
            r".*?add\s+x\1,\s+x\1,\s+#0x([0-9a-fA-F]+).*?\n"
            r".*?ldr\s+x\d+,\s+\[x\1,\s+#0x([0-9a-fA-F]+)\]!",
            re.DOTALL,
        )
        m = pattern.search(disass)
        if m is None:
            return None
        return sum(int(m.group(i), 16) for i in [2, 3, 4])

    def _db_list(self) -> int | None:
        offset = 0x10  # offset of the lock
        disass = self.disass(self.db_list_heuristic_func)
        if not disass:
            return None
        result = self.qword_adrp_add_const(disass)
        if result is not None:
            return result - offset
        return None

    def _map_idr(self) -> int | None:
        disass = self.disass(self.map_idr_heuristic_func)
        if not disass:
            return None
        result = self.qword_adrp_add_const(disass, nth=1)
        if result is not None:
            return result
        return self.qword_adrp_add_const(disass)

    def _prog_idr(self) -> int | None:
        disass = self.disass(self.prog_idr_heuristic_func)
        if not disass:
            return None
        result = self.qword_adrp_add_const(disass, nth=1)
        if result is not None:
            return result
        return self.qword_adrp_add_const(disass)

    def current_task(self) -> int | None:
        return pwndbg.aglib.regs.read_reg("sp_el0")
