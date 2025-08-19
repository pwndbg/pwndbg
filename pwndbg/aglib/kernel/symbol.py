from __future__ import annotations

import re
from typing import Tuple

import pwndbg.aglib.kernel
import pwndbg.aglib.symbol
import pwndbg.lib.cache
import pwndbg.lib.kernel
from pwndbg.dbg import EventType

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
def migratetype_names() -> Tuple[str, ...]:
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
def try_usymbol(name: str, size=pwndbg.aglib.kernel.ptr_size) -> int:
    if not pwndbg.aglib.kernel.has_debug_symbols():
        return None
    try:
        if pwndbg.aglib.kernel.has_debug_info():
            return pwndbg.aglib.symbol.lookup_symbol_value(name)
        symbol = pwndbg.aglib.symbol.lookup_symbol_addr(name)
        if symbol is None:
            return None
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


def npcplist() -> int:
    """returns NR_PCP_LISTS (https://elixir.bootlin.com/linux/v6.13/source/include/linux/mmzone.h#L671)"""
    if (
        not pwndbg.aglib.kernel.has_debug_symbols("node_zones")
        or not pwndbg.aglib.kernel.has_debug_info()
    ):
        if pwndbg.aglib.kernel.krelease() < (5, 14):
            return 3
        else:
            return 12
    node_data0 = pwndbg.aglib.kernel.node_data()
    if "CONFIG_NUMA" in pwndbg.aglib.kernel.kconfig():
        node_data0 = node_data0.dereference()
    zone = node_data0[0]["node_zones"][0]
    # index 0 should always exist
    if zone.type.has_field("per_cpu_pageset"):
        lists = zone["per_cpu_pageset"]["lists"]
        return lists.type.array_len
    if zone.type.has_field("pageset"):
        lists = zone["pageset"]["pcp"]["lists"]
        return lists.type.array_len
    return 0


def kversion_cint(kversion: Tuple[int, int, int] = None):
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
#include <linux/version.h>
typedef unsigned char u8;
typedef char s8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef long long s64;
#define bool int
#if UINTPTR_MAX == 0xffffffff
    typedef int16_t arch_word_t;
#else
    typedef int32_t arch_word_t;
#endif
typedef struct {
    int counter;
} atomic_t;

struct list_head {
    struct list_head *next, *prev;
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

"""


def load_common_structs():
    if pwndbg.aglib.kernel.has_debug_info() or not kversion_cint():
        return
    if pwndbg.aglib.typeinfo.lookup_types("struct page") is not None:
        return
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
    struct page { // just a simplied page struct with relavent fields
        unsigned long flags;
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
    header_file_path = pwndbg.commands.cymbol.create_temp_header_file(result)
    pwndbg.commands.cymbol.add_structure_from_header(
        header_file_path, "common_kernel_structs", True
    )


@pwndbg.dbg.event_handler(EventType.NEW_MODULE)
def load_common_structs_on_load():
    if pwndbg.aglib.qemu.is_qemu_kernel():
        load_common_structs()


class ArchSymbols:
    def disass(self, name):
        sym = pwndbg.aglib.symbol.lookup_symbol(name)
        if sym is None:
            return None
        disass = "\n".join(pwndbg.aglib.nearpc.nearpc(int(sym)))
        return pwndbg.color.strip(disass)

    def regex(self, s, pattern):
        pattern = re.compile(pattern)
        return pattern.search(s)

    def node_data(self):
        node_data = pwndbg.aglib.symbol.lookup_symbol("node_data")
        if node_data is None:
            node_data = self._node_data()
        elif pwndbg.aglib.kernel.has_debug_info():
            return node_data
        if node_data is None:
            return None
        if pwndbg.aglib.kernel.has_debug_info():
            return pwndbg.aglib.memory.get_typed_pointer("struct pglist_data", node_data)
        return pwndbg.aglib.memory.get_typed_pointer("unsigned long", node_data)

    def slab_caches(self):
        slab_caches = pwndbg.aglib.symbol.lookup_symbol("slab_caches")
        if slab_caches is None:
            slab_caches = self._slab_caches()
        if slab_caches is None:
            return None
        return pwndbg.aglib.memory.get_typed_pointer_value("struct list_head", slab_caches)

    def per_cpu_offset(self):
        per_cpu_offset = pwndbg.aglib.symbol.lookup_symbol("__per_cpu_offset")
        if per_cpu_offset is not None:
            return per_cpu_offset
        return self._per_cpu_offset()

    def _node_data(self):
        raise NotImplementedError()

    def _slab_caches(self):
        raise NotImplementedError()

    def _per_cpu_offset(self):
        raise NotImplementedError()


class x86_64Symbols(ArchSymbols):
    # mov reg, [... - 0x...]
    # the ``-0x...` is a kernel address displayed as a negative number
    # returns the first 0x... as an int if exists
    def dword_mov_reg_memoff(self, disass):
        result = self.regex(disass, r".*?\bmov.*\[.*-.*(0x[0-9a-f]+)\]")
        if result is not None:
            return (1 << 64) - int(result.group(1), 16)
        return None

    # add reg, [... - 0x...]
    # the `-0x...`` is a kernel address displayed as a negative number
    # returns the first 0x... as an int if exists
    def dword_add_reg_memoff(self, disass):
        result = self.regex(disass, r".*?\badd.*\[.*-.*(0x[0-9a-f]+)\]")
        if result is not None:
            return (1 << 64) - int(result.group(1), 16)
        return None

    # mov reg, <kernel address as a constant>
    def qword_mov_reg_const(self, disass):
        result = self.regex(disass, r".*?\bmov.*(0x[0-9a-f]{16})")
        if result is not None:
            return int(result.group(1), 16)
        return None

    def qword_mov_reg_ripoff(self, disass):
        result = self.regex(
            "".join(disass.splitlines()),
            r".*?\bmov.*\[rip\s\+\s(0x[0-9a-f]+)\].*?(0x[0-9a-f]{16})\s\<",
        )
        if result is not None:
            return int(result.group(1), 16) + int(result.group(2), 16)
        return None

    def _node_data(self):
        disass = self.disass("first_online_pgdat")
        result = self.dword_mov_reg_memoff(disass)
        if result is not None:
            return result
        return self.qword_mov_reg_const(disass)

    def _slab_caches(self):
        disass = self.disass("slab_next")
        return self.qword_mov_reg_const(disass)

    def _per_cpu_offset(self):
        disass = self.disass("nr_iowait_cpu")
        result = self.dword_add_reg_memoff(disass)
        if result is not None:
            return result
        result = self.qword_mov_reg_const(disass)
        if result is not None:
            return result
        return self.qword_mov_reg_ripoff(disass)


class Aarch64Symbols(ArchSymbols):
    # adrp x?, <kernel address>
    # add x?, x?, #0x...
    def qword_adrp_add_const(self, disass):
        prev = ""
        for line in disass.splitlines():
            if "adrp" in prev and "add" in line:
                result = self.regex(prev, r"\,\s*0x([0-9a-f]+)")
                if result is None:
                    return None
                tmp = int(result.group(1), 16)
                result = self.regex(line, r"#0x([0-9a-f]+)")
                if result is None:
                    return None
                return tmp + int(result.group(1), 16)
            prev = line
        return None

    def _node_data(self):
        disass = self.disass("first_online_pgdat")
        return self.qword_adrp_add_const(disass)

    def _slab_caches(self):
        disass = self.disass("slab_next")
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
        return sum([int(m.group(i), 16) for i in [2, 3, 4]])

    def _per_cpu_offset(self):
        disass = self.disass("nr_iowait_cpu")
        return self.qword_adrp_add_const(disass)
