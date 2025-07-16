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
zone_names = (
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


@pwndbg.aglib.kernel.requires_debug_symbols(["zone_names"], default=4)
def nzones() -> int:
    _zone_names = pwndbg.aglib.symbol.lookup_symbol_addr("zone_names")
    for i in range(len(zone_names) + 1):
        char_ptr = pwndbg.aglib.memory.u64(_zone_names + i * 8)
        if pwndbg.aglib.memory.string(char_ptr).decode() not in zone_names:
            return i
    assert False, "cannot determine the number of zones"


def nmtypes() -> int:
    return len(migratetype_names())


def npcplist() -> int:
    """returns NR_PCP_LISTS (https://elixir.bootlin.com/linux/v6.13/source/include/linux/mmzone.h#L671)"""
    if (
        not pwndbg.aglib.kernel.has_debug_symbols(["node_zones"])
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


#########################################
# common structurs
#
#########################################
COMMON_TYPES = """
#include <stdint.h>
typedef unsigned char u8;
typedef char s8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned int spinlock_t;
#if UINTPTR_MAX == 0xffffffff
    typedef int16_t arch_word_t;
#else
    typedef int32_t arch_word_t;
#endif

struct list_head {
    struct list_head *next, *prev;
};
struct kmem_cache;
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
        // for < v5.17
        struct {	/* slab, slob and slub */
			union {
				struct list_head slab_list;
				struct {	/* Partial pages */
					struct page *next;
					arch_word_t pages;	/* Nr of pages left */
					arch_word_t pobjects;	/* Approximate count */
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
        char _pad[0x40]; // the rest are not relavent to this project but needs to be 0x40 bytes
    };
};
typedef struct {
	int counter;
} atomic_t;
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
    if pwndbg.aglib.kernel.has_debug_info():
        return
    if pwndbg.aglib.typeinfo.lookup_types("struct page") is not None:
        return
    header_file_path = pwndbg.commands.cymbol.create_temp_header_file(COMMON_TYPES)
    pwndbg.commands.cymbol.add_structure_from_header(header_file_path, "")


@pwndbg.dbg.event_handler(EventType.NEW_MODULE)
def load_common_structs_on_load():
    if pwndbg.aglib.qemu.is_qemu_kernel():
        load_common_structs()


class ArchSymbols:
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
        return pwndbg.aglib.memory.get_typed_pointer("ulong", node_data)

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
    def _node_data(self):
        slab_next = pwndbg.aglib.symbol.lookup_symbol("first_online_pgdat")
        if slab_next is None:
            return None
        disass = "\n".join(pwndbg.aglib.nearpc.nearpc(int(slab_next)))
        disass = pwndbg.color.strip(disass)
        result = self.regex(disass, r".*?\bmov.*\[.*-.*(0x[0-9a-f]+)\]")
        if result is not None:
            return (1 << 64) - int(result.group(1), 16)
        result = self.regex(disass, r".*?\bmov.*(0x[0-9a-f]{16})")
        if result is None:
            return None
        return int(result.group(1), 16)

    def _slab_caches(self):
        slab_next = pwndbg.aglib.symbol.lookup_symbol("slab_next")
        if slab_next is None:
            return None
        disass = "\n".join(pwndbg.aglib.nearpc.nearpc(int(slab_next)))
        disass = pwndbg.color.strip(disass)
        return int(self.regex(disass, r".*?\bmov\s+[^,]+,\s*(0x[0-9a-f]+)").group(1), 16)

    def _per_cpu_offset(self):
        nr_iowait_cpu = pwndbg.aglib.symbol.lookup_symbol("nr_iowait_cpu")
        if nr_iowait_cpu is None:
            return None
        disass = "\n".join(pwndbg.aglib.nearpc.nearpc(int(nr_iowait_cpu)))
        disass = pwndbg.color.strip(disass)
        # ex: add    rax,QWORD PTR [rdi*8-0x5fdba960]
        result = self.regex(disass, r".*?\badd.*\[.*-.*(0x[0-9a-f]+)\]")
        if result is not None:
            return (1 << 64) - int(result.group(1), 16)
        # ex: mov    rax,0xabcd
        result = self.regex(disass, r".*?\bmov.*(0x[0-9a-f]+)")
        if result is None:
            return None
        return int(result.group(1), 16)


class Aarch64Symbols(ArchSymbols):
    def _node_data(self):
        raise NotImplementedError()

    def _slab_caches(self):
        raise NotImplementedError()
