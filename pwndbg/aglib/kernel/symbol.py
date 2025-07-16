from __future__ import annotations

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
migratetype_names = (
    "Unmovable",
    "Movable",
    "Reclaimable",
    "HighAtomic",
    "CMA",
    "Isolate",
)


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


# TODO: move nproc and npcplist here
@pwndbg.aglib.kernel.requires_debug_symbols()
def nzones() -> int:
    _zone_names = pwndbg.aglib.symbol.lookup_symbol_addr("zone_names")
    for i in range(len(zone_names) + 1):
        char_ptr = pwndbg.aglib.memory.u64(_zone_names + i * 8)
        if pwndbg.aglib.memory.string(char_ptr).decode() not in zone_names:
            return i
    assert False, "cannot determine the number of zones"


@pwndbg.aglib.kernel.requires_debug_symbols(4)
def nmtypes() -> int:
    _mtype_names = pwndbg.aglib.symbol.lookup_symbol_addr("migratetype_names")
    for i in range(len(migratetype_names) + 1):
        char_ptr = pwndbg.aglib.memory.u64(_mtype_names + i * 8)
        if pwndbg.aglib.memory.string(char_ptr).decode() not in migratetype_names:
            return i
    assert False, "cannot determine the number of mtypes"


@pwndbg.aglib.kernel.requires_debug_symbols()
def npcplist() -> int:
    """returns NR_PCP_LISTS (https://elixir.bootlin.com/linux/v6.13/source/include/linux/mmzone.h#L671)"""
    if not pwndbg.aglib.kernel.has_debug_info():
        if pwndbg.aglib.kernel.krelease() < (5, 14):
            return 3
        else:
            return 12
    node_data = pwndbg.aglib.symbol.lookup_symbol("node_data")
    zone = node_data.dereference()[0]["node_zones"][0]
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
