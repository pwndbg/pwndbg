from __future__ import annotations

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


#########################################
# structurs relevant to buddydump
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
MAX_ORDER = 11


def get_pcp_struct(pcp_sz) -> str:
    kconfig = pwndbg.aglib.kernel.kconfig()
    defs = []
    if not pwndbg.aglib.kernel.krelease() < (5, 14):
        if pwndbg.aglib.kernel.krelease() < (6, 7):
            defs.append("BETWEEN_V5_14_AND_V6_6")
    else:
        defs.append("BEFORE_V5_14")
    if not pwndbg.aglib.kernel.krelease() < (6, 0):
        defs.append("SINCE_V6_0")
    if not pwndbg.aglib.kernel.krelease() < (6, 7):
        defs.append("SINCE_V6_7")
    for config in (
        "CONFIG_NUMA",
        "CONFIG_SMP",
    ):
        if config in kconfig:
            defs.append(config)
    result = "\n".join(f"#define {s}" for s in defs)
    result += f"""
    struct per_cpu_pages {{
#ifdef SINCE_V6_0
        spinlock_t lock;/* Protects lists field, MOST OF THE TIME IT IS 4 BYTES */
#endif
        int count;		/* number of pages in the list */
        int high;		/* high watermark, emptying needed */
#ifdef SINCE_V6_7
        int high_min;		/* min high watermark */
        int high_max;		/* max high watermark */
#endif
        int batch;		/* chunk size for buddy add/remove */
#ifdef SINCE_V6_7
        u8 flags;		/* protected by pcp->lock */
        u8 alloc_factor;	/* batch scaling factor during allocate */
#ifdef CONFIG_NUMA
        u8 expire;		/* When 0, remote pagesets are drained */
#endif
        short free_count;	/* consecutive free count */
#endif
#ifdef BETWEEN_V5_14_AND_V6_6
        short free_factor;	/* batch scaling factor during free */
#ifdef CONFIG_NUMA
        short expire;		/* When 0, remote pagesets are drained */
#endif
#else

#endif
        /* Lists of pages, one per migrate type stored on the pcp-lists */
        struct list_head lists[{npcplist()}]; // constant is sufficient for now
    }};
#ifdef BEFORE_V5_14
    struct per_cpu_pageset {{
        union {{
            struct per_cpu_pages pcp;
            char _pad[{pcp_sz}];
        }};
    }};
#endif
    """
    return result


def find_zone_offsets() -> Tuple[int, int, int, int, int]:
    pcp_off, name_off, freelist_off, pcp_sz, zone_sz = None, None, None, None, None
    start_idx = 10
    ptr = try_usymbol("node_data") + start_idx * 8
    for i in range(start_idx, 20):  # the pcp offset should exist in those range
        val = pwndbg.aglib.memory.u64(ptr)
        ptr += 8
        if pwndbg.aglib.memory.is_kernel(val):
            # we have found `zone_pgdat`
            pcp_off = (i + 1) * 8
            break
    assert pcp_off, "can't find pcp offset"
    if pwndbg.aglib.kernel.krelease() < (5, 14):
        pcp_ptr = pwndbg.aglib.kernel.per_cpu(
            pwndbg.aglib.memory.get_typed_pointer("struct page", pwndbg.aglib.memory.u64(ptr))
        )
        first_pcp_ptr, second_pcp_ptr = None, None
        prev = 0
        for i in range(30):
            addr = int(pcp_ptr) + i * 8
            cur = pwndbg.aglib.memory.u64(addr)
            if prev >> 56 == 0 and cur >> 56 == 0xFF:
                if not first_pcp_ptr:
                    first_pcp_ptr = addr
                else:
                    second_pcp_ptr = addr
                    break
            prev = cur
        assert first_pcp_ptr and second_pcp_ptr, "can't determine pcp ptrs"
        pcp_sz = second_pcp_ptr - first_pcp_ptr
        assert pcp_sz < 0x100, "can't determine pcp_sz"
    for i in range(20):
        char_ptr = pwndbg.aglib.memory.u64(ptr)
        ptr += 8
        if pwndbg.aglib.memory.string(char_ptr).decode() in zone_names:
            name_off = i * 8 + pcp_off  # plus 1 to skip over previous
            break
    assert name_off, "can't find name offset"
    prev = pwndbg.aglib.memory.u64(ptr)
    ptr += 8
    for i in range(1, 20):
        cur = pwndbg.aglib.memory.u64(ptr)
        ptr += 8
        # prev is the write cache padding followed by the freelist
        if prev == 0 and pwndbg.aglib.memory.is_kernel(cur):
            freelist_off = (i + 1) * 8 + name_off
            break
        prev = cur
    assert freelist_off, "can't find freelist offset"
    ptr += (
        MAX_ORDER * (nmtypes() * 0x10 + 8)
    ) + 0x10  # guessed MAX_ORDER * sizeof(struct list_head) + some other fields
    # find the next `zone_pgdat`
    for i in range(100):  # the pcp offset should exist in those range
        val = pwndbg.aglib.memory.u64(ptr)
        ptr += 8
        if pwndbg.aglib.memory.is_kernel(val):
            # we have found `zone_pgdat`
            zone_sz = ptr - pcp_off - try_usymbol("node_data")
            break
    assert (
        zone_sz and zone_sz < 0x4000 and zone_sz & 0xF == 0
    ), f"can't determine sizeof(struct zone) = {zone_sz}"  # just to make sure it is sane
    return pcp_off, name_off, freelist_off, pcp_sz, zone_sz


@pwndbg.aglib.kernel.requires_debug_symbols()
def load_buddydump_typeinfo():
    if pwndbg.aglib.typeinfo.lookup_types("struct pglist_data") is not None:
        return
    load_common_structs()

    pglist_data = f"""
    typedef struct pglist_data {{
        struct zone node_zones[{nzones()}];
        // ... the rest of the fields are not important
        // but make the struct dynamic
        char _pad[];
    }} pg_data_t;
    typedef struct pglist_data *node_data_t[1]; // just support 1 node for now, the most common case
    """
    pcp_off, name_off, freearea_off, pcp_sz, zone_sz = find_zone_offsets()
    per_cpu_pages = get_pcp_struct(pcp_sz)
    zone = ""
    if pwndbg.aglib.kernel.krelease() < (5, 14):
        zone = "#define BEFORE_V5_14\n"
    zone += f"""
    struct zone {{
        char _pad1[{hex(pcp_off)}];
#ifdef BEFORE_V5_14
        struct per_cpu_pageset *pageset;
#else
        struct per_cpu_pages *per_cpu_pageset;
#endif
        char _pad2[{hex(name_off - pcp_off - 8)}];
        char* name;
        char _pad3[{hex(freearea_off - name_off - 8)}];
        struct free_area free_area[{MAX_ORDER}]; // just defaults to 11 is sufficient here
        char _pad[{hex(zone_sz - freearea_off - (MAX_ORDER * (nmtypes() * 0x10 + 8)))}];
    }};
    """
    free_area = f"""
    struct free_area {{
        struct list_head	free_list[{nmtypes()}];
        unsigned long		nr_free;
    }};
    """
    result = COMMON_TYPES + free_area + zone + per_cpu_pages + pglist_data
    header_file_path = pwndbg.commands.cymbol.create_temp_header_file(result)
    pwndbg.commands.cymbol.add_structure_from_header(header_file_path, "")


#########################################
# structurs relevant to slab
#
#########################################


def kmem_cache_pad_sz(kconfig) -> int:
    # find the distance between the first kmem_cache's name and its first node cache
    # the name for the first kmem_cache (most likely) has the name "kmem_cache"
    # and the global var is also named "kmem_cache"
    name = "kmem_cache"
    name_off = None
    kmem_cache = try_usymbol(name)
    assert kmem_cache, "can't find kmem_cache"
    for i in range(0x20):
        val = pwndbg.aglib.memory.u64(kmem_cache + i * 8)
        if pwndbg.aglib.memory.string(val) == name.encode():
            name_off = i * 8
            break
    assert name_off, "can't determine kmem_cache name offset"
    distance = None
    for i in range(3, 0x20):
        val = pwndbg.aglib.memory.u64(kmem_cache + i * 8 + name_off)
        if pwndbg.aglib.memory.peek(val):
            nr_partial = pwndbg.aglib.memory.u64(val + 0x8)
            next = pwndbg.aglib.memory.u64(val + 0x10)
            prev = pwndbg.aglib.memory.u64(val + 0x18)
            if (
                nr_partial < 0x20
                and pwndbg.aglib.memory.is_kernel(next)
                and pwndbg.aglib.memory.is_kernel(prev)
            ):
                distance = i * 8
                break
    assert distance, "can't find kmem_cache node"
    distance -= 0x18  # the name ptr + list_head
    configs = (
        "CONFIG_SLAB_FREELIST_HARDENED",
        "CONFIG_NUMA",
        "CONFIG_SLAB_FREELIST_RANDOM",
        "CONFIG_KASAN_GENERIC",
    )
    for config in configs:
        if config in kconfig:
            distance -= 8
    if "CONFIG_HARDENED_USERCOPY" in kconfig or pwndbg.aglib.kernel.krelease() < (6, 2):
        distance -= 8
    assert distance < 0x1000, "cannot find kmem_cache padding size"
    return distance


def kmem_cache_structs():
    to_define = None
    if pwndbg.aglib.kernel.krelease() < (5, 17):
        to_define = "BEFORE_V5_17"
    elif pwndbg.aglib.kernel.krelease() < (6, 8):
        to_define = "BETWEEN_V5_17_AND_V6_7"
    else:
        to_define = "SINCE_V6_8"
    result = f"#define {to_define}\n"
    result += """
    struct kmem_cache_node {
        spinlock_t list_lock;
        unsigned long nr_partial;
        struct list_head partial;
    };
    struct kmem_cache_order_objects {
        unsigned int x;
    };
    struct reciprocal_value {
        u32 m;
        u8 sh1, sh2;
    };
    typedef unsigned int gfp_t;
    typedef unsigned int slab_flags_t;
    // struct page is already defined in COMMON_TYPES
#ifndef BEFORE_V5_17
    struct slab {
        unsigned long __page_flags;
#ifdef SINCE_V6_8
        struct kmem_cache *slab_cache;
#endif
        union {
            struct list_head slab_list;
            struct {
                struct slab *next;
                int slabs;	/* Nr of slabs left */
            };
        };
#ifdef BETWEEN_V5_17_AND_V6_7
        struct kmem_cache *slab_cache;
#endif
        void *freelist;		/* first free object */
        union {
            unsigned long counters;
            struct {
                unsigned inuse:16;
                unsigned objects:15;
                unsigned frozen:1;
            };
        };
        // rcu_head in later versions is not important for our purposes
        unsigned int __page_type;
        atomic_t __page_refcount;
    };
#endif
    struct kmem_cache_cpu {
        void **freelist;	/* Pointer to next available object */
        unsigned long tid;	/* Globally unique transaction id */
#ifdef BEFORE_V5_17
        struct page *page;	/* The slab from which we are allocating */
        struct page *partial;	/* Partially allocated frozen slabs */
#else
        struct slab *slab;	/* The slab from which we are allocating */
        struct slab *partial;	/* Partially allocated frozen slabs */
#endif
    };
    """
    return result


@pwndbg.aglib.kernel.requires_debug_symbols()
def load_slab_typeinfo():
    if pwndbg.aglib.typeinfo.lookup_types("struct kmem_cache") is not None:
        return
    load_common_structs()
    kconfig = pwndbg.aglib.kernel.kconfig()
    defs = []
    if pwndbg.aglib.kernel.krelease() < (6, 2):
        defs.append("BEFORE_V6_2")
    if pwndbg.aglib.kernel.krelease() < (5, 19):
        defs.append("BEFORE_V5_19")
    configs = (
        "CONFIG_SLUB_TINY",
        "CONFIG_SLUB_CPU_PARTIAL",
        "CONFIG_SLAB_FREELIST_HARDENED",
        "CONFIG_NUMA",
        "CONFIG_SLAB_FREELIST_RANDOM",
        "CONFIG_KASAN_GENERIC",
        "CONFIG_HARDENED_USERCOPY",
    )
    for config in configs:
        if config in kconfig:
            defs.append(config)
    sz = kmem_cache_pad_sz(kconfig)
    result = "\n".join(f"#define {s}" for s in defs)
    result += COMMON_TYPES
    result += kmem_cache_structs()
    # this is the kmem_cache SLUB representation for all 5.x and 6.x
    result += f"""
    struct kmem_cache {{
#if !defined(CONFIG_SLUB_TINY) || defined(BEFORE_V6_2)
        struct kmem_cache_cpu *cpu_slab;
#endif
        /* Used for retrieving partial slabs, etc. */
        slab_flags_t flags;
        unsigned long min_partial;
        unsigned int size;		/* Object size including metadata */
        unsigned int object_size;	/* Object size without metadata */
        struct reciprocal_value reciprocal_size;
        unsigned int offset;		/* Free pointer offset */
#ifdef CONFIG_SLUB_CPU_PARTIAL
        /* Number of per cpu partial objects to keep around */
        unsigned int cpu_partial;
        /* Number of per cpu partial slabs to keep around */
        unsigned int cpu_partial_slabs;
#endif
        struct kmem_cache_order_objects oo;
        /* Allocation and freeing of slabs */
        struct kmem_cache_order_objects min;
#ifdef BEFORE_V5_19
        struct kmem_cache_order_objects max;
#endif
        gfp_t allocflags;		/* gfp flags to use on each alloc */
        int refcount;			/* Refcount for slab cache destroy */
        void (*ctor)(void *object);	/* Object constructor */
        unsigned int inuse;		/* Offset to metadata */
        unsigned int align;		/* Alignment */
        unsigned int red_left_pad;	/* Left redzone padding size */
        const char *name;		/* Name (only for display!) */
        struct list_head list;		/* List of slab caches */

        char _pad1[{sz}]; // collapse the struct(s) that are version dependent and complex
#ifdef CONFIG_SLAB_FREELIST_HARDENED
        unsigned long random;
#endif
#ifdef CONFIG_NUMA
        unsigned int remote_node_defrag_ratio;
#endif
#ifdef CONFIG_SLAB_FREELIST_RANDOM
        unsigned int *random_seq;
#endif
#ifdef CONFIG_KASAN_GENERIC
        char _pad2[8]; // the kasan_cache struct includes only 2 int's
#endif
#if defined(BEFORE_V6_2) || defined(CONFIG_HARDENED_USERCOPY)
        unsigned int useroffset;	/* Usercopy region offset */
        unsigned int usersize;		/* Usercopy region size */
#endif
        // ensure it has at least num_numa_nodes, sufficient for us
        struct kmem_cache_node *node[{pwndbg.aglib.kernel.num_numa_nodes()}];
    }};
    """
    header_file_path = pwndbg.commands.cymbol.create_temp_header_file(result)
    pwndbg.commands.cymbol.add_structure_from_header(header_file_path, "")
