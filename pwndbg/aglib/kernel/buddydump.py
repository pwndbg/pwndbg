from __future__ import annotations

from typing import Tuple

import pwndbg
import pwndbg.aglib.kernel.symbol
import pwndbg.aglib.memory
import pwndbg.aglib.symbol
import pwndbg.aglib.typeinfo

#########################################
# structurs relevant to buddydump
#
#########################################
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
        struct list_head lists[{pwndbg.aglib.kernel.symbol.npcplist()}]; // constant is sufficient for now
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
    node_data0 = pwndbg.aglib.kernel.node_data()
    if "CONFIG_NUMA" in pwndbg.aglib.kernel.kconfig():
        node_data0 = node_data0.dereference()
    ptr = int(node_data0) + start_idx * 8
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
        assert 0 < pcp_sz < 0x100, "can't determine pcp_sz"
    for i in range(20):
        char_ptr = pwndbg.aglib.memory.u64(ptr)
        ptr += 8
        if (
            pwndbg.aglib.memory.string(char_ptr).decode()
            in pwndbg.aglib.kernel.symbol.POSSIBLE_ZONE_NAMES
        ):
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
        MAX_ORDER * (pwndbg.aglib.kernel.symbol.nmtypes() * 0x10 + 8)
    ) + 0x10  # guessed MAX_ORDER * sizeof(struct list_head) + some other fields
    # find the next `zone_pgdat`
    for i in range(100):  # the pcp offset should exist in those range
        val = pwndbg.aglib.memory.u64(ptr)
        ptr += 8
        if pwndbg.aglib.memory.is_kernel(val):
            # we have found `zone_pgdat`
            zone_sz = ptr - pcp_off - int(node_data0)
            break
    assert (
        zone_sz and zone_sz < 0x4000 and zone_sz & 0xF == 0
    ), f"can't determine sizeof(struct zone) = {zone_sz}"  # just to make sure it is sane
    return pcp_off, name_off, freelist_off, pcp_sz, zone_sz


def load_buddydump_typeinfo():
    nmtypes = pwndbg.aglib.kernel.symbol.nmtypes()
    nzones = pwndbg.aglib.kernel.symbol.nzones()
    if not nmtypes or not nzones:
        return
    if pwndbg.aglib.typeinfo.lookup_types("struct pglist_data") is not None:
        return
    pwndbg.aglib.kernel.symbol.load_common_structs()

    pglist_data = f"""
    typedef struct pglist_data {{
        struct zone node_zones[{nzones}];
        // ... the rest of the fields are not important
        // but make the struct dynamic
        char _pad[];
    }} pg_data_t;
    """
    pcp_off, name_off, freearea_off, pcp_sz, zone_sz = find_zone_offsets()
    per_cpu_pages = get_pcp_struct(pcp_sz)
    zone = ""
    if pwndbg.aglib.kernel.krelease() < (5, 14):
        zone = "#define BEFORE_V5_14\n"
    if "CONFIG_NUMA" in pwndbg.aglib.kernel.kconfig():
        zone += "#define CONFIG_NUMA\n"
    zone += f"""
#ifdef CONFIG_NUMA
    typedef struct pglist_data *node_data_t[1]; // just support 1 node for now, the most common case
#else
    typedef struct pglist_data node_data_t;
#endif
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
        char _pad[{hex(zone_sz - freearea_off - (MAX_ORDER * (nmtypes * 0x10 + 8)))}];
    }};
    """
    free_area = f"""
    struct free_area {{
        struct list_head	free_list[{nmtypes}];
        unsigned long		nr_free;
    }};
    """
    result = (
        pwndbg.aglib.kernel.symbol.COMMON_TYPES + free_area + zone + per_cpu_pages + pglist_data
    )
    header_file_path = pwndbg.commands.cymbol.create_temp_header_file(result)
    pwndbg.commands.cymbol.add_structure_from_header(header_file_path, "buddydump_structs", True)
