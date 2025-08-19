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


def find_zone_offsets() -> Tuple[int, int, int, int, int]:
    pcp_off, name_off, freelist_off, pcp_pad, zone_sz = None, None, None, None, None
    node_data0 = pwndbg.aglib.kernel.node_data()
    if "CONFIG_NUMA" in pwndbg.aglib.kernel.kconfig():
        node_data0 = node_data0.dereference()
    node_data0 = int(node_data0)
    ptr = node_data0
    for i in range(20):  # the pcp offset should exist in those range
        val = pwndbg.aglib.memory.u64(ptr)
        ptr += 8
        if pwndbg.aglib.memory.is_kernel(val):
            # we have found `zone_pgdat`
            pcp_off = (i + 1) * 8
            break
    assert pcp_off, "can't find pcp offset"
    pcp_ptr = int(pwndbg.aglib.kernel.per_cpu(pwndbg.aglib.memory.u64(node_data0 + pcp_off)))
    for i in range(6):
        val = pwndbg.aglib.memory.u64(pcp_ptr + i * 8)
        if pwndbg.aglib.memory.is_kernel(val):
            pcp_pad = i * 8
            break
    assert pcp_pad, "can't find pcp pad"
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
        if not pwndbg.aglib.memory.is_kernel(prev) and pwndbg.aglib.memory.is_kernel(cur):
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
            zone_sz = ptr - pcp_off - node_data0
            break
    assert (
        zone_sz and zone_sz < 0x4000 and zone_sz & 0xF == 0
    ), f"can't determine sizeof(struct zone) = {zone_sz}"  # just to make sure it is sane
    return pcp_off, name_off, freelist_off, pcp_pad, zone_sz


def load_buddydump_typeinfo():
    if pwndbg.aglib.typeinfo.lookup_types("struct pglist_data") is not None:
        return
    if pwndbg.aglib.kernel.symbol.kversion_cint() is None:
        return
    nmtypes = pwndbg.aglib.kernel.symbol.nmtypes()
    nzones = pwndbg.aglib.kernel.symbol.nzones()
    nnodes = pwndbg.aglib.kernel.num_numa_nodes()
    npcplist = pwndbg.aglib.kernel.symbol.npcplist()
    pwndbg.aglib.kernel.symbol.load_common_structs()

    result = f"#define KVERSION {pwndbg.aglib.kernel.symbol.kversion_cint()}\n"
    result += pwndbg.aglib.kernel.symbol.COMMON_TYPES
    pcp_off, name_off, freearea_off, pcp_pad, zone_sz = find_zone_offsets()
    if "CONFIG_NUMA" in pwndbg.aglib.kernel.kconfig():
        result += "#define CONFIG_NUMA\n"
    result += f"""
    struct free_area {{
        struct list_head	free_list[{nmtypes}];
        unsigned long		nr_free;
    }};
    """
    result += f"""
    struct per_cpu_pages {{
        char _pad[{pcp_pad}];
        /* Lists of pages, one per migrate type stored on the pcp-lists */
        struct list_head lists[{npcplist}]; // constant is sufficient for now
    }};
#if KVERSION < KERNEL_VERSION(5, 14, 0)
    struct per_cpu_pageset {{
        struct per_cpu_pages pcp;
    }};
#endif
/* custom type for page list data */
#ifdef CONFIG_NUMA
    typedef struct pglist_data *node_data_t[{nnodes}];
#else
    typedef struct pglist_data node_data_t;
#endif
    struct zone {{
        char _pad1[{pcp_off}];
#if KVERSION < KERNEL_VERSION(5, 14, 0)
        struct per_cpu_pageset *pageset;
#else
        struct per_cpu_pages *per_cpu_pageset;
#endif
        char _pad2[{name_off - pcp_off - 8}];
        char* name;
        char _pad3[{freearea_off - name_off - 8}];
        struct free_area free_area[{MAX_ORDER}]; // just defaults to 11 is sufficient here
        char _pad[{zone_sz - freearea_off - (MAX_ORDER * (nmtypes * 0x10 + 8))}];
    }};
    """
    result += f"""
    typedef struct pglist_data {{
        struct zone node_zones[{nzones}];
        // ... the rest of the fields are not important
    }} pg_data_t;
    """
    header_file_path = pwndbg.commands.cymbol.create_temp_header_file(result)
    pwndbg.commands.cymbol.add_structure_from_header(header_file_path, "buddydump_structs", True)
