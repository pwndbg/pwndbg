from __future__ import annotations

from typing import List
from typing import Tuple

import pwndbg
import pwndbg.aglib.vmmap_custom
import pwndbg.color.message as message
import pwndbg.lib.cache
import pwndbg.lib.memory
from pwndbg.dbg import MemoryMap

pwndbg.config.add_param(
    "vmmap-prefer-relpaths",
    True,
    "show relative paths by default in vmmap",
    param_class=pwndbg.lib.config.PARAM_BOOLEAN,
)


@pwndbg.lib.cache.cache_until("start", "stop")
def get_memory_map() -> MemoryMap:
    return pwndbg.dbg.selected_inferior().vmmap()


@pwndbg.lib.cache.cache_until("start", "stop")
def get() -> Tuple[pwndbg.lib.memory.Page, ...]:
    return tuple(get_memory_map().ranges())


@pwndbg.lib.cache.cache_until("start", "stop")
def find(address: int | pwndbg.dbg_mod.Value | None) -> pwndbg.lib.memory.Page | None:
    if address is None:
        return None

    address = int(address)
    if address < 0:
        return None

    page = get_memory_map().lookup_page(address)

    if page is not None:
        return page

    return pwndbg.aglib.vmmap_custom.explore(address)


def addr_region_start(address: int | pwndbg.dbg_mod.Value) -> int | None:
    """
    Let's define a "region" as contiguous memory compromised of memory mappings
    which all have the same object file name. Also referred to as "File (Base)" by
    `xinfo`.

    Returns:
        The start of the memory region this address belongs to, or None if the address
        is not mapped or a valid memory region couldn't be found.
    """
    address = int(address)
    if address < 0:
        return None

    page = find(address)
    if page is None:
        return None

    file_name = page.objfile
    objpages = filter(lambda p: p.objfile == file_name, pwndbg.aglib.vmmap.get())
    sorted_pages: List[pwndbg.lib.memory.Page] = sorted(objpages, key=lambda p: p.vaddr)

    # Check the region is contiguous.
    for i in range(len(sorted_pages) - 1):
        if sorted_pages[i].end != sorted_pages[i + 1].start:
            print(message.error(f"Pages backed by {file_name} aren't contiguous."))
            return None

    return sorted_pages[0].start
