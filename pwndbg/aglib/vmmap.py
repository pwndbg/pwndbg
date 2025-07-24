from __future__ import annotations

from typing import Tuple

import pwndbg
import pwndbg.aglib.vmmap_custom
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
        is not mapped.
    """
    address = int(address)
    if address < 0:
        return None

    mappings = sorted(pwndbg.aglib.vmmap.get(), key=lambda p: p.vaddr)
    idx = -1
    for i in range(len(mappings)):
        if mappings[i].start <= address < mappings[i].end:
            idx = i
            break

    if idx == -1:
        # Maybe we can find the page by exploring.
        explored_page = pwndbg.aglib.vmmap_custom.explore(address)
        if not explored_page:
            return None

        # We know vmmap_custom.explore() can only find one page, it does
        # not cascade a whole region so there is no need to look backwards.
        return explored_page.start

    # Look backwards from i to find all the mappings with the same name.
    objname = mappings[i].objfile
    while i > 0 and objname == mappings[i - 1].objfile:
        i -= 1

    # There might be other mappings with the name "objname" in the address space
    # but they are not contiguous with us, so we don't care.
    return mappings[i].start
