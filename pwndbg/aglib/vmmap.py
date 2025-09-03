from __future__ import annotations

import bisect
from typing import Tuple

import pwndbg
import pwndbg.aglib.arch
import pwndbg.aglib.vmmap_custom
import pwndbg.lib.cache
import pwndbg.lib.memory
from pwndbg.dbg import MemoryMap
from pwndbg.lib.arch import Platform
from pwndbg.lib.memory import Page

pwndbg.config.add_param(
    "vmmap-prefer-relpaths",
    True,
    "show relative paths by default in vmmap",
    param_class=pwndbg.lib.config.PARAM_BOOLEAN,
)


def _refine_memory_map(pages: MemoryMap) -> MemoryMap:
    if not (
        pwndbg.aglib.arch.platform == Platform.DARWIN
        and pwndbg.aglib.macho.shared_cache() is not None
    ):
        return pages

    # Darwin platforms use something called the Shared Cache for system
    # libraries. Debuggers may report mapping ranges that belong to the
    # shared cache in many ways, but we would like to tag those with a
    # little more information.
    final_pages = []

    shared_cache = pwndbg.aglib.macho.shared_cache()
    shared_cache_start = shared_cache.base
    shared_cache_end = shared_cache_start + shared_cache.size

    images = list(shared_cache.images_sorted)
    images_base = [image[1] for image in images]

    for page in pages.ranges():
        if page.end < shared_cache_start or page.start >= shared_cache_end:
            # No overlap with the shared cache.
            final_pages.append(page)
            continue

        # We do not support partial overlaps between other mappings and the
        # shared cache.
        #
        # While conceptually there's nothing stopping these from happening,
        # if we ever encounter such a situation, it likely means that we
        # either got something wrong, or that Darwin/LLDB has changed in
        # such a way that we are likely not able to gracefully handle.
        #
        assert page.start >= shared_cache_start and page.end <= shared_cache_end

        one_past_index = bisect.bisect_right(images_base, page.start)
        curr_base = page.start

        while True:
            if one_past_index > len(images):
                break

            if one_past_index == 0:
                # Indicates that this mapping is not part of any image, but
                # still part of the shared cache itself. Use a special name
                # for it.
                objfile = "[SharedCacheHeader]"
            elif images_base[one_past_index - 1] >= page.end:
                break
            else:
                # Name this mapping after the image it belongs to.
                objfile = images[one_past_index - 1][0].decode("ascii")
                curr_base = max(images_base[one_past_index - 1], page.start)

            if one_past_index == len(images):
                end = page.end
            else:
                end = min(page.end, images_base[one_past_index])

            final_pages.append(
                Page(
                    curr_base,
                    end - curr_base,
                    page.flags,
                    curr_base - shared_cache_start,
                    objfile,
                    in_darwin_shared_cache=True,
                )
            )

            one_past_index += 1

    return type(pages)(final_pages)


@pwndbg.lib.cache.cache_until("start", "stop")
def get_memory_map() -> MemoryMap:
    return _refine_memory_map(pwndbg.dbg.selected_inferior().vmmap())


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
