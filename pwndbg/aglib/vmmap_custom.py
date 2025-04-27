from __future__ import annotations

import bisect
from typing import List
from typing import Set
from typing import Tuple

import pwndbg
import pwndbg.aglib.memory
import pwndbg.aglib.stack
import pwndbg.color.message as M
import pwndbg.lib.cache
import pwndbg.lib.config
import pwndbg.lib.memory
from pwndbg.dbg import EventType

# List of manually-explored pages which were discovered
# by analyzing the stack or register context.
explored_pages: List[pwndbg.lib.memory.Page] = []

# List of custom pages that can be managed manually by vmmap_* commands family
custom_pages: List[pwndbg.lib.memory.Page] = []

auto_explore = pwndbg.config.add_param(
    "auto-explore-pages",
    "warn",
    "whether to try to infer page permissions when memory maps are missing",
    param_class=pwndbg.lib.config.PARAM_ENUM,
    enum_sequence=["yes", "warn", "no"],
    help_docstring="""
This command can cause errors.
""",
)


_warn_cache: Set[int] = set()


@pwndbg.dbg.event_handler(EventType.NEW_MODULE)
def clear_warn_cache():
    _warn_cache.clear()


def get_custom_pages() -> Tuple[pwndbg.lib.memory.Page, ...]:
    """
    Returns a tuple of `Page` objects representing the memory mappings of the
    target, sorted by virtual address ascending.
    """
    pages: List[pwndbg.lib.memory.Page] = [*explored_pages, *custom_pages]
    pages.sort()
    return tuple(pages)


def add_custom_page(page: pwndbg.lib.memory.Page) -> None:
    bisect.insort(custom_pages, page)

    # Reset all the cache
    # We can not reset get() only, since the result may be used by others.
    # TODO: avoid flush all caches
    pwndbg.lib.cache.clear_caches()


def clear_custom_page() -> None:
    while custom_pages:
        custom_pages.pop()

    # Reset all the cache
    # We can not reset get() only, since the result may be used by others.
    # TODO: avoid flush all caches
    pwndbg.lib.cache.clear_caches()


def explore(address_maybe: int) -> pwndbg.lib.memory.Page | None:
    """
    Given a potential address, check to see what permissions it has.

    Returns:
        Page object

    Note:
        Adds the Page object to a persistent list of pages which are
        only reset when the process dies. This means pages which are
        added this way will not be removed when unmapped.

        Also assumes the entire contiguous section has the same permission.
    """
    if not pwndbg.dbg.selected_inferior().is_linux():
        return None

    if auto_explore.value == "warn":
        page_start = pwndbg.lib.memory.page_align(address_maybe)
        if page_start not in _warn_cache:
            _warn_cache.add(page_start)
            is_readable_addr = pwndbg.aglib.memory.peek(page_start)
            if is_readable_addr:
                print(
                    M.warn(
                        f"Warning: Avoided exploring possible address {address_maybe:#x}.\n"
                        f"You can explicitly explore it with `vmmap-explore {page_start:#x}`"
                    )
                )
        return None
    elif auto_explore.value == "no":
        return None

    address_maybe = pwndbg.lib.memory.page_align(address_maybe)
    flags = get_memory_flags(address_maybe)
    if flags is None:
        return None

    page = find_boundaries(address_maybe)
    page.objfile = f"<explored_{address_maybe >> 12:05x}>"
    page.flags = flags

    explored_pages.append(page)

    # Reset all the cache
    # We can not reset get() only, since the result may be used by others.
    # TODO: avoid flush all caches
    pwndbg.lib.cache.clear_caches()

    return page


def get_memory_flags(address_maybe: int) -> int | None:
    flags = 4 if pwndbg.aglib.memory.peek(address_maybe) else 0
    if not flags:
        return None

    if pwndbg.aglib.memory.poke(address_maybe):
        flags |= 2

    # It's really hard to check for executability, so we just make some guesses:
    # 1. If it's in the same page as the instruction pointer, assume it's executable.
    # 2. If it's in the same page as the stack pointer, try to check the NX bit.
    # 3. Otherwise, just say it's not executable.
    if address_maybe == pwndbg.lib.memory.page_align(pwndbg.aglib.regs.pc):
        flags |= 1
    # TODO: could maybe make this check look at the stacks in pwndbg.aglib.stack.get() but that might have issues
    elif (
        address_maybe == pwndbg.lib.memory.page_align(pwndbg.aglib.regs.sp)
        and pwndbg.aglib.stack.is_executable()
    ):
        flags |= 1

    return flags


def find_boundaries(addr: int, name: str = "", min: int = 0) -> pwndbg.lib.memory.Page:
    """
    Given a single address, find all contiguous pages
    which are mapped.
    """
    start = pwndbg.aglib.memory.find_lower_boundary(addr)
    end = pwndbg.aglib.memory.find_upper_boundary(addr)

    start = max(start, min)
    end = max(end, min)

    return pwndbg.lib.memory.Page(start, end - start, 4, 0, name)
