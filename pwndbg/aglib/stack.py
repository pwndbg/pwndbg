"""
Helpers for finding address mappings which are used as a stack.

Generally not needed, except under qemu-user and for when
binaries do things to remap the stack (e.g. pwnies' postit).
"""

from __future__ import annotations

from typing import Dict
from typing import List

import pwndbg
import pwndbg.aglib.elf
import pwndbg.aglib.memory
import pwndbg.aglib.regs
import pwndbg.aglib.vmmap
import pwndbg.aglib.vmmap_custom
import pwndbg.color.message as M
import pwndbg.lib.cache
import pwndbg.lib.config
import pwndbg.lib.memory

auto_explore = pwndbg.config.add_param(
    "auto-explore-stack",
    "warn",
    "stack exploration; it may be really slow",
    param_class=pwndbg.lib.config.PARAM_ENUM,
    enum_sequence=["warn", "yes", "no"],
)


def find(address: int) -> pwndbg.lib.memory.Page | None:
    """
    Returns a pwndbg.lib.memory.Page object which corresponds to given address stack
    or None if it does not exist
    """
    for stack in get().values():
        if address in stack:
            return stack

    return None


def find_upper_stack_boundary(stack_ptr: int, max_pages: int = 1024) -> int:
    stack_ptr = pwndbg.lib.memory.page_align(int(stack_ptr))

    # We can't get the stack size from stack layout and page fault on bare metal mode,
    # so we return current page as a walkaround.
    if not pwndbg.dbg.selected_inferior().is_linux():
        return stack_ptr + pwndbg.aglib.memory.PAGE_SIZE

    return pwndbg.aglib.memory.find_upper_boundary(stack_ptr, max_pages)


@pwndbg.lib.cache.cache_until("stop")
def get() -> Dict[int, pwndbg.lib.memory.Page]:
    """
    For each running thread, return the known address range for its stack
    Returns a dict which should never be modified (since its cached)
    """
    stacks = _fetch_via_vmmap()

    if stacks:
        return stacks

    # Note: exploration is slow
    return _fetch_via_exploration()


@pwndbg.lib.cache.cache_until("stop")
def current() -> pwndbg.lib.memory.Page | None:
    """
    Returns the bounds for the stack for the current thread.
    """
    return find(pwndbg.aglib.regs.sp)


@pwndbg.lib.cache.cache_until("start")
def is_executable() -> bool:
    ehdr = pwndbg.aglib.elf.exe()
    if ehdr is None:
        return True

    for phdr in pwndbg.aglib.elf.iter_phdrs(ehdr):
        # check if type is PT_GNU_STACK
        if phdr.p_type == 0x6474E551:
            return False

    return True


def _fetch_via_vmmap() -> Dict[int, pwndbg.lib.memory.Page]:
    stacks: Dict[int, pwndbg.lib.memory.Page] = {}

    pages = pwndbg.aglib.vmmap.get()

    for thread in pwndbg.dbg.selected_inferior().threads():
        with thread.bottom_frame() as frame:
            sp = frame.sp()

        # Skip if sp is 0 (it might be 0 if we debug a qemu kernel)
        if not sp:
            continue

        # Find the given SP in pages
        page = next((page for page in pages if sp in page), None)
        if not page:
            # TODO: Handle case where the page is not found;
            #  consider exploring the `sp` register using method `_fetch_via_exploration`?
            continue
        stacks[thread.index()] = page

    return stacks


def _fetch_via_exploration() -> Dict[int, pwndbg.lib.memory.Page]:
    """
    TODO/FIXME: This exploration is not great since it now hits on each stop
    (based on how this function is used). Ideally, explored stacks should be
    cached globally and cleared only with new debugged target.

    This way, we should also explore the stack only for a maximum of few pages
    so that we won't take too much time finding its bounds. Then, on each stop
    we can explore one more (or a few more) pages for the given current stack
    we are currently on, ideally not taking the precious time of our users.

    An alternative to this is dumping this functionality completely and this
    will be decided hopefully after a next release.
    """
    if auto_explore.value == "warn":
        print(
            M.warn(
                "Warning: All methods to detect STACK have failed.\n"
                "You can explore STACK using exploration, but it may be very slow.\n"
                "To explicitly explore, use the command: `stack-explore`\n"
                "Alternatively, enable it by default with: `set auto-explore-stack yes`"
            )
        )
        return {}
    elif auto_explore.value == "no":
        return {}

    thread_sp = []
    for thread in pwndbg.dbg.selected_inferior().threads():
        with thread.bottom_frame() as frame:
            sp = frame.sp()

        # Skip if sp is None or 0
        # (it might be 0 if we debug a qemu kernel)
        if not sp:
            continue
        thread_sp.append((sp, thread.index()))

    # Sort by the `sp` register (stack pointer), starting with the smallest value.
    # This helps prevent scanning the same page multiple times.
    thread_sp.sort(key=lambda t: t[0])

    stacks: Dict[int, pwndbg.lib.memory.Page] = {}
    for sp, thread_idx in thread_sp:
        start = pwndbg.lib.memory.page_align(sp) - pwndbg.lib.memory.PAGE_SIZE

        page_found = next((page for page in stacks.values() if start in page), None)
        if page_found:
            # Skip further exploration of stacks that have already been scanned.
            stacks[thread_idx] = page_found
            continue

        stop = find_upper_stack_boundary(sp)
        page = pwndbg.lib.memory.Page(
            start, stop - start, 6 if not is_executable() else 7, 0, f"[stack:{thread_idx}]"
        )
        stacks[thread_idx] = page
        pwndbg.aglib.vmmap_custom.add_custom_page(page)

    return stacks


def callstack() -> List[int]:
    """
    Return the address of the return address for the current frame.
    """
    frame = pwndbg.dbg.selected_frame()
    addresses = []
    while frame:
        addr = frame.pc()
        if pwndbg.aglib.memory.is_readable_address(addr):
            addresses.append(addr)
        frame = frame.parent()

    return addresses
