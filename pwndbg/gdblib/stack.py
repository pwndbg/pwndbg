"""
Helpers for finding address mappings which are used as a stack.

Generally not needed, except under qemu-user and for when
binaries do things to remap the stack (e.g. pwnies' postit).
"""

from __future__ import annotations

from typing import Dict

import gdb

import pwndbg.gdblib.abi
import pwndbg.gdblib.elf
import pwndbg.gdblib.events
import pwndbg.gdblib.memory
import pwndbg.lib.cache


def find(address: int):
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
    if not pwndbg.gdblib.abi.linux:
        return stack_ptr + pwndbg.gdblib.memory.PAGE_SIZE

    return pwndbg.gdblib.memory.find_upper_boundary(stack_ptr, max_pages)


@pwndbg.lib.cache.cache_until("stop")
def get() -> Dict[int, pwndbg.lib.memory.Page]:
    """
    For each running thread, return the known address range for its stack
    Returns a dict which should never be modified (since its cached)
    """
    stacks = _fetch_via_vmmap()

    # This is slow :(
    if not stacks:
        _fetch_via_exploration()

    return stacks


@pwndbg.lib.cache.cache_until("stop")
def current():
    """
    Returns the bounds for the stack for the current thread.
    """
    return find(pwndbg.gdblib.regs.sp)


@pwndbg.gdblib.events.stop
@pwndbg.lib.cache.cache_until("exit")
def is_executable() -> bool:
    nx = False

    PT_GNU_STACK = 0x6474E551
    ehdr = pwndbg.gdblib.elf.exe()

    for phdr in pwndbg.gdblib.elf.iter_phdrs(ehdr):
        if phdr.p_type == PT_GNU_STACK:
            nx = True

    return not nx


def _fetch_via_vmmap() -> Dict[int, pwndbg.lib.memory.Page]:
    stacks: Dict[int, pwndbg.lib.memory.Page] = {}

    pages = pwndbg.gdblib.vmmap.get()

    curr_thread = gdb.selected_thread()
    for thread in gdb.selected_inferior().threads():
        thread.switch()

        # Need to clear regs values cache after switching thread
        # So we get proper value of the SP register
        pwndbg.gdblib.regs.__getattr__.cache.clear()

        sp = pwndbg.gdblib.regs.sp

        # Skip if sp is 0 (it might be 0 if we debug a qemu kernel)
        if not sp:
            continue

        page = None

        # Find the given SP in pages
        for p in pages:
            if sp in p:
                page = p
                break

        if page:
            stacks[thread.num] = page
            continue
    curr_thread.switch()

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
    stacks: Dict[int, pwndbg.lib.memory.Page] = {}

    curr_thread = gdb.selected_thread()
    for thread in gdb.selected_inferior().threads():
        thread.switch()
        pwndbg.gdblib.regs.__getattr__.cache.clear()
        sp = pwndbg.gdblib.regs.sp

        # Skip if sp is None or 0
        # (it might be 0 if we debug a qemu kernel)
        if not sp:
            continue

        sp_low = sp & ~(0xFFF)
        sp_low -= 0x1000

        start = sp_low
        stop = find_upper_stack_boundary(sp)
        page = pwndbg.lib.memory.Page(
            start, stop - start, 6 if not is_executable() else 7, 0, f"[stack:{thread.num}]"
        )
        stacks[thread.num] = page
        continue

    curr_thread.switch()

    return stacks
