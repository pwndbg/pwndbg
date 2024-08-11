"""
Helpers for finding address mappings which are used as a stack.

Generally not needed, except under qemu-user and for when
binaries do things to remap the stack (e.g. pwnies' postit).
"""

from __future__ import annotations

from typing import Dict
from typing import List

import gdb

import pwndbg
import pwndbg.gdblib.abi
import pwndbg.gdblib.elf
import pwndbg.gdblib.memory
import pwndbg.lib.cache
from pwndbg.dbg import EventType


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

    if stacks:
        return stacks

    # Note: exploration is slow
    return _fetch_via_exploration()


@pwndbg.lib.cache.cache_until("stop")
def current() -> pwndbg.lib.memory.Page | None:
    """
    Returns the bounds for the stack for the current thread.
    """
    return find(pwndbg.gdblib.regs.sp)


@pwndbg.dbg.event_handler(EventType.STOP)
@pwndbg.lib.cache.cache_until("exit")
def is_executable() -> bool:
    ehdr = pwndbg.gdblib.elf.exe()

    for phdr in pwndbg.gdblib.elf.iter_phdrs(ehdr):
        # check if type is PT_GNU_STACK
        if phdr.p_type == 0x6474E551:
            return False

    return True


def _fetch_via_vmmap() -> Dict[int, pwndbg.lib.memory.Page]:
    stacks: Dict[int, pwndbg.lib.memory.Page] = {}

    pages = pwndbg.gdblib.vmmap.get()

    curr_thread = gdb.selected_thread()
    for thread in gdb.selected_inferior().threads():
        thread.switch()

        # Need to clear regs values cache after switching thread
        # So we get proper value of the SP register
        pwndbg.gdblib.regs.read_reg.cache.clear()

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
        pwndbg.gdblib.regs.read_reg.cache.clear()
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


def callstack() -> List[int]:
    """
    Return the address of the return address for the current frame.
    """
    frame = gdb.newest_frame()
    addresses = []
    while frame:
        addr = int(frame.pc())
        if pwndbg.gdblib.memory.is_readable_address(addr):
            addresses.append(addr)
        frame = frame.older()

    return addresses
