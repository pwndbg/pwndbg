"""
Helpers for finding address mappings which are used as
a stack.

Generally not needed, except under qemu-user and for when
binaries do things to remap the stack (e.g. pwnies' postit).
"""

from typing import Dict

import gdb

import pwndbg.gdblib.abi
import pwndbg.gdblib.elf
import pwndbg.gdblib.events
import pwndbg.gdblib.memory
import pwndbg.lib.memoize

# Dictionary of stack ranges.
# Key is the gdb thread ptid
# Value is a pwndbg.lib.memory.Page object
stacks: Dict[int, pwndbg.lib.memory.Page] = {}

# Whether the stack is protected by NX.
# This is updated automatically by is_executable.
nx = False


def find(address):
    """
    Returns a pwndbg.lib.memory.Page object which corresponds to the
    currently-loaded stack.
    """
    if not stacks:
        update()

    for stack in stacks:
        if address in stack:
            return stack


def find_upper_stack_boundary(stack_ptr, max_pages=1024):
    stack_ptr = pwndbg.lib.memory.page_align(int(stack_ptr))

    # We can't get the stack size from stack layout and page fault on bare metal mode,
    # so we return current page as a walkaround.
    if not pwndbg.gdblib.abi.linux:
        return stack_ptr + pwndbg.gdblib.memory.PAGE_SIZE

    return pwndbg.gdblib.memory.find_upper_boundary(stack_ptr, max_pages)


@pwndbg.gdblib.events.stop
@pwndbg.lib.memoize.reset_on_stop
def update():
    """
    For each running thread, updates the known address range
    for its stack.
    """
    curr_thread = gdb.selected_thread()
    try:
        for thread in gdb.selected_inferior().threads():
            thread.switch()
            sp = pwndbg.gdblib.regs.sp

            # Skip if sp is None or 0
            # (it might be 0 if we debug a qemu kernel)
            if not sp:
                continue

            sp_low = sp & ~(0xFFF)
            sp_low -= 0x1000

            # If we don't already know about this thread, create
            # a new Page mapping for it.
            page = stacks.get(thread.ptid, None)
            if page is None:
                start = sp_low
                stop = find_upper_stack_boundary(sp)
                page = pwndbg.lib.memory.Page(
                    start, stop - start, 6 if not is_executable() else 7, 0, "[stack]"
                )
                stacks[thread.ptid] = page
                continue
            elif page.objfile is None:
                pid, tid, _ = thread.ptid
                if pid == tid:
                    page.objfile = "[stack]"
                else:
                    page.objfile = "[stack:%i]" % tid

            # If we *DO* already know about this thread, just
            # update the lower boundary if it got any lower.
            low = min(page.vaddr, sp_low)
            if low != page.vaddr:
                page.memsz += page.vaddr - low
                page.vaddr = low
    finally:
        if curr_thread:
            curr_thread.switch()


@pwndbg.lib.memoize.reset_on_stop
def current():
    """
    Returns the bounds for the stack for the current thread.
    """
    return find(pwndbg.gdblib.regs.sp)


@pwndbg.gdblib.events.exit
def clear():
    """
    Clears everything we know about any stack memory ranges.

    Called when the target process exits.
    """
    stacks.clear()
    global nx
    nx = False


@pwndbg.gdblib.events.stop
@pwndbg.lib.memoize.reset_on_exit
def is_executable():
    global nx
    nx = False

    PT_GNU_STACK = 0x6474E551
    ehdr = pwndbg.gdblib.elf.exe()

    for phdr in pwndbg.gdblib.elf.iter_phdrs(ehdr):
        if phdr.p_type == PT_GNU_STACK:
            nx = True

    return not nx
