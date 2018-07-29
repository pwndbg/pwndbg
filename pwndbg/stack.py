#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Helpers for finding address mappings which are used as
a stack.

Generally not needed, except under qemu-user and for when
binaries do things to remap the stack (e.g. pwnies' postit).
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import gdb

import pwndbg.elf
import pwndbg.events
import pwndbg.memoize
import pwndbg.memory

# Dictionary of stack ranges.
# Key is the gdb thread ptid
# Value is a pwndbg.memory.Page object
stacks = {}

# Whether the stack is protected by NX.
# This is updated automatically by is_executable.
nx     = False


def find(address):
    """
    Returns a pwndbg.memory.Page object which corresponds to the
    currently-loaded stack.
    """
    if not stacks:
        update()

    for stack in stacks:
        if address in stack:
            return stack


def find_upper_stack_boundary(addr, max_pages=1024):
    addr = pwndbg.memory.page_align(int(addr))

    # We can't get the stack size from stack layout and page fault on bare metal mode,
    # so we return current page as a walkaround.
    if not pwndbg.abi.linux:
        return addr + pwndbg.memory.PAGE_SIZE

    return pwndbg.elf.find_elf_magic(addr, max_pages=max_pages, ret_addr_anyway=True)


@pwndbg.events.stop
@pwndbg.memoize.reset_on_stop
def update():
    """
    For each running thread, updates the known address range
    for its stack.
    """
    curr_thread = gdb.selected_thread()
    try:
        for thread in gdb.selected_inferior().threads():
            thread.switch()
            sp = pwndbg.regs.sp

            if sp is None:
                continue

            sp_low = sp & ~(0xfff)
            sp_low -= 0x1000

            # If we don't already know about this thread, create
            # a new Page mapping for it.
            page = stacks.get(thread.ptid, None)
            if page is None:
                start = sp_low
                stop  = find_upper_stack_boundary(sp)
                page  = pwndbg.memory.Page(start, stop-start, 6 if not is_executable() else 7, 0, '[stack]')
                stacks[thread.ptid] = page
                continue
            elif page.objfile is None:
                pid, tid, _ = thread.ptid
                if pid == tid:
                    page.objfile = '[stack]'
                else:
                    page.objfile = '[stack:%i]' % tid

            # If we *DO* already know about this thread, just
            # update the lower boundary if it got any lower.
            low = min(page.vaddr, sp_low)
            if low != page.vaddr:
                page.memsz  += (page.vaddr - low)
                page.vaddr   = low
    finally:
        if curr_thread:
            curr_thread.switch()


@pwndbg.memoize.reset_on_stop
def current():
    """
    Returns the bounds for the stack for the current thread.
    """
    return find(pwndbg.regs.sp)


@pwndbg.events.exit
def clear():
    """
    Clears everything we know about any stack memory ranges.

    Called when the target process exits.
    """
    stacks.clear()
    global nx
    nx = False


@pwndbg.events.stop
@pwndbg.memoize.reset_on_exit
def is_executable():
    global nx
    nx = False

    PT_GNU_STACK = 0x6474e551
    ehdr         = pwndbg.elf.exe()

    for phdr in pwndbg.elf.iter_phdrs(ehdr):
        if phdr.p_type == PT_GNU_STACK:
            nx = True

    return not nx
