from __future__ import annotations

import pwndbg.aglib
import pwndbg.aglib.memory
import pwndbg.aglib.stack
import pwndbg.aglib.vmmap
import pwndbg.chain
import pwndbg.commands
import pwndbg.lib.cache
from pwndbg.commands import CommandCategory
from pwndbg.commands.vmmap import print_vmmap_table_header


@pwndbg.commands.Command(
    "Print out the stack addresses that contain return addresses.", category=CommandCategory.STACK
)
@pwndbg.commands.OnlyWhenRunning
def retaddr() -> None:
    addresses = pwndbg.aglib.stack.callstack()

    sp = pwndbg.aglib.regs.sp

    if sp is None:
        print("Stack pointer not found.")
        return

    stack = pwndbg.aglib.vmmap.find(sp)

    if stack is None:
        print(f"No mapping found at sp = {hex(sp)}.")
        return

    # Find all return addresses on the stack
    start = stack.vaddr
    stop = start + stack.memsz
    while addresses and start < sp < stop:
        value = pwndbg.aglib.memory.u(sp)

        if value in addresses:
            index = addresses.index(value)
            del addresses[:index]
            print(pwndbg.chain.format(sp))

        sp += pwndbg.aglib.arch.ptrsize


@pwndbg.commands.Command("Explore stack from all threads.", category=CommandCategory.STACK)
@pwndbg.commands.OnlyWhenRunning
def stack_explore() -> None:
    old_value = pwndbg.config.auto_explore_stack.value
    pwndbg.config.auto_explore_stack.value = "yes"
    try:
        pwndbg.lib.cache.clear_function_cache(pwndbg.aglib.stack.get)
        pages = pwndbg.aglib.stack.get()
    finally:
        pwndbg.config.auto_explore_stack.value = old_value

    print_vmmap_table_header()
    for page in pages.values():
        print(page)
