from __future__ import annotations

import argparse

import pwndbg.aglib.memory
import pwndbg.aglib.regs
import pwndbg.aglib.stack
import pwndbg.auxv
import pwndbg.commands
import pwndbg.commands.telescope
import pwndbg.search
from pwndbg.color import message
from pwndbg.commands import CommandCategory

DEFAULT_NUM_CANARIES_TO_DISPLAY = 1


def canary_value():
    at_random = pwndbg.auxv.get().AT_RANDOM
    if at_random is None:
        return None, None

    global_canary = pwndbg.aglib.memory.pvoid(at_random)

    # masking canary value as canaries on the stack has last byte = 0
    global_canary &= pwndbg.aglib.arch.ptrmask ^ 0xFF

    return global_canary, at_random


parser = argparse.ArgumentParser(description="Print out the current stack canary.")
parser.add_argument(
    "-a",
    "--all",
    action="store_true",
    help="Print out stack canaries for all threads instead of the current thread only.",
)


@pwndbg.commands.Command(parser, command_name="canary", category=CommandCategory.STACK)
@pwndbg.commands.OnlyWhenRunning
def canary(all) -> None:
    global_canary, at_random = canary_value()

    if global_canary is None or at_random is None:
        print(message.error("Couldn't find AT_RANDOM - can't display canary."))
        return

    print(
        message.notice("AT_RANDOM = %#x # points to (not masked) global canary value" % at_random)
    )
    print(message.notice("Canary    = 0x%x (may be incorrect on != glibc)" % global_canary))

    found_canaries = False
    global_canary_packed = pwndbg.aglib.arch.pack(global_canary)
    thread_stacks = pwndbg.aglib.stack.get()
    some_canaries_not_shown = False

    for thread in thread_stacks:
        thread_stack = thread_stacks[thread]

        stack_canaries = list(
            pwndbg.search.search(
                global_canary_packed, start=thread_stack.start, end=thread_stack.end
            )
        )

        if not stack_canaries:
            continue

        found_canaries = True
        num_canaries = len(stack_canaries)
        num_canaries_to_display = num_canaries

        if not all:
            num_canaries_to_display = min(DEFAULT_NUM_CANARIES_TO_DISPLAY, num_canaries)
            if num_canaries_to_display < num_canaries:
                some_canaries_not_shown = True

        if num_canaries > 1:
            print(message.success(f"Thread {thread}: Found valid canaries."))
        else:
            print(message.success(f"Thread {thread}: Found valid canary."))

        for stack_canary in stack_canaries[:num_canaries_to_display]:
            pwndbg.commands.telescope.telescope(address=stack_canary, count=1)

    if found_canaries is False:
        print(message.warn("No canaries found."))

    if some_canaries_not_shown is True:
        print(message.warn("Additional results hidden. Use --all to see them."))
