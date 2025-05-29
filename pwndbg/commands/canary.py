from __future__ import annotations

import argparse
from typing import Optional
from typing import Tuple

import pwndbg.aglib.memory
import pwndbg.aglib.regs
import pwndbg.aglib.stack
import pwndbg.aglib.tls
import pwndbg.auxv
import pwndbg.commands
import pwndbg.commands.telescope
import pwndbg.search
from pwndbg.color import message
from pwndbg.commands import CommandCategory

DEFAULT_NUM_CANARIES_TO_DISPLAY = 1

# Architecture-specific TLS canary offsets
# These offsets are from the TLS base to the canary
# References:
# - x86_64: fs:0x28 (https://elixir.bootlin.com/glibc/glibc-2.41.9000/source/sysdeps/x86_64/nptl/tls.h)
# - i386: gs:0x14 (https://elixir.bootlin.com/glibc/glibc-2.41.9000/source/sysdeps/i386/nptl/tls.h)
# - aarch64: tpidr_el0 + 0x28 (https://elixir.bootlin.com/glibc/glibc-2.41.9000/source/sysdeps/aarch64/nptl/tls.h)
TLS_CANARY_OFFSETS = {
    "x86-64": 0x28,
    "i386": 0x14,
    "aarch64": 0x28,
}


def canary_value() -> Tuple[Optional[int], Optional[int]]:
    """Get the global canary value from AT_RANDOM with its last byte masked (as glibc does)

    Returns:
        tuple: (canary_value, at_random_addr) or (None, None) if not found
    """
    at_random = pwndbg.auxv.get().AT_RANDOM
    if at_random is None:
        return None, None

    global_canary = pwndbg.aglib.memory.read_pointer_width(at_random)

    # masking canary value as canaries on the stack has last byte = 0
    global_canary &= pwndbg.aglib.arch.ptrmask ^ 0xFF

    return global_canary, at_random


def find_tls_canary_addr() -> Optional[int]:
    """Find the address of the canary in the Thread Local Storage (TLS).

    The canary is stored at a fixed offset from the TLS base, which varies by architecture.
    The TLS base can be accessed through architecture-specific registers:
    - x86_64: fs register
    - i386: gs register
    - aarch64: tpidr_el0 register

    Returns:
        int: The virtual address of the canary in TLS, or None if not found/supported
    """
    arch = pwndbg.aglib.arch.name

    # Get TLS base address
    tls_base = (
        pwndbg.aglib.tls.find_address_with_register()
        or pwndbg.aglib.tls.find_address_with_pthread_self()
    )
    if not tls_base:
        return None

    # Get architecture-specific offset
    offset = TLS_CANARY_OFFSETS.get(arch)
    if offset is None:
        return None

    return tls_base + offset


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
    """Display information about the stack canary, including its location in TLS and any copies found on the stack."""
    global_canary, at_random = canary_value()

    if global_canary is None or at_random is None:
        print(message.error("Couldn't find AT_RANDOM - can't display canary."))
        return

    print(message.notice(f"AT_RANDOM  = {at_random:#x} # points to global canary seed value"))

    # Get and display the TLS canary address
    tls_addr = find_tls_canary_addr()
    if tls_addr is not None:
        print(message.notice(f"TLS Canary = {tls_addr:#x} # address where canary is stored"))

        # Verify the value at the TLS address matches our computed canary
        try:
            tls_canary = pwndbg.aglib.memory.read_pointer_width(tls_addr) & (
                pwndbg.aglib.arch.ptrmask ^ 0xFF
            )
            if tls_canary != global_canary:
                print(message.warn("Warning: TLS canary value doesn't match global canary!"))
        except Exception:
            print(message.warn("Warning: Could not read TLS canary value"))
    else:
        print(message.warn("Note: Could not determine TLS canary address for current architecture"))

    print(message.notice(f"Canary     = {global_canary:#x} (may be incorrect on != glibc)"))

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
