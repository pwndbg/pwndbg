from __future__ import annotations

import argparse

import pwndbg.aglib
import pwndbg.aglib.memory
import pwndbg.aglib.stack
import pwndbg.aglib.tls
import pwndbg.auxv
import pwndbg.commands
import pwndbg.commands.telescope
import pwndbg.dbg_mod
import pwndbg.libc
import pwndbg.search
from pwndbg.color import message
from pwndbg.commands import CommandCategory
from pwndbg.libc.dispatch import LibcType

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


def canary_from_at_random() -> tuple[int | None, int | None]:
    """
    Get the global canary value from AT_RANDOM with its last byte masked (as glibc does)

    Since glibc 2.44, after ld sets up the canary in TLS, it will refill AT_RANDOM with new
    random bytes. For glibc >= 2.44, this function always returns canary value None.

    Returns:
        tuple: (canary_value | None, at_random_addr | None)
    """
    at_random = pwndbg.auxv.get().AT_RANDOM
    if at_random is None:
        return None, None

    # assuming glibc or accurately versioned unknown
    if pwndbg.libc.version() >= (2, 44):
        return None, at_random

    try:
        global_canary = pwndbg.aglib.memory.read_pointer_width(at_random)
    except pwndbg.dbg_mod.Error:
        return None, at_random

    # masking canary value as canaries on the stack has last byte = 0
    global_canary &= pwndbg.aglib.arch.ptrmask ^ 0xFF

    return global_canary, at_random


def find_tls_canary_addr() -> int | None:
    """
    Find the address of the canary in the Thread Local Storage (TLS).

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


def canary_from_tls() -> tuple[int | None, int | None]:
    """
    Get the global canary value from TLS stack_guard

    Returns:
        tuple: (canary_value | None, canary_addr | None)
    """
    canary_addr = find_tls_canary_addr()
    if canary_addr is None:
        return None, None

    try:
        canary_value = pwndbg.aglib.memory.read_pointer_width(canary_addr)
    except pwndbg.dbg_mod.Error:
        return None, canary_addr

    return canary_value, canary_addr


def canary_value() -> int | None:
    """
    Unified entry to get global canary value, selecting AT_RANDOM below
    glibc 2.44 while selecting TLS stack_guard above glibc 2.44 (inclusive).

    AT_RANDOM is much more light-weight so we prefer it.

    Returns:
        tuple: canary_value or None if not found
    """
    if pwndbg.libc.version() >= (2, 44):
        return canary_from_tls()[0]
    return canary_from_at_random()[0]


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
    """
    Display information about the stack canary, including its location in TLS
    and any copies found on the stack.
    """
    if pwndbg.libc.which() not in (LibcType.GLIBC, LibcType.UNKNOWN):
        print(message.error("Supported only on glibc for now. PRs welcome!"))
        return

    # Check whether we can recover the canary from AT_RANDOM
    global_canary, at_random = canary_from_at_random()

    at_random_msg: str = ""
    if at_random is None:
        assert global_canary is None
        at_random_msg = message.error("Couldn't find AT_RANDOM.")
    else:
        at_random_msg = message.notice(f"AT_RANDOM  = {at_random:#x}")

    # AT_RANDOM is refilled after canary initialization since glibc 2.44
    # https://sourceware.org/git/?p=glibc.git;a=commitdiff;h=337e18d6617bb93a6c718818c4d77d000878dbb6
    # Also note that new thread descriptor stack_guard is copied from old ones
    # https://elixir.bootlin.com/glibc/glibc-2.44/source/nptl/pthread_create.c#L740 (not yet exist)

    if pwndbg.libc.version() >= (2, 44):
        at_random_msg += message.notice(" # overwritten after canary is sourced since glibc 2.44")
    else:
        at_random_msg += message.notice(" # points to the canary value on glibc < 2.44")

    print(at_random_msg)

    # Check whether we can recover the canary from TLS
    tls_canary, tls_addr = canary_from_tls()

    tls_canary_msg: str = ""
    if tls_addr is None:
        tls_canary_msg = message.error("Could not find canary in TLS.")
    else:
        tls_canary_msg = message.notice(f"TLS Canary @ {tls_addr:#x}")
        if tls_canary is None:
            tls_canary_msg += message.error(" (unreadable?)")

    tls_canary_msg += message.notice(" # address where canary is stored")
    print(tls_canary_msg)

    if tls_canary is None and global_canary is None:
        print(message.error("Could not recover canary. Open an issue?"))
        return

    # If we found a valid canary, take it
    actual_canary: int = -1

    if tls_canary is not None and global_canary is not None and tls_canary != global_canary:
        print(
            message.warn(
                f"Warning: TLS canary value {tls_canary:#x} doesn't match global canary {global_canary:#x}!"
            )
        )
        # Let's trust TLS more /shrug
        actual_canary = tls_canary
    elif tls_canary is not None:
        actual_canary = tls_canary
    else:
        assert global_canary is not None  # we would've returned above
        actual_canary = global_canary

    print(message.notice(f"Canary     = {actual_canary:#x}"))

    found_canaries = False
    actual_canary_packed = pwndbg.aglib.arch.pack(actual_canary)
    thread_stacks = pwndbg.aglib.stack.get()
    some_canaries_not_shown = False

    for thread in thread_stacks:
        thread_stack = thread_stacks[thread]

        stack_canaries = list(
            pwndbg.search.search(
                actual_canary_packed, start=thread_stack.start, end=thread_stack.end
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
