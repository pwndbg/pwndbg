#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pwndbglib.auxv
import pwndbglib.commands
import pwndbglib.commands.telescope
import pwndbglib.memory
import pwndbglib.regs
import pwndbglib.search
from pwndbglib.color import message


def canary_value():
    auxv = pwndbglib.auxv.get()
    at_random = auxv.get('AT_RANDOM', None)
    if at_random is None:
        return None, None

    global_canary = pwndbglib.memory.pvoid(at_random)

    # masking canary value as canaries on the stack has last byte = 0
    global_canary &= (pwndbglib.arch.ptrmask ^ 0xFF)

    return global_canary, at_random


@pwndbglib.commands.ArgparsedCommand('Print out the current stack canary.')
@pwndbglib.commands.OnlyWhenRunning
def canary():
    global_canary, at_random = canary_value()

    if global_canary is None or at_random is None:
        print(message.error("Couldn't find AT_RANDOM - can't display canary."))
        return

    print(message.notice("AT_RANDOM = %#x # points to (not masked) global canary value" % at_random))
    print(message.notice("Canary    = 0x%x (may be incorrect on != glibc)" % global_canary))

    stack_canaries = list(
        pwndbglib.search.search(pwndbglib.arch.pack(global_canary), mappings=pwndbglib.stack.stacks.values())
    )

    if not stack_canaries:
        print(message.warn('No valid canaries found on the stacks.'))
        return

    print(message.success('Found valid canaries on the stacks:'))
    for stack_canary in stack_canaries:
        pwndbglib.commands.telescope.telescope(address=stack_canary, count=1)
