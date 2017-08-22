#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse

import pwndbg.auxv
import pwndbg.color
import pwndbg.commands
import pwndbg.commands.telescope
import pwndbg.memory
import pwndbg.regs
import pwndbg.search

parser = argparse.ArgumentParser(description='Print out the current stack canary')


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def canary():
    auxv = pwndbg.auxv.get()
    at_random = auxv.get('AT_RANDOM', None)
    if at_random is None:
        print("Couldn't find AT_RANDOM - can't display canary.")
        return

    global_canary = pwndbg.memory.pvoid(at_random)

    # masking canary value as canaries on the stack has last byte = 0
    global_canary &= (pwndbg.arch.ptrmask ^ 0xFF)

    print("AT_RANDOM = %#x # points to (not masked) global canary value" % at_random)
    print("Canary    = 0x%x" % global_canary)

    stack_canaries = list(
        pwndbg.search.search(pwndbg.arch.pack(global_canary), mappings=pwndbg.stack.stacks.values())
    )

    if not stack_canaries:
        print(pwndbg.color.yellow('No valid canaries found on the stacks.'))
        return

    print(pwndbg.color.green('Found valid canaries on the stacks:'))
    for stack_canary in stack_canaries:
        pwndbg.commands.telescope.telescope(address=stack_canary, count=1, print_offsets=False)
