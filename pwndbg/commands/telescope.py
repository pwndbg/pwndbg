#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Prints out pointer chains starting at some address in memory.

Generally used to print out the stack or register values.
"""
import pwndbg.chain
import pwndbg.commands
import pwndbg.memory
import pwndbg.regs
import pwndbg.typeinfo


@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def telescope(address=None, count=8, to_string=False):
    """
    Recursively dereferences pointers starting at the specified address
    ($sp by default)
    """
    if None not in (address, count) and int(address) < int(count):
        count -= address

    if address is None:
        address = pwndbg.regs.sp

    if address < 100:
        count   = address
        address = pwndbg.regs.sp

    address = int(address)
    count   = int(count)

    reg_values = {r:v for (r,v) in pwndbg.regs.items()}
    # address    = pwndbg.memory.poi(pwndbg.typeinfo.ppvoid, address)
    ptrsize    = pwndbg.typeinfo.ptrsize

    start = address
    stop  = address + (count*ptrsize)
    step  = ptrsize

    # Find all registers which show up in the trace
    regs = {}
    for i in range(start, stop, step):
        regs[i] = []
        for reg, regval in reg_values.items():
            if i <= regval < i+ptrsize:
                regs[i].append(reg)
        regs[i] = ' '.join(regs[i])

    # Find the longest set of register information
    if regs:
        longest_regs = max(map(len, regs.values())) + 1
    else:
        longest_regs = 0

    # Print everything out
    result = []
    for i,addr in enumerate(range(start, stop, step)):
        line = ' '.join(("%02x:%04x|" % (i, addr-start),
                         regs[addr].ljust(longest_regs),
                         pwndbg.chain.format(addr)))
        result.append(line)

    if not to_string:
        print('\n'.join(result))

    return result



@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def stack(*a):
    """
    Recursively dereferences pointers on the stack
    """
    telescope(*a)
