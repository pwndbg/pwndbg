#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Prints out pointer chains starting at some address in memory.

Generally used to print out the stack or register values.
"""
import collections
import pwndbg.arch
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

    address = int(address) & pwndbg.arch.ptrmask
    count   = int(count)

    reg_values = collections.defaultdict(lambda: [])
    for reg in pwndbg.regs.common:
        reg_values[pwndbg.regs[reg]].append(reg)
    # address    = pwndbg.memory.poi(pwndbg.typeinfo.ppvoid, address)
    ptrsize    = pwndbg.typeinfo.ptrsize

    start = address
    stop  = address + (count*ptrsize)
    step  = ptrsize

    # Find all registers which show up in the trace
    regs = {}
    for i in range(start, stop, step):
        values = list(reg_values[i])

        for width in range(1, pwndbg.arch.ptrsize):
            values.extend('%s-%i' % (r,width) for r in reg_values[i+width])

        regs[i] = ' '.join(values)

    # Find the longest set of register information
    if regs:
        longest_regs = max(map(len, regs.values())) + 1
    else:
        longest_regs = 0

    # Print everything out
    result = []
    for i,addr in enumerate(range(start, stop, step)):
        if not pwndbg.memory.peek(addr):
            result.append("<Could not read memory at %#x>" % addr)
            break
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
