#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Prints out pointer chains starting at some address in memory.

Generally used to print out the stack or register values.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import collections

import pwndbg.arch
import pwndbg.chain
import pwndbg.color.telescope as T
import pwndbg.color.theme as theme
import pwndbg.commands
import pwndbg.config
import pwndbg.memory
import pwndbg.regs
import pwndbg.typeinfo

telescope_lines = pwndbg.config.Parameter('telescope-lines',
                                         8,
                                         'number of lines to printed by the telescope command')
offset_separator = theme.Parameter('telescope-offset-separator', '│', 'offset separator of the telescope command')
offset_delimiter = theme.Parameter('telescope-offset-delimiter', ':', 'offset delimiter of the telescope command')
repeating_maker  = theme.Parameter('telescope-repeating-marker', '... ↓', 'repeating values marker of the telescope command')


@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def telescope(address=None, count=telescope_lines, to_string=False):
    """
    Recursively dereferences pointers starting at the specified address
    ($sp by default)
    """
    address = int(address if address else pwndbg.regs.sp) & pwndbg.arch.ptrmask
    count   = int(count) & pwndbg.arch.ptrmask
    delimiter = T.delimiter(offset_delimiter)
    separator = T.separator(offset_separator)

    # Allow invocation of "hexdump 20" to dump 20 bytes at the stack pointer
    if address < pwndbg.memory.MMAP_MIN_ADDR and not pwndbg.memory.peek(address):
        count   = address
        address = pwndbg.regs.sp

    # Allow invocation of "hexdump a b" to dump all bytes from A to B
    if int(address) < int(count):
        count -= address

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
    last   = None
    skip   = False
    for i,addr in enumerate(range(start, stop, step)):
        if not pwndbg.memory.peek(addr):
            result.append("<Could not read memory at %#x>" % addr)
            break

        # Collapse repeating values.
        value = pwndbg.memory.pvoid(addr)
        if last == value:
            if not skip:
                result.append(T.repeating_marker('%s' % repeating_maker))
                skip = True
            continue
        last = value
        skip = False

        line = ' '.join((T.offset("%02x%s%04x%s" % (i, delimiter, addr-start, separator)),
                         T.register(regs[addr].ljust(longest_regs)),
                         pwndbg.chain.format(addr)))
        result.append(line)

    if not to_string:
        print('\n'.join(result))

    return result


parser = argparse.ArgumentParser(description='dereferences on stack data with specified count and offset')
parser.add_argument('count', nargs='?', default=8, type=int,
                    help='number of element to dump')
parser.add_argument('offset', nargs='?', default=0, type=int,
                    help='Element offset from $sp (support negative offset)')
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def stack(count, offset):
    """
    Recursively dereferences pointers on the stack
    """
    ptrsize = pwndbg.typeinfo.ptrsize
    telescope(address=pwndbg.regs.sp + offset * ptrsize, count=count)
