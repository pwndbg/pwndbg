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
import math

import pwndbg.arch
import pwndbg.chain
import pwndbg.color.telescope as T
import pwndbg.color.theme as theme
import pwndbg.commands
import pwndbg.config
import pwndbg.memory
import pwndbg.regs
import pwndbg.typeinfo

telescope_lines = pwndbg.config.Parameter('telescope-lines', 8, 'number of lines to printed by the telescope command')
skip_repeating_values = pwndbg.config.Parameter('telescope-skip-repeating-val', True,
                                                'whether to skip repeating values of the telescope command')

offset_separator = theme.Parameter('telescope-offset-separator', '│', 'offset separator of the telescope command')
offset_delimiter = theme.Parameter('telescope-offset-delimiter', ':', 'offset delimiter of the telescope command')
repeating_marker = theme.Parameter('telescope-repeating-marker', '... ↓',
                                   'repeating values marker of the telescope command')


parser = argparse.ArgumentParser(description="""
    Recursively dereferences pointers starting at the specified address
    ($sp by default)
    """)
parser.add_argument("address", nargs="?", default=None, type=int, help="The address to telescope at.")
parser.add_argument("count", nargs="?", default=telescope_lines, type=int, help="The number of lines to show.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def telescope(address=None, count=None, to_string=False):
    """
    Recursively dereferences pointers starting at the specified address
    ($sp by default)
    """
    ptrsize   = pwndbg.typeinfo.ptrsize
    if telescope.repeat:
        address = telescope.last_address + ptrsize
        telescope.offset += 1
    else:
        telescope.offset = 0

    address = int(address if address else pwndbg.regs.sp) & pwndbg.arch.ptrmask
    count   = max(int(count), 1) & pwndbg.arch.ptrmask
    delimiter = T.delimiter(offset_delimiter)
    separator = T.separator(offset_separator)

    # Allow invocation of "telescope 20" to dump 20 bytes at the stack pointer
    if address < pwndbg.memory.MMAP_MIN_ADDR and not pwndbg.memory.peek(address):
        count   = address
        address = pwndbg.regs.sp

    # Allow invocation of "telescope a b" to dump all bytes from A to B
    if int(address) <= int(count):
        # adjust count if it is an address. use ceil divison as count is number of
        # ptrsize values and we don't want to strip out a value if dest is unaligned
        count -= address
        count = max(math.ceil(count / ptrsize), 1)

    reg_values = collections.defaultdict(lambda: [])
    for reg in pwndbg.regs.common:
        reg_values[pwndbg.regs[reg]].append(reg)
    # address    = pwndbg.memory.poi(pwndbg.typeinfo.ppvoid, address)

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
        if skip_repeating_values and last == value:
            if not skip:
                result.append(T.repeating_marker('%s' % repeating_marker))
                skip = True
            continue
        last = value
        skip = False

        line = ' '.join((T.offset("%02x%s%04x%s" % (i + telescope.offset, delimiter,
                                                    addr - start + (telescope.offset * ptrsize), separator)),
                         T.register(regs[addr].ljust(longest_regs)),
                         pwndbg.chain.format(addr)))
        result.append(line)
    telescope.offset += i
    telescope.last_address = addr

    if not to_string:
        print('\n'.join(result))

    return result


parser = argparse.ArgumentParser(description='dereferences on stack data with specified count and offset.')
parser.add_argument('count', nargs='?', default=8, type=int,
                    help='number of element to dump')
parser.add_argument('offset', nargs='?', default=0, type=int,
                    help='Element offset from $sp (support negative offset)')


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def stack(count, offset):
    ptrsize = pwndbg.typeinfo.ptrsize
    telescope.repeat = stack.repeat
    telescope(address=pwndbg.regs.sp + offset * ptrsize, count=count)


telescope.last_address = 0
telescope.offset = 0
