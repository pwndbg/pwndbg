#!/usr/bin/env python
# -*- coding: utf-8 -*-
from capstone import *

import pwndbg.arguments
import pwndbg.color
import pwndbg.disasm
import pwndbg.disasm.color
import pwndbg.functions
import pwndbg.ida
import pwndbg.regs
import pwndbg.strings
import pwndbg.symbol
import pwndbg.ui
import pwndbg.vmmap


@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def nearpc(pc=None, lines=None, to_string=False):
    """
    Disassemble near a specified address.
    """
    # Fix the case where we only have one argument, and
    # it's a small value.
    if lines is None and (pc is None or int(pc) < 0x100):
        lines = pc
        pc    = None

    if pc is None:
        pc = pwndbg.regs.pc

    if lines is None:
        lines = 5

    pc    = int(pc)
    lines = int(lines)

    result = []
    instructions = pwndbg.disasm.near(pc, lines)

    # In case $pc is in a new map we don't know about,
    # this will trigger an exploratory search.
    pwndbg.vmmap.find(pc)

    # Find all of the symbols for the addresses
    symbols = []
    for i in instructions:
        symbol = pwndbg.symbol.get(i.address)
        if symbol:
            symbol = '<%s> ' % symbol
        symbols.append(symbol)

    # Find the longest symbol name so we can adjust
    if symbols:
        longest_sym = max(map(len, symbols))
    else:
        longest_sym = ''

    # Pad them all out
    for i,s in enumerate(symbols):
        symbols[i] = s.ljust(longest_sym)

    # Print out each instruction
    prev = None
    for i,s in zip(instructions, symbols):
        asm    = pwndbg.disasm.color.instruction(i)
        prefix = ' =>' if i.address == pc else '   '

        pre = pwndbg.ida.Anterior(i.address)
        if pre:
            result.append(pwndbg.color.bold(pre))

        line   = ' '.join((prefix, "%#x" % i.address, s or '', asm))

        old, prev = prev, i

        # Put an ellipsis between discontiguous code groups
        if not old:
            pass
        elif old.address + old.size != i.address:
            result.append('...')
        # Put an empty line after fall-through basic blocks
        elif any(g in old.groups for g in (CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET)):
            result.append('')

        result.append(line)

        # For call instructions, attempt to resolve the target and
        # determine the number of arguments.
        for arg, value in pwndbg.arguments.arguments(i):
            code   = False if arg.type == 'char' else True
            pretty = pwndbg.chain.format(value, code=code)
            result.append('%8s%-10s %s' % ('',arg.name+':', pretty))


    if not to_string:
        print('\n'.join(result))

    return result
