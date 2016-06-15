#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from __future__ import unicode_literals

import collections

from capstone import *

import gdb
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


pwndbg.config.Parameter('highlight-pc', True, 'whether to highlight the current instruction')

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def nearpc(pc=None, lines=None, to_string=False, emulate=False):
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

    # # Load source data if it's available
    # pc_to_linenos = collections.defaultdict(lambda: [])
    # lineno_to_src = {}
    # frame = gdb.selected_frame()
    # if frame:
    #     sal = frame.find_sal()
    #     if sal:
    #         symtab = sal.symtab
    #         objfile = symtab.objfile
    #         sourcefilename = symtab.filename
    #         with open(sourcefilename, 'r') as sourcefile:
    #             lineno_to_src = {i:l for i,l in enumerate(sourcefile.readlines())}

    #         for line in symtab.linetable():
    #             pc_to_linenos[line.pc].append(line.line)

    result = []
    instructions = pwndbg.disasm.near(pc, lines, emulate=emulate)

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

    prev = None

    # Print out each instruction
    for i,s in zip(instructions, symbols):
        asm    = pwndbg.disasm.color.instruction(i)
        prefix = ' =>' if i.address == pc else '   '

        pre = pwndbg.ida.Anterior(i.address)
        if pre:
            result.append(pwndbg.color.bold(pre))

        # for line in pc_to_linenos[i.address]:
        #     result.append('%s %s' % (line, lineno_to_src[line].strip()))

        line   = ' '.join((prefix, "%#x" % i.address, s or '', asm))

        # Highlight the current line if the config is enabled
        if pwndbg.config.highlight_pc and i.address == pc:
            line = pwndbg.color.highlight(line)

        # If there was a branch before this instruction which was not
        # contiguous, put in some ellipses.
        if prev and prev.address + prev.size != i.address:
            result.append('...')

        # Otherwise if it's a branch and it *is* contiguous, just put
        # and empty line.
        elif prev and any(g in prev.groups for g in (CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET)):
            result.append('')


        # For syscall instructions, put the name on the side
        if i.address == pc:
            syscall_name = pwndbg.arguments.get_syscall_name(i)
            if syscall_name:
                line += ' <%s>' % syscall_name

        result.append(line)

        # For call instructions, attempt to resolve the target and
        # determine the number of arguments.
        for arg, value in pwndbg.arguments.get(i):
            code   = False if arg.type == 'char' else True
            pretty = pwndbg.chain.format(value, code=code)
            result.append('%8s%-10s %s' % ('',arg.name+':', pretty))

        prev = i


    if not to_string:
        print('\n'.join(result))

    return result

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def emulate(pc=None, lines=None, to_string=False, emulate=True):
    """
    Like nearpc, but will emulate instructions from the current $PC forward.
    """
    return nearpc(pc, lines, to_string, emulate)
