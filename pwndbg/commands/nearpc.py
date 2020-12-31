#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse

from capstone import *

import pwndbg.arguments
import pwndbg.color
import pwndbg.color.context as C
import pwndbg.color.disasm as D
import pwndbg.color.nearpc as N
import pwndbg.color.theme
import pwndbg.commands.comments
import pwndbg.config
import pwndbg.disasm
import pwndbg.functions
import pwndbg.ida
import pwndbg.regs
import pwndbg.strings
import pwndbg.symbol
import pwndbg.ui
import pwndbg.vmmap
from pwndbg.color import message


def ljust_padding(lst):
    longest_len = max(map(len, lst)) if lst else 0
    return [s.ljust(longest_len) for s in lst]

nearpc_branch_marker = pwndbg.color.theme.Parameter('nearpc-branch-marker', '    ↓', 'branch marker line for nearpc command')
nearpc_branch_marker_contiguous = pwndbg.color.theme.Parameter('nearpc-branch-marker-contiguous', ' ', 'contiguous branch marker line for nearpc command')
pwndbg.color.theme.Parameter('highlight-pc', True, 'whether to highlight the current instruction')
pwndbg.color.theme.Parameter('nearpc-prefix', '►', 'prefix marker for nearpc command')
pwndbg.config.Parameter('left-pad-disasm', True, 'whether to left-pad disassembly')
nearpc_lines = pwndbg.config.Parameter('nearpc-lines', 10, 'number of additional lines to print for the nearpc command')
show_args = pwndbg.config.Parameter('nearpc-show-args', True, 'show call arguments below instruction')

parser = argparse.ArgumentParser(description='''Disassemble near a specified address.''')
parser.add_argument("pc", type=int, nargs="?", default=None, help="Address to dissassemble near.")
parser.add_argument("lines", type=int, nargs="?", default=None, help="Number of lines to show on either side of the address.")
#parser.add_argument("to_string", type=bool, nargs="?", default=False, help="Whether to print it or not.") #TODO make sure this should not be exposed
parser.add_argument("emulate", type=bool, nargs="?", default=False, help="Whether to emulate instructions to find the next ones or just linearly disassemble.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def nearpc(pc=None, lines=None, to_string=False, emulate=False):
    """
    Disassemble near a specified address.
    """

    # Repeating nearpc (pressing enter) makes it show next addresses
    # (writing nearpc explicitly again will reset its state)
    if nearpc.repeat:
        pc = nearpc.next_pc

    result = []

    # Fix the case where we only have one argument, and
    # it's a small value.
    if lines is None and (pc is None or int(pc) < 0x100):
        lines = pc
        pc    = None

    if pc is None:
        pc = pwndbg.regs.pc

    if lines is None:
        lines = nearpc_lines // 2

    pc    = int(pc)
    lines = int(lines)

    # Check whether we can even read this address
    if not pwndbg.memory.peek(pc):
        result.append(message.error('Invalid address %#x' % pc))

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
    instructions = pwndbg.disasm.near(pc, lines, emulate=emulate, show_prev_insns=not nearpc.repeat)

    if pwndbg.memory.peek(pc) and not instructions:
        result.append(message.error('Invalid instructions at %#x' % pc))

    # In case $pc is in a new map we don't know about,
    # this will trigger an exploratory search.
    pwndbg.vmmap.find(pc)

    # Gather all addresses and symbols for each instruction
    symbols = [pwndbg.symbol.get(i.address) for i in instructions]
    addresses = ['%#x' % i.address for i in instructions]

    nearpc.next_pc = instructions[-1].address + instructions[-1].size if instructions else 0

    # Format the symbol name for each instruction
    symbols = ['<%s> ' % sym if sym else '' for sym in symbols]

    # Pad out all of the symbols and addresses
    if pwndbg.config.left_pad_disasm and not nearpc.repeat:
        symbols   = ljust_padding(symbols)
        addresses = ljust_padding(addresses)

    prev = None

    first_pc = True

    # Print out each instruction
    for address_str, symbol, instr in zip(addresses, symbols, instructions):
        asm    = D.instruction(instr)
        prefix_sign  = pwndbg.config.nearpc_prefix

        # Show prefix only on the specified address and don't show it while in repeat-mode
        # or when showing current instruction for the second time
        show_prefix = instr.address == pc and not nearpc.repeat and first_pc
        prefix = ' %s' % (prefix_sign if show_prefix else ' ' * len(prefix_sign))
        prefix = N.prefix(prefix)

        pre = pwndbg.ida.Anterior(instr.address)
        if pre:
            result.append(N.ida_anterior(pre))

        # Colorize address and symbol if not highlighted
        # symbol is fetched from gdb and it can be e.g. '<main+8>'
        if instr.address != pc or not pwndbg.config.highlight_pc or nearpc.repeat:
            address_str = N.address(address_str)
            symbol = N.symbol(symbol)
        elif pwndbg.config.highlight_pc and first_pc:
            prefix = C.highlight(prefix)
            address_str = C.highlight(address_str)
            symbol = C.highlight(symbol)
            first_pc = False

        line   = ' '.join((prefix, address_str, symbol, asm))

        # If there was a branch before this instruction which was not
        # contiguous, put in some ellipses.
        if prev and prev.address + prev.size != instr.address:
            result.append(N.branch_marker('%s' % nearpc_branch_marker))

        # Otherwise if it's a branch and it *is* contiguous, just put
        # and empty line.
        elif prev and any(g in prev.groups for g in (CS_GRP_CALL, CS_GRP_JUMP, CS_GRP_RET)):
            if len('%s' % nearpc_branch_marker_contiguous) > 0:
                result.append('%s' % nearpc_branch_marker_contiguous)

        # For syscall instructions, put the name on the side
        if instr.address == pc:
            syscall_name = pwndbg.arguments.get_syscall_name(instr)
            if syscall_name:
                line += ' <%s>' % N.syscall_name(syscall_name)

        # For Comment Function
        try:
            line += " "*10 + C.comment(pwndbg.commands.comments.file_lists[pwndbg.proc.exe][hex(instr.address)])
        except:
            pass

        result.append(line)

        # For call instructions, attempt to resolve the target and
        # determine the number of arguments.
        if show_args:
            result.extend(['%8s%s' % ('', arg) for arg in pwndbg.arguments.format_args(instruction=instr)])

        prev = instr

    if not to_string:
        print('\n'.join(result))

    return result


parser = argparse.ArgumentParser(description='''Like nearpc, but will emulate instructions from the current $PC forward.''')
parser.add_argument("pc", type=int, nargs="?", default=None, help="Address to emulate near.")
parser.add_argument("lines", type=int, nargs="?", default=None, help="Number of lines to show on either side of the address.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def emulate(pc=None, lines=None, to_string=False, emulate=True):
    """
    Like nearpc, but will emulate instructions from the current $PC forward.
    """
    nearpc.repeat = emulate_command.repeat
    return nearpc(pc, lines, to_string, emulate)


emulate_command = emulate


parser = argparse.ArgumentParser(description='''Compatibility layer for PEDA's pdisass command.''')
parser.add_argument("pc", type=int, nargs="?", default=None, help="Address to disassemble near.")
parser.add_argument("lines", type=int, nargs="?", default=None, help="Number of lines to show on either side of the address.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def pdisass(pc=None, lines=None, to_string=False):
    """
    Compatibility layer for PEDA's pdisass command
    """
    nearpc.repeat = pdisass.repeat
    return nearpc(pc, lines, to_string, False)


nearpc.next_pc = 0
