#!/usr/bin/env python
# -*- coding: utf-8 -*-

import capstone

import pwndbglib.chain
import pwndbglib.color.context as C
import pwndbglib.color.memory as M
import pwndbglib.color.syntax_highlight as H
import pwndbglib.color.theme as theme
import pwndbglib.config as config
import pwndbglib.disasm.jump
from pwndbglib.color import generateColorFunction
from pwndbglib.color import ljust_colored
from pwndbglib.color.message import on

capstone_branch_groups = set((
    capstone.CS_GRP_CALL,
    capstone.CS_GRP_JUMP
))

config_branch = theme.ColoredParameter('disasm-branch-color', 'bold', 'color for disasm (branch/call instruction)')

def branch(x):
    return generateColorFunction(config.disasm_branch_color)(x)


def syntax_highlight(ins):
    return H.syntax_highlight(ins, filename='.asm')


def instruction(ins):
    asm = '%-06s %s' % (ins.mnemonic, ins.op_str)
    if pwndbglib.config.syntax_highlight:
        asm = syntax_highlight(asm)
    is_branch = set(ins.groups) & capstone_branch_groups

    # Highlight the current line if enabled
    if pwndbglib.config.highlight_pc and ins.address == pwndbglib.regs.pc:
        asm = C.highlight(asm)

    # tl;dr is a branch?
    if ins.target not in (None, ins.address + ins.size):
        sym    = pwndbglib.symbol.get(ins.target) or None
        target = M.get(ins.target)
        const  = ins.target_const
        hextarget = hex(ins.target)
        hexlen    = len(hextarget)

        # If it's a constant expression, color it directly in the asm.
        if const:
            asm = '%s <%s>' % (ljust_colored(asm, 36), target)
            asm = asm.replace(hex(ins.target), sym or target)

        # It's not a constant expression, but we've calculated the target
        # address by emulation or other means (for example showing ret instruction target)
        elif sym:
            asm = '%s <%s; %s>' % (ljust_colored(asm, 36), target, sym)

        # We were able to calculate the target, but there is no symbol
        # name for it.
        else:
            asm += '<%s>' % (target)

    # not a branch
    elif ins.symbol:
        if is_branch and not ins.target:
            asm = '%s <%s>' % (asm, ins.symbol)

            # XXX: not sure when this ever happens
            asm += '<-- file a pwndbg bug for this'
        else:
            asm = asm.replace(hex(ins.symbol_addr), ins.symbol)
            asm = '%s <%s>' % (ljust_colored(asm, 36), M.get(ins.symbol_addr))

    # Style the instruction mnemonic if it's a branch instruction.
    if is_branch:
        asm = asm.replace(ins.mnemonic, branch(ins.mnemonic), 1)

    # If we know the conditional is taken, mark it as taken.
    if ins.condition is None:
        asm = '  ' + asm
    elif ins.condition:
        asm = on('✔ ') + asm
    else:
        asm = '  ' + asm

    return asm
