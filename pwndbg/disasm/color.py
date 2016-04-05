#!/usr/bin/env python
# -*- coding: utf-8 -*-
import capstone
import pwndbg.chain
import pwndbg.color
import pwndbg.disasm.jump

capstone_branch_groups = set((
capstone.CS_GRP_CALL,
capstone.CS_GRP_JUMP
))

def instruction(ins):
    asm = u'%-06s %s' % (ins.mnemonic, ins.op_str)

    branch = set(ins.groups) & capstone_branch_groups

    if branch:
        asm = pwndbg.color.bold(asm)


    if ins.condition:
        asm = pwndbg.color.green(u'✔ ') + asm
    else:
        asm = '  ' + asm

    if ins.target not in (None, ins.address + ins.size):
        sym    = pwndbg.symbol.get(ins.target)
        target = pwndbg.color.get(ins.target)
        const  = ins.target_constant

        # If it's a constant expression, color it directly in the asm.
        if const:
            asm = asm.replace(hex(ins.target), target)

            if sym:
                asm = '%-36s <%s>' % (asm, sym)
        elif sym:
            asm = '%-36s <%s; %s>' % (asm, target, sym)
        else:
            asm = '%-36s <%s>' % (asm, target)

    elif ins.symbol:
        if branch and not ins.target:
            asm = '%s <%s>' % (asm, ins.symbol)
        else:
            asm = '%-50s # %s <%s>' % (asm, pwndbg.color.get(ins.symbol_addr), ins.symbol)

    return asm
