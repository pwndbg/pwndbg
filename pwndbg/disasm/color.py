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

    asm = asm.ljust(36)

    if branch:
        asm = pwndbg.color.bold(asm)


    if ins.condition:
        asm = pwndbg.color.green(u'✔ ') + asm
    else:
        asm = '  ' + asm

    if ins.target not in (None, ins.address + ins.size):
        sym    = pwndbg.symbol.get(ins.target) or None
        target = pwndbg.color.get(ins.target)
        const  = ins.target_const
        hextarget = hex(ins.target)
        hexlen    = len(hextarget)

        # If it's a constant expression, color it directly in the asm.
        if const:
            if sym:
                asm = asm.replace(hextarget, sym.ljust(hexlen))
                asm += '<%s>' % (target)
            else:
                targ_col_len = target.ljust(hexlen)
                targ_col_len = pwndbg.color.get(ins.target, targ_col_len)
                asm = asm.replace(hextarget, targ_col_len)
                asm += '<%s>' % (sym)
        elif sym:
            asm += '<%s; %s>' % (target, sym)
        else:
            asm += '<%s>' % (target)

    elif ins.symbol:
        if branch and not ins.target:
            asm += '<%s>' % (ins.symbol)
        else:
            asm += '<%s>' % (pwndbg.color.get(ins.symbol_addr, ins.symbol or None))

    return asm
