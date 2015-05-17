#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Commands for setting temporary breakpoints on the next
instruction of some type (call, branch, etc.)
"""
import gdb
import pwndbg.disasm
import pwndbg.regs

import capstone

jumps = set((
    capstone.CS_GRP_CALL,
    capstone.CS_GRP_JUMP,
    capstone.CS_GRP_RET,
    capstone.CS_GRP_IRET
))

def next_branch(address=None):
    if address is None:
        ins = pwndbg.disasm.one(pwndbg.regs.pc)
        if not ins:
            return None
        address = ins.next

    ins = pwndbg.disasm.one(address)
    while ins:
        if set(ins.groups) & jumps:
            return ins
        ins = pwndbg.disasm.one(ins.next)

    return None

def break_next_branch(address=None):
    ins = next_branch(address)

    if ins:
        gdb.Breakpoint("*%#x" % ins.address, internal=True, temporary=True)
        gdb.execute('continue')
        return ins

def break_next_call(address=None):
    while True:
        ins = break_next_branch(address)

        if not ins:
            break

        if capstone.CS_GRP_CALL in ins.groups:
            return ins

