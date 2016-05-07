#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Commands for setting temporary breakpoints on the next
instruction of some type (call, branch, etc.)
"""
from __future__ import print_function
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

interrupts = set((capstone.CS_GRP_INT,))

def next_int(address=None):
    """
    If there is a syscall in the current basic black,
    return the instruction of the one closest to $PC.

    Otherwise, return None.
    """
    if address is None:
        ins = pwndbg.disasm.one(pwndbg.regs.pc)
        if not ins:
            return None
        address = ins.next

    ins = pwndbg.disasm.one(address)
    while ins:
        if set(ins.groups) & jumps:
            return None
        if set(ins.groups) & interrupts:
            return ins
        ins = pwndbg.disasm.one(ins.next)

    return None

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
        gdb.execute('continue', from_tty=False, to_string=True)
        return ins

def break_next_interrupt(address=None):
    ins = next_int(address)

    if ins:
        gdb.Breakpoint("*%#x" % ins.address, internal=True, temporary=True)
        gdb.execute('continue', from_tty=False, to_string=True)
        return ins

def break_next_call(address=None):
    while True:
        ins = break_next_branch(address)

        if not ins:
            break

        if capstone.CS_GRP_CALL in ins.groups:
            return ins

def break_on_next(address=None):
    address = address or pwndbg.regs.pc
    ins = pwndbg.disasm.one(address)

    gdb.Breakpoint("*%#x" % (ins.address + ins.size), temporary=True)
    gdb.execute('continue', from_tty=False, to_string=True)


