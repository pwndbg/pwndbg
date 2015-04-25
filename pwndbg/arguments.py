#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Allows describing functions, specifically enumerating arguments which
may be passed in a combination of registers and stack values.
"""
import gdb
import pwndbg.arch
import pwndbg.disasm
import pwndbg.memory
import pwndbg.regs
import pwndbg.typeinfo
import pwndbg.functions
import pwndbg.symbol

def arguments():
    """
    Returns an array containing the arguments to the current function,
    if $pc is a 'call' or 'bl' type instruction.

    Otherwise, returns None.
    """
    pwndbg.disasm.calls

def argument(n):
    """
    Returns the nth argument, as if $pc were a 'call' or 'bl' type
    instruction.
    """
    arch = pwndbg.arch.current

    regs = {
        'x86-64':  ['rdi','rsi','rdx','rcx','r8','r9'],
        'arm':     ['r%i' % i for i in range(0, 4)],
        'aarch64': ['x%i' % i for i in range(0, 4)],
        'powerpc': ['r%i' % i for i in range(3, 10+1)],
        'mips':    ['r%i' % i for i in range(4, 7+1)],
        'sparc':   ['i%i' % i for i in range(0,8)],
    }[arch]

    if n < len(regs):
        return getattr(pwndbg.regs, regs[n])

    n -= len(regs)

    sp = pwndbg.regs.sp + (n * pwndbg.arch.ptrsize)

    return int(pwndbg.memory.poi(pwndbg.typeinfo.ppvoid, sp))

