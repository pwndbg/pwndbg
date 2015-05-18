#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Allows describing functions, specifically enumerating arguments which
may be passed in a combination of registers and stack values.
"""
import gdb
import pwndbg.arch
import pwndbg.disasm
import pwndbg.functions
import pwndbg.funcparser
import pwndbg.ida
import pwndbg.memory
import pwndbg.regs
import pwndbg.symbol
import pwndbg.typeinfo

from capstone import CS_GRP_CALL

ida_replacements = {
    '__int64': 'signed long long int',
    '__int32': 'signed int',
    '__int16': 'signed short',
    '__int8': 'signed char',
    '__uint64': 'unsigned long long int',
    '__uint32': 'unsigned int',
    '__uint16': 'unsigned short',
    '__uint8': 'unsigned char',
    '_BOOL_1': 'unsigned char',
    '_BOOL_2': 'unsigned short',
    '_BOOL_4': 'unsigned int',
    '_BYTE': 'unsigned char',
    '_WORD': 'unsigned short',
    '_DWORD': 'unsigned int',
    '_QWORD': 'unsigned long long',
    '__pure': '',
    '__hidden': '',
    '__return_ptr': '',
    '__struct_ptr': '',
    '__array_ptr': '',
    '__fastcall': '',
    '__cdecl': '',
    '__thiscall': '',
    '__userpurge': '',
}


def get(instruction):
    """
    Returns an array containing the arguments to the current function,
    if $pc is a 'call' or 'bl' type instruction.

    Otherwise, returns None.
    """
    if instruction.address != pwndbg.regs.pc:
        return []

    if CS_GRP_CALL not in instruction.groups:
        return []

    # Not sure of any OS which allows multiple operands on
    # a call instruction.
    assert len(instruction.operands) == 1

    target = instruction.operands[0].int

    if not target:
        return []

    sym = pwndbg.symbol.get(target)
    if not sym:
        return []

    sym  = sym.strip().lstrip('_')    # _malloc
    sym  = sym.replace('isoc99_', '') # __isoc99_sscanf
    sym  = sym.replace('@plt', '')    # getpwiod@plt
    sym  = sym.replace('_chk', '')    # __printf_chk
    func = pwndbg.functions.functions.get(sym, None)

    result = []
    args   = []

    # Try to grab the data out of IDA
    if not func and target:
        typename = pwndbg.ida.GetType(target)

        if typename:
            typename += ';'

            # GetType() does not include the name.
            typename = typename.replace('(', ' function_name(', 1)

            for k,v in ida_replacements.items():
                typename = typename.replace(k,v)

            func     = pwndbg.funcparser.ExtractFuncDeclFromSource(typename + ';')

    if func:
        args = func.args
    else:
        args = [pwndbg.functions.Argument('int',0,argname(i)) for i in range(4)]

    for i,arg in enumerate(args):
        result.append((arg, argument(i)))

    return result


REGS = {
    'x86-64':  ['rdi','rsi','rdx','rcx','r8','r9'],
    'arm':     ['r%i' % i for i in range(0, 4)],
    'aarch64': ['x%i' % i for i in range(0, 4)],
    'powerpc': ['r%i' % i for i in range(3, 10+1)],
    'mips':    ['r%i' % i for i in range(4, 7+1)],
    'sparc':   ['i%i' % i for i in range(0,8)],
}

def argname(n):
    regs = REGS.get(pwndbg.arch.current, [])

    if n < len(regs):
        return regs[n]

    return 'arg[%i]' % n

def argument(n):
    """
    Returns the nth argument, as if $pc were a 'call' or 'bl' type
    instruction.
    """
    regs = REGS.get(pwndbg.arch.current, [])

    if n < len(regs):
        return getattr(pwndbg.regs, regs[n])

    n -= len(regs)

    sp = pwndbg.regs.sp + (n * pwndbg.arch.ptrsize)

    return int(pwndbg.memory.poi(pwndbg.typeinfo.ppvoid, sp))

