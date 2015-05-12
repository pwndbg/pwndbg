#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Functionality for disassmebling code at an address, or at an
address +/- a few instructions.
"""
import collections

import gdb
import pwndbg.arch
import pwndbg.disasm.mips
import pwndbg.disasm.arm
import pwndbg.disasm.ppc
import pwndbg.disasm.x86
import pwndbg.disasm.jump
import pwndbg.disasm.sparc
import pwndbg.ida
import pwndbg.memory
import pwndbg.symbol
import pwndbg.memoize
import pwndbg.jump

import capstone
from capstone import *


Instruction = collections.namedtuple('Instruction', ['address', 'length', 'asm', 'target'])

disassembler = None
last_arch    = None


CapstoneArch = {
    'arm':     Cs(CS_ARCH_ARM, CS_MODE_ARM),
    'aarch64': Cs(CS_ARCH_ARM64, CS_MODE_ARM),
    'i386':    Cs(CS_ARCH_X86, CS_MODE_32),
    'x86-64':  Cs(CS_ARCH_X86, CS_MODE_64),
    'powerpc': Cs(CS_ARCH_PPC, CS_MODE_32),
    'mips':    Cs(CS_ARCH_MIPS, CS_MODE_32),
    'sparc':   Cs(CS_ARCH_SPARC, 0),
}

for cs in CapstoneArch.values():
    cs.detail = True

# For variable-instruction-width architectures
# (x86 and amd64), we keep a cache of instruction
# sizes, and where the end of the instruction falls.
#
# This allows us to consistently disassemble backward.
VariableInstructionSizeMax = {
    'i386': 16,
    'x86-64': 16,
}

backward_cache = {}


def get_target(instruction):
    """
    Make a best effort to determine what value or memory address
    is important in a given instruction.  For example:

    - Any single-operand instruction ==> that value
        - push rax ==> evaluate rax
    - Jump or call ==> target address
        - jmp rax ==> evaluate rax
        - jmp 0xdeadbeef ==> deadbeef
    - Memory load or store ==> target address
        - mov [eax], ebx ==> evaluate eax
    - Register move ==> source value
        - mov eax, ebx ==> evaluate ebx
    - Register manipulation ==> value after execution*
        - lea eax, [ebx*4] ==> evaluate ebx*4

    Register arguments are only evaluated for the next instruction.

    Returns:
        A tuple containing the resolved value (or None) and
        a boolean indicating whether the value is a constant.
    """
    return {
        'i386': pwndbg.disasm.x86.resolve,
        'x86-64': pwndbg.disasm.x86.resolve
    }.get(pwndbg.arch.current, lambda *a: (None,None))(instruction)


def get_disassembler(pc):
    arch = pwndbg.arch.current
    d    = CapstoneArch[arch]
    if arch in ('arm', 'aarch64'):
        d.mode = {0:CS_MODE_ARM,1:CS_MODE_THUMB}[pc & 1]
    else:
        d.mode = {4:CS_MODE_32, 8:CS_MODE_64}[pwndbg.arch.ptrsize]
    return d

def get_one_instruction(address):
    md   = get_disassembler(address)
    size = VariableInstructionSizeMax.get(pwndbg.arch.current, 4)
    data = pwndbg.memory.read(address, size, partial=True)
    for ins in md.disasm(bytes(data), address, 1):
        ins.target, ins.target_constant = get_target(ins)
        return ins

def one(address=None):
    if address is None:
        address = pwndbg.regs.pc
    for insn in get(address, 1):
        return insn

def fix(i):
    for op in i.operands:
        if op.type == CS_OP_IMM and op.va:
            i.op_str = i.op_str.replace()

    return i

def get(address, instructions=1):
    address = int(address)

    # Dont disassemble if there's no memory
    if not pwndbg.memory.peek(address):
        return []

    retval = []
    for _ in range(instructions):
        i = get_one_instruction(address)
        if i is None:
            break
        backward_cache[address+i.size] = address
        address += i.size
        retval.append(i)

    return retval

def near(address, instructions=1):
    # # If we have IDA, we can just use it to find out where the various
    # # isntructions are.
    # if pwndbg.ida.available():
    #     head = address
    #     for i in range(instructions):
    #         head = pwndbg.ida.PrevHead(head)

    #     retval = []
    #     for i in range(2*instructions + 1):
    #         retval.append(get(head))
    #         head = pwndbg.ida.NextHead(head)

    # See if we can satisfy the request based on the instruction
    # length cache.
    needle = address
    insns  = []
    while len(insns) < instructions and needle in backward_cache:
        needle = backward_cache[needle]
        insn   = one(needle)
        if not insn:
            return insns
        insns.insert(0, insn)

    current = one(address)

    if not current:
        return insns

    target  = current.target

    if not pwndbg.disasm.jump.is_jump_taken(current):
        target = current.address + current.size

    backward_cache[target] = address

    insns.append(current)
    insns.extend(get(target, instructions))

    return insns
