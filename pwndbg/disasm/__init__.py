#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Functionality for disassmebling code at an address, or at an
address +/- a few instructions.
"""
import collections

import gdb
import pwndbg.arch
import pwndbg.disasm.arch
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
    'i386':   16,
    'x86-64': 16,
}

smart_backward_cache = collections.defaultdict(lambda: 0)
backward_cache = collections.defaultdict(lambda: 0)


def get_disassembler(pc):
    arch = pwndbg.arch.current
    d    = CapstoneArch[arch]
    if arch in ('arm', 'aarch64'):
        d.mode = {0:CS_MODE_ARM,0x20:CS_MODE_THUMB}[pwndbg.regs.cpsr & 0x20]
    else:
        d.mode = {4:CS_MODE_32, 8:CS_MODE_64}[pwndbg.arch.ptrsize]
    return d

@pwndbg.memoize.reset_on_cont
def get_one_instruction(address):
    md   = get_disassembler(address)
    size = VariableInstructionSizeMax.get(pwndbg.arch.current, 4)
    data = pwndbg.memory.read(address, size, partial=True)
    for ins in md.disasm(bytes(data), address, 1):
        pwndbg.disasm.arch.DisassemblyAssistant.enhance(ins)
        return ins

def one(address=None):
    if address == 0:
        return None
    if address is None:
        address = pwndbg.regs.pc
    for insn in get(address, 1):
        smart_backward_cache[insn.next] = insn.address
        backward_cache[insn.address + insn.size] = insn.address
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
        address = i.next
        retval.append(i)

    return retval

def near(address, instructions=1):
    current = one(address)

    if not current:
        return []

    # Try to go backward by seeing which instructions we've returned
    # before, which were followed by this one.
    needle = address
    insns  = []
    insn   = one(backward_cache[current.address])
    while insn and len(insns) < instructions:
        insns.append(insn)
        insn = one(backward_cache[insn.address])
    insns.reverse()
    insns.append(current)

    # Now find all of the instructions moving forward.
    next = current.next
    while len(insns) < 1+(2*instructions):
        insn = one(next)
        if not insn:
            break
        insns.append(insn)
        next = insn.next

        # On a short backward jump, we may get an annoying cycle in the
        # disassembly listing, because we're reading the jump target and
        # have evaluated the destination.
        #
        # We don't want this loop to show up in the future, so force it
        # to fall-through, as long as the jump destination is a small-enough
        # backward jump that it also shows up in the disassembly.
        if insn.address == current.address and any(i.address == next for i in insns):
            next = insn.address + insn.size

    return insns
