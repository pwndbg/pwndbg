#!/usr/bin/env python
# -*- coding: utf-8 -*-
import collections

import pwndbg.arch
import pwndbg.memory
import pwndbg.regs

from capstone import *
from capstone.x86 import *

groups = {v:k for k,v in globals().items() if k.startswith('X86_GRP_')}
ops    = {v:k for k,v in globals().items() if k.startswith('X86_OP_')}
regs   = {v:k for k,v in globals().items() if k.startswith('X86_REG_')}
access = {v:k for k,v in globals().items() if k.startswith('CS_AC_')}

class DisassemblyAssistant(pwndbg.disasm.arch.DisassemblyAssistant):
    def memory_sz(self, instruction, operand):
        segment = ''
        parts   = []

        if op.mem.segment != 0:
            segment = '%s:' % instructions.reg_name(op.mem.segment)


        if op.mem.base != 0:
            parts.append(instruction.reg_name(op.mem.base))

        if op.mem.disp != 0:
            parts.append("%#x" % op.value.mem.disp)

        if op.mem.index != 0:
            index = pwndbg.regs[instruction.reg_name(op.mem.index)]
            scale = op.mem.scale
            parts.append("%s*%#x" % (index, scale))

        return "%s[%s]" % (segment, ' + '.join(parts))

assistant = DisassemblyAssistant()

def is_memory_op(op):
    return op.type == X86_OP_MEM

def get_access(ac):
    rv = []
    for k,v in access.items():
        if ac & k: rv.append(v)
    return ' | '.join(rv)

    def dump(self, instruction):
        ins = instruction
        rv  = []
        rv.append('%s %s' % (ins.mnemonic,ins.op_str))
        for i, group in enumerate(ins.groups):
            rv.append('   groups[%i]   = %s' % (i, groups[group]))
        for i, op in enumerate(ins.operands):
            rv.append('   operands[%i] = %s' % (i, ops[op.type]))
            rv.append('       access   = %s' % (get_access(op.access)))
        return '\n'.join(rv)

def resolve(instruction):
    ops = list(instruction.operands)

    if instruction.mnemonic == 'nop' or not ops:
        return (None,None)

    # 'ret', 'syscall'
    if not ops:
        return

    # 'jmp rax', 'call 0xdeadbeef'
    if len(ops) == 1:
        return get_operand_target(instruction, ops[0])

    # 'mov eax, ebx'  ==> ebx
    # 'mov [eax], ebx' ==> [eax]
    # 'mov eax, 0xdeadbeef' ==> 0xdeadbeef
    if len(ops) == 2:
        # If there are any memory operands, prefer those
        for op in filter(is_memory_op, ops):
            return get_operand_target(instruction, op)

        # Otherwise, prefer the 'source' operand
        return get_operand_target(instruction, ops[1])


    print("Weird number of operands!!!!!")
    print(dump(instruction))

def register(i, op):
    assert CS_OP_REG == op.type
    regname = instruction.reg_name(op.value.reg)
    return pwndbg.regs[regname]

def immediate(i, op):
    assert CS_OP_IMM == op.type
    return op.value.imm

def memory():
    current = (instruction.address == pwndbg.regs.pc)

    constant = bool(op.mem.base == 0 and op.mem.index == 0)
    if not current and not constant:
        return (None, False)

    if op.mem.segment != 0:
        return (None, False)

    if op.mem.base != 0:
        regname = instruction.reg_name(op.mem.base)
        target += pwndbg.regs[regname]

    if op.mem.disp != 0:
        target += op.value.mem.disp

    if op.mem.index != 0:
        scale = op.mem.scale
        index = pwndbg.regs[instruction.reg_name(op.mem.index)]
        target += (scale * index)

    # for source operands, resolve
    if op.access == CS_AC_READ:
        try:
            target = pwndbg.memory.u(target, op.size * 8)
        except:
            return (None, False)

    return (target, constant)

resolvers = {
    CS_OP_REG: register,
    CS_OP_IMM: immediate,
    CS_OP_MEM: memory
}

def get_operand_target(instruction, op):
    current = (instruction.address == pwndbg.regs.pc)

    # EB/E8/E9 or similar "call $+offset"
    # Capstone handles the instruction + instruction size.
    if op.type == X86_OP_IMM:
        return (op.value.imm, True)

    # jmp/call REG
    if op.type == X86_OP_REG:
        if not current:
            return (None, False)

        regname = instruction.reg_name(op.value.reg)
        return (pwndbg.regs[regname], False)

    # base + disp + scale * offset
    assert op.type == X86_OP_MEM, "Invalid operand type %i (%s)" % (op.type, ops[op.type])

    target = 0

    # Don't resolve registers
    constant = bool(op.mem.base == 0 and op.mem.index == 0)
    if not current and not constant:
        return (None, False)

    if op.mem.segment != 0:
        return (None, False)

    if op.mem.base != 0:
        regname = instruction.reg_name(op.mem.base)
        target += pwndbg.regs[regname]

    if op.mem.disp != 0:
        target += op.value.mem.disp

    if op.mem.index != 0:
        scale = op.mem.scale
        index = pwndbg.regs[instruction.reg_name(op.mem.index)]
        target += (scale * index)

    # for source operands, resolve
    if op.access == CS_AC_READ:
        try:
            target = pwndbg.memory.u(target, op.size * 8)
        except:
            return (None, False)

    return (target, constant)


def is_jump_taken(instruction):
    efl = pwndbg.regs.eflags

    cf = efl & (1<<0)
    pf = efl & (1<<2)
    af = efl & (1<<4)
    zf = efl & (1<<6)
    sf = efl & (1<<7)
    of = efl & (1<<11)

    return {
    X86_INS_JO: of,
    X86_INS_JNO: not of,
    X86_INS_JS: sf,
    X86_INS_JNS: not sf,
    X86_INS_JE: zf,
    X86_INS_JNE: not zf,
    X86_INS_JB: cf,
    X86_INS_JAE: not cf,
    X86_INS_JBE: cf or zf,
    X86_INS_JA: not (cf or zf),
    X86_INS_JL: sf != of,
    X86_INS_JGE: sf == of,
    X86_INS_JLE: zf or (sf != of),
    X86_INS_JP: pf,
    X86_INS_JNP: not pf,
    X86_INS_JMP: True,
    }.get(instruction.id, None)
