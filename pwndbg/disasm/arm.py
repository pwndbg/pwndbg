#!/usr/bin/env python
# -*- coding: utf-8 -*-

from capstone import *
from capstone.arm import *

import pwndbg.arch
import pwndbg.disasm.arch
import pwndbg.memory
import pwndbg.regs


class DisassemblyAssistant(pwndbg.disasm.arch.DisassemblyAssistant):
    def memory_sz(self, instruction, op):
        segment = ''
        parts   = []

        if op.mem.base != 0:
            parts.append(instruction.reg_name(op.mem.base))

        if op.mem.disp != 0:
            parts.append("%#x" % op.value.mem.disp)

        if op.mem.index != 0:
            index = pwndbg.regs[instruction.reg_name(op.mem.index)]
            scale = op.mem.scale
            parts.append("%s*%#x" % (index, scale))

        return "[%s]" % (', '.join(parts))

    def immediate_sz(self, instruction, operand):
        return '#' + super(DisassemblyAssistant, self).immediate_sz(instruction, operand)

    def condition(self, instruction):

        # We can't reason about anything except the current instruction
        if instruction.cc == ARM_CC_AL:
            return None

        if instruction.address != pwndbg.regs.pc:
            return False

        value = pwndbg.regs.cpsr if pwndbg.arch.current == 'arm' else pwndbg.regs.xpsr

        N = value & (1<<31)
        Z = value & (1<<30)
        C = value & (1<<29)
        V = value & (1<<28)

        cc = {
            ARM_CC_EQ: Z,
            ARM_CC_NE: not Z,
            ARM_CC_HS: C,
            ARM_CC_LO: not C,
            ARM_CC_MI: N,
            ARM_CC_PL: not N,
            ARM_CC_VS: V,
            ARM_CC_VC: not V,
            ARM_CC_HI: C and not Z,
            ARM_CC_LS: Z or not C,
            ARM_CC_GE: N == V,
            ARM_CC_LT: N != V,
            ARM_CC_GT: not Z and (N==V),
            ARM_CC_LE: Z or (N != V),
        }.get(instruction.cc, None)

        return cc

assistant = DisassemblyAssistant('arm')
