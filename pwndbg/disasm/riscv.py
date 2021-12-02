#!/usr/bin/env python
# -*- coding: utf-8 -*-

import collections

from capstone import *
from capstone.riscv import *

import pwndbg.arch
import pwndbg.disasm.arch
import pwndbg.memory
import pwndbg.regs


class DisassemblyAssistant(pwndbg.disasm.arch.DisassemblyAssistant):

    def __init__(self, architecture):
        super(DisassemblyAssistant, self).__init__(architecture)
        self.architecture = architecture

    def _is_condition_taken(self, instruction):
        """
        B-Type Instruction format
        
        |31           24|23           16|15            8|7             0|
        +---------------+---------------+---------------+---------------+
        |     Byte 0    |     Byte 1    |     Byte 2    |     Byte 3    |
        +-------------+-+-------+-------+-+-----+-------+-+-------------+
        |    imm      |   rs2   |   rs1   |fct3 |  imm    |   opcode    |
        +-------------+---------+---------+-----+---------+-------------+
        |31         25|24     20|19     15|14 12|11      7|6           0|
        """
        # B-type instructions have two source registers that are compared
        # FIXME: Check if register in pwndbg is signed by default
        src1_unsigned = self.register(instruction.op_find(CS_OP_REG, 1))
        src2_unsigned = self.register(instruction.op_find(CS_OP_REG, 2))

        if architecture == 'rv32':
            src1_signed = src1_unsigned - ((src1_unsigned & 0x80000000) << 1)
            src2_signed = src2_unsigned - ((src2_unsigned & 0x80000000) << 1)
        elif architecture == 'rv64':
            src1_signed = src1_unsigned - ((src1_unsigned & 0x80000000_00000000) << 1)
            src2_signed = src2_unsigned - ((src2_unsigned & 0x80000000_00000000) << 1)
        elif architecture == 'rv128':
            src1_signed = src1_unsigned - ((src1_unsigned & 0x80000000_00000000_00000000_00000000) << 1)
            src2_signed = src2_unsigned - ((src2_unsigned & 0x80000000_00000000_00000000_00000000) << 1)

        return {
            RISCV_INS_BEQ:  src1_signed   == src2_signed,
            RISCV_INS_BNE:  src1_signed   != src2_signed,
            RISCV_INS_BLT:  src1_signed   <  src2_signed,
            RISCV_INS_BGE:  src1_signed   >= src2_signed,
            RISCV_INS_BLTU: src1_unsigned <  src2_unsigned,
            RISCV_INS_BGEU: src1_unsigned >= src2_unsigned,
        }.get(instruction.id, None)

    def condition(self, instruction):
        """ Checks if the current instruction is a jump that is taken.

        Returns None if the instruction is executed unconditionally,
        True if the instruction is executed for sure, False otherwise.
        """
        # JAL / JALR is unconditional
        if instruction.id in (RISCV_INS_JAL, RISCV_INS_JALR):
            return None

        # We can't reason about anything except the current instruction
        # as the comparison result is dependent on the register state.
        if instruction.address != pwndbg.regs.pc:
            return False

        # Determine if the conditional jump is taken
        if instruction.id in (RISCV_INS_BEQ, RISCV_INS_BNE, RISCV_INS_BLT, RISCV_INS_BGE, RISCV_INS_BLTU, RISCV_INS_BGEU):
            return self._is_condition_taken(instruction)

        return None

    def next(self, instruction, call=False):
        """ Return the address of the jump / conditional jump,
        None if the next address is not dependent on instruction.
        """
        # JAL is unconditional and independent of current register status
        if instruction.id == RISCV_INS_JAL:
            # FIXME: Check if immediate is returned as signed from op_find
            return instruction.address + instruction.op_find(RISCV_OP_IMM, 1) * 2

        # We can't reason about anything except the current instruction
        # as the comparison result is dependent on the register state.
        if instruction.address != pwndbg.regs.pc:
            return None

        # Determine if the conditional jump is taken
        if instruction.id in (RISCV_INS_BEQ, RISCV_INS_BNE, RISCV_INS_BLT, RISCV_INS_BGE, RISCV_INS_BLTU, RISCV_INS_BGEU) \
                and self._is_condition_taken(instruction):
            # FIXME: Check if immediate is returned as signed from op_find
            return instruction.address + instruction.op_find(RISCV_OP_IMM, 1) * 2

        # Determine the target address of the indirect jump
        if instruction.id == RISCV_INS_JALR:
            # FIXME: Check if immediate is returned as signed from op_find
            target = self.register(instruction.op_find(CS_OP_REG, 1)) \
                + instruction.op_find(RISCV_OP_IMM, 1)
            # Clear the lowest bit without knowing the register width
            return target ^ (target & 1)

        return None


assistant_rv32 = DisassemblyAssistant('rv32')
assistant_rv64 = DisassemblyAssistant('rv64')
assistant_rv128 = DisassemblyAssistant('rv128')
