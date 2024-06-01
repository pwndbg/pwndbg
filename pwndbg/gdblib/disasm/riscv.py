from __future__ import annotations

from capstone import *  # noqa: F403
from capstone.riscv import *  # noqa: F403

import pwndbg.gdblib.disasm.arch
import pwndbg.gdblib.arch
import pwndbg.gdblib.regs
from pwndbg.gdblib.disasm.instruction import InstructionCondition
from pwndbg.gdblib.disasm.instruction import PwndbgInstruction
from pwndbg.emu.emulator import Emulator


class DisassemblyAssistant(pwndbg.gdblib.disasm.arch.DisassemblyAssistant):
    def __init__(self, architecture) -> None:
        super().__init__(architecture)
        self.architecture = architecture

    def _is_condition_taken(
        self, instruction: PwndbgInstruction, emu: Emulator | None
    ) -> InstructionCondition:
        # B-type instructions have two source registers that are compared
        src1_unsigned = instruction.op_find(CS_OP_REG, 1).before_value
        # compressed instructions c.beqz and c.bnez only use one register operand.
        if instruction.op_count(CS_OP_REG) > 1:
            src2_unsigned = instruction.op_find(CS_OP_REG, 2).before_value
        else:
            src2_unsigned = 0

        if self.architecture == "rv32":
            src1_signed = src1_unsigned - ((src1_unsigned & 0x80000000) << 1)
            src2_signed = src2_unsigned - ((src2_unsigned & 0x80000000) << 1)
        elif self.architecture == "rv64":
            src1_signed = src1_unsigned - ((src1_unsigned & 0x80000000_00000000) << 1)
            src2_signed = src2_unsigned - ((src2_unsigned & 0x80000000_00000000) << 1)
        else:
            raise NotImplementedError(f"architecture '{self.architecture}' not implemented")

        condition = {
            RISCV_INS_BEQ: src1_signed == src2_signed,
            RISCV_INS_BNE: src1_signed != src2_signed,
            RISCV_INS_BLT: src1_signed < src2_signed,
            RISCV_INS_BGE: src1_signed >= src2_signed,
            RISCV_INS_BLTU: src1_unsigned < src2_unsigned,
            RISCV_INS_BGEU: src1_unsigned >= src2_unsigned,
            RISCV_INS_C_BEQZ: src1_signed == 0,
            RISCV_INS_C_BNEZ: src1_signed != 0,
        }.get(instruction.id, None)

        if condition is None:
            return InstructionCondition.UNDETERMINED

        return InstructionCondition.TRUE if bool(condition) else InstructionCondition.FALSE

    def _condition(self, instruction: PwndbgInstruction, emu: Emulator) -> InstructionCondition:
        """Checks if the current instruction is a jump that is taken.
        Returns None if the instruction is executed unconditionally,
        True if the instruction is executed for sure, False otherwise.
        """
        # JAL / JALR is unconditional
        if RISCV_GRP_CALL in instruction.groups:
            return InstructionCondition.UNDETERMINED

        # We can't reason about anything except the current instruction
        # as the comparison result is dependent on the register state.
        if instruction.address != pwndbg.gdblib.regs.pc:
            return InstructionCondition.UNDETERMINED

        # Determine if the conditional jump is taken
        if RISCV_GRP_BRANCH_RELATIVE in instruction.groups:
            return self._is_condition_taken(instruction, emu)

        return InstructionCondition.UNDETERMINED

    def _resolve_target(self, instruction: PwndbgInstruction, emu: Emulator | None, call=False):
        """Return the address of the jump / conditional jump,
        None if the next address is not dependent on instruction.
        """
        ptrmask = pwndbg.gdblib.arch.ptrmask
        # JAL is unconditional and independent of current register status
        if instruction.id in [RISCV_INS_JAL, RISCV_INS_C_JAL]:
            # But that doesn't apply to ARM anyways :)
            return (instruction.address + instruction.op_find(CS_OP_IMM, 1).imm) & ptrmask

        # We can't reason about anything except the current instruction
        # as the comparison result is dependent on the register state.
        if instruction.address != pwndbg.gdblib.regs.pc:
            return None

        # Determine if the conditional jump is taken
        if RISCV_GRP_BRANCH_RELATIVE in instruction.groups and self._is_condition_taken(
            instruction, emu
        ):
            return (instruction.address + instruction.op_find(CS_OP_IMM, 1).imm) & ptrmask

        # Determine the target address of the indirect jump
        if instruction.id in [RISCV_INS_JALR, RISCV_INS_C_JALR]:
            target = instruction.op_find(CS_OP_REG, 1).before_value
            if instruction.id == RISCV_INS_JALR:
                target += instruction.op_find(CS_OP_IMM, 1).imm
            target &= ptrmask
            # Clear the lowest bit without knowing the register width
            return target ^ (target & 1)

        return super()._resolve_target(instruction, emu, call)


assistant_rv32 = DisassemblyAssistant("rv32")
assistant_rv64 = DisassemblyAssistant("rv64")
