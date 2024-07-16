from __future__ import annotations

from capstone import *  # noqa: F403
from capstone.riscv import *  # noqa: F403
from typing_extensions import override

import pwndbg.color.memory as MemoryColor
import pwndbg.gdblib.arch
import pwndbg.gdblib.disasm.arch
import pwndbg.gdblib.regs
import pwndbg.lib.disasm.helpers as bit_math
from pwndbg.emu.emulator import Emulator
from pwndbg.gdblib.disasm.instruction import EnhancedOperand
from pwndbg.gdblib.disasm.instruction import InstructionCondition
from pwndbg.gdblib.disasm.instruction import PwndbgInstruction

RISCV_LOAD_INSTRUCTIONS = {
    # Sign-extend loads
    RISCV_INS_LB: 1,
    RISCV_INS_LH: 2,
    RISCV_INS_LW: 4,
    RISCV_INS_LD: 8,
    # Zero-extend loads
    RISCV_INS_LBU: 1,
    RISCV_INS_LHU: 2,
    RISCV_INS_LWU: 4,
}

# Due to a bug in Capstone, these instructions have incorrect operands to represent a memory address.
# So we temporarily separate them to handle them differently
# This will be fixed in Capstone 6 - https://github.com/capstone-engine/capstone/pull/2393
# TODO: remove this when updating to Capstone 6
RISCV_COMPRESSED_LOAD_INSTRUCTIONS = {RISCV_INS_C_LW: 4, RISCV_INS_C_LD: 8, RISCV_INS_C_LDSP: 8}

RISCV_STORE_INSTRUCTIONS = {
    RISCV_INS_SB: 1,
    RISCV_INS_SH: 2,
    RISCV_INS_SW: 4,
    RISCV_INS_SD: 8,
}

# TODO: remove this when updating to Capstone 6
RISCV_COMPRESSED_STORE_INSTRUCTIONS = {
    RISCV_INS_C_SW: 4,
    RISCV_INS_C_SD: 8,
}


class DisassemblyAssistant(pwndbg.gdblib.disasm.arch.DisassemblyAssistant):
    def __init__(self, architecture) -> None:
        super().__init__(architecture)
        self.architecture = architecture

    @override
    def _set_annotation_string(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        if instruction.id in RISCV_LOAD_INSTRUCTIONS:
            self._common_load_annotator(
                instruction,
                emu,
                instruction.operands[1].before_value,
                RISCV_LOAD_INSTRUCTIONS[instruction.id],
                instruction.operands[0].str,
                instruction.operands[1].str,
            )

        if instruction.id in RISCV_COMPRESSED_LOAD_INSTRUCTIONS:
            address = self._resolve_compressed_target_addr(instruction, emu)
            if address is not None:
                dest_str = f"[{MemoryColor.get_address_or_symbol(address)}]"

                self._common_load_annotator(
                    instruction,
                    emu,
                    address,
                    RISCV_COMPRESSED_LOAD_INSTRUCTIONS[instruction.id],
                    instruction.operands[0].str,
                    dest_str,
                )

        return super()._set_annotation_string(instruction, emu)

    def _resolve_compressed_target_addr(
        self, instruction: PwndbgInstruction, emu: Emulator
    ) -> int | None:
        """
        Calculate the address used in a compressed load/store instruction.
        None if address cannot be resolved.

        TODO: remove this when updating to Capstone 6
        """
        _, disp, reg = instruction.operands

        if disp.before_value is None or reg.before_value is None:
            return None

        return disp.before_value + reg.before_value

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

        src1_signed = bit_math.to_signed(src1_unsigned, pwndbg.gdblib.arch.ptrsize * 8)
        src2_signed = bit_math.to_signed(src2_unsigned, pwndbg.gdblib.arch.ptrsize * 8)

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

    @override
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

    @override
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

    @override
    def _parse_memory(
        self, instruction: PwndbgInstruction, op: EnhancedOperand, emu: Emulator
    ) -> int | None:
        """
        Parse the `RISCVOpMem` Capstone object to determine the concrete memory address used.
        """
        target = op.mem.disp

        if op.mem.base != 0:
            base = self._read_register(instruction, op.mem.base, emu)
            if base is None:
                return None
            target += base

        return target


assistant_rv32 = DisassemblyAssistant("rv32")
assistant_rv64 = DisassemblyAssistant("rv64")
