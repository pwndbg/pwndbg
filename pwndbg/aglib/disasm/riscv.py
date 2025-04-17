from __future__ import annotations

from typing import TYPE_CHECKING

from capstone import *  # noqa: F403
from capstone.riscv import *  # noqa: F403
from typing_extensions import override

import pwndbg.aglib.arch
import pwndbg.aglib.disasm.arch
import pwndbg.aglib.regs
import pwndbg.color.memory as MemoryColor
import pwndbg.lib.disasm.helpers as bit_math
from pwndbg.aglib.disasm.arch import register_assign
from pwndbg.aglib.disasm.instruction import InstructionCondition
from pwndbg.aglib.disasm.instruction import PwndbgInstruction

# Emulator currently requires GDB, and we only use it here for type checking.
if TYPE_CHECKING:
    from pwndbg.emu.emulator import Emulator

RISCV_LOAD_INSTRUCTIONS = {
    # Sign-extend loads
    RISCV_INS_LB: -1,
    RISCV_INS_LH: -2,
    RISCV_INS_LW: -4,
    # Zero-extend loads
    RISCV_INS_LBU: 1,
    RISCV_INS_LHU: 2,
    RISCV_INS_LWU: 4,
    RISCV_INS_LD: 8,
    RISCV_INS_C_LW: -4,
    RISCV_INS_C_LWSP: -4,
    RISCV_INS_C_LD: 8,
    RISCV_INS_C_LDSP: 8,
}

RISCV_STORE_INSTRUCTIONS = {
    RISCV_INS_SB: 1,
    RISCV_INS_SH: 2,
    RISCV_INS_SW: 4,
    RISCV_INS_SD: 8,
    RISCV_INS_C_SW: 4,
    RISCV_INS_C_SWSP: 4,
    RISCV_INS_C_SD: 8,
    RISCV_INS_C_SDSP: 8,
}


RISCV_MATH_INSTRUCTIONS = {
    RISCV_INS_ADDI: "+",
    RISCV_INS_ADD: "+",
    RISCV_INS_C_ADDI: "+",
    RISCV_INS_C_ADD: "+",
    RISCV_INS_SUB: "-",
    RISCV_INS_C_SUB: "-",
    RISCV_INS_XORI: "^",
    RISCV_INS_XOR: "^",
    RISCV_INS_C_XOR: "^",
    RISCV_INS_ORI: "|",
    RISCV_INS_OR: "|",
    RISCV_INS_C_OR: "|",
    RISCV_INS_ANDI: "&",
    RISCV_INS_C_ANDI: "&",
    RISCV_INS_AND: "&",
    RISCV_INS_C_AND: "&",
    RISCV_INS_SLLI: "<<",
    RISCV_INS_C_SLLI: "<<",
    RISCV_INS_SLL: "<<",
    RISCV_INS_SRLI: ">>",
    RISCV_INS_C_SRLI: ">>",
    RISCV_INS_SRL: ">>",
    RISCV_INS_SRAI: ">>s",
    RISCV_INS_C_SRAI: ">>s",
    RISCV_INS_SRA: ">>s",
    RISCV_INS_MUL: "*",
    RISCV_INS_MULH: "*",
    RISCV_INS_MULHSU: "*",
    RISCV_INS_MULHU: "*",
    RISCV_INS_DIV: "/",
    RISCV_INS_DIVU: "/",
    RISCV_INS_REM: "%",
    RISCV_INS_REMU: "%",
    RISCV_INS_C_ADDI4SPN: "+",
    RISCV_INS_C_ADDI16SP: "+",
    # RV64I unique instructions
    RISCV_INS_ADDIW: "+",
    RISCV_INS_ADDW: "+",
    RISCV_INS_SUBW: "-",
    RISCV_INS_SLLIW: "<<",
    RISCV_INS_SLLW: "<<",
    RISCV_INS_SRLIW: ">>",
    RISCV_INS_SRLW: ">>",
    RISCV_INS_SRAIW: ">>s",
    RISCV_INS_SRAW: ">>s",
    # RV64M unique instructions
    RISCV_INS_MULW: "*",
    RISCV_INS_DIVW: "/",
    RISCV_INS_DIVUW: "/",
    RISCV_INS_REMW: "%",
    RISCV_INS_REMUW: "%",
    # RV64C unique instructions
    RISCV_INS_C_ADDIW: "+",
    RISCV_INS_C_ADDW: "+",
    RISCV_INS_C_SUBW: "-",
}

RISCV_EMULATED_ANNOTATIONS = {
    RISCV_INS_SLT,
    RISCV_INS_SLTU,
    RISCV_INS_SLTI,
    RISCV_INS_SLTIU,
}


class RISCVDisassemblyAssistant(pwndbg.aglib.disasm.arch.DisassemblyAssistant):
    def __init__(self, architecture) -> None:
        super().__init__(architecture)
        self.architecture = architecture

        self.annotation_handlers: Dict[int, Callable[[PwndbgInstruction, Emulator], None]] = {
            # AUIPC
            RISCV_INS_AUIPC: self._auipc_annotator,
            # C.MV
            RISCV_INS_C_MV: self._common_move_annotator,
            # C.LI
            RISCV_INS_C_LI: self._common_move_annotator,
            # LUI
            RISCV_INS_LUI: self._lui_annotator,
            RISCV_INS_C_LUI: self._lui_annotator,
        }

    @override
    def _set_annotation_string(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        if instruction.id in RISCV_LOAD_INSTRUCTIONS:
            read_size = RISCV_LOAD_INSTRUCTIONS[instruction.id]
            self._common_load_annotator(
                instruction,
                emu,
                instruction.operands[1].before_value,
                abs(read_size),
                read_size < 0,
                pwndbg.aglib.arch.ptrsize,
                instruction.operands[0].str,
                instruction.operands[1].str,
            )
        elif instruction.id in RISCV_STORE_INSTRUCTIONS:
            self._common_store_annotator(
                instruction,
                emu,
                instruction.operands[1].before_value,
                instruction.operands[0].before_value,
                RISCV_STORE_INSTRUCTIONS[instruction.id],
                instruction.operands[1].str,
            )
        elif instruction.id in RISCV_MATH_INSTRUCTIONS:
            # We need this check, because some of these instructions can encoded as aliases
            # Example: NOP is an alias of ADDI where target is x0. In Capstone, the ID will still be that of ADDI but with no operands
            if len(instruction.operands) >= 2:
                self._common_binary_op_annotator(
                    instruction,
                    emu,
                    instruction.operands[0],
                    instruction.operands[-2].before_value,
                    instruction.operands[-1].before_value,
                    RISCV_MATH_INSTRUCTIONS[instruction.id],
                )
        elif instruction.id in RISCV_EMULATED_ANNOTATIONS:
            self._common_generic_register_destination(instruction, emu)
        else:
            self.annotation_handlers.get(instruction.id, lambda *a: None)(instruction, emu)

    def _auipc_annotator(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        result_operand, right = instruction.operands
        if result_operand.str and right.before_value is not None:
            if (address := result_operand.after_value) is None:
                # Resolve it manually without emulation
                address = instruction.address + (right.before_value << 12)

            instruction.annotation = register_assign(
                result_operand.str, MemoryColor.get_address_and_symbol(address)
            )

    def _lui_annotator(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        result_operand, right = instruction.operands
        if result_operand.str and right.before_value is not None:
            if (address := result_operand.after_value) is None:
                # Resolve it manually without emulation
                address = right.before_value << 12

            instruction.annotation = register_assign(
                result_operand.str, MemoryColor.get_address_and_symbol(address)
            )

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

        if src1_unsigned is None or src2_unsigned is None:
            return InstructionCondition.UNDETERMINED

        src1_signed = bit_math.to_signed(src1_unsigned, pwndbg.aglib.arch.ptrsize * 8)
        src2_signed = bit_math.to_signed(src2_unsigned, pwndbg.aglib.arch.ptrsize * 8)

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
        """
        Checks if the current instruction is a jump that is taken.
        """
        # JAL / JALR is unconditional
        if RISCV_GRP_CALL in instruction.groups:
            return InstructionCondition.UNDETERMINED

        # Determine if the conditional jump is taken
        if RISCV_GRP_BRANCH_RELATIVE in instruction.groups:
            return self._is_condition_taken(instruction, emu)

        return InstructionCondition.UNDETERMINED

    @override
    def _resolve_target(self, instruction: PwndbgInstruction, emu: Emulator | None):
        """Return the address of the jump / conditional jump,
        None if the next address is not dependent on instruction.
        """
        ptrmask = pwndbg.aglib.arch.ptrmask
        # JAL is unconditional and independent of current register status
        if instruction.id in (RISCV_INS_JAL, RISCV_INS_C_JAL, RISCV_INS_C_J):
            # But that doesn't apply to ARM anyways :)
            return (instruction.address + instruction.op_find(CS_OP_IMM, 1).imm) & ptrmask

        # Determine target of branch - all of them are offset to address
        if RISCV_GRP_BRANCH_RELATIVE in instruction.groups:
            return (instruction.address + instruction.op_find(CS_OP_IMM, 1).imm) & ptrmask

        # Determine the target address of the indirect jump
        if instruction.id == RISCV_INS_JALR:
            # jalr can be represented as:
            # 1. jalr r1, rd, offset
            # 2. jalr rd
            # 3. jalr rd, offset
            # If source is omitted, ra is implied as link register
            # To find target, get the LAST
            reg_op_count = instruction.op_count(CS_OP_REG)
            if (target := instruction.op_find(CS_OP_REG, reg_op_count).before_value) is None:
                return None

            if (imm_op := instruction.op_find(CS_OP_IMM, 1)) is not None:
                target += imm_op.imm
            target &= ptrmask
            # Clear the lowest bit without knowing the register width
            return target ^ (target & 1)

        if instruction.id == RISCV_INS_C_JALR:
            if (target := instruction.op_find(CS_OP_REG, 1).before_value) is None:
                return None
            return target ^ (target & 1)

        return super()._resolve_target(instruction, emu)

    @override
    def _parse_memory(
        self, instruction: PwndbgInstruction, op: EnhancedOperand, emu: Emulator
    ) -> int | None:
        """
        Parse the `RISCVOpMem` Capstone object to determine the concrete memory address used.
        """
        base = self._read_register(instruction, op.mem.base, emu)
        if base is None:
            return None
        return base + op.mem.disp
