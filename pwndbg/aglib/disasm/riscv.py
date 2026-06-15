from __future__ import annotations

from collections.abc import Callable
from typing import TYPE_CHECKING

from capstone6pwndbg import *  # noqa: F403
from capstone6pwndbg.riscv import *  # noqa: F403
from typing_extensions import override

import pwndbg.aglib
import pwndbg.aglib.disasm.assistant
import pwndbg.color.memory as mem_color
import pwndbg.dintegration
import pwndbg.lib.disasm.helpers as bit_math
from pwndbg.aglib.disasm.assistant import register_assign
from pwndbg.aglib.disasm.instruction import EnhancedOperand
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

# Input is a list of unsigned operands
CONDITION_RESOLVERS: dict[int, Callable[[list[int]], bool]] = {
    RISCV_INS_BEQ: lambda ops: (
        bit_math.to_signed(ops[0], pwndbg.aglib.arch.ptrbits)
        == bit_math.to_signed(ops[1], pwndbg.aglib.arch.ptrbits)
    ),
    RISCV_INS_BNE: lambda ops: (
        bit_math.to_signed(ops[0], pwndbg.aglib.arch.ptrbits)
        != bit_math.to_signed(ops[1], pwndbg.aglib.arch.ptrbits)
    ),
    RISCV_INS_BLT: lambda ops: (
        bit_math.to_signed(ops[0], pwndbg.aglib.arch.ptrbits)
        < bit_math.to_signed(ops[1], pwndbg.aglib.arch.ptrbits)
    ),
    RISCV_INS_BGE: lambda ops: (
        bit_math.to_signed(ops[0], pwndbg.aglib.arch.ptrbits)
        >= bit_math.to_signed(ops[1], pwndbg.aglib.arch.ptrbits)
    ),
    RISCV_INS_BLTU: lambda ops: ops[0] < ops[1],
    RISCV_INS_BGEU: lambda ops: ops[0] >= ops[1],
    RISCV_INS_C_BEQZ: lambda ops: bit_math.to_signed(ops[0], pwndbg.aglib.arch.ptrbits) == 0,
    RISCV_INS_C_BNEZ: lambda ops: bit_math.to_signed(ops[0], pwndbg.aglib.arch.ptrbits) != 0,
}


class RISCVDisassemblyAssistant(pwndbg.aglib.disasm.assistant.DisassemblyAssistant):
    def __init__(self, architecture) -> None:
        super().__init__(architecture)
        self.architecture = architecture

        self.annotation_handlers: dict[int, Callable[[PwndbgInstruction, Emulator], None]] = {
            # AUIPC
            RISCV_INS_AUIPC: self._auipc_annotator,
            # C.MV
            RISCV_INS_C_MV: self._common_move_annotator,
            # C.LI
            RISCV_INS_C_LI: self._common_move_annotator,
            RISCV_INS_LI: self._common_move_annotator,
            RISCV_INS_ALIAS_LI: self._common_move_annotator,
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
                result_operand.str,
                mem_color.get_address_and_symbol(
                    address, pwndbg.dintegration.manager.get_stack_var_dict_all()
                ),
            )

    def _lui_annotator(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        result_operand, right = instruction.operands
        if result_operand.str and right.before_value is not None:
            if (address := result_operand.after_value) is None:
                # Resolve it manually without emulation
                address = right.before_value << 12

            instruction.annotation = register_assign(
                result_operand.str,
                mem_color.get_address_and_symbol(
                    address, pwndbg.dintegration.manager.get_stack_var_dict_all()
                ),
            )

    @override
    def _condition(self, instruction: PwndbgInstruction, emu: Emulator) -> InstructionCondition:
        """
        Checks if the current instruction is a jump that is taken.
        """
        condition_resolver = CONDITION_RESOLVERS.get(instruction.id)

        # Determine if the conditional jump is taken
        if condition_resolver is None:
            return InstructionCondition.UNCONDITIONAL

        # B-type instructions have two source registers that are compared
        src1_unsigned = instruction.op_find(CS_OP_REG, 1).before_value

        # compressed instructions c.beqz and c.bnez only use one register operand.
        if instruction.op_count(CS_OP_REG) > 1:
            src2_unsigned = instruction.op_find(CS_OP_REG, 2).before_value
        else:
            src2_unsigned = 0

        if src1_unsigned is None or src2_unsigned is None:
            return InstructionCondition.UNDETERMINED_CONDITIONAL

        resolved_operands: list[int] = [src1_unsigned, src2_unsigned]

        condition = condition_resolver(resolved_operands)

        return InstructionCondition.TRUE if condition else InstructionCondition.FALSE

    @override
    def _resolve_target(self, instruction: PwndbgInstruction, emu: Emulator | None):
        """Return the address of the jump / conditional jump,
        None if the next address is not dependent on instruction.
        """
        ptrmask = pwndbg.aglib.arch.ptrmask

        if instruction.id in (RISCV_INS_JAL, RISCV_INS_C_JAL, RISCV_INS_C_J):
            return instruction.op_find(CS_OP_IMM, 1).imm & ptrmask

        # Handle jumps with register target + immediate offset
        if instruction.id in (
            RISCV_INS_JALR,
            RISCV_INS_ALIAS_JALR,
            RISCV_INS_ALIAS_JR,
            RISCV_INS_ALIAS_RET,
        ):
            # jalr can be represented in the following ways:
            # 1. jalr rd                // Jump to rd
            # 2. jalr rd, offset        // Jump to rd+offset
            # 3. jalr rX, rd, offset    // Return address stored in rX, jump to rd+offset
            # 4. jalr x0, x1, 0         // Disassembles as "ret", jump to ra

            # To find target, get the LAST register
            reg_op_count = instruction.op_count(CS_OP_REG)

            # This handles the case when it disassembles to "ret"
            if reg_op_count == 0:
                # ra is implied as link register
                return self._read_register_name(instruction, "ra", emu)

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

        # Handle the rest of the jumps
        if RISCV_GRP_BRANCH_RELATIVE in instruction.groups:
            return instruction.op_find(CS_OP_IMM, 1).imm & ptrmask

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
