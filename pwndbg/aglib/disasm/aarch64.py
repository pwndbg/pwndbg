from __future__ import annotations

from typing import TYPE_CHECKING
from typing import Callable
from typing import Dict

from capstone import *  # noqa: F403
from capstone.aarch64 import *  # noqa: F403
from typing_extensions import override

import pwndbg.aglib.arch
import pwndbg.aglib.disasm.arch
import pwndbg.aglib.memory
import pwndbg.aglib.regs
import pwndbg.enhance
import pwndbg.lib.disasm.helpers as bit_math
from pwndbg.aglib.disasm.arch import register_assign
from pwndbg.aglib.disasm.instruction import ALL_JUMP_GROUPS
from pwndbg.aglib.disasm.instruction import EnhancedOperand
from pwndbg.aglib.disasm.instruction import InstructionCondition
from pwndbg.aglib.disasm.instruction import PwndbgInstruction
from pwndbg.aglib.disasm.instruction import boolean_to_instruction_condition

# Emulator currently requires GDB, and we only use it here for type checking.
if TYPE_CHECKING:
    from pwndbg.emu.emulator import Emulator

# Negative size indicates signed read
# None indicates the read size depends on the target register
AARCH64_SINGLE_LOAD_INSTRUCTIONS: Dict[int, int | None] = {
    AARCH64_INS_LDRB: 1,
    AARCH64_INS_ALIAS_LDRB: 1,
    AARCH64_INS_LDURB: 1,
    AARCH64_INS_ALIAS_LDURB: 1,
    AARCH64_INS_LDRSB: -1,
    AARCH64_INS_ALIAS_LDRSB: -1,
    AARCH64_INS_LDURSB: -1,
    AARCH64_INS_ALIAS_LDURSB: -1,
    AARCH64_INS_LDRH: 2,
    AARCH64_INS_ALIAS_LDRH: 2,
    AARCH64_INS_LDURH: 2,
    AARCH64_INS_ALIAS_LDURH: 2,
    AARCH64_INS_LDRSH: -2,
    AARCH64_INS_ALIAS_LDRSH: -2,
    AARCH64_INS_LDURSH: -2,
    AARCH64_INS_ALIAS_LDURSH: -2,
    AARCH64_INS_LDURSW: -4,
    AARCH64_INS_ALIAS_LDURSW: -4,
    AARCH64_INS_LDRSW: -4,
    AARCH64_INS_ALIAS_LDRSW: -4,
    AARCH64_INS_LDUR: None,
    AARCH64_INS_ALIAS_LDUR: None,
    AARCH64_INS_LDR: None,
    AARCH64_INS_ALIAS_LDR: None,
    AARCH64_INS_LDTRB: 1,
    AARCH64_INS_LDTRSB: -1,
    AARCH64_INS_LDTRH: 2,
    AARCH64_INS_LDTRSH: -2,
    AARCH64_INS_LDTRSW: -4,
    AARCH64_INS_LDTR: None,
    AARCH64_INS_ALIAS_LDTR: None,
    AARCH64_INS_LDXRB: 1,
    AARCH64_INS_LDXRH: 2,
    AARCH64_INS_LDXR: None,
    AARCH64_INS_LDARB: 1,
    AARCH64_INS_LDARH: 2,
    AARCH64_INS_LDAR: None,
}

# None indicates that the write size depends on the source register
AARCH64_SINGLE_STORE_INSTRUCTIONS: Dict[int, int | None] = {
    AARCH64_INS_STRB: 1,
    AARCH64_INS_ALIAS_STRB: 1,
    AARCH64_INS_STURB: 1,
    AARCH64_INS_ALIAS_STURB: 1,
    AARCH64_INS_STRH: 2,
    AARCH64_INS_ALIAS_STRH: 2,
    AARCH64_INS_STURH: 2,
    AARCH64_INS_ALIAS_STURH: 2,
    AARCH64_INS_STUR: None,
    AARCH64_INS_ALIAS_STUR: None,
    AARCH64_INS_STR: None,
    AARCH64_INS_ALIAS_STR: None,
    # Store Register (unprivileged)
    AARCH64_INS_STTRB: 1,
    AARCH64_INS_STTRH: 2,
    AARCH64_INS_STTR: None,
    # Store-Release
    AARCH64_INS_STLRB: 1,
    AARCH64_INS_STLRH: 2,
    AARCH64_INS_STLR: None,
}

# The first operand of these instructions gets the status result of the operation
AARCH64_EXCLUSIVE_STORE_INSTRUCTIONS = {
    # Store Exclusive
    AARCH64_INS_STXRB: 1,
    AARCH64_INS_STXRH: 2,
    AARCH64_INS_STXR: None,
    # Store-Release Exclusive
    AARCH64_INS_STLXRB: 1,
    AARCH64_INS_STLXRH: 2,
    AARCH64_INS_STLXR: None,
}

CONDITIONAL_SELECT_INSTRUCTIONS = {
    AARCH64_INS_CSEL,
    AARCH64_INS_CSINC,
    AARCH64_INS_CSINV,
    AARCH64_INS_CSNEG,
    AARCH64_INS_ALIAS_CSET,
    AARCH64_INS_ALIAS_CSETM,
    AARCH64_INS_ALIAS_CINC,
    AARCH64_INS_ALIAS_CINV,
    AARCH64_INS_ALIAS_CNEG,
}

AARCH64_EMULATED_ANNOTATIONS = CONDITIONAL_SELECT_INSTRUCTIONS | {
    AARCH64_INS_SXTB,
    AARCH64_INS_SXTH,
    AARCH64_INS_SXTW,
    AARCH64_INS_UXTB,
    AARCH64_INS_UXTH,
    AARCH64_INS_UXTW,
    AARCH64_INS_RBIT,
    AARCH64_INS_CLS,
    AARCH64_INS_CLZ,
    AARCH64_INS_ALIAS_BFXIL,
    AARCH64_INS_ALIAS_UBFIZ,
    AARCH64_INS_UBFM,
    AARCH64_INS_ALIAS_UBFX,
    AARCH64_INS_ALIAS_SBFIZ,
    AARCH64_INS_SBFM,
    AARCH64_INS_ALIAS_SBFX,
    AARCH64_INS_ALIAS_BFI,
    AARCH64_INS_NEG,
    AARCH64_INS_ALIAS_NEGS,
    AARCH64_INS_REV,
    AARCH64_INS_BIC,
    AARCH64_INS_BICS,
}

AARCH64_CONSTANT_SHIFTS = {AARCH64_SFT_LSL, AARCH64_SFT_LSR, AARCH64_SFT_ASR, AARCH64_SFT_ROR}

# Parameters to each function: (value, shift_amt, bit_width)
AARCH64_BIT_SHIFT_MAP: Dict[int, Callable[[int, int, int], int]] = {
    AARCH64_SFT_LSL: bit_math.logical_shift_left,
    AARCH64_SFT_LSR: bit_math.logical_shift_right,
    AARCH64_SFT_ASR: bit_math.arithmetic_shift_right,
    AARCH64_SFT_ROR: bit_math.rotate_right,
}


# These are "Extend" operations - https://devblogs.microsoft.com/oldnewthing/20220728-00/?p=106912
# They take in a number, extract a byte, halfword, or word,
# and perform a zero- or sign-extend operation.
AARCH64_EXTEND_MAP: Dict[int, Callable[[int], int]] = {
    AARCH64_EXT_UXTB: lambda x: x & ((1 << 8) - 1),
    AARCH64_EXT_UXTH: lambda x: x & ((1 << 16) - 1),
    AARCH64_EXT_UXTW: lambda x: x & ((1 << 32) - 1),
    AARCH64_EXT_UXTX: lambda x: x,  # UXTX has no effect. It extracts 64-bits from a 64-bit register.
    AARCH64_EXT_SXTB: lambda x: bit_math.to_signed(x, 8),
    AARCH64_EXT_SXTH: lambda x: bit_math.to_signed(x, 16),
    AARCH64_EXT_SXTW: lambda x: bit_math.to_signed(x, 32),
    AARCH64_EXT_SXTX: lambda x: bit_math.to_signed(x, 64),
}

AARCH64_MATH_INSTRUCTIONS = {
    AARCH64_INS_ADD: "+",
    AARCH64_INS_ALIAS_ADD: "+",
    AARCH64_INS_ADDS: "+",
    AARCH64_INS_ALIAS_ADDS: "+",
    AARCH64_INS_SUB: "-",
    AARCH64_INS_ALIAS_SUB: "-",
    AARCH64_INS_SUBS: "-",
    AARCH64_INS_ALIAS_SUBS: "-",
    AARCH64_INS_AND: "&",
    AARCH64_INS_ALIAS_AND: "&",
    AARCH64_INS_ANDS: "&",
    AARCH64_INS_ALIAS_ANDS: "&",
    AARCH64_INS_ORR: "|",
    AARCH64_INS_ALIAS_ORR: "|",
    AARCH64_INS_EOR: "^",
    AARCH64_INS_ALIAS_EOR: "^",
    AARCH64_INS_UDIV: "/",
    AARCH64_INS_SDIV: "/",
    AARCH64_INS_SMULH: "*",
    AARCH64_INS_SMULL: "*",
    AARCH64_INS_ALIAS_SMULL: "*",
    AARCH64_INS_UMULH: "*",
    AARCH64_INS_UMULL: "*",
    AARCH64_INS_ALIAS_UMULL: "*",
    AARCH64_INS_MUL: "*",
    AARCH64_INS_ALIAS_MUL: "*",
}

AARCH64_SHIFT_INSTRUCTIONS = {
    AARCH64_INS_LSL: "<<",
    AARCH64_INS_ALIAS_LSL: "<<",
    AARCH64_INS_LSR: ">>",
    AARCH64_INS_ALIAS_LSR: ">>",
    AARCH64_INS_ASR: ">>s",
    AARCH64_INS_ALIAS_ASR: ">>s",
    AARCH64_INS_ROR: ">>r",
    AARCH64_INS_ALIAS_ROR: ">>r",
}


def resolve_condition(condition: int, cpsr: int) -> InstructionCondition:
    """
    Given a condition and the NZCV flag bits, determine when the condition is satisfied

    The condition is a Capstone constant
    """

    n = (cpsr >> 31) & 1
    z = (cpsr >> 30) & 1
    c = (cpsr >> 29) & 1
    v = (cpsr >> 28) & 1

    condition = {
        AArch64CC_EQ: z == 1,
        AArch64CC_NE: z == 0,
        AArch64CC_HS: c == 1,
        AArch64CC_LO: c == 0,
        AArch64CC_MI: n == 1,
        AArch64CC_PL: n == 0,
        AArch64CC_VS: v == 1,
        AArch64CC_VC: v == 0,
        AArch64CC_HI: c == 1 and z == 0,
        AArch64CC_LS: not (c == 1 and z == 0),
        AArch64CC_GE: n == v,
        AArch64CC_LT: n != v,
        AArch64CC_GT: z == 0 and n == v,
        AArch64CC_LE: not (z == 0 and n == v),
        AArch64CC_AL: True,
        AArch64CC_NV: True,
        AArch64CC_Invalid: True,
    }.get(condition, False)

    return InstructionCondition.TRUE if condition else InstructionCondition.FALSE


class AArch64DisassemblyAssistant(pwndbg.aglib.disasm.arch.DisassemblyAssistant):
    def __init__(self, architecture) -> None:
        super().__init__(architecture)

        self.annotation_handlers: Dict[int, Callable[[PwndbgInstruction, Emulator], None]] = {
            # MOV
            AARCH64_INS_MOV: self._common_move_annotator,
            AARCH64_INS_ALIAS_MOV: self._common_move_annotator,
            # MOVZ
            AARCH64_INS_MOVZ: self._common_move_annotator,
            # MOV WITH KEEP
            AARCH64_INS_MOVK: self._common_generic_register_destination,
            # ADR
            AARCH64_INS_ADR: self._common_generic_register_destination,
            # ADRP
            AARCH64_INS_ADRP: self._handle_adrp,
            # CMP
            AARCH64_INS_ALIAS_CMP: self._common_cmp_annotator_builder("cpsr", "-"),
            # CMN
            AARCH64_INS_ALIAS_CMN: self._common_cmp_annotator_builder("cpsr", "+"),
            # TST (bitwise "and")
            AARCH64_INS_ALIAS_TST: self._common_cmp_annotator_builder("cpsr", "&"),
            # CCMP (conditional compare)
            AARCH64_INS_CCMP: self._common_cmp_annotator_builder("cpsr", ""),
            # CCMN
            AARCH64_INS_CCMN: self._common_cmp_annotator_builder("cpsr", ""),
        }

    @override
    def _set_annotation_string(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        # Dispatch to the correct handler
        if instruction.id in AARCH64_SINGLE_LOAD_INSTRUCTIONS:
            target_reg_size = self._register_width(instruction, instruction.operands[0]) // 8
            read_size = AARCH64_SINGLE_LOAD_INSTRUCTIONS[instruction.id] or target_reg_size

            self._common_load_annotator(
                instruction,
                emu,
                instruction.operands[1].before_value,
                abs(read_size),
                read_size < 0,
                target_reg_size,
                instruction.operands[0].str,
                instruction.operands[1].str,
            )
        elif instruction.id in AARCH64_SINGLE_STORE_INSTRUCTIONS:
            self._common_store_annotator(
                instruction,
                emu,
                instruction.operands[1].before_value,
                instruction.operands[0].before_value,
                AARCH64_SINGLE_STORE_INSTRUCTIONS[instruction.id],
                instruction.operands[1].str,
            )
        elif instruction.id in AARCH64_EXCLUSIVE_STORE_INSTRUCTIONS:
            self._common_store_annotator(
                instruction,
                emu,
                instruction.operands[-1].before_value,
                instruction.operands[-2].before_value,
                AARCH64_EXCLUSIVE_STORE_INSTRUCTIONS[instruction.id],
                instruction.operands[-1].str,
            )
        elif instruction.id in AARCH64_MATH_INSTRUCTIONS:
            self._common_binary_op_annotator(
                instruction,
                emu,
                instruction.operands[0],
                instruction.operands[-2].before_value,
                instruction.operands[-1].before_value,
                AARCH64_MATH_INSTRUCTIONS[instruction.id],
            )
        elif instruction.id in AARCH64_SHIFT_INSTRUCTIONS:
            # AArch64 encoding of shifts forces special attention: https://github.com/capstone-engine/capstone/issues/2631
            if len(instruction.operands) == 2:
                if instruction.operands[1].cs_op.shift.type in AARCH64_CONSTANT_SHIFTS:
                    self._common_binary_op_annotator(
                        instruction,
                        emu,
                        instruction.operands[0],
                        instruction.operands[1].before_value_no_modifiers,
                        instruction.operands[1].cs_op.shift.value,
                        AARCH64_SHIFT_INSTRUCTIONS[instruction.id],
                    )
                else:
                    self._common_generic_register_destination(instruction, emu)
        elif instruction.id in AARCH64_EMULATED_ANNOTATIONS:
            self._common_generic_register_destination(instruction, emu)
        else:
            self.annotation_handlers.get(instruction.id, lambda *a: None)(instruction, emu)

    def _handle_adrp(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        result_operand, right = instruction.operands
        if result_operand.str and right.before_value is not None:
            address = right.before_value & pwndbg.aglib.arch.ptrmask

            TELESCOPE_DEPTH = max(0, int(pwndbg.config.disasm_telescope_depth))

            addresses = self._telescope(address, TELESCOPE_DEPTH, instruction, emu)

            telescope = self._telescope_format_list(addresses, TELESCOPE_DEPTH, emu)

            instruction.annotation = register_assign(result_operand.str, telescope)

    @override
    def _prepare(
        self, instruction: PwndbgInstruction, emu: pwndbg.aglib.disasm.arch.Emulator
    ) -> None:
        if CS_GRP_INT in instruction.groups:
            # https://github.com/capstone-engine/capstone/issues/2630
            instruction.groups.remove(CS_GRP_CALL)

    @override
    def _condition(
        self, instruction: PwndbgInstruction, emu: Emulator
    ) -> pwndbg.aglib.disasm.arch.InstructionCondition:
        # In ARM64, only branches have the conditional code in the instruction,
        # as opposed to ARM32 which allows most instructions to be conditional
        if instruction.id == AARCH64_INS_B:
            # The B instruction can be made conditional by the condition codes
            if instruction.cs_insn.cc in (AArch64CC_Invalid, AArch64CC_AL):
                instruction.declare_conditional = False
            else:
                flags = super()._read_register_name(instruction, "cpsr", emu)
                if flags is not None:
                    return resolve_condition(instruction.cs_insn.cc, flags)

        elif instruction.id == AARCH64_INS_CBNZ:
            op_val = instruction.operands[0].before_value
            return boolean_to_instruction_condition(op_val is not None and op_val != 0)

        elif instruction.id == AARCH64_INS_CBZ:
            op_val = instruction.operands[0].before_value
            return boolean_to_instruction_condition(op_val is not None and op_val == 0)

        elif instruction.id == AARCH64_INS_TBNZ:
            op_val, bit = (
                instruction.operands[0].before_value,
                instruction.operands[1].before_value,
            )

            if op_val is not None and bit is not None:
                return boolean_to_instruction_condition(bool((op_val >> bit) & 1))

        elif instruction.id == AARCH64_INS_TBZ:
            op_val, bit = (
                instruction.operands[0].before_value,
                instruction.operands[1].before_value,
            )

            if op_val is not None and bit is not None:
                return boolean_to_instruction_condition(not ((op_val >> bit) & 1))
        elif instruction.id in CONDITIONAL_SELECT_INSTRUCTIONS:
            # Capstone places the condition to be satisfied in the `cc` field of the instruction
            # for all conditional select instructions
            flags = self._read_register_name(instruction, "cpsr", emu)

            if flags is not None:
                return resolve_condition(instruction.cs_insn.cc, flags)

        return super()._condition(instruction, emu)

    @override
    def _resolve_target(self, instruction: PwndbgInstruction, emu: Emulator | None):
        if not bool(instruction.groups & ALL_JUMP_GROUPS):
            return None

        if len(instruction.operands) > 0:
            # For all AArch64 branches, the target is either an immediate or a register and is the last operand
            if (val := instruction.operands[-1].before_value) is not None:
                return val & pwndbg.aglib.arch.ptrmask
            return None
        elif instruction.id in (AARCH64_INS_RET, AARCH64_INS_ALIAS_RET):
            # If this is a ret WITHOUT an operand, it means we should read from the LR/x30 register
            return super()._read_register_name(instruction, "lr", emu)

        return super()._resolve_target(instruction, emu)

    @override
    def _parse_memory(
        self, instruction: PwndbgInstruction, op: EnhancedOperand, emu: Emulator
    ) -> int | None:
        """
        Parse the `Arm64OpMem` Capstone object to determine the concrete memory address used.

        Three types of AArch64 memory operands:
        1. Register base with optional immediate offset
        Examples:
              ldrb   w3, [x2]
              str    x1, [x2, #0xb58]
              ldr x4,[x3], 4
        2. Register + another register with an optional shift
        Examples:
              ldrb   w1, [x9, x2]
              str x1, [x2, x0, lsl #3]
        3. Register + 32-bit register extended and shifted.
        The shift in this case is implicitly a LSL
        Examples:
              ldr x1, [x2, w22, UXTW #3]

        """

        target = 0

        # Handle case of LDR instructions memory operands that uses immediate as memory location
        # Example: ldr x1, 0x30
        if op.mem.base == 0:
            return op.mem.disp

        base = self._read_register(instruction, op.mem.base, emu)
        if base is None:
            return None
        target = base

        if not instruction.cs_insn.post_index:
            # Unlike in arm32, the sign of `disp` is encoded in the number already.
            # There is no separate ".subtracted" value in Capstone
            target += op.mem.disp

        # If there is an index register
        if op.mem.index != 0:
            index = self._read_register(instruction, op.mem.index, emu)
            if index is None:
                return None

            # Optionally apply an extend to the index register
            if op.cs_op.ext != 0:
                index = AARCH64_EXTEND_MAP[op.cs_op.ext](index)

            # Optionally apply shift to the index register
            # This handles shifts in the extend operation as well:
            # As in the case of `ldr x1, [x2, w22, UXTW #3]`,
            # Capstone will automatically make the shift a LSL and set the value to 3
            if op.cs_op.shift.type != 0:
                # The form of instructions with a shift always apply the shift to a 64-bit value
                index = AARCH64_BIT_SHIFT_MAP[op.cs_op.shift.type](index, op.cs_op.shift.value, 64)

            target += index

        return target

    def _register_width(self, instruction: PwndbgInstruction, op: EnhancedOperand) -> int:
        return 32 if instruction.cs_insn.reg_name(op.reg)[0] == "w" else 64

    @override
    def _parse_immediate(self, instruction: PwndbgInstruction, op: EnhancedOperand, emu: Emulator):
        """
        In AArch64, there can be an optional shift applied to constants, typically only a `LSL #12`

        Ex:
            cmp    x8, #1, lsl #12      (1 << 12)
        """
        target = op.imm
        if target is None:
            return None

        if op.cs_op.shift.type != 0:
            target = AARCH64_BIT_SHIFT_MAP[op.cs_op.shift.type](target, op.cs_op.shift.value, 64)

        return target

    @override
    def _parse_register(
        self, instruction: PwndbgInstruction, op: EnhancedOperand, emu: Emulator
    ) -> int | None:
        """
        Register operands can have optional extend and shift modifiers.

        Ex:
            cmp x5, x3, LSL #12         (x3 << 12)
            cmp x5, w3, SXTB 4          (Signed extend byte, then left shift 4)

        The extend operation is always applied first (if present), and then shifts take effect.
        """
        target = super()._parse_register(instruction, op, emu)
        if target is None:
            return None

        # We need this to retain the value of the un-shifted register in some annotations, such as shifts
        op.before_value_no_modifiers = target

        # The shift and sign-extend operations depend on the target bit width.
        # This is sometimes implicit in the target register size, which is always
        # the first operand.
        target_bit_width = (
            self._register_width(instruction, instruction.operands[0])
            if instruction.operands[0].type == CS_OP_REG
            else 64
        )

        if op.cs_op.ext != 0:
            target = AARCH64_EXTEND_MAP[op.cs_op.ext](target) & ((1 << target_bit_width) - 1)

        if op.cs_op.shift.type != 0:
            target = AARCH64_BIT_SHIFT_MAP.get(op.cs_op.shift.type, lambda *a: None)(
                target, op.cs_op.shift.value, target_bit_width
            )

            if target is not None:
                target = target & ((1 << target_bit_width) - 1)

        return target
