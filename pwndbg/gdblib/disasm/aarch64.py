from __future__ import annotations

from typing import Callable
from typing import Dict

from capstone import *  # noqa: F403
from capstone.arm64 import *  # noqa: F403
from typing_extensions import override

import pwndbg.enhance
import pwndbg.gdblib.arch
import pwndbg.gdblib.disasm.arch
import pwndbg.gdblib.memory
import pwndbg.gdblib.regs
import pwndbg.lib.disasm.helpers as bit_math
from pwndbg.emu.emulator import Emulator
from pwndbg.gdblib.disasm.instruction import ALL_JUMP_GROUPS
from pwndbg.gdblib.disasm.instruction import EnhancedOperand
from pwndbg.gdblib.disasm.instruction import InstructionCondition
from pwndbg.gdblib.disasm.instruction import PwndbgInstruction
from pwndbg.gdblib.disasm.instruction import boolean_to_instruction_condition


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
        ARM64_CC_INVALID: True,  # Capstone uses this code for the 'B' instruction, the unconditional branch
        ARM64_CC_EQ: z == 1,
        ARM64_CC_NE: z == 0,
        ARM64_CC_HS: c == 1,
        ARM64_CC_LO: c == 0,
        ARM64_CC_MI: n == 1,
        ARM64_CC_PL: n == 0,
        ARM64_CC_VS: v == 1,
        ARM64_CC_VC: v == 0,
        ARM64_CC_HI: c == 1 and z == 0,
        ARM64_CC_LS: not (c == 1 and z == 0),
        ARM64_CC_GE: n == v,
        ARM64_CC_LT: n != v,
        ARM64_CC_GT: z == 0 and n == v,
        ARM64_CC_LE: not (z == 0 and n == v),
        ARM64_CC_AL: True,
        ARM64_CC_NV: True,
    }.get(condition, False)

    return InstructionCondition.TRUE if condition else InstructionCondition.FALSE


# Parameters to each function: (value, shift_amt, bit_width)
AARCH64_BIT_SHIFT_MAP: Dict[int, Callable[[int, int, int], int]] = {
    ARM64_SFT_LSL: bit_math.logical_shift_left,
    ARM64_SFT_LSR: bit_math.logical_shift_right,
    ARM64_SFT_ASR: bit_math.arithmetic_shift_right,
    ARM64_SFT_ROR: bit_math.rotate_right,
}

# These are "Extend" operations - https://devblogs.microsoft.com/oldnewthing/20220728-00/?p=106912
# They take in a number, extract a byte, halfword, or word,
# and perform a zero- or sign-extend operation.
AARCH64_EXTEND_MAP: Dict[int, Callable[[int], int]] = {
    ARM64_EXT_UXTB: lambda x: x & ((1 << 8) - 1),
    ARM64_EXT_UXTH: lambda x: x & ((1 << 16) - 1),
    ARM64_EXT_UXTW: lambda x: x & ((1 << 32) - 1),
    ARM64_EXT_UXTX: lambda x: x,  # UXTX has no effect. It extracts 64-bits from a 64-bit register.
    ARM64_EXT_SXTB: lambda x: bit_math.to_signed(x, 8),
    ARM64_EXT_SXTH: lambda x: bit_math.to_signed(x, 16),
    ARM64_EXT_SXTW: lambda x: bit_math.to_signed(x, 32),
    ARM64_EXT_SXTX: lambda x: bit_math.to_signed(x, 64),
}


class DisassemblyAssistant(pwndbg.gdblib.disasm.arch.DisassemblyAssistant):
    def __init__(self, architecture: str) -> None:
        super().__init__(architecture)

        self.annotation_handlers: Dict[int, Callable[[PwndbgInstruction, Emulator], None]] = {
            # MOV
            ARM64_INS_MOV: self._common_generic_register_destination,
            # ADR
            ARM64_INS_ADR: self._common_generic_register_destination,
            # ADRP
            ARM64_INS_ADRP: self._common_generic_register_destination,
            # LDR
            ARM64_INS_LDR: self._common_generic_register_destination,
            # ADD
            ARM64_INS_ADD: self._common_generic_register_destination,
            # SUB
            ARM64_INS_SUB: self._common_generic_register_destination,
            # CMP
            ARM64_INS_CMP: self._common_cmp_annotator_builder("cpsr", "-"),
            # CMN
            ARM64_INS_CMN: self._common_cmp_annotator_builder("cpsr", "+"),
            # TST (bitwise "and")
            ARM64_INS_TST: self._common_cmp_annotator_builder("cpsr", "&"),
            # CCMP (conditional compare)
            ARM64_INS_CCMP: self._common_cmp_annotator_builder("cpsr", ""),
            # CCMN
            ARM64_INS_CCMN: self._common_cmp_annotator_builder("cpsr", ""),
        }

    @override
    def _condition(
        self, instruction: PwndbgInstruction, emu: Emulator
    ) -> pwndbg.gdblib.disasm.arch.InstructionCondition:
        # In ARM64, only branches have the conditional code in the instruction,
        # as opposed to ARM32 which allows most instructions to be conditional
        if instruction.id == ARM64_INS_B:
            flags = super()._read_register_name(instruction, "cpsr", emu)
            if flags is not None:
                return resolve_condition(instruction.cs_insn.cc, flags)

        elif instruction.id == ARM64_INS_CBNZ:
            op_val = instruction.operands[0].before_value
            return boolean_to_instruction_condition(op_val is not None and op_val != 0)

        elif instruction.id == ARM64_INS_CBZ:
            op_val = instruction.operands[0].before_value
            return boolean_to_instruction_condition(op_val is not None and op_val == 0)

        elif instruction.id == ARM64_INS_TBNZ:
            op_val, bit = (
                instruction.operands[0].before_value,
                instruction.operands[1].before_value,
            )

            if op_val is not None and bit is not None:
                return boolean_to_instruction_condition(bool((op_val >> bit) & 1))

        elif instruction.id == ARM64_INS_TBZ:
            op_val, bit = (
                instruction.operands[0].before_value,
                instruction.operands[1].before_value,
            )

            if op_val is not None and bit is not None:
                return boolean_to_instruction_condition(not ((op_val >> bit) & 1))

        # TODO: Additionally, the "conditional comparisons" and "conditional selects" support conditional execution

        return super()._condition(instruction, emu)

    @override
    def _resolve_target(self, instruction: PwndbgInstruction, emu: Emulator | None, call=False):
        if not bool(instruction.groups_set & ALL_JUMP_GROUPS):
            return None

        if len(instruction.operands) > 0:
            # For all AArch64 branches, the target is either an immediate or a register and is the last operand
            return instruction.operands[-1].before_value
        elif instruction.id == ARM64_INS_RET:
            # If this is a ret WITHOUT an operand, it means we should read from the LR/x30 register
            return super()._read_register_name(instruction, "lr", emu)

        return super()._resolve_target(instruction, emu, call)

    @override
    def _set_annotation_string(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        # Dispatch to the correct handler
        self.annotation_handlers.get(instruction.id, lambda *a: None)(instruction, emu)

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
            print(target, op.cs_op.shift.type, op.cs_op.shift.value)
            target = AARCH64_BIT_SHIFT_MAP[op.cs_op.shift.type](
                target, op.cs_op.shift.value, target_bit_width
            ) & ((1 << target_bit_width) - 1)

        return target


assistant = DisassemblyAssistant("aarch64")
