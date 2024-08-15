from __future__ import annotations

from typing import Callable
from typing import Dict

from capstone import *  # noqa: F403
from capstone.arm import *  # noqa: F403
from pwnlib.util.misc import align_down
from typing_extensions import override

import pwndbg.gdblib.arch
import pwndbg.gdblib.disasm.arch
import pwndbg.gdblib.memory
import pwndbg.gdblib.regs
import pwndbg.lib.disasm.helpers as bit_math
from pwndbg.emu.emulator import Emulator
from pwndbg.gdblib.disasm.instruction import EnhancedOperand
from pwndbg.gdblib.disasm.instruction import InstructionCondition
from pwndbg.gdblib.disasm.instruction import PwndbgInstruction

# Note: this map does not contain all the Arm32 shift types, just the ones relevent to register and memory modifier operations
ARM_BIT_SHIFT_MAP: Dict[int, Callable[[int, int, int], int]] = {
    ARM_SFT_ASR: bit_math.arithmetic_shift_right,
    ARM_SFT_LSL: bit_math.logical_shift_left,
    ARM_SFT_LSR: bit_math.logical_shift_right,
    ARM_SFT_ROR: bit_math.rotate_right,
}

ARM_SINGLE_LOAD_INSTRUCTIONS = {
    ARM_INS_LDRB: 1,
    ARM_INS_LDRSB: -1,
    ARM_INS_LDRH: 2,
    ARM_INS_LDRSH: -2,
    ARM_INS_LDR: 4,
    ARM_INS_LDRBT: 1,
    ARM_INS_LDRSBT: -1,
    ARM_INS_LDRHT: 2,
    ARM_INS_LDRSHT: -2,
    ARM_INS_LDRT: 4,
    ARM_INS_LDREXB: 1,
    ARM_INS_LDREXH: 2,
    ARM_INS_LDREX: 4,
}

ARM_SINGLE_STORE_INSTRUCTIONS = {
    ARM_INS_STRB: 1,
    ARM_INS_STRH: 2,
    ARM_INS_STR: 4,
    ARM_INS_STRBT: 1,
    ARM_INS_STRHT: 2,
    ARM_INS_STRT: 4,
    ARM_INS_STREXB: 1,
    ARM_INS_STREXH: 2,
    ARM_INS_STREX: 4,
}

ARM_MATH_INSTRUCTIONS = {
    ARM_INS_ADD: "+",
    ARM_INS_ADDW: "+",
    ARM_INS_SUB: "-",
    ARM_INS_ORR: "|",
    ARM_INS_AND: "&",
    ARM_INS_EOR: "^",
    ARM_INS_ASR: ">>s",
    ARM_INS_LSR: ">>",
    ARM_INS_LSL: "<<",
    ARM_INS_UDIV: "/",
    ARM_INS_SDIV: "/",
    ARM_INS_MUL: "*",
    ARM_INS_UMULL: "*",
    ARM_INS_SMULL: "*",
}


class DisassemblyAssistant(pwndbg.gdblib.disasm.arch.DisassemblyAssistant):
    def __init__(self, architecture: str) -> None:
        super().__init__(architecture)

        self.annotation_handlers: Dict[int, Callable[[PwndbgInstruction, Emulator], None]] = {
            # MOV
            ARM_INS_MOV: self._common_move_annotator,
            ARM_INS_MOVW: self._common_move_annotator,
            # MOVT
            ARM_INS_MOVT: self._common_generic_register_destination,
            # MOVN
            ARM_INS_MVN: self._common_generic_register_destination,
            # CMP
            ARM_INS_CMP: self._common_cmp_annotator_builder("cpsr", "-"),
            # CMN
            ARM_INS_CMN: self._common_cmp_annotator_builder("cpsr", "+"),
            # TST (bitwise "and")
            ARM_INS_TST: self._common_cmp_annotator_builder("cpsr", "&"),
            # TEQ (bitwise exclusive "or")
            ARM_INS_TEQ: self._common_cmp_annotator_builder("cpsr", "^"),
        }

    @override
    def _set_annotation_string(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        if instruction.id in ARM_SINGLE_LOAD_INSTRUCTIONS:
            read_size = ARM_SINGLE_LOAD_INSTRUCTIONS[instruction.id]
            self._common_load_annotator(
                instruction,
                emu,
                instruction.operands[1].before_value,
                abs(read_size),
                read_size < 0,
                4,
                instruction.operands[0].str,
                instruction.operands[1].str,
            )
        elif instruction.id in ARM_SINGLE_STORE_INSTRUCTIONS:
            self._common_store_annotator(
                instruction,
                emu,
                instruction.operands[1].before_value,
                instruction.operands[0].before_value,
                ARM_SINGLE_STORE_INSTRUCTIONS[instruction.id],
                instruction.operands[1].str,
            )
        elif instruction.id in ARM_MATH_INSTRUCTIONS:
            # In Arm assembly, if there are two operands, than the first source operand is also the destination
            # Example: add    sl, r3
            # Or, it can be a seperate register. We use -1 and -2 indexes here to access the source operands either way
            self._common_binary_op_annotator(
                instruction,
                emu,
                instruction.operands[0],
                instruction.operands[-2].before_value,
                instruction.operands[-1].before_value,
                ARM_MATH_INSTRUCTIONS[instruction.id],
            )
        else:
            self.annotation_handlers.get(instruction.id, lambda *a: None)(instruction, emu)

    @override
    def _condition(self, instruction: PwndbgInstruction, emu: Emulator) -> InstructionCondition:
        if instruction.cs_insn.cc == ARM_CC_AL:
            if instruction.id in (ARM_INS_B, ARM_INS_BL, ARM_INS_BLX, ARM_INS_BX, ARM_INS_BXJ):
                instruction.declare_conditional = False
            return InstructionCondition.UNDETERMINED

        # We can't reason about anything except the current instruction
        if instruction.address != pwndbg.gdblib.regs.pc:
            return InstructionCondition.UNDETERMINED

        value = (
            pwndbg.gdblib.regs.cpsr
            if pwndbg.gdblib.arch.current == "arm"
            else pwndbg.gdblib.regs.xpsr
        )

        N = (value >> 31) & 1
        Z = (value >> 30) & 1
        C = (value >> 29) & 1
        V = (value >> 28) & 1

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
            ARM_CC_GT: not Z and (N == V),
            ARM_CC_LE: Z or (N != V),
        }.get(instruction.cs_insn.cc, None)

        if cc is None:
            return InstructionCondition.UNDETERMINED

        return InstructionCondition.TRUE if bool(cc) else InstructionCondition.FALSE

    @override
    def _resolve_target(self, instruction: PwndbgInstruction, emu: Emulator | None):
        target = super()._resolve_target(instruction, emu)
        if target is not None:
            # On interworking branches - branches that can enable Thumb mode - the target of a jump
            # has the least significant bit set to 1. This is not actually written to the PC
            # and instead the CPU puts it into the Thumb mode register bit.
            # This means we have to clear the least significant bit of the target.
            target = target & ~1
        return target

    # Currently not used
    def _memory_string_old(self, instruction: PwndbgInstruction, op: EnhancedOperand) -> str:
        parts = []

        if op.mem.base != 0:
            parts.append(instruction.cs_insn.reg_name(op.mem.base))

        if op.mem.disp != 0:
            parts.append("%#x" % op.mem.disp)

        if op.mem.index != 0:
            index = pwndbg.gdblib.regs[instruction.cs_insn.reg_name(op.mem.index)]
            scale = op.mem.scale
            parts.append(f"{index}*{scale:#x}")

        return f"[{(', '.join(parts))}]"

    def read_thumb_bit(self, instruction: PwndbgInstruction, emu: Emulator) -> int | None:
        return 1 if instruction.cs_insn._cs._mode & CS_MODE_THUMB else 0

    @override
    def _immediate_string(self, instruction, operand):
        return "#" + super()._immediate_string(instruction, operand)

    @override
    def _read_register(
        self, instruction: PwndbgInstruction, operand_id: int, emu: Emulator
    ) -> int | None:
        # When `pc` is referenced in an operand (typically in a memory operand), the value it takes on
        # is `pc_at_instruction + 8`. In Thumb mode, you only add 4 to the instruction address.
        if operand_id == ARM_REG_PC:
            return instruction.address + (4 if self.read_thumb_bit(instruction, emu) else 8)

        return super()._read_register(instruction, operand_id, emu)

    @override
    def _parse_memory(
        self, instruction: PwndbgInstruction, op: EnhancedOperand, emu: Emulator
    ) -> int | None:
        """
        Parse the `ArmOpMem` Capstone object to determine the concrete memory address used.

        Types of memory operands:
            [Rn]
            [Rn, #imm]
            [Rn, Rm]
            [Rn, Rm, <shift> #imm]

        Capstone represents the object a bit differently then AArch64 to align with the underlying architecture of Arm.

        This representation will change in Capstone 6:
            https://github.com/capstone-engine/capstone/issues/2281
            https://github.com/capstone-engine/capstone/pull/1949
        """

        target = 0

        # All memory operands have `base` defined
        base = self._read_register(instruction, op.mem.base, emu)
        if base is None:
            return None

        if op.mem.base == ARM_REG_PC:
            # The PC as the base register is a special case - it will align the address to a word (32-bit) boundary
            # Explanation: https://stackoverflow.com/a/29588678
            # See "Operation" at the bottom of https://developer.arm.com/documentation/ddi0597/2024-03/Base-Instructions/LDR--literal---Load-Register--literal--
            base = align_down(4, base)

        target = base + op.mem.disp

        # If there is an index register
        if op.mem.index != 0:
            index = self._read_register(instruction, op.mem.index, emu)
            if index is None:
                return None

            # Optionally apply shift to the index register
            if op.cs_op.shift.type != 0:
                index = ARM_BIT_SHIFT_MAP[op.cs_op.shift.type](index, op.cs_op.shift.value, 32)

            target += index * (-1 if op.cs_op.subtracted else 1)

        return target

    @override
    def _parse_register(
        self, instruction: PwndbgInstruction, op: EnhancedOperand, emu: Emulator
    ) -> int | None:
        """
        Register operands can have optional shifts in Arm
        """
        target = super()._parse_register(instruction, op, emu)
        if target is None:
            return None

        # Optionally apply shift to the index register
        if op.cs_op.shift.type != 0:
            target = ARM_BIT_SHIFT_MAP.get(op.cs_op.shift.type, lambda *a: None)(
                target, op.cs_op.shift.value, 32
            )

        return target


assistant = DisassemblyAssistant("arm")
