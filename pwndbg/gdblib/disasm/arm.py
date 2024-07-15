from __future__ import annotations

from typing import Callable
from typing import Dict

from capstone import *  # noqa: F403
from capstone.arm import *  # noqa: F403
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

}

class DisassemblyAssistant(pwndbg.gdblib.disasm.arch.DisassemblyAssistant):
    def __init__(self, architecture: str) -> None:
        super().__init__(architecture)

        self.annotation_handlers: Dict[int, Callable[[PwndbgInstruction, Emulator], None]] = {
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
        # Dispatch to the correct handler
        self.annotation_handlers.get(instruction.id, lambda *a: None)(instruction, emu)

    @override
    def _condition(self, instruction: PwndbgInstruction, emu: Emulator) -> InstructionCondition:
        if instruction.cs_insn.cc == ARM_CC_AL:
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
    def _resolve_target(self, instruction: PwndbgInstruction, emu: Emulator | None, call=False):
        target = super()._resolve_target(instruction, emu, call)
        if target is not None:
            # On interworking branches - branches that can enable Thumb mode - the target of a jump
            # has the least significant bit set to 1. This is not actually written to the PC
            # and instead the CPU puts it into the Thumb mode register bit.
            # This means we have to clear the least significant bit of the target.
            target = target & ~1
        return target

    @override
    def _memory_string(self, instruction: PwndbgInstruction, op: EnhancedOperand) -> str:
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

    @override
    def _immediate_string(self, instruction, operand):
        return "#" + super()._immediate_string(instruction, operand)

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
