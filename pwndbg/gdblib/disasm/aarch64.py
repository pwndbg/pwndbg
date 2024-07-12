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
from pwndbg.emu.emulator import Emulator
from pwndbg.gdblib.disasm.instruction import ALL_JUMP_GROUPS
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

    def generic_register_destination(self, instruction, emu: Emulator) -> None:
        """
        This function can be used to annotate instructions that have a register destination,
        which in AArch64 is always the first register. Works only while we are using emulation.

        In an ideal world, we have more specific code on a case-by-case basis to allow us to
        annotate results even when not emulating (as is done in many x86 handlers)
        """

        left = instruction.operands[0]

        # Emulating determined the value that was set in the destination register
        if left.after_value is not None:
            TELESCOPE_DEPTH = max(0, int(pwndbg.config.disasm_telescope_depth))

            # Telescope the address
            telescope_addresses = super()._telescope(
                left.after_value,
                TELESCOPE_DEPTH + 1,
                instruction,
                left,
                emu,
                read_size=pwndbg.gdblib.arch.ptrsize,
            )

            if not telescope_addresses:
                return

            instruction.annotation = f"{left.str} => {super()._telescope_format_list(telescope_addresses, TELESCOPE_DEPTH, emu)}"

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


assistant = DisassemblyAssistant("aarch64")
