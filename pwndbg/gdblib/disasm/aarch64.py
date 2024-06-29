from __future__ import annotations

from typing import Callable
from typing import Dict

from capstone import *  # noqa: F403
from capstone.arm64 import *  # noqa: F403
from typing_extensions import override

import pwndbg.color.memory as MemoryColor
import pwndbg.gdblib.arch
import pwndbg.gdblib.disasm.arch
import pwndbg.gdblib.memory
import pwndbg.gdblib.regs
from pwndbg.emu.emulator import Emulator
from pwndbg.gdblib.disasm.instruction import ALL_JUMP_GROUPS
from pwndbg.gdblib.disasm.instruction import InstructionCondition
from pwndbg.gdblib.disasm.instruction import PwndbgInstruction
from pwndbg.gdblib.disasm.instruction import boolean_to_instruction_condition
from pwndbg.gdblib.disasm.instruction import instruction_condition_choose

CONDITIONAL_SELECT_INSTRUCTIONS = {
    ARM64_INS_CSEL,
    ARM64_INS_CSINC,
    ARM64_INS_CSINV,
    ARM64_INS_CSNEG,
    ARM64_INS_CSET,
    ARM64_INS_CSETM,
    ARM64_INS_CINC,
    ARM64_INS_CINV,
    ARM64_INS_CNEG,
}


CONDITION_RESOLVERS: Dict[int, Callable[[int, int, int, int], bool]] = {
    ARM64_CC_INVALID: (
        lambda n, z, c, v: True
    ),  # Capstone uses this code for the 'B' instruction, the unconditional branch
    ARM64_CC_EQ: (lambda n, z, c, v: z == 1),
    ARM64_CC_NE: (lambda n, z, c, v: z == 1),
    ARM64_CC_HS: (lambda n, z, c, v: c == 1),
    ARM64_CC_LO: (lambda n, z, c, v: c == 0),
    ARM64_CC_MI: (lambda n, z, c, v: n == 1),
    ARM64_CC_PL: (lambda n, z, c, v: n == 0),
    ARM64_CC_VS: (lambda n, z, c, v: v == 1),
    ARM64_CC_VC: (lambda n, z, c, v: v == 0),
    ARM64_CC_HI: (lambda n, z, c, v: c == 1 and z == 0),
    ARM64_CC_LS: (lambda n, z, c, v: not (c == 1 and z == 0)),
    ARM64_CC_GE: (lambda n, z, c, v: n == v),
    ARM64_CC_LT: (lambda n, z, c, v: n != v),
    ARM64_CC_GT: (lambda n, z, c, v: z == 0 and n == v),
    ARM64_CC_LE: (lambda n, z, c, v: not (z == 0 and n == v)),
    ARM64_CC_AL: (lambda n, z, c, v: True),
    ARM64_CC_NV: (lambda n, z, c, v: True),
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

    condition = CONDITION_RESOLVERS.get(condition, lambda *a: False)(n, z, c, v)

    return InstructionCondition.TRUE if condition else InstructionCondition.FALSE


class DisassemblyAssistant(pwndbg.gdblib.disasm.arch.DisassemblyAssistant):
    def __init__(self, architecture: str) -> None:
        super().__init__(architecture)

        self.annotation_handlers: Dict[int, Callable[[PwndbgInstruction, Emulator], None]] = {
            # MOV
            ARM64_INS_MOV: self.generic_register_destination,
            # ADR
            ARM64_INS_ADR: self.generic_register_destination,
            # ADRP
            ARM64_INS_ADRP: self.generic_register_destination,
            # LDR
            ARM64_INS_LDR: self.generic_register_destination,
            # ADD
            ARM64_INS_ADD: self.generic_register_destination,
            # SUB
            ARM64_INS_SUB: self.generic_register_destination,
            # conditional select instructions
            ARM64_INS_CSEL: self.conditional_select_annotator(self.csel_manual_resolver),
            ARM64_INS_CSINC: self.conditional_select_annotator(self.csinc_manual_resolver),
            ARM64_INS_CSINV: self.conditional_select_annotator(self.csinv_manual_resolver),
            ARM64_INS_CSNEG: self.conditional_select_annotator(self.csneg_manual_resolver),
            ARM64_INS_CSET: self.conditional_select_annotator(self.cset_manual_resolver),
            ARM64_INS_CSETM: self.conditional_select_annotator(self.csetm_manual_resolver),
            ARM64_INS_CINC: self.conditional_select_annotator(self.cinc_manual_resolver),
            ARM64_INS_CINV: self.conditional_select_annotator(self.cinv_manual_resolver),
            ARM64_INS_CNEG: self.conditional_select_annotator(self.cneg_manual_resolver),
        }

    def conditional_select_annotator(
        self, manual_resolver: Callable[[PwndbgInstruction, Emulator], int | None]
    ) -> Callable[[PwndbgInstruction, Emulator], None]:
        """
        This method returns a function that will handle annotations for a given conditional select type instruction.

        These instructions mutate the destination register based on the flags register.

        The general logic is the same between all of them, and using the callback function we can manually resolve the result of the instruction,
        allowing for these annotations even without emulation
        """

        def handler(instruction: PwndbgInstruction, emu: Emulator):
            # The destination register is always the first one
            op = instruction.operands[0]

            # If emulating, then op.after_value is not None.
            resolved_value = op.after_value

            # If not emulating (or emulation failed), see if we can resolve it manually
            if resolved_value is None:
                resolved_value = manual_resolver(instruction, emu)

            if resolved_value is not None:
                instruction.annotation = (
                    f"{op.str} => {MemoryColor.get_address_or_symbol(resolved_value)}"
                )

        return handler

    def csel_manual_resolver(self, instruction: PwndbgInstruction, emu: Emulator) -> int | None:
        _, middle, right = instruction.operands

        result_op = instruction_condition_choose(instruction.condition, middle, right, None)

        if result_op is not None:
            return result_op.before_value

        return None

    def csinc_manual_resolver(self, instruction: PwndbgInstruction, emu: Emulator) -> int | None:
        _, middle, right = instruction.operands

        return instruction_condition_choose(
            instruction.condition,
            middle.before_value,
            right.before_value + 1 if right.before_value is not None else None,
            None,
        )

    def csinv_manual_resolver(self, instruction: PwndbgInstruction, emu: Emulator) -> int | None:
        _, middle, right = instruction.operands

        # Capstone doesn't provide an API on AArch64 to determine if a register operand is 32-bit or 64-bit.
        # That information is hidden. We can, however, just read the resolved register name to see if it starts with a `w` or not
        mask = (1 << 32) - 1 if middle.str.startswith("w") else (1 << 64) - 1

        return instruction_condition_choose(
            instruction.condition,
            middle.before_value,
            (~right.before_value & mask) if right.before_value is not None else None,
            None,
        )

    def csneg_manual_resolver(self, instruction: PwndbgInstruction, emu: Emulator) -> int | None:
        _, middle, right = instruction.operands

        mask = (1 << 32) - 1 if middle.str.startswith("w") else (1 << 64) - 1

        return instruction_condition_choose(
            instruction.condition,
            middle.before_value,
            (-right.before_value & mask) if right.before_value is not None else None,
            None,
        )

    def cset_manual_resolver(self, instruction: PwndbgInstruction, emu: Emulator) -> int | None:
        return instruction_condition_choose(instruction.condition, 1, 0, None)

    def csetm_manual_resolver(self, instruction: PwndbgInstruction, emu: Emulator) -> int | None:
        op = instruction.operands[0]

        mask = (1 << 32) - 1 if op.str.startswith("w") else (1 << 64) - 1

        return instruction_condition_choose(instruction.condition, mask, 0, None)

    def cinc_manual_resolver(self, instruction: PwndbgInstruction, emu: Emulator) -> int | None:
        _, right = instruction.operands
        return instruction_condition_choose(
            instruction.condition,
            right.before_value + 1 if right.before_value is not None else None,
            right.before_value,
            None,
        )

    def cinv_manual_resolver(self, instruction: PwndbgInstruction, emu: Emulator) -> int | None:
        _, right = instruction.operands

        mask = (1 << 32) - 1 if left.str.startswith("w") else (1 << 64) - 1

        return instruction_condition_choose(
            instruction.condition,
            (~right.before_value & mask) if right.before_value is not None else None,
            right.before_value,
            None,
        )

    def cneg_manual_resolver(self, instruction: PwndbgInstruction, emu: Emulator) -> int | None:
        _, right = instruction.operands

        mask = (1 << 32) - 1 if right.str.startswith("w") else (1 << 64) - 1

        return instruction_condition_choose(
            instruction.condition,
            (-right.before_value & mask) if right.before_value is not None else None,
            right.before_value,
            None,
        )

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
            flags = self._read_register_name(instruction, "cpsr", emu)
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

        elif instruction.id in CONDITIONAL_SELECT_INSTRUCTIONS:
            # Capstone places the condition to be satisfied in the `cc` field of the instruction
            # for all conditional select instructions
            flags = self._read_register_name(instruction, "cpsr", emu)

            print(repr(instruction))
            if flags is not None:
                return resolve_condition(instruction.cs_insn.cc, flags)

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
            return self._read_register_name(instruction, "lr", emu)

        return super()._resolve_target(instruction, emu, call)

    @override
    def _set_annotation_string(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        # Dispatch to the correct handler
        self.annotation_handlers.get(instruction.id, lambda *a: None)(instruction, emu)


assistant = DisassemblyAssistant("aarch64")
