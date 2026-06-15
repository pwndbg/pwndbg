from __future__ import annotations

from collections.abc import Callable

from capstone6pwndbg import *  # noqa: F403
from capstone6pwndbg.ppc_const import *  # noqa: F403
from typing_extensions import override

import pwndbg.aglib.disasm.assistant
from pwndbg.aglib.disasm.instruction import InstructionCondition
from pwndbg.aglib.disasm.instruction import PwndbgInstruction
from pwndbg.emu.emulator import Emulator

POWERPC_CONDITIONAL_BRANCHES = {
    PPC_INS_BC,
    PPC_INS_ALIAS_BT,
    PPC_INS_ALIAS_BF,
    PPC_INS_ALIAS_BTLR,
    PPC_INS_ALIAS_BFLR,
}

POWERPC_RETURN_INSTRUCTION = {PPC_INS_ALIAS_BLR, PPC_INS_ALIAS_BTLR, PPC_INS_ALIAS_BFLR}


# PowerPC branch instructions are pretty complex and whether or not the branch is taken depends on 3 factors:
# 1. bi - index into cr register, a flags register with conditions (less than, greater than, equal, overflow)
# 2. bo - a bitfield that modifies the evaluation of the condition
# 3. CTR register - a register that, depending on bo, can be read and modified and effects the result of the branch
def is_branch_taken(cr: int, ctr: int, bi: int, bo: int) -> bool | None:
    # Valid values for bo (5 bit value): https://www.ibm.com/docs/en/aix/7.2.0?topic=set-bc-branch-conditional-instruction
    # The `x` mean it can be either 0 or 1, it is irrelevant to the branch condition (used to hint that the branch is or isn't taken)
    # 0000x - Decrement CTR. Branch if CTR is not 0 and condition is false
    # 0001x - Decrement CTR. Branch if CTR is 0 and condition is false
    # 001xx - Branch if condition is false
    # 0100x - Decrement CTR. Branch if CTR is not 0 and condition is true
    # 0101x - Decrement CTR. Branch if CTR is 0 and condition is true
    # 011xx - Branch if the condition is true.
    # 1x00x - Decrement CTR. Branch if CTR is not 0.
    # 1x01x - Decrement CTR. Branch if CTR is 0
    # 1x1xx - Always branch

    # GDB `cr` register consists of cr0 .... cr7, where cr0 composes the most-significant bit positions.
    # This is why we flip the offset that we access.
    check_cr_offset = 31 - bi
    condition = (cr >> check_cr_offset) & 1 == 1

    if (bo & 0b11110) == 0b00000:  # 0000x
        ctr -= 1
        return ctr != 0 and not condition
    if (bo & 0b11110) == 0b00010:  # 0001x
        ctr -= 1
        return ctr == 0 and not condition
    if (bo & 0b11100) == 0b00100:  # 001xx
        return not condition
    if (bo & 0b11110) == 0b01000:  # 0100x
        ctr -= 1
        return ctr != 0 and condition
    if (bo & 0b11110) == 0b01010:  # 0101x
        ctr -= 1
        return ctr == 0 and condition
    if (bo & 0b11100) == 0b01100:  # 011xx
        return condition
    if (bo & 0b10110) == 0b10000:  # 1x00x
        ctr -= 1
        return ctr != 0
    if (bo & 0b10110) == 0b10010:  # 1x01x
        ctr -= 1
        return ctr == 0
    if (bo & 0b10100) == 0b10100:  # 1x1xx
        return True

    # This case should never be reached
    return None


class PowerPCDisassemblyAssistant(pwndbg.aglib.disasm.assistant.DisassemblyAssistant):
    saved_ctr: int | None = None

    def __init__(self, architecture) -> None:
        super().__init__(architecture)

        self.annotation_handlers: dict[int, Callable[[PwndbgInstruction, Emulator], None]] = {}

    @override
    def _prepare(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        # Prepare is called before emulation.
        # At this point, we want to read the value of the ctr register.
        # This is because branch instructions might mutate ctr within the emulator, which the read_register_name may fetch from
        # The _conditional() function is called after emulation is stepped, so to read the original
        # value of CTR, we have to read it beforehand.

        if instruction.id in POWERPC_CONDITIONAL_BRANCHES:
            self.saved_ctr = self._read_register_name(instruction, "ctr", emu)

    @override
    def _condition(self, instruction: PwndbgInstruction, emu: Emulator) -> InstructionCondition:
        if instruction.id in POWERPC_CONDITIONAL_BRANCHES:
            cr = self._read_register_name(instruction, "cr", emu)

            if cr is None or self.saved_ctr is None:
                # We can't reason about the value of cr register
                return InstructionCondition.UNDETERMINED_CONDITIONAL

            is_taken = is_branch_taken(
                cr, self.saved_ctr, instruction.cs_insn.bc.bi, instruction.cs_insn.bc.bo
            )

            if is_taken is None:
                return InstructionCondition.UNDETERMINED_CONDITIONAL

            return InstructionCondition.TRUE if is_taken else InstructionCondition.FALSE

        return InstructionCondition.UNCONDITIONAL

    @override
    def _resolve_target(self, instruction: PwndbgInstruction, emu: Emulator | None):
        if instruction.id in POWERPC_RETURN_INSTRUCTION:
            return self._read_register_name(instruction, "lr", emu)

        return super()._resolve_target(instruction, emu)
