# When single stepping in Unicorn with MIPS, the address it arrives at in Unicorn
# is often incorrect with branches.
# This is due to "Delay slots" - the instruction AFTER a branch is always executed
# before the jump, and the Unicorn emulator respects this behavior.
# This causes single stepping branches to not arrive at the correct instruction -
# it will simply go to the next location in memory, not respecting the branch. It doesn't appear to be extremely consistent.
# Unicorn doesn't have a workaround for this single stepping issue:
# https://github.com/unicorn-engine/unicorn/issues/332
#
# The way to fix the issue this causes (incorrect instruction.next) is by implementing the
# condition function to manually specify when a jump is taken. Our manual decision will override the emulator.

from __future__ import annotations

from typing import Callable
from typing import Dict
from typing import List

from capstone import *  # noqa: F403
from capstone.mips import *  # noqa: F403
from typing_extensions import override

import pwndbg.gdblib.disasm.arch
import pwndbg.gdblib.regs
from pwndbg.emu.emulator import Emulator
from pwndbg.gdblib.disasm.instruction import FORWARD_JUMP_GROUP
from pwndbg.gdblib.disasm.instruction import InstructionCondition
from pwndbg.gdblib.disasm.instruction import PwndbgInstruction

BRANCH_LIKELY_INSTRUCTIONS = {
    MIPS_INS_BC0TL,
    MIPS_INS_BC1TL,
    MIPS_INS_BC0FL,
    MIPS_INS_BC1FL,
    MIPS_INS_BEQL,
    MIPS_INS_BGEZALL,
    MIPS_INS_BGEZL,
    MIPS_INS_BGTZL,
    MIPS_INS_BLEZL,
    MIPS_INS_BLTZALL,
    MIPS_INS_BLTZL,
    MIPS_INS_BNEL,
}


def to_signed(unsigned: int):
    if pwndbg.gdblib.arch.ptrsize == 8:
        return unsigned - ((unsigned & 0x80000000_00000000) << 1)
    else:
        return unsigned - ((unsigned & 0x80000000) << 1)


CONDITION_RESOLVERS: Dict[int, Callable[[List[int]], bool]] = {
    MIPS_INS_BEQZ: lambda ops: ops[0] == 0,
    MIPS_INS_BNEZ: lambda ops: ops[0] != 0,
    MIPS_INS_BEQ: lambda ops: ops[0] == ops[1],
    MIPS_INS_BNE: lambda ops: ops[0] != ops[1],
    MIPS_INS_BGEZ: lambda ops: to_signed(ops[0]) >= 0,
    MIPS_INS_BGEZAL: lambda ops: to_signed(ops[0]) >= 0,
    MIPS_INS_BGTZ: lambda ops: to_signed(ops[0]) > 0,
    MIPS_INS_BLEZ: lambda ops: to_signed(ops[0]) <= 0,
    MIPS_INS_BLTZAL: lambda ops: to_signed(ops[0]) < 0,
    MIPS_INS_BLTZ: lambda ops: to_signed(ops[0]) < 0,
}

# These are instructions that have the first operand as the destination register.
# They all do some computation and set the register to the result.
# These were derived from "MIPS Architecture for Programmers Volume II: The MIPS64 Instruction Set Reference Manual"
MIPS_SIMPLE_DESTINATION_INSTRUCTIONS = {
    MIPS_INS_ADD,
    MIPS_INS_ADDI,
    MIPS_INS_ADDIU,
    MIPS_INS_ADDU,
    MIPS_INS_CLO,
    MIPS_INS_CLZ,
    MIPS_INS_DADD,
    MIPS_INS_DADDI,
    MIPS_INS_DADDIU,
    MIPS_INS_DADDU,
    MIPS_INS_DCLO,
    MIPS_INS_DCLZ,
    MIPS_INS_DSUB,
    MIPS_INS_DSUBU,
    MIPS_INS_LB,
    MIPS_INS_LBU,
    MIPS_INS_LD,
    MIPS_INS_LDL,
    MIPS_INS_LDPC,
    MIPS_INS_LDR,
    MIPS_INS_LH,
    MIPS_INS_LHU,
    MIPS_INS_LSA,
    MIPS_INS_DLSA,
    MIPS_INS_LUI,
    MIPS_INS_LW,
    MIPS_INS_LWL,
    MIPS_INS_LWPC,
    MIPS_INS_LWR,
    MIPS_INS_LWU,
    MIPS_INS_LWUPC,
    MIPS_INS_MFHI,
    MIPS_INS_MFLO,
    MIPS_INS_SEB,
    MIPS_INS_SEH,
    MIPS_INS_SUB,
    MIPS_INS_SUBU,
    MIPS_INS_WSBH,
    MIPS_INS_MOVE,
    MIPS_INS_LI,
    MIPS_INS_SLT,
    MIPS_INS_SLTI,
    MIPS_INS_SLTIU,
    MIPS_INS_SLTU,
}


# This class enhances 32-bit, 64-bit, and micro MIPS
class DisassemblyAssistant(pwndbg.gdblib.disasm.arch.DisassemblyAssistant):
    def __init__(self, architecture: str) -> None:
        super().__init__(architecture)

    @override
    def _set_annotation_string(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        if instruction.id in MIPS_SIMPLE_DESTINATION_INSTRUCTIONS:
            self._common_generic_register_destination(instruction, emu)

    @override
    def _condition(self, instruction: PwndbgInstruction, emu: Emulator) -> InstructionCondition:
        if len(instruction.operands) == 0:
            return InstructionCondition.UNDETERMINED

        # Not using list comprehension because they run in a separate scope in which super() does not exist
        resolved_operands: List[int] = []
        for op in instruction.operands:
            resolved_operands.append(
                super()._resolve_used_value(op.before_value, instruction, op, emu)
            )

        # If any of the relevent operands are None (we can't reason about them), quit.
        if any(value is None for value in resolved_operands[:-1]):
            # Note the [:-1]. MIPS jump instructions have the target as the last operand
            # https://www.doc.ic.ac.uk/lab/secondyear/spim/node16.html
            return InstructionCondition.UNDETERMINED

        conditional = CONDITION_RESOLVERS.get(instruction.id, lambda *a: None)(resolved_operands)

        if conditional is None:
            return InstructionCondition.UNDETERMINED

        return InstructionCondition.TRUE if conditional else InstructionCondition.FALSE

    @override
    def _resolve_target(self, instruction: PwndbgInstruction, emu: Emulator | None, call=False):
        if bool(instruction.groups_set & FORWARD_JUMP_GROUP) and not bool(
            instruction.groups_set & BRANCH_LIKELY_INSTRUCTIONS
        ):
            instruction.causes_branch_delay = True

        return super()._resolve_target(instruction, emu, call)


assistant = DisassemblyAssistant("mips")
