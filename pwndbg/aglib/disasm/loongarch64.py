from __future__ import annotations

from typing import TYPE_CHECKING
from typing import Callable
from typing import Dict
from typing import List

from capstone import *  # noqa: F403
from capstone.loongarch import *  # noqa: F403
from typing_extensions import override

import pwndbg.aglib.disasm.arch
import pwndbg.lib.disasm.helpers as bit_math
from pwndbg.aglib.disasm.instruction import InstructionCondition
from pwndbg.aglib.disasm.instruction import PwndbgInstruction

# Emulator currently requires GDB, and we only use it here for type checking.
if TYPE_CHECKING:
    from pwndbg.emu.emulator import Emulator

CONDITION_RESOLVERS: Dict[int, Callable[[List[int]], bool]] = {
    LOONGARCH_INS_BEQZ: lambda ops: ops[0] == 0,
    LOONGARCH_INS_BNEZ: lambda ops: ops[0] != 0,
    LOONGARCH_INS_BEQ: lambda ops: ops[0] == ops[1],
    LOONGARCH_INS_BNE: lambda ops: ops[0] != ops[1],
    LOONGARCH_INS_BGE: lambda ops: bit_math.to_signed(ops[0], pwndbg.aglib.arch.ptrsize * 8)
    >= bit_math.to_signed(ops[1], pwndbg.aglib.arch.ptrsize * 8),
    LOONGARCH_INS_BLT: lambda ops: bit_math.to_signed(ops[0], pwndbg.aglib.arch.ptrsize * 8)
    < bit_math.to_signed(ops[1], pwndbg.aglib.arch.ptrsize * 8),
    LOONGARCH_INS_BLTU: lambda ops: ops[0] < ops[1],
    LOONGARCH_INS_BGEU: lambda ops: ops[0] >= ops[1],
}


LOONGARCH_LOAD_INSTRUCTIONS: Dict[int, int] = {}

LOONGARCH_STORE_INSTRUCTIONS: Dict[int, int] = {}

LOONGARCH_BINARY_OPERATIONS: Dict[int, str] = {}


# This class enhances 64-bit Loongarch
class Loong64DisassemblyAssistant(pwndbg.aglib.disasm.arch.DisassemblyAssistant):
    def __init__(self, architecture) -> None:
        super().__init__(architecture)

        self.annotation_handlers: Dict[int, Callable[[PwndbgInstruction, Emulator], None]] = {}

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
            # Note the [:-1]. Loongarch jump instructions have the target as the last operand
            # https://loongson.github.io/LoongArch-Documentation/LoongArch-Vol1-EN.html#_beqz_bnez
            return InstructionCondition.UNDETERMINED

        conditional = CONDITION_RESOLVERS.get(instruction.id, lambda *a: None)(resolved_operands)

        if conditional is None:
            return InstructionCondition.UNDETERMINED

        return InstructionCondition.TRUE if conditional else InstructionCondition.FALSE

    @override
    def _resolve_target(self, instruction: PwndbgInstruction, emu: Emulator | None):
        if instruction.id == LOONGARCH_INS_ALIAS_RET:
            return self._read_register_name(instruction, "ra", emu)

        # Manually compute target addresses for relative branches
        if instruction.id in (
            LOONGARCH_INS_B,
            LOONGARCH_INS_BL,
            LOONGARCH_INS_BEQ,
            LOONGARCH_INS_BNE,
            LOONGARCH_INS_BLT,
            LOONGARCH_INS_BGE,
            LOONGARCH_INS_BGEU,
            LOONGARCH_INS_BLTU,
            LOONGARCH_INS_BEQZ,
            LOONGARCH_INS_BNEZ,
        ):
            # The relative offset is always the last operand
            return instruction.address + instruction.operands[-1].before_value

        if instruction.id == LOONGARCH_INS_JIRL:
            if (offset_reg := instruction.operands[1].before_value) is not None:
                return offset_reg + (instruction.operands[2].before_value << 2)

        return super()._resolve_target(instruction, emu)
