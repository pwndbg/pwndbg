from __future__ import annotations

from typing import TYPE_CHECKING
from typing import Callable
from typing import Dict
from typing import List

from capstone import *  # noqa: F403
from capstone.mips import *  # noqa: F403
from typing_extensions import override

import pwndbg.aglib.disasm.arch
import pwndbg.color.memory as MemoryColor
import pwndbg.lib.disasm.helpers as bit_math
from pwndbg.aglib.disasm.arch import register_assign
from pwndbg.aglib.disasm.instruction import FORWARD_JUMP_GROUP
from pwndbg.aglib.disasm.instruction import InstructionCondition
from pwndbg.aglib.disasm.instruction import PwndbgInstruction

# Emulator currently requires GDB, and we only use it here for type checking.
if TYPE_CHECKING:
    from pwndbg.emu.emulator import Emulator

# These branch instructions do not have a branch delay
BRANCH_WITHOUT_DELAY_SLOT_INSTRUCTIONS = {
    MIPS_INS_BC,
    MIPS_INS_BALC,
    MIPS_INS_JIALC,
    MIPS_INS_JIC,
    MIPS_INS_BLEZALC,
    MIPS_INS_BGEZALC,
    MIPS_INS_BGTZALC,
    MIPS_INS_BLTZALC,
    MIPS_INS_BEQZALC,
    MIPS_INS_BNEZALC,
    MIPS_INS_BLEZC,
    MIPS_INS_BGEZC,
    MIPS_INS_BGEUC,
    MIPS_INS_BGEIC,
    MIPS_INS_BGEUC,
    MIPS_INS_BGEIUC,
    MIPS_INS_BGTZC,
    MIPS_INS_BLTZC,
    MIPS_INS_BEQZC,
    MIPS_INS_ALIAS_BEQZC,
    MIPS_INS_BNEZC,
    MIPS_INS_ALIAS_BNEZC,
    MIPS_INS_BEQC,
    MIPS_INS_ALIAS_BEQC,
    MIPS_INS_BEQIC,
    MIPS_INS_BNEC,
    MIPS_INS_ALIAS_BNEC,
    MIPS_INS_BNEIC,
    MIPS_INS_BLTC,
    MIPS_INS_BLTIC,
    MIPS_INS_BLTUC,
    MIPS_INS_BLTIUC,
    MIPS_INS_BGEC,
    MIPS_INS_BLTUC,
    MIPS_INS_BNVC,
    MIPS_INS_BOVC,
    MIPS_INS_BRSC,
    MIPS_INS_BALRSC,
    MIPS_INS_BBEQZC,
    MIPS_INS_BBNEZC,
}

# Instruction in branch delay slot is ignored if the branch it NOT taken
# Currently unused
BRANCH_LIKELY_INSTRUCTIONS = {
    MIPS_INS_BC1FL,
    MIPS_INS_ALIAS_BC1FL,
    MIPS_INS_BC1TL,
    MIPS_INS_ALIAS_BC1TL,
    MIPS_INS_BEQL,
    MIPS_INS_BGEZALL,
    MIPS_INS_BGEZL,
    MIPS_INS_BGTZL,
    MIPS_INS_BLEZL,
    MIPS_INS_BLTZALL,
    MIPS_INS_BLTZL,
    MIPS_INS_BNEL,
    MIPS_INS_ALIAS_BNEZL,
    MIPS_INS_ALIAS_BEQZL,
}

CONDITION_RESOLVERS: Dict[int, Callable[[List[int]], bool]] = {
    MIPS_INS_BEQZ: lambda ops: ops[0] == 0,
    MIPS_INS_BNEZ: lambda ops: ops[0] != 0,
    MIPS_INS_BEQ: lambda ops: ops[0] == ops[1],
    MIPS_INS_BNE: lambda ops: ops[0] != ops[1],
    MIPS_INS_BGEZ: lambda ops: bit_math.to_signed(ops[0], pwndbg.aglib.arch.ptrsize * 8) >= 0,
    MIPS_INS_BGEZAL: lambda ops: bit_math.to_signed(ops[0], pwndbg.aglib.arch.ptrsize * 8) >= 0,
    MIPS_INS_BGTZ: lambda ops: bit_math.to_signed(ops[0], pwndbg.aglib.arch.ptrsize * 8) > 0,
    MIPS_INS_BLEZ: lambda ops: bit_math.to_signed(ops[0], pwndbg.aglib.arch.ptrsize * 8) <= 0,
    MIPS_INS_BLTZAL: lambda ops: bit_math.to_signed(ops[0], pwndbg.aglib.arch.ptrsize * 8) < 0,
    MIPS_INS_BLTZ: lambda ops: bit_math.to_signed(ops[0], pwndbg.aglib.arch.ptrsize * 8) < 0,
}

CONDITION_RESOLVERS[MIPS_INS_ALIAS_BEQZ] = CONDITION_RESOLVERS[MIPS_INS_BEQZ]
CONDITION_RESOLVERS[MIPS_INS_ALIAS_BNEZ] = CONDITION_RESOLVERS[MIPS_INS_BNEZ]

# These are instructions that have the first operand as the destination register.
# They all do some computation and set the register to the result.
# These were derived from "MIPS Architecture for Programmers Volume II: The MIPS64 Instruction Set Reference Manual"
MIPS_SIMPLE_DESTINATION_INSTRUCTIONS = {
    MIPS_INS_CLO,
    MIPS_INS_CLZ,
    MIPS_INS_DCLO,
    MIPS_INS_DCLZ,
    MIPS_INS_LSA,
    MIPS_INS_DLSA,
    MIPS_INS_MFHI,
    MIPS_INS_MFLO,
    MIPS_INS_SEB,
    MIPS_INS_SEH,
    MIPS_INS_WSBH,
    MIPS_INS_SLT,
    MIPS_INS_SLTI,
    MIPS_INS_SLTIU,
    MIPS_INS_SLTU,
    MIPS_INS_MOVN,
    # Rare - unaligned read - have complex loading logic
    MIPS_INS_LDL,
    MIPS_INS_LDR,
    # Rare - partial load on portions of address
    MIPS_INS_LWL,
    MIPS_INS_LWR,
}

# All MIPS load instructions
MIPS_LOAD_INSTRUCTIONS = {
    MIPS_INS_LB: -1,
    MIPS_INS_LBU: 1,
    MIPS_INS_LH: -2,
    MIPS_INS_LHU: 2,
    MIPS_INS_LW: -4,
    MIPS_INS_LWU: 4,
    MIPS_INS_LWPC: -4,
    MIPS_INS_LWUPC: 4,
    MIPS_INS_LD: -8,
    MIPS_INS_LDPC: 8,
}

MIPS_STORE_INSTRUCTIONS = {
    MIPS_INS_SB: 1,
    MIPS_INS_SH: 2,
    MIPS_INS_SW: 4,
    MIPS_INS_SD: 8,
}

MIPS_BINARY_OPERATIONS = {
    MIPS_INS_ADD: "+",
    MIPS_INS_ADDI: "+",
    MIPS_INS_ADDIU: "+",
    MIPS_INS_ADDU: "+",
    MIPS_INS_DADD: "+",
    MIPS_INS_DADDI: "+",
    MIPS_INS_DADDIU: "+",
    MIPS_INS_DADDU: "+",
    MIPS_INS_SUB: "-",
    MIPS_INS_SUBU: "-",
    MIPS_INS_DSUB: "-",
    MIPS_INS_DSUBU: "-",
    MIPS_INS_ANDI: "&",
    MIPS_INS_AND: "&",
    MIPS_INS_ORI: "|",
    MIPS_INS_OR: "|",
    MIPS_INS_XOR: "^",
    MIPS_INS_XORI: "^",
    MIPS_INS_SLL: "<<",
    MIPS_INS_SLLV: "<<",
    MIPS_INS_DSLL: "<<",
    MIPS_INS_DSLLV: "<<",
    MIPS_INS_SRL: ">>",
    MIPS_INS_SRLV: ">>",
    MIPS_INS_DSRL: ">>",
    MIPS_INS_DSRLV: ">>",
}


# This class enhances 32-bit, 64-bit, and micro MIPS
class MipsDisassemblyAssistant(pwndbg.aglib.disasm.arch.DisassemblyAssistant):
    def __init__(self, architecture) -> None:
        super().__init__(architecture)

        self.annotation_handlers: Dict[int, Callable[[PwndbgInstruction, Emulator], None]] = {
            # MOVE
            MIPS_INS_MOVE: self._common_move_annotator,
            MIPS_INS_ALIAS_MOVE: self._common_move_annotator,
            # LI
            MIPS_INS_LI: self._common_move_annotator,
            # LUI
            MIPS_INS_LUI: self._lui_annotator,
        }

    @override
    def _set_annotation_string(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        if instruction.id in MIPS_LOAD_INSTRUCTIONS:
            read_size = MIPS_LOAD_INSTRUCTIONS[instruction.id]

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
        elif instruction.id in MIPS_STORE_INSTRUCTIONS:
            self._common_store_annotator(
                instruction,
                emu,
                instruction.operands[1].before_value,
                instruction.operands[0].before_value,
                MIPS_STORE_INSTRUCTIONS[instruction.id],
                instruction.operands[1].str,
            )
        elif instruction.id in MIPS_BINARY_OPERATIONS:
            self._common_binary_op_annotator(
                instruction,
                emu,
                instruction.operands[0],
                instruction.operands[1].before_value,
                instruction.operands[2].before_value,
                MIPS_BINARY_OPERATIONS[instruction.id],
            )
        elif instruction.id in MIPS_SIMPLE_DESTINATION_INSTRUCTIONS:
            self._common_generic_register_destination(instruction, emu)
        else:
            self.annotation_handlers.get(instruction.id, lambda *a: None)(instruction, emu)

    def _lui_annotator(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        result_operand, right = instruction.operands
        if result_operand.str and right.before_value is not None:
            if (address := result_operand.after_value) is None:
                # Resolve it manually without emulation
                address = right.before_value << 16

            instruction.annotation = register_assign(
                result_operand.str, MemoryColor.get_address_and_symbol(address)
            )

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
    def _resolve_target(self, instruction: PwndbgInstruction, emu: Emulator | None):
        if bool(instruction.groups & FORWARD_JUMP_GROUP) and not bool(
            instruction.groups & BRANCH_WITHOUT_DELAY_SLOT_INSTRUCTIONS
        ):
            instruction.causes_branch_delay = True

        return super()._resolve_target(instruction, emu)

    @override
    def _parse_memory(
        self,
        instruction: PwndbgInstruction,
        op: pwndbg.aglib.disasm.arch.EnhancedOperand,
        emu: Emulator,
    ) -> int | None:
        """
        Parse the `MipsOpMem` Capstone object to determine the concrete memory address used.
        """
        base = self._read_register(instruction, op.mem.base, emu)
        if base is None:
            return None
        return base + op.mem.disp
