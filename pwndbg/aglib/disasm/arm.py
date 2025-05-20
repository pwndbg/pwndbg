from __future__ import annotations

# Emulator currently requires GDB, and we only use it here for type checking.
from typing import TYPE_CHECKING
from typing import Callable
from typing import Dict
from typing import Literal

from capstone import *  # noqa: F403
from capstone.arm import *  # noqa: F403
from pwnlib.util.misc import align_down
from typing_extensions import override

import pwndbg.aglib.arch
import pwndbg.aglib.disasm.arch
import pwndbg.aglib.memory
import pwndbg.aglib.regs
import pwndbg.aglib.saved_register_frames
import pwndbg.lib.disasm.helpers as bit_math
from pwndbg.aglib.disasm.instruction import EnhancedOperand
from pwndbg.aglib.disasm.instruction import InstructionCondition
from pwndbg.aglib.disasm.instruction import PwndbgInstruction

if TYPE_CHECKING:
    from pwndbg.emu.emulator import Emulator

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
}

ARM_EXCLUSIVE_STORE_INSTRUCTIONS = {
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
    ARM_INS_UDIV: "/",
    ARM_INS_SDIV: "/",
    ARM_INS_MUL: "*",
    ARM_INS_UMULL: "*",
    ARM_INS_SMULL: "*",
}

ARM_SHIFT_INSTRUCTIONS = {
    ARM_INS_ASR: ">>s",
    ARM_INS_ALIAS_ASR: ">>s",
    ARM_INS_LSR: ">>",
    ARM_INS_ALIAS_LSR: ">>",
    ARM_INS_LSL: "<<",
    ARM_INS_ALIAS_LSL: "<<",
    ARM_INS_ROR: ">>r",
    ARM_INS_ALIAS_ROR: ">>r",
}

# All of these instructions can write to the PC
# https://developer.arm.com/documentation/ddi0406/cb/Application-Level-Architecture/Application-Level-Programmers--Model/ARM-core-registers/Writing-to-the-PC?lang=en
# If they do write to PC, Capstone gives the instructions the `ARM_GRP_JUMP` group
# Note that we don't have the flag-setting variants - "ands", "subs" - because these generate an illegal instruction interrupt at runtime
ARM_CAN_WRITE_TO_PC_INSTRUCTIONS = {
    ARM_INS_LDM,
    ARM_INS_ALIAS_LDM,
    ARM_INS_POP,
    ARM_INS_ALIAS_POP,
    ARM_INS_LDR,
    ARM_INS_ADC,
    ARM_INS_ADD,
    ARM_INS_ADR,
    ARM_INS_AND,
    ARM_INS_ASR,
    ARM_INS_ALIAS_ASR,
    ARM_INS_BIC,
    ARM_INS_EOR,
    ARM_INS_LSL,
    ARM_INS_ALIAS_LSL,
    ARM_INS_LSR,
    ARM_INS_ALIAS_LSR,
    ARM_INS_MOV,
    ARM_INS_MVN,
    ARM_INS_ORR,
    ARM_INS_ROR,
    ARM_INS_ALIAS_ROR,
    ARM_INS_RRX,
    ARM_INS_ALIAS_RRX,
    ARM_INS_RSB,
    ARM_INS_RSC,
    ARM_INS_SBC,
    ARM_INS_SUB,
}


def itstate_from_cpsr(cpsr_value: int) -> int:
    """
    ITSTATE == If-Then execution state bits for the Thumb IT instruction
    The ITSTATE bits are spread across 3 sections of Arm flags register to a total of 8 bits.
    This function extracts them and reorders the bits into their logical order
    - https://developer.arm.com/documentation/ddi0403/d/System-Level-Architecture/System-Level-Programmers--Model/Registers/The-special-purpose-program-status-registers--xPSR#:~:text=shows%20the%20assignment%20of%20the%20ICI/IT%20bits.

    Bits of the flags register: EPSR[26:25]    EPSR[15:12]    EPSR[11:10]
    Bits of ITSTATE:            IT[1:0]        IT[7:4]        IT[3:2]

    The lower 5 bits has information that indicates the number of instructions in the IT Block.
    The top 3 bits indicate the base condition of the block.
    - https://developer.arm.com/documentation/ddi0406/cb/Application-Level-Architecture/Application-Level-Programmers--Model/Execution-state-registers/IT-block-state-register--ITSTATE?lang=en

    If the value is zero, it means we are not in an IT block.
    """

    return (
        ((cpsr_value >> 25) & 0b11)
        | ((cpsr_value >> 10) & 0b11) << 2
        | ((cpsr_value >> 12) & 0b1111) << 4
    )


# This class enhances both ARM A-profile and ARM M-profile (Cortex-M)
class ArmDisassemblyAssistant(pwndbg.aglib.disasm.arch.DisassemblyAssistant):
    def __init__(self, architecture, flags_reg: Literal["cpsr", "xpsr"]) -> None:
        super().__init__(architecture)

        self.flags_reg = flags_reg

        self.annotation_handlers: Dict[int, Callable[[PwndbgInstruction, Emulator], None]] = {
            # MOV
            ARM_INS_MOV: self._common_move_annotator,
            ARM_INS_MOVW: self._common_move_annotator,
            # MOVT
            ARM_INS_MOVT: self._common_generic_register_destination,
            # MOVN
            ARM_INS_MVN: self._common_generic_register_destination,
            # CMP
            ARM_INS_CMP: self._common_cmp_annotator_builder(flags_reg, "-"),
            # CMN
            ARM_INS_CMN: self._common_cmp_annotator_builder(flags_reg, "+"),
            # TST (bitwise "and")
            ARM_INS_TST: self._common_cmp_annotator_builder(flags_reg, "&"),
            # TEQ (bitwise exclusive "or")
            ARM_INS_TEQ: self._common_cmp_annotator_builder(flags_reg, "^"),
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
        elif instruction.id in ARM_EXCLUSIVE_STORE_INSTRUCTIONS:
            # These store instructions include the "Store Register Exclusive", which
            # have an additional register at the front which pushes the source and destination one to the right.
            self._common_store_annotator(
                instruction,
                emu,
                instruction.operands[-1].before_value,
                instruction.operands[-2].before_value,
                ARM_EXCLUSIVE_STORE_INSTRUCTIONS[instruction.id],
                instruction.operands[-1].str,
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
        elif instruction.id in ARM_SHIFT_INSTRUCTIONS:
            # The encoding of shifts has changed between past Capstone versions: https://github.com/capstone-engine/capstone/pull/2638
            # This check avoids a crash
            if len(instruction.operands) == 3:
                self._common_binary_op_annotator(
                    instruction,
                    emu,
                    instruction.operands[0],
                    instruction.operands[1].before_value_no_modifiers,
                    instruction.operands[2].before_value,
                    ARM_SHIFT_INSTRUCTIONS[instruction.id],
                )
        else:
            self.annotation_handlers.get(instruction.id, lambda *a: None)(instruction, emu)

    @override
    def _prepare(
        self, instruction: PwndbgInstruction, emu: pwndbg.aglib.disasm.arch.Emulator
    ) -> None:
        if CS_GRP_INT in instruction.groups:
            # https://github.com/capstone-engine/capstone/issues/2630
            instruction.groups.remove(CS_GRP_CALL)

        # Disable Unicorn while in IT instruction blocks since Unicorn cannot be paused in it.
        flags_value = pwndbg.aglib.regs[self.flags_reg]
        it_state = itstate_from_cpsr(flags_value)

        if (instruction.id == ARM_INS_IT or it_state != 0) and emu:
            emu.valid = False

    @override
    def _condition(self, instruction: PwndbgInstruction, emu: Emulator) -> InstructionCondition:
        if ARM_GRP_JUMP in instruction.groups:
            if instruction.id in ARM_CAN_WRITE_TO_PC_INSTRUCTIONS:
                # Since Capstone V6, instructions that write to the PC are given the jump group.
                # However, in Pwndbg code, unless stated otherwise, jumps are assumed to be conditional, so we set this attribute
                # to indicate that this is an unconditional branch.
                instruction.declare_is_unconditional_jump = True

        # These condition codes indicate unconditionally/condition is not relevant
        if instruction.cs_insn.cc in (ARM_CC_AL, ARMCC_UNDEF):
            if instruction.id in (ARM_INS_B, ARM_INS_BL, ARM_INS_BLX, ARM_INS_BX, ARM_INS_BXJ):
                instruction.declare_conditional = False
            return InstructionCondition.UNDETERMINED

        # We can't reason about anything except the current instruction
        if instruction.address != pwndbg.aglib.regs.pc:
            return InstructionCondition.UNDETERMINED

        value = pwndbg.aglib.regs[self.flags_reg]

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

            if pwndbg.aglib.arch.name == "armcm" and target & 0xFF00_0000 == 0xFF00_0000:
                # If the top 8-bits of the return address are 0xFF, this indicates we are returning from an exception,
                # where the return address has been saved onto the stack
                return pwndbg.aglib.saved_register_frames.ARM_CORTEX_M_EXCEPTION_STACK.read_saved_register(
                    "pc"
                )

        return target

    # Currently not used
    def _memory_string_old(self, instruction: PwndbgInstruction, op: EnhancedOperand) -> str:
        parts = []

        if op.mem.base != 0:
            parts.append(instruction.cs_insn.reg_name(op.mem.base))

        if op.mem.disp != 0:
            parts.append("%#x" % op.mem.disp)

        if op.mem.index != 0:
            index = pwndbg.aglib.regs[instruction.cs_insn.reg_name(op.mem.index)]
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

        target = base

        # On post index, the base pointer is incremented after the memory dereference
        if not instruction.cs_insn.post_index:
            target += op.mem.disp * (-1 if op.cs_op.subtracted else 1)

        # If there is an index register
        if op.mem.index != 0:
            index = self._read_register(instruction, op.mem.index, emu)
            if index is None:
                return None

            # Optionally apply shift to the index register
            if op.cs_op.shift.type != 0:
                index = ARM_BIT_SHIFT_MAP[op.cs_op.shift.type](index, op.cs_op.shift.value, 32)

            target += index * op.mem.scale

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

        # We need this to retain the value of the un-shifted register in some annotations, such as shifts
        op.before_value_no_modifiers = target

        # Optionally apply shift to the index register
        if op.cs_op.shift.type != 0:
            target = ARM_BIT_SHIFT_MAP.get(op.cs_op.shift.type, lambda *a: None)(
                target, op.cs_op.shift.value, 32
            )

        return target
