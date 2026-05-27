from __future__ import annotations

from collections.abc import Callable

from capstone6pwndbg.sparc import *  # noqa: F403
from typing_extensions import override

import pwndbg.aglib.disasm.assistant
from pwndbg.aglib.disasm.instruction import ALL_JUMP_GROUPS
from pwndbg.aglib.disasm.instruction import InstructionCondition
from pwndbg.aglib.disasm.instruction import PwndbgInstruction
from pwndbg.emu.emulator import Emulator

# Instruction groups for future use
SPARC_LOAD_INSTRUCTIONS = {
    SPARC_INS_LDUB: 1,
    SPARC_INS_LDSB: 1,
    SPARC_INS_LDUH: 2,
    SPARC_INS_LDSH: 2,
    SPARC_INS_LD: 4,
    SPARC_INS_LDD: 8,
}

SPARC_STORE_INSTRUCTIONS = {
    SPARC_INS_STB: 1,
    SPARC_INS_STH: 2,
    SPARC_INS_ST: 4,
    SPARC_INS_STD: 8,
}

SPARC_CONDITIONAL_BRANCHES = {
    SPARC_INS_B,  # This is only conditional if .cc != SPARC_CC_ICC_A
    SPARC_INS_ALIAS_BE,
    SPARC_INS_ALIAS_BNE,
    SPARC_INS_ALIAS_BNEG,
    SPARC_INS_ALIAS_BPOS,
    SPARC_INS_ALIAS_BVS,
    SPARC_INS_ALIAS_BVC,
    SPARC_INS_ALIAS_BCS,
    SPARC_INS_ALIAS_BCC,
    SPARC_INS_ALIAS_BL,
    SPARC_INS_ALIAS_BLE,
    SPARC_INS_ALIAS_BG,
    SPARC_INS_ALIAS_BGE,
    SPARC_INS_ALIAS_BLEU,
    SPARC_INS_ALIAS_BGU,
}

# CCR BITS:
# 0 = C (Carry)
# 1 = V (Overflow)
# 2 = Z (Zero)
# 3 = N (Negative)
CCR_C_MASK = 1 << 0
CCR_V_MASK = 1 << 1
CCR_Z_MASK = 1 << 2
CCR_N_MASK = 1 << 3

# Key is ICC code
# lambda parameters: (current ccr value)
# Source of conditions: https://arcb.csc.ncsu.edu/~mueller/codeopt/codeopt00/notes/condbranch.html
ICC_CONDITION_RESOLVERS: dict[int, Callable[[int], bool]] = {
    SPARC_CC_ICC_NE: lambda ccr: not (ccr & CCR_Z_MASK),
    SPARC_CC_ICC_E: lambda ccr: bool(ccr & CCR_Z_MASK),
    SPARC_CC_ICC_G: lambda ccr: (
        not ((ccr & CCR_N_MASK) ^ (ccr & CCR_V_MASK)) and not (ccr & CCR_Z_MASK)
    ),
    SPARC_CC_ICC_LE: lambda ccr: (
        bool((ccr & CCR_N_MASK) ^ (ccr & CCR_V_MASK)) or bool(ccr & CCR_Z_MASK)
    ),
    SPARC_CC_ICC_GE: lambda ccr: not ((ccr & CCR_N_MASK) ^ (ccr & CCR_V_MASK)),
    SPARC_CC_ICC_L: lambda ccr: bool((ccr & CCR_N_MASK) ^ (ccr & CCR_V_MASK)),
    SPARC_CC_ICC_GU: lambda ccr: not (ccr & CCR_Z_MASK) and not (ccr & CCR_C_MASK),
    SPARC_CC_ICC_LEU: lambda ccr: bool(ccr & CCR_Z_MASK) or bool(ccr & CCR_C_MASK),
    SPARC_CC_ICC_CC: lambda ccr: not (ccr & CCR_C_MASK),
    SPARC_CC_ICC_CS: lambda ccr: bool(ccr & CCR_C_MASK),
    SPARC_CC_ICC_POS: lambda ccr: not (ccr & CCR_N_MASK),
    SPARC_CC_ICC_NEG: lambda ccr: bool(ccr & CCR_N_MASK),
    SPARC_CC_ICC_VC: lambda ccr: not (ccr & CCR_V_MASK),
    SPARC_CC_ICC_VS: lambda ccr: bool(ccr & CCR_V_MASK),
}


class SparcDisassemblyAssistant(pwndbg.aglib.disasm.assistant.DisassemblyAssistant):
    @override
    def _condition(self, instruction: PwndbgInstruction, emu: Emulator) -> InstructionCondition:
        if instruction.id in SPARC_CONDITIONAL_BRANCHES:
            cc_field = instruction.cs_insn.cc_field

            if cc_field == SPARC_CC_FIELD_ICC:
                cc = instruction.cs_insn.cc

                # This indicates it is an unconditional branch
                if cc == SPARC_CC_ICC_A:
                    instruction.declare_is_unconditional_jump = True
                    return InstructionCondition.UNCONDITIONAL

                ccr = self._read_register_name(instruction, "ccr", emu)

                if ccr is None:
                    return InstructionCondition.UNDETERMINED_CONDITIONAL

                conditional = ICC_CONDITION_RESOLVERS.get(cc, lambda *a: None)(ccr)

                if conditional is None:
                    return InstructionCondition.UNDETERMINED_CONDITIONAL

                return InstructionCondition.TRUE if conditional else InstructionCondition.FALSE

        return InstructionCondition.UNCONDITIONAL

    @override
    def _resolve_target(self, instruction: PwndbgInstruction, emu: Emulator | None):
        if bool(instruction.groups & ALL_JUMP_GROUPS):
            instruction.causes_branch_delay = True

        return super()._resolve_target(instruction, emu)
