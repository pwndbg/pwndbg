from __future__ import annotations

from capstone import *  # noqa: F403
from capstone.arm import *  # noqa: F403

import pwndbg.disasm.arch
import pwndbg.gdblib.arch
import pwndbg.gdblib.memory
import pwndbg.gdblib.regs
from pwndbg.disasm.instruction import EnhancedOperand
from pwndbg.disasm.instruction import PwndbgInstruction
from pwndbg.emu.emulator import Emulator


class DisassemblyAssistant(pwndbg.disasm.arch.DisassemblyAssistant):
    def condition(self, instruction: PwndbgInstruction, emu: Emulator):
        # We can't reason about anything except the current instruction
        if instruction.cs_insn.cc == ARM_CC_AL:
            return None

        if instruction.address != pwndbg.gdblib.regs.pc:
            return False

        value = (
            pwndbg.gdblib.regs.cpsr
            if pwndbg.gdblib.arch.current == "arm"
            else pwndbg.gdblib.regs.xpsr
        )

        N = value & (1 << 31)
        Z = value & (1 << 30)
        C = value & (1 << 29)
        V = value & (1 << 28)

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

        return cc

    def memory_string(self, instruction: PwndbgInstruction, op: EnhancedOperand) -> str:
        segment = ""
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

    def immediate_string(self, instruction, operand):
        return "#" + super().immediate_string(instruction, operand)


assistant = DisassemblyAssistant("arm")
