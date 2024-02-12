

# When single stepping in Unicorn with MIPS, the address it arrives at
# is often incorrect with branches.
# This is due to "Delay slots" - the instruction AFTER a branch is always executed 
# before the jump, and the Unicorn emulator respects this behavior.
# This causes single stepping branches to not arrive at the correct instruction - 
# it will simply go to the next location in memory, not respecting the branch. It doesn't appear to be extremely consistent.
# Unicorn doesn't have a workaround for this single stepping issue:
# https://github.com/unicorn-engine/unicorn/issues/332


from __future__ import annotations

from typing import Callable

from capstone import *

import pwndbg.gdblib.regs
import pwndbg.disasm.arch
from pwndbg.disasm.instruction import PwndbgInstruction
from pwndbg.disasm.instruction import InstructionCondition
from pwndbg.emu.emulator import Emulator  # noqa: F403

# Capstone operand type for x86 is capstone.x86.X86Op
class DisassemblyAssistant(pwndbg.disasm.arch.DisassemblyAssistant):
    def __init__(self, architecture: str) -> None:
        super().__init__(architecture)

    # Override
    def condition(self, instruction: PwndbgInstruction, emu: Emulator) -> InstructionCondition:
        return InstructionCondition.UNDETERMINED
    
        # # We can't reason about anything except the current instruction
        # if instruction.address != pwndbg.gdblib.regs.pc:
        #     return False


        # return {

        # }.get(instruction.id, None)


assistant = DisassemblyAssistant("mips")
