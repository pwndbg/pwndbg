from __future__ import annotations
from typing import Callable

from capstone import *  # noqa: F403
from capstone.arm64 import *  # noqa: F403

import pwndbg.disasm.arch
import pwndbg.gdblib.arch
import pwndbg.gdblib.memory
import pwndbg.gdblib.regs
from pwndbg.disasm.instruction import EnhancedOperand
from pwndbg.disasm.instruction import InstructionCondition
from pwndbg.disasm.instruction import PwndbgInstruction
from pwndbg.emu.emulator import Emulator


class DisassemblyAssistant(pwndbg.disasm.arch.DisassemblyAssistant):
    
    def __init__(self, architecture: str) -> None:
        super().__init__(architecture)

        self.annotation_handlers: dict[int, Callable[[PwndbgInstruction, Emulator], None]] = {
            ARM64_INS_MOV: self.handle_mov
        }


    def handle_mov(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        
        left = instruction.operands[0]


        # Emulating determined the value that was set in the destination register
        if left.after_value is not None:
            TELESCOPE_DEPTH = max(0, int(pwndbg.gdblib.config.disasm_telescope_depth))

            # Telescope the address
            telescope_addresses, did_telescope = super().telescope(
                left.after_value,
                TELESCOPE_DEPTH + 1,
                instruction,
                left,
                emu,
                read_size=pwndbg.gdblib.arch.ptrsize,
            )

            if not telescope_addresses:
                return
            
            instruction.annotation = f"{left.str} => {super().telescope_format_list(telescope_addresses, TELESCOPE_DEPTH, emu, did_telescope)}"


    # Override
    def set_annotation_string(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        # Dispatch to the correct handler
        self.annotation_handlers.get(instruction.id, lambda *a: None)(instruction, emu)






assistant = DisassemblyAssistant("aarch64")
