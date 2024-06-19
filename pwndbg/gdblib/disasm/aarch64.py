from __future__ import annotations

from typing import Callable
from typing import Dict
from typing_extensions import override

from capstone import *  # noqa: F403
from capstone.arm64 import *  # noqa: F403

import pwndbg.gdblib.arch
import pwndbg.gdblib.disasm.arch
import pwndbg.gdblib.memory
import pwndbg.gdblib.regs
from pwndbg.emu.emulator import Emulator
from pwndbg.gdblib.disasm.instruction import PwndbgInstruction


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
        }

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
            TELESCOPE_DEPTH = max(0, int(pwndbg.gdblib.config.disasm_telescope_depth))

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
    def _set_annotation_string(self, instruction: PwndbgInstruction, emu: Emulator) -> None:
        # Dispatch to the correct handler
        self.annotation_handlers.get(instruction.id, lambda *a: None)(instruction, emu)


assistant = DisassemblyAssistant("aarch64")
