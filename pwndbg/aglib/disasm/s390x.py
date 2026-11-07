from __future__ import annotations

from typing import TYPE_CHECKING

from capstone6pwndbg import CS_GRP_CALL
from capstone6pwndbg import CS_GRP_INT
from capstone6pwndbg.systemz import SYSTEMZ_INS_SVC
from typing_extensions import override

import pwndbg.aglib.disasm.assistant
from pwndbg.aglib.disasm.instruction import PwndbgInstruction
from pwndbg.lib.syscall import syscall_number_to_name

# Emulator currently requires GDB, and we only use it here for type checking.
if TYPE_CHECKING:
    from pwndbg.emu.emulator import Emulator


class S390xDisassemblyAssistant(pwndbg.aglib.disasm.assistant.DisassemblyAssistant):
    @override
    def _prepare(self, instruction: PwndbgInstruction, emu: Emulator | None) -> None:
        # Capstone puts `svc` in the call group, but it is a syscall
        if instruction.id == SYSTEMZ_INS_SVC:
            instruction.groups.discard(CS_GRP_CALL)
            instruction.groups.add(CS_GRP_INT)

    @override
    def _enhance_syscall(self, instruction: PwndbgInstruction, emu: Emulator | None) -> None:
        # `svc N` encodes syscall numbers below 256 in the instruction; `svc 0` uses r1 instead.
        # We read .imm directly, because at this point we haven't enhanced the operands with values
        number = instruction.operands[0].imm if instruction.id == SYSTEMZ_INS_SVC else 0
        if number == 0:
            super()._enhance_syscall(instruction, emu)
            return

        instruction.syscall = number
        instruction.syscall_name = syscall_number_to_name(number, "s390x") or f"<unk_{number}>"
