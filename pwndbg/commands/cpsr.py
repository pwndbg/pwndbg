from __future__ import annotations

import pwndbg.commands
import pwndbg.gdblib.arch
import pwndbg.gdblib.regs
from pwndbg.color import context
from pwndbg.commands import CommandCategory


@pwndbg.commands.ArgparsedCommand(
    "Print out ARM CPSR or xPSR register.",
    aliases=["xpsr", "pstate"],
    category=CommandCategory.REGISTER,
)
@pwndbg.commands.OnlyWithArch(["arm", "armcm", "aarch64"])
@pwndbg.commands.OnlyWhenRunning
def cpsr() -> None:
    reg = "xpsr" if pwndbg.gdblib.arch.name == "armcm" else "cpsr"
    reg_val = getattr(pwndbg.gdblib.regs, reg)
    reg_flags = pwndbg.gdblib.regs.flags[reg]
    print(f"{reg} {context.format_flags(reg_val, reg_flags)}")
