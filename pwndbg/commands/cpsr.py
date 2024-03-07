from __future__ import annotations

import argparse

import pwndbg.commands
import pwndbg.gdblib.arch
import pwndbg.gdblib.regs
from pwndbg.color import context
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(description="Print out ARM CPSR or xPSR register.")

parser.add_argument(
    "cpsr_value", help="Parse the given CPSR value instead of the actual one.", nargs="?", type=int
)


@pwndbg.commands.ArgparsedCommand(
    parser,
    aliases=["xpsr", "pstate"],
    category=CommandCategory.REGISTER,
)
@pwndbg.commands.OnlyWithArch(["arm", "armcm", "aarch64"])
@pwndbg.commands.OnlyWhenRunning
def cpsr(cpsr_value=None) -> None:
    reg = "xpsr" if pwndbg.gdblib.arch.name == "armcm" else "cpsr"
    reg_flags = pwndbg.gdblib.regs.flags[reg]

    if cpsr_value is not None:
        reg_val = cpsr_value
    else:
        reg_val = getattr(pwndbg.gdblib.regs, reg)

    print(f"{reg} {context.format_flags(reg_val, reg_flags)}")
