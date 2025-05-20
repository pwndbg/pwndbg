from __future__ import annotations

import argparse

import pwndbg.aglib.regs
import pwndbg.commands
import pwndbg.integration
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser(
    description="Use the current integration to decompile code near an address."
)

parser.add_argument(
    "addr",
    type=pwndbg.commands.sloppy_gdb_parse,
    nargs="?",
    default=None,
    help="Address to decompile near.",
)
parser.add_argument(
    "lines",
    type=int,
    nargs="?",
    default=None,
    help="Number of lines of decompilation to show.",
)


@pwndbg.commands.Command(
    parser,
    category=CommandCategory.INTEGRATIONS,
)
@pwndbg.commands.OnlyWhenRunning
def decomp(addr: None | int, lines: None | int) -> None:
    if addr is None:
        addr = pwndbg.aglib.regs.pc
    if lines is None:
        lines = 10
    decomp = pwndbg.integration.provider.decompile(int(addr), int(lines))
    if decomp is None:
        print("Could not retrieve decompilation.")
    else:
        print("\n".join(decomp))
