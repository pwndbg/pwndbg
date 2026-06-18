# fmtarg command. Check EOF for license
from __future__ import annotations

import argparse
from typing import Tuple

import pwndbg.aglib.arch
import pwndbg.aglib.memory
import pwndbg.aglib.regs
import pwndbg.aglib.stack
import pwndbg.chain
import pwndbg.commands
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser()
parser.description = "Dump arguments for format string exploits."
parser.add_argument("n", nargs="?", type=int, default=16, help="Number of arguments to print")


@pwndbg.commands.Command(parser, category=CommandCategory.MISC)
@pwndbg.commands.OnlyWhenRunning
def fmtarg(n=16):
    """
    Show first n arguments as used in a format string
    """

    n += 1  # to show first n arguments including the formatstring.
    index_width = len(str(n)) + 2
    ret_addrs = set(pwndbg.aglib.stack.callstack())

    abi = pwndbg.aglib.arch.function_abi
    if abi is None:
        raise pwndbg.dbg_mod.Error(
            f"Function ABI not defined for current architecture, {pwndbg.aglib.arch.function_abi}"
        )

    regs = abi.register_arguments
    longest_reg = max(regs, key=len)
    longest_reg_len = len(longest_reg)

    for i in range(n):
        loc, arg = argument(i)
        annotation = " [RETADDR]" if arg in ret_addrs else ""
        index = str(i).center(index_width)
        if isinstance(loc, str):
            loc = loc.upper()
            loc = loc.ljust(longest_reg_len + 2)
            print("%s│ %s%s%s" % (index, loc, pwndbg.chain.format(arg), annotation))
        else:
            print("%s│ %s%s" % (index, pwndbg.chain.format(loc), annotation))


def argument(n: int) -> Tuple[int | str, int]:
    """
    Returns the nth argument, as if $pc were a 'call' or 'bl' type
    instruction.
    Works only for ABIs that use registers for arguments.
    """
    abi = pwndbg.aglib.arch.function_abi
    if abi is None:
        raise pwndbg.dbg_mod.Error(
            f"Function ABI not defined for current architecture, {pwndbg.aglib.arch.function_abi}"
        )
    regs = abi.register_arguments

    if n < len(regs):
        return regs[n], getattr(pwndbg.aglib.regs, regs[n])

    n -= len(regs)

    sp = pwndbg.aglib.regs.sp + (n * pwndbg.aglib.arch.ptrsize)

    return sp, pwndbg.aglib.memory.read_pointer_width(sp)
