# fmtarg command. Check EOF for license
import argparse
import pwndbg.commands
import pwndbg.chain
import pwndbg.aglib.arch
import pwndbg.aglib.memory
import pwndbg.aglib.stack
import pwndbg.aglib.regs
from pwndbg.commands import CommandCategory

parser = argparse.ArgumentParser()
parser.description = "Dump arguments for format string exploits."
parser.add_argument(
    "n", nargs="?", type=int, default=16, help="Number of arguments to print"
)


@pwndbg.commands.Command(parser, category=CommandCategory.MISC)
@pwndbg.commands.OnlyWhenRunning
def fmtarg(n=16):
    """
    Show first n arguments as used in a format string, following
    System V AMD64 calling convention.
    """

    # System V AMD64 calling convention: rsi, rdx, rcx, r8, r9
    regs64 = ["rsi", "rdx", "rcx", "r8", "r9"]

    if pwndbg.aglib.arch.name != "x86-64":
        print("Only x86-64 supported right now")
        return

    ptrsize = pwndbg.aglib.arch.ptrsize
    rsp = pwndbg.aglib.regs.rsp
    assert rsp is not None
    # figure out how wide the index column should be
    index_width = len(str(n))
    ret_addrs = set(pwndbg.aglib.stack.callstack())

    for i, reg in enumerate(regs64):
        if i >= n:
            return
        val = pwndbg.aglib.regs[reg]
        reg = reg.upper()
        # Align index, register name, and formatted value
        print(f"{i+1:{index_width}d} │ {reg:<4} {pwndbg.chain.format(val)}")

    for i in range(6, n):
        addr = rsp + (i - 6) * ptrsize
        val = pwndbg.aglib.memory.u(addr)

        annotation = " [RETADDR]" if val in ret_addrs else ""
        print(f"{i:{index_width}d} │ {pwndbg.chain.format(addr)}{annotation}")


