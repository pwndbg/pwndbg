import gdb
import pwndbg.arch
import pwndbg.memory
import pwndbg.regs
import pwndbg.typeinfo


def arguments():
    """
    Returns an array containing the arguments to the current function,
    if $pc is a 'call' or 'bl' type instruction.

    Otherwise, returns None.
    """

def argument(n):
    """
    Returns the nth argument, as if $pc were a 'call' or 'bl' type
    instruction.
    """
    arch = pwndbg.arch.current
    regs = []

    if 'x86-64' in arch:
        regs = ['rdi','rsi','rdx','rcx','r8','r9']
    elif 'arm' == arch:
        regs = ['r0','r1','r2','r3']

    if n < len(regs):
        return getattr(pwndbg.regs, regs[n])

    n -= len(regs)

    sp = pwndbg.regs.sp + (n * pwndbg.arch.ptrsize)

    return int(pwndbg.memory.poi(pwndbg.typeinfo.ppvoid, sp))
