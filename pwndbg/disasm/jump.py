from capstone import CS_GRP_JUMP

import pwndbg.disasm.x86
import pwndbg.gdblib.arch


def is_jump_taken(instruction):
    """
    Attempt to determine if a conditional instruction is executed.
    Only valid for the current instruction.

    Returns:
        Returns True IFF the current instruction is a conditional
        *or* jump instruction, and it is taken.

        Returns False in all other cases.
    """
    if CS_GRP_JUMP not in instruction.groups:
        return False
    if pwndbg.gdblib.regs.pc != instruction.address:
        return False

    return {
        "i386": pwndbg.disasm.x86.is_jump_taken,
        "x86-64": pwndbg.disasm.x86.is_jump_taken,
    }.get(pwndbg.gdblib.arch.current, lambda *a: False)(instruction)
