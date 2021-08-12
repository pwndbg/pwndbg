#!/usr/bin/env python
# -*- coding: utf-8 -*-

from capstone import CS_GRP_JUMP

import pwndbglib.arch
import pwndbglib.disasm.x86


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
    if pwndbglib.regs.pc != instruction.address:
        return False

    return {
        'i386': pwndbglib.disasm.x86.is_jump_taken,
        'x86-64': pwndbglib.disasm.x86.is_jump_taken,
    }.get(pwndbglib.arch.current, lambda *a: False)(instruction)
