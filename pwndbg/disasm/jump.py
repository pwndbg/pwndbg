#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

from capstone import CS_GRP_JUMP

import pwndbg.arch
import pwndbg.disasm.x86


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
    if pwndbg.regs.pc != instruction.address:
        return False

    return {
        'i386': pwndbg.disasm.x86.is_jump_taken,
        'x86-64': pwndbg.disasm.x86.is_jump_taken,
    }.get(pwndbg.arch.current, lambda *a: False)(instruction)
