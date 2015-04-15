#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Commands for setting temporary breakpoints on the next
instruction of some type (call, branch, etc.)
"""
import gdb
import pwndbg.disasm
import pwndbg.regs


def next_branch(callback, address=None):
    if address is None:
        address = pwndbg.regs.pc

    # Disassemble forward until we find *any* branch instruction
    # Set a temporary, internal breakpoint on it so the user is
    # not bothered.
