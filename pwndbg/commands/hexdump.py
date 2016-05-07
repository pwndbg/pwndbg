#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
import pwndbg.arch
import pwndbg.commands
import pwndbg.hexdump
import pwndbg.memory
import pwndbg.regs


@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def hexdump(address=None, count=64):
    """
    Hexdumps data at the specified address.
    Optionally provide the number of bytes to dump (default 64)

    Note that repeating rows are collapsed.
    """
    address = int(address if address is not None else pwndbg.regs.sp)
    address &= pwndbg.arch.ptrmask
    count   = int(count)

    # if None not in (address, count):
    #     address = int(address)
    #     count   = int(count):

    if count > address > 0x10000:
        count -= address

    # if address is None:
    # 	address =

    data = pwndbg.memory.read(address, count, partial=True)

    for line in pwndbg.hexdump.hexdump(data, address=address):
        print(line)
