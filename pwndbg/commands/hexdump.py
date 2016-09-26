#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse

import pwndbg.arch
import pwndbg.commands
import pwndbg.config
import pwndbg.hexdump
import pwndbg.memory
import pwndbg.regs

pwndbg.config.Parameter('hexdump-width',
                         16,
                         'line width of hexdump command')
pwndbg.config.Parameter('hexdump-bytes',
                         64,
                         'number of bytes printed by hexdump command')

parser = argparse.ArgumentParser(description='Hexdumps data at the specified address (or at $sp)')
parser.add_argument('address', nargs='?', default='$sp', 
                    help='Address to dump')
parser.add_argument('count', nargs='?', default=pwndbg.config.hexdump_bytes, 
                    help='Number of bytes to dump')

@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def hexdump(address=None, count=pwndbg.config.hexdump_bytes):
    address = int(address)
    address &= pwndbg.arch.ptrmask
    count   = int(count)
    width   = int(pwndbg.config.hexdump_width)

    if count > address > 0x10000:
        count -= address

    data = pwndbg.memory.read(address, count, partial=True)

    for line in pwndbg.hexdump.hexdump(data, address=address, width=width):
        print(line)
