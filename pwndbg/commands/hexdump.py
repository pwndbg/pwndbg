#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse

import gdb

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

    if hexdump.repeat:
        address = hexdump.last_address
        hexdump.offset += 1
    else:
        hexdump.offset = 0

    address = int(address)
    address &= pwndbg.arch.ptrmask
    count   = max(int(count), 0)
    width   = int(pwndbg.config.hexdump_width)

    if count > address > 0x10000:
        count -= address

    try:
        data = pwndbg.memory.read(address, count, partial=True)
        hexdump.last_address = (address + count)
    except gdb.error as e:
        print(e)
        return

    for i, line in enumerate(pwndbg.hexdump.hexdump(data, address=address, width=width, offset=hexdump.offset)):
        print(line)
    hexdump.offset += i

hexdump.last_address = 0
hexdump.offset = 0
