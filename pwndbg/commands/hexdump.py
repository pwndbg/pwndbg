#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse

import gdb
import six

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

def address_or_module_name(s):
    gdbval_or_str = pwndbg.commands.sloppy_gdb_parse(s)
    if isinstance(gdbval_or_str, six.string_types):
        module_name = gdbval_or_str
        pages = list(filter(lambda page: module_name in page.objfile, pwndbg.vmmap.get()))
        if pages:
            return pages[0].vaddr
        else:
            raise argparse.ArgumentError('Could not find pages for module %s' % module_name)
    elif isinstance(gdbval_or_str, six.integer_types + (gdb.Value,)):
        addr = gdbval_or_str
        return addr
    else:
        raise argparse.ArgumentTypeError('Unknown hexdump argument type.')

parser = argparse.ArgumentParser(description='Hexdumps data at the specified address or module name (or at $sp)')
parser.add_argument('address_or_module', type=address_or_module_name, nargs='?', default='$sp',
                    help='Address or module name to dump')
parser.add_argument('count', nargs='?', default=pwndbg.config.hexdump_bytes,
                    help='Number of bytes to dump')


@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def hexdump(address_or_module=None, count=pwndbg.config.hexdump_bytes):
    address = address_or_module
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
