#!/usr/bin/env python
# -*- coding: utf-8 -*-
import argparse

import gdb

import pwndbglib.arch
import pwndbglib.commands
import pwndbglib.config
import pwndbglib.hexdump
import pwndbglib.memory
import pwndbglib.regs

pwndbglib.config.Parameter('hexdump-width',
                           16,
                         'line width of hexdump command')
pwndbglib.config.Parameter('hexdump-bytes',
                           64,
                         'number of bytes printed by hexdump command')
pwndbglib.config.Parameter('hexdump-group-width',
                           4,
                         "number of bytes grouped in hexdump command (If -1, the architecture's pointer size is used)")
pwndbglib.config.Parameter('hexdump-group-use-big-endian',
                           False,
                         'Use big-endian within each group of bytes. Only applies to raw bytes, not the ASCII part. '
                         'See also hexdump-highlight-group-lsb.')

def address_or_module_name(s):
    gdbval_or_str = pwndbglib.commands.sloppy_gdb_parse(s)
    if isinstance(gdbval_or_str, str):
        module_name = gdbval_or_str
        pages = list(filter(lambda page: module_name in page.objfile, pwndbglib.vmmap.get()))
        if pages:
            return pages[0].vaddr
        else:
            raise argparse.ArgumentError('Could not find pages for module %s' % module_name)
    elif isinstance(gdbval_or_str, (int, gdb.Value)):
        addr = gdbval_or_str
        return addr
    else:
        raise argparse.ArgumentTypeError('Unknown hexdump argument type.')

parser = argparse.ArgumentParser(description='Hexdumps data at the specified address or module name (or at $sp)')
parser.add_argument('address_or_module', type=address_or_module_name, nargs='?', default='$sp',
                    help='Address or module name to dump')
parser.add_argument('count', nargs='?', default=pwndbglib.config.hexdump_bytes,
                    help='Number of bytes to dump')


@pwndbglib.commands.ArgparsedCommand(parser)
@pwndbglib.commands.OnlyWhenRunning
def hexdump(address_or_module=None, count=pwndbglib.config.hexdump_bytes):
    address = address_or_module
    if hexdump.repeat:
        address = hexdump.last_address
        hexdump.offset += 1
    else:
        hexdump.offset = 0

    address     = int(address)
    address     &= pwndbglib.arch.ptrmask
    count       = max(int(count), 0)
    width       = int(pwndbglib.config.hexdump_width)
    group_width = int(pwndbglib.config.hexdump_group_width)
    group_width = pwndbglib.typeinfo.ptrsize if group_width == -1 else group_width
    flip_group_endianess = pwndbglib.config.hexdump_group_use_big_endian and pwndbglib.arch.endian == 'little'

    if count > address > 0x10000:
        count -= address

    try:
        data = pwndbglib.memory.read(address, count, partial=True)
        hexdump.last_address = (address + count)
    except gdb.error as e:
        print(e)
        return

    for i, line in enumerate(pwndbglib.hexdump.hexdump(data, address=address, width=width, group_width=group_width, flip_group_endianess=flip_group_endianess, offset=hexdump.offset)):
        print(line)
    hexdump.offset += i

hexdump.last_address = 0
hexdump.offset = 0
