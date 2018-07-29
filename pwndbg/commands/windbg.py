#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Compatibility functionality for Windbg users.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import codecs
import math
import sys
from builtins import str

import gdb

import pwndbg.arch
import pwndbg.commands
import pwndbg.memory
import pwndbg.strings
import pwndbg.symbol
import pwndbg.typeinfo


def get_type(size):
    return {
    1: pwndbg.typeinfo.uint8,
    2: pwndbg.typeinfo.uint16,
    4: pwndbg.typeinfo.uint32,
    8: pwndbg.typeinfo.uint64,
    }[size]

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def db(address, count=64):
    """
    Starting at the specified address, dump N bytes
    (default 64).
    """
    return dX(1, (address), (count))

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def dw(address, count=32):
    """
    Starting at the specified address, dump N words
    (default 32).
    """
    return dX(2, (address), (count))

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def dd(address, count=16):
    """
    Starting at the specified address, dump N dwords
    (default 16).
    """
    return dX(4, (address), (count))

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def dq(address, count=8):
    """
    Starting at the specified address, dump N qwords
    (default 8).
    """
    return dX(8, (address), (count))

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def dc(address, count=8):
    return pwndbg.commands.hexdump.hexdump(address=address, count=count)

def dX(size, address, count, to_string=False):
    """
    Traditionally, windbg will display 16 bytes of data per line.
    """
    values = []
    address = int(address) & pwndbg.arch.ptrmask
    type   = get_type(size)
    count = int(count)
    for i in range(count):
        try:
            gval = pwndbg.memory.poi(type, address + i * size)
            # print(str(gval))
            values.append(int(gval))
        except gdb.MemoryError:
            break

    n_rows = int(math.ceil(count * size / float(16)))
    row_sz = int(16 / size)
    rows   = [values[i*row_sz:(i+1)*row_sz] for i in range(n_rows)]
    lines  = []

    # sys.stdout.write(repr(rows) + '\n')

    for i, row in enumerate(rows):
        if not row:
            continue
        line = [enhex(pwndbg.arch.ptrsize, address + (i*16)),'   ']
        for value in row:
            line.append(enhex(size, value))
        lines.append(' '.join(line))

    if not to_string:
        print('\n'.join(lines))

    return lines

def enhex(size, value):
    value = value & pwndbg.arch.ptrmask
    x = "%x" % abs(value)
    x = x.rjust(size * 2, '0')
    return x


@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def eb(address, *data):
    """
    Write hex bytes at the specified address.
    """
    return eX(1, address, data)

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def ew(address, *data):
    """
    Write hex words at the specified address.
    """
    return eX(2, address, data)

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def ed(address, *data):
    """
    Write hex dwords at the specified address.
    """
    return eX(4, address, data)

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def eq(address, *data):
    """
    Write hex qwords at the specified address.
    """
    return eX(8, address, data)

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def ez(address, *data):
    """
    Write a string at the specified address.
    """
    return eX(1, address, data[0], hex=False)

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def eza(address, *data):
    """
    Write a string at the specified address.
    """
    return ez(address, data)

def eX(size, address, data, hex=True):
    """
    This relies on windbg's default hex encoding being enforced
    """
    address = pwndbg.commands.fix(address)

    if address is None:
        return

    for i, bytestr in enumerate(data):
        if hex:
            bytestr = str(bytestr)

            if bytestr.startswith('0x'):
                bytestr = bytestr[2:]

            bytestr = bytestr.rjust(size*2, '0')

            data    = codecs.decode(bytestr, 'hex')
        else:
            data    = bytestr

        if pwndbg.arch.endian == 'little':
            data = data[::-1]

        pwndbg.memory.write(address + (i * size), data)

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def dds(*a):
    """
    Dump pointers and symbols at the specified address.
    """
    return pwndbg.commands.telescope.telescope(*a)

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def kd(*a):
    """
    Dump pointers and symbols at the specified address.
    """
    return pwndbg.commands.telescope.telescope(*a)

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def dps(*a):
    """
    Dump pointers and symbols at the specified address.
    """
    return pwndbg.commands.telescope.telescope(*a)

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def dqs(*a):
    """
    Dump pointers and symbols at the specified address.
    """
    return pwndbg.commands.telescope.telescope(*a)


da_parser = argparse.ArgumentParser()
da_parser.description = 'Dump a string at the specified address.'
da_parser.add_argument('address', help='Address to dump')
da_parser.add_argument('max', type=int, nargs='?', default=256,
                       help='Maximum string length')
@pwndbg.commands.ArgparsedCommand(da_parser)
@pwndbg.commands.OnlyWhenRunning
def da(address, max):
    address = int(address)
    address &= pwndbg.arch.ptrmask
    print("%x" % address, repr(pwndbg.strings.get(address, max)))

ds_parser = argparse.ArgumentParser()
ds_parser.description = 'Dump a string at the specified address.'
ds_parser.add_argument('address', help='Address to dump')
ds_parser.add_argument('max', type=int, nargs='?', default=256,
                       help='Maximum string length')
@pwndbg.commands.ArgparsedCommand(ds_parser)
@pwndbg.commands.OnlyWhenRunning
def ds(address, max):
    address = int(address)
    address &= pwndbg.arch.ptrmask
    print("%x" % address, repr(pwndbg.strings.get(address, max)))

@pwndbg.commands.ParsedCommand
def bl():
    """
    List breakpoints
    """
    gdb.execute('info breakpoints')

@pwndbg.commands.Command
def bd(which = '*'):
    """
    Disable the breapoint with the specified index.
    """
    if which == '*':
        gdb.execute('disable breakpoints')
    else:
        gdb.execute('disable breakpoints %s' % which)


@pwndbg.commands.Command
def be(which = '*'):
    """
    Enable the breapoint with the specified index.
    """
    if which == '*':
        gdb.execute('enable breakpoints')
    else:
        gdb.execute('enable breakpoints %s' % which)

@pwndbg.commands.Command
def bc(which = '*'):
    """
    Clear the breapoint with the specified index.
    """
    if which == '*':
        gdb.execute('delete breakpoints')
    else:
        gdb.execute('delete breakpoints %s' % which)


@pwndbg.commands.ParsedCommand
def bp(where):
    """
    Set a breakpoint at the specified address.
    """
    result = pwndbg.commands.fix(where)
    if result is not None:
        gdb.execute('break *%#x' % int(result))

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def u(where=None, n=5, to_string=False):
    """
    Starting at the specified address, disassemble
    N instructions (default 5).
    """
    if where is None:
        where = pwndbg.regs.pc
    return pwndbg.commands.nearpc.nearpc(where, n, to_string)

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def k():
    """
    Print a backtrace (alias 'bt')
    """
    gdb.execute('bt')

@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
def ln(value=None):
    """
    List the symbols nearest to the provided value.
    """
    if value is None: value = pwndbg.regs.pc
    x = pwndbg.symbol.get(value)
    if x:
        result = '(%#x)   %s' % (value, x)

@pwndbg.commands.QuietSloppyParsedCommand
@pwndbg.commands.OnlyWhenRunning
def lm(map):
    """
    Windbg compatibility alias for 'vmmap' command.
    """
    return pwndbg.commands.vmmap.vmmap(map)

@pwndbg.commands.QuietSloppyParsedCommand
@pwndbg.commands.OnlyWhenRunning
def address(map):
    """
    Windbg compatibility alias for 'vmmap' command.
    """
    return pwndbg.commands.vmmap.vmmap(map)


@pwndbg.commands.QuietSloppyParsedCommand
@pwndbg.commands.OnlyWhenRunning
def vprot(map):
    """
    Windbg compatibility alias for 'vmmap' command.
    """
    return pwndbg.commands.vmmap.vmmap(map)

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def peb(*a):
    print("This isn't Windows!")

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def go():
    '''
    Windbg compatibility alias for 'continue' command.
    '''
    gdb.execute('continue')

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def pc():
    '''
    Windbg compatibility alias for 'nextcall' command.
    '''
    return pwndbg.commands.next.nextcall()
