#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Compatibility functionality for Windbg users.
"""

import argparse
import codecs
import math
import sys
from builtins import str

import gdb

import pwndbglib.arch
import pwndbglib.commands
import pwndbglib.memory
import pwndbglib.strings
import pwndbglib.symbol
import pwndbglib.typeinfo


def get_type(size):
    return {
    1: pwndbglib.typeinfo.uint8,
    2: pwndbglib.typeinfo.uint16,
    4: pwndbglib.typeinfo.uint32,
    8: pwndbglib.typeinfo.uint64,
    }[size]

parser = argparse.ArgumentParser(description="Starting at the specified address, dump N bytes.")
parser.add_argument("address", type=int, help="The address to dump from.")
parser.add_argument("count", type=int, default=64, nargs="?", help="The number of bytes to dump.")
@pwndbglib.commands.ArgparsedCommand(parser)
@pwndbglib.commands.OnlyWhenRunning
def db(address, count=64):
    """
    Starting at the specified address, dump N bytes
    (default 64).
    """
    return dX(1, address, count, repeat=db.repeat)


parser = argparse.ArgumentParser(description="Starting at the specified address, dump N words.")
parser.add_argument("address", type=int, help="The address to dump from.")
parser.add_argument("count", type=int, default=32, nargs="?", help="The number of words to dump.")
@pwndbglib.commands.ArgparsedCommand(parser)
@pwndbglib.commands.OnlyWhenRunning
def dw(address, count=32):
    """
    Starting at the specified address, dump N words
    (default 32).
    """
    return dX(2, address, count, repeat=dw.repeat)


parser = argparse.ArgumentParser(description="Starting at the specified address, dump N dwrods.")
parser.add_argument("address", type=int, help="The address to dump from.")
parser.add_argument("count", type=int, default=16, nargs="?", help="The number of dwords to dump.")
@pwndbglib.commands.ArgparsedCommand(parser)
@pwndbglib.commands.OnlyWhenRunning
def dd(address, count=16):
    """
    Starting at the specified address, dump N dwords
    (default 16).
    """
    return dX(4, address, count, repeat=dd.repeat)

parser = argparse.ArgumentParser(description="Starting at the specified address, dump N qwords.")
parser.add_argument("address", type=int, help="The address to dump from.")
parser.add_argument("count", type=int, default=8, nargs="?", help="The number of qwords to dump.")
@pwndbglib.commands.ArgparsedCommand(parser)
@pwndbglib.commands.OnlyWhenRunning
def dq(address, count=8):
    """
    Starting at the specified address, dump N qwords
    (default 8).
    """
    return dX(8, address, count, repeat=dq.repeat)

parser = argparse.ArgumentParser(description="Starting at the specified address, hexdump.")
parser.add_argument("address", type=int, help="The address to dump from.")
parser.add_argument("count", type=int, default=8, nargs="?", help="The number of bytes to hexdump.")
@pwndbglib.commands.ArgparsedCommand(parser)
@pwndbglib.commands.OnlyWhenRunning
def dc(address, count=8):
    return pwndbglib.commands.hexdump.hexdump(address=address, count=count, repeat=dc.repeat)

def dX(size, address, count, to_string=False, repeat=False):
    """
    Traditionally, windbg will display 16 bytes of data per line.
    """
    values = []

    if repeat:
        count = dX.last_count
        address = dX.last_address
    else:
        address = int(address) & pwndbglib.arch.ptrmask
        count = int(count)

    type   = get_type(size)

    for i in range(count):
        try:
            gval = pwndbglib.memory.poi(type, address + i * size)
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
        line = [enhex(pwndbglib.arch.ptrsize, address + (i * 16)), '   ']
        for value in row:
            line.append(enhex(size, value))
        lines.append(' '.join(line))

    if not to_string:
        print('\n'.join(lines))

    dX.last_count = count
    dX.last_address = address + len(rows)*16

    return lines

def enhex(size, value):
    value = value & pwndbglib.arch.ptrmask
    x = "%x" % abs(value)
    x = x.rjust(size * 2, '0')
    return x


parser = argparse.ArgumentParser(description="Write hex bytes at the specified address.")
parser.add_argument("address", type=int, help="The address to write to.")
parser.add_argument("data", type=str, nargs="*", help="The bytes to write.")
@pwndbglib.commands.ArgparsedCommand(parser)
@pwndbglib.commands.OnlyWhenRunning
def eb(address, data):
    """
    Write hex bytes at the specified address.
    """
    return eX(1, address, data)


parser = argparse.ArgumentParser(description="Write hex words at the specified address.")
parser.add_argument("address", type=int, help="The address to write to.")
parser.add_argument("data", type=str, nargs="*", help="The words to write.")
@pwndbglib.commands.ArgparsedCommand(parser)
@pwndbglib.commands.OnlyWhenRunning
def ew(address, data):
    """
    Write hex words at the specified address.
    """
    return eX(2, address, data)


parser = argparse.ArgumentParser(description="Write hex dwords at the specified address.")
parser.add_argument("address", type=int, help="The address to write to.")
parser.add_argument("data", type=str, nargs="*", help="The dwords to write.")
@pwndbglib.commands.ArgparsedCommand(parser)
@pwndbglib.commands.OnlyWhenRunning
def ed(address, data):
    """
    Write hex dwords at the specified address.
    """
    return eX(4, address, data)


parser = argparse.ArgumentParser(description="Write hex qwords at the specified address.")
parser.add_argument("address", type=int, help="The address to write to.")
parser.add_argument("data", type=str, nargs="*", help="The qwords to write.")
@pwndbglib.commands.ArgparsedCommand(parser)
@pwndbglib.commands.OnlyWhenRunning
def eq(address, data):
    """
    Write hex qwords at the specified address.
    """
    return eX(8, address, data)


parser = argparse.ArgumentParser(description="Write a string at the specified address.")
parser.add_argument("address", type=int, help="The address to write to.")
parser.add_argument("data", type=str, help="The string to write.")
@pwndbglib.commands.ArgparsedCommand(parser)
@pwndbglib.commands.OnlyWhenRunning
def ez(address, data):
    """
    Write a character at the specified address.
    """
    return eX(1, address, data, hex=False)

parser = argparse.ArgumentParser(description="Write a string at the specified address.") #TODO Is eza just ez? If so just alias. I had trouble finding windbg documentation defining ez
parser.add_argument("address", type=int, help="The address to write to.")
parser.add_argument("data", type=str, help="The string to write.")
@pwndbglib.commands.ArgparsedCommand(parser)
@pwndbglib.commands.OnlyWhenRunning
def eza(address, data):
    """
    Write a string at the specified address.
    """
    return ez(address, data)

def eX(size, address, data, hex=True):
    """
    This relies on windbg's default hex encoding being enforced
    """
    address = pwndbglib.commands.fix(address)

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

        if pwndbglib.arch.endian == 'little':
            data = data[::-1]

        pwndbglib.memory.write(address + (i * size), data)

parser = argparse.ArgumentParser(description="Dump pointers and symbols at the specified address.")
parser.add_argument("addr", type=int, help="The address to dump from.")
@pwndbglib.commands.ArgparsedCommand(parser, aliases=['kd', 'dps', 'dqs']) #TODO are these really all the same? They had identical implementation...
@pwndbglib.commands.OnlyWhenRunning
def dds(addr):
    """
    Dump pointers and symbols at the specified address.
    """
    return pwndbglib.commands.telescope.telescope(addr)


da_parser = argparse.ArgumentParser()
da_parser.description = 'Dump a string at the specified address.'
da_parser.add_argument('address', help='Address to dump')
da_parser.add_argument('max', type=int, nargs='?', default=256,
                       help='Maximum string length')
@pwndbglib.commands.ArgparsedCommand(da_parser)
@pwndbglib.commands.OnlyWhenRunning
def da(address, max):
    address = int(address)
    address &= pwndbglib.arch.ptrmask
    print("%x" % address, repr(pwndbglib.strings.get(address, max)))

ds_parser = argparse.ArgumentParser()
ds_parser.description = 'Dump a string at the specified address.'
ds_parser.add_argument('address', help='Address to dump')
ds_parser.add_argument('max', type=int, nargs='?', default=256,
                       help='Maximum string length')
@pwndbglib.commands.ArgparsedCommand(ds_parser)
@pwndbglib.commands.OnlyWhenRunning
def ds(address, max):
    address = int(address)
    address &= pwndbglib.arch.ptrmask
    print("%x" % address, repr(pwndbglib.strings.get(address, max)))


@pwndbglib.commands.ArgparsedCommand("List breakpoints.")
def bl():
    """
    List breakpoints
    """
    gdb.execute('info breakpoints')


parser = argparse.ArgumentParser(description="Disable the breakpoint with the specified index.")
parser.add_argument("which", nargs="?", type=str, default='*', help="Index of the breakpoint to disable.")
@pwndbglib.commands.ArgparsedCommand(parser)
def bd(which = '*'):
    """
    Disable the breakpoint with the specified index.
    """
    if which == '*':
        gdb.execute('disable breakpoints')
    else:
        gdb.execute('disable breakpoints %s' % which)


parser = argparse.ArgumentParser(description="Enable the breakpoint with the specified index.")
parser.add_argument("which", nargs="?", type=str, default='*', help="Index of the breakpoint to enable.")
@pwndbglib.commands.ArgparsedCommand(parser)
def be(which = '*'):
    """
    Enable the breakpoint with the specified index.
    """
    if which == '*':
        gdb.execute('enable breakpoints')
    else:
        gdb.execute('enable breakpoints %s' % which)

parser = argparse.ArgumentParser(description="Clear the breakpoint with the specified index.")
parser.add_argument("which", nargs="?", type=str, default='*', help="Index of the breakpoint to clear.")
@pwndbglib.commands.ArgparsedCommand(parser)
def bc(which = '*'):
    """
    Clear the breakpoint with the specified index.
    """
    if which == '*':
        gdb.execute('delete breakpoints')
    else:
        gdb.execute('delete breakpoints %s' % which)


parser = argparse.ArgumentParser(description="Set a breakpoint at the specified address.")
parser.add_argument("where", type=int, help="The address to break at.")
@pwndbglib.commands.ArgparsedCommand(parser)
def bp(where):
    """
    Set a breakpoint at the specified address.
    """
    result = pwndbglib.commands.fix(where)
    if result is not None:
        gdb.execute('break *%#x' % int(result))


parser = argparse.ArgumentParser(description="Starting at the specified address, disassemble N instructions.")
parser.add_argument("where", type=int, nargs="?", default=None, help="The address to disassemble at.")
parser.add_argument("n", type=int, nargs="?", default=5, help="The number of instructions to disassemble.")
@pwndbglib.commands.ArgparsedCommand(parser)
@pwndbglib.commands.OnlyWhenRunning
def u(where=None, n=5, to_string=False):
    """
    Starting at the specified address, disassemble
    N instructions (default 5).
    """
    if where is None:
        where = pwndbglib.regs.pc
    return pwndbglib.commands.nearpc.nearpc(where, n, to_string)

@pwndbglib.commands.ArgparsedCommand("Print a backtrace (alias 'bt').")
@pwndbglib.commands.OnlyWhenRunning
def k():
    """
    Print a backtrace (alias 'bt')
    """
    gdb.execute('bt')


parser = argparse.ArgumentParser(description="List the symbols nearest to the provided value.")
parser.add_argument("value", type=int, nargs="?", default=None, help="The address you want the name of.")
@pwndbglib.commands.ArgparsedCommand(parser)
@pwndbglib.commands.OnlyWhenRunning
def ln(value=None):
    """
    List the symbols nearest to the provided value.
    """
    if value is None: value = pwndbglib.regs.pc
    value = int(value)
    x = pwndbglib.symbol.get(value)
    if x:
        result = '(%#x)   %s' % (value, x)
        print(result)
# The three commands are aliases for `vmmap` and are set so in vmmap.py
# lm
# address
# vprot

@pwndbglib.commands.ArgparsedCommand("Not be windows.")
@pwndbglib.commands.OnlyWhenRunning
def peb():
    print("This isn't Windows!")

@pwndbglib.commands.ArgparsedCommand("Windbg compatibility alias for 'continue' command.")
@pwndbglib.commands.OnlyWhenRunning
def go():
    '''
    Windbg compatibility alias for 'continue' command.
    '''
    gdb.execute('continue')

@pwndbglib.commands.ArgparsedCommand("Windbg compatibility alias for 'nextcall' command.")
@pwndbglib.commands.OnlyWhenRunning
def pc():
    '''
    Windbg compatibility alias for 'nextcall' command.
    '''
    return pwndbglib.commands.next.nextcall()
