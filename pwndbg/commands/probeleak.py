#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import math

import gdb

import pwndbg.arch
import pwndbg.color.memory as M
import pwndbg.color.message as message
import pwndbg.commands
import pwndbg.elf
import pwndbg.vmmap


def find_module(addr, max_distance):
    mod_filter = lambda page: page.start <= addr < page.end
    pages = list(filter(mod_filter, pwndbg.vmmap.get()))

    if not pages:
        if max_distance != 0:
            mod_filter = lambda page: page.start - max_distance <= addr < page.end + max_distance
            pages = list(filter(mod_filter, pwndbg.vmmap.get()))

        if not pages:
            return None

    return pages[-1]

parser = argparse.ArgumentParser(description='''
Pointer scan for possible offset leaks.
Examples:
    probeleak $rsp 0x64 - leaks 0x64 bytes starting at stack pointer and search for valid pointers
    probeleak $rsp 0x64 0x10 - as above, but pointers may point 0x10 bytes outside of memory page
''')
parser.add_argument('address', nargs='?', default='$sp',
                    help='Leak memory address')
parser.add_argument('count', nargs='?', default=0x40,
                    help='Leak size in bytes')
parser.add_argument('max_distance', nargs='?', default=0x0,
                    help='Max acceptable distance between memory page boundry and leaked pointer')

@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def probeleak(address=None, count=0x40, max_distance=0x0):

    address = int(address)
    address &= pwndbg.arch.ptrmask
    ptrsize = pwndbg.arch.ptrsize
    count   = max(int(count), ptrsize)
    off_zeros = int(math.ceil(math.log(count,2)/4))

    if count > address > 0x10000: # in case someone puts in an end address and not a count (smh)
        print(message.warn("Warning: you gave an end address, not a count. Substracting 0x%x from the count." % (address)))
        count -= address

    try:
        data = pwndbg.memory.read(address, count, partial=True)
    except gdb.error as e:
        print(message.error(str(e)))
        return

    if not data:
        print(message.error("Couldn't read memory at 0x%x. See 'probeleak -h' for the usage." % (address,)))
        return

    found = False
    for i in range(0, len(data) - ptrsize + 1):
        p = pwndbg.arch.unpack(data[i:i+ptrsize])
        page = find_module(p, max_distance)
        if page:
            if not found:
                print(M.legend())
                found = True

            mod_name = page.objfile
            if not mod_name:
                mod_name = '[anon]'

            if p >= page.end:
                right_text = '(%s) %s + 0x%x + 0x%x (outside of the page)' % (page.permstr, mod_name, page.memsz, p - page.end)
            elif p < page.start:
                right_text = '(%s) %s - 0x%x (outside of the page)' % (page.permstr, mod_name, page.start - p)
            else:
                right_text = '(%s) %s + 0x%x' % (page.permstr, mod_name, p - page.start)

            offset_text = '0x%0*x' % (off_zeros, i)
            p_text = '0x%0*x' % (int(ptrsize*2), p)
            text = '%s: %s = %s' % (offset_text, M.get(p, text=p_text), M.get(p, text=right_text))

            symbol = pwndbg.symbol.get(p)
            if symbol:
                text += ' (%s)' % symbol

            print(text)

    if not found:
        print(message.hint('No leaks found at 0x%x-0x%x :(' % (address, address+count)))
