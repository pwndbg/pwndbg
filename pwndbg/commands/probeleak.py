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


def find_module(addr):
    mod_filter = lambda page: page.vaddr <= addr < page.vaddr + page.memsz
    pages = list(filter(mod_filter, pwndbg.vmmap.get()))

    if not pages:
        return None

    if len(pages) > 1:
        print(message.warn('Warning: There is more than one page containing address 0x%x (wtf?)', addr))

    return pages[0]

parser = argparse.ArgumentParser()
parser.description = 'Pointer scan for possible offset leaks.'
parser.add_argument('address', nargs='?', default='$sp',
                    help='Leak memory address')
parser.add_argument('count', nargs='?', default=0x40,
                    help='Leak size in bytes')

@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def probeleak(address=None, count=0x40):

    address = int(address)
    address &= pwndbg.arch.ptrmask
    count   = max(int(count), 0)
    ptrsize = pwndbg.arch.ptrsize
    off_zeros = int(math.ceil(math.log(count,2)/4))

    if count > address > 0x10000: # in case someone puts in an end address and not a count (smh)
        count -= address

    if count % ptrsize > 0:
        newcount = count - (count % ptrsize)
        print(message.warning("Warning: count 0x%x is not a multiple of 0x%x; truncating to 0x%x." % (count, ptrsize, newcount)))
        count = newcount

    try:
        data = pwndbg.memory.read(address, count, partial=True)
    except gdb.error as e:
        print(message.error(str(e)))
        return

    if not data:
        print(message.error("Couldn't read memory at 0x%x" % (address,)))
        return

    found = False
    for i in range(0, count, ptrsize):
        p = pwndbg.arch.unpack(data[i:i+ptrsize])
        page = find_module(p)
        if page:
            if not found:
                print(M.legend())
                found = True

            mod_name = page.objfile
            if not mod_name:
                mod_name = '[anon]'
            fmt = '+0x{offset:0{n1}x}: 0x{ptr:0{n2}x} = {page}'
            right_text = ('(%s) %s + 0x%x') % (page.permstr, mod_name, p - page.vaddr + page.offset)
            print(fmt.format(n1=off_zeros, n2=ptrsize*2, offset=i, ptr=p, page=M.get(p, text=right_text)))
    if not found:
        print(message.hint('No leaks found at 0x{:x}-0x{:x} :('.format(address, address+count)))
