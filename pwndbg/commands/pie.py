#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Command to print the virtual memory map a la /proc/self/maps.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse

import gdb
import six
from elftools.elf.constants import SH_FLAGS
from elftools.elf.elffile import ELFFile

import pwndbg.commands
import pwndbg.compat
import pwndbg.elf
import pwndbg.vmmap
import pwndbg.auxv

def translate_addr(offset, module):
    mod_filter = lambda page: module in page.objfile
    pages = list(filter(mod_filter, pwndbg.vmmap.get()))

    if not pages:
        print('There are no mappings for specified address or module.')
        return

    for page in pages:
        if page.execute:
            return page.vaddr + offset
    print("No executeable segments found")
    return

parser = argparse.ArgumentParser()
parser.description = 'Calculate VA of RVA from PIE base.'
parser.add_argument('offset', nargs='?', default='0',
                    help='Offset from PIE base.')
parser.add_argument('module', type=str, nargs='?', default='',
                    help='Module to choose as base. Defaults to the target executable.')

@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def piebase(offset=None, module=None):
    offset = int(offset)
    if not module:
        module = pwndbg.auxv.get()['AT_EXECFN']
    addr = translate_addr(offset, module)
    print(hex(addr))


parser = argparse.ArgumentParser()
parser.description = 'Break at RVA from PIE base.'
parser.add_argument('offset', nargs='?', default='0',
                    help='Offset to add.')
parser.add_argument('module', type=str, nargs='?', default='',
                    help='Module to choose as base. Defaults to the target executable.')

@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def breakrva(offset=None, module=None):
    offset = int(offset)
    if not module:
        module = pwndbg.auxv.get()['AT_EXECFN']
    addr = translate_addr(offset, module)
    spec = "*%#x" % (addr)
    gdb.Breakpoint(spec)


@pwndbg.commands.QuietSloppyParsedCommand
@pwndbg.commands.OnlyWhenRunning
def brva(map):
    return breakrva(map)
