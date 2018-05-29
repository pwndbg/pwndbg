#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse

import gdb

import pwndbg.auxv
import pwndbg.commands
import pwndbg.vmmap


def translate_addr(offset, module):
    mod_filter = lambda page: module in page.objfile
    pages = list(filter(mod_filter, pwndbg.vmmap.get()))

    if not pages:
        print('There are no mappings for specified address or module.')
        return

    return min(map(lambda page: page.vaddr, pages)) + offset

def get_exe_name():
    return pwndbg.auxv.get().get('AT_EXECFN', pwndbg.proc.exe)

parser = argparse.ArgumentParser()
parser.description = 'Calculate VA of RVA from PIE base.'
parser.add_argument('offset', nargs='?', default=0,
                    help='Offset from PIE base.')
parser.add_argument('module', type=str, nargs='?', default='',
                    help='Module to choose as base. Defaults to the target executable.')

@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def piebase(offset=None, module=None):
    offset = int(offset)
    if not module:
        module = get_exe_name()
    addr = translate_addr(offset, module)
    print(hex(addr))


parser = argparse.ArgumentParser()
parser.description = 'Break at RVA from PIE base.'
parser.add_argument('offset', nargs='?', default=0,
                    help='Offset to add.')
parser.add_argument('module', type=str, nargs='?', default='',
                    help='Module to choose as base. Defaults to the target executable.')

@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWhenRunning
def breakrva(offset=None, module=None):
    offset = int(offset)
    if not module:
        module = get_exe_name()
    addr = translate_addr(offset, module)
    spec = "*%#x" % (addr)
    gdb.Breakpoint(spec)


@pwndbg.commands.QuietSloppyParsedCommand
@pwndbg.commands.OnlyWhenRunning
def brva(map):
    """Alias for breakrva."""
    return breakrva(map)
