#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import os

import gdb

import pwndbg.auxv
import pwndbg.commands
import pwndbg.vmmap


def get_exe_name():
    """
    Returns exe name, tries AUXV first which should work fine on both
    local and remote (gdbserver, qemu gdbserver) targets.

    If the value is somehow not present in AUXV, we just fallback to
    local exe filepath.

    NOTE: This might be wrong for remote targets.
    """
    path = pwndbg.auxv.get().get('AT_EXECFN')

    # When GDB is launched on a file that is a symlink to the target,
    # the AUXV's AT_EXECFN stores the absolute path of to the symlink.
    # On the other hand, the vmmap, if taken from /proc/pid/maps will contain
    # the absolute and real path of the binary (after symlinks).
    # And so we have to read this path here.
    real_path = pwndbg.file.readlink(path)

    if real_path == '':  # the `path` was not a symlink
        real_path = path

    if real_path is not None:
        # We normalize the path as `AT_EXECFN` might contain e.g. './a.out'
        # so matching it against Page.objfile later on will be wrong;
        # We want just 'a.out'
        return os.path.normpath(real_path)

    return pwndbg.proc.exe


def translate_addr(offset, module):
    mod_filter = lambda page: module in page.objfile
    pages = list(filter(mod_filter, pwndbg.vmmap.get()))

    if not pages:
        print('There are no memory pages in `vmmap` '
              'for specified address=0x%x and module=%s' % (offset, module))
        return

    first_page = min(pages, key=lambda page: page.vaddr)

    addr = first_page.vaddr + offset

    if not any(addr in p for p in pages):
        print('Offset 0x%x rebased to module %s as 0x%x is beyond module\'s '
              'memory pages:' % (offset, module, addr))
        for p in pages:
            print(p)
        return

    return addr


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

    if addr is not None:
        print('Calculated VA from %s = 0x%x' % (module, addr))


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

    if addr is not None:
        spec = "*%#x" % (addr)
        gdb.Breakpoint(spec)


@pwndbg.commands.QuietSloppyParsedCommand #TODO should this just be an alias or does the QuietSloppy have an effect?
@pwndbg.commands.OnlyWhenRunning
def brva(map):
    """Alias for breakrva."""
    return breakrva(map)
