#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import bz2
import datetime
import os

import gdb

import pwndbg.commands
import pwndbg.commands.context
import pwndbg.ida
import pwndbg.regs
from pwndbg.gdbutils.functions import GdbFunction


@pwndbg.commands.ParsedCommand
@pwndbg.commands.OnlyWhenRunning
@pwndbg.events.stop
@pwndbg.ida.withIDA
def j(*args):
    """
    Synchronize IDA's cursor with GDB
    """
    try:
        pc = int(gdb.selected_frame().pc())
        pwndbg.ida.Jump(pc)
    except Exception:
        pass



@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def up(n=1):
    """
    Select and print stack frame that called this one.
    An argument says how many frames up to go.
    """
    f = gdb.selected_frame()

    for i in range(int(n)):
        if f.older():
            f = f.older()
    f.select()

    bt = pwndbg.commands.context.context_backtrace(with_banner=False)
    print('\n'.join(bt))

    j()


@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def down(n=1):
    """
    Select and print stack frame called by this one.
    An argument says how many frames down to go.
    """
    f = gdb.selected_frame()

    for i in range(int(n)):
        if f.newer():
            f = f.newer()
    f.select()

    bt = pwndbg.commands.context.context_backtrace(with_banner=False)
    print('\n'.join(bt))

    j()


@pwndbg.commands.Command
@pwndbg.ida.withIDA
def save_ida():
    """Save the IDA database"""
    if not pwndbg.ida.available():
        return

    path = pwndbg.ida.GetIdbPath()

    # Need to handle emulated paths for Wine
    if path.startswith('Z:'):
        path = path[2:].replace('\\', '/')
        pwndbg.ida.SaveBase(path)

    basename = os.path.basename(path)
    dirname = os.path.dirname(path)
    backups = os.path.join(dirname, 'ida-backup')

    if not os.path.isdir(backups):
        os.mkdir(backups)

    basename, ext = os.path.splitext(basename)
    basename += '-%s' % datetime.datetime.now().isoformat()
    basename += ext

    # Windows doesn't like colons in paths
    basename = basename.replace(':', '_')

    full_path = os.path.join(backups, basename)

    pwndbg.ida.SaveBase(full_path)

    data = open(full_path, 'rb').read()

    # Compress!
    full_path_compressed = full_path + '.bz2'
    bz2.BZ2File(full_path_compressed, 'w').write(data)

    # Remove old version
    os.unlink(full_path)

save_ida()


@GdbFunction()
def ida(name):

    """Evaluate ida.LocByName() on the supplied value."""
    name = name.string()
    result = pwndbg.ida.LocByName(name)

    if 0xffffe000 <= result <= 0xffffffff or 0xffffffffffffe000 <= result <= 0xffffffffffffffff:
        raise ValueError("ida.LocByName(%r) == BADADDR" % name)

    return result
