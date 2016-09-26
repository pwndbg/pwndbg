#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Compatibility functionality for GDBINIT users.

https://github.com/gdbinit/Gdbinit/blob/master/gdbinit
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import gdb

import pwndbg.commands


@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def init():
    """GDBINIT compatibility alias for 'start' command."""
    pwndbg.commands.start.start()

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def sstart():
    """GDBINIT compatibility alias for 'tbreak __libc_start_main; run' command."""
    gdb.execute('tbreak __libc_start_main')
    gdb.execute('run')

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def main():
    """GDBINIT compatibility alias for 'main' command."""
    pwndbg.commands.start.start()

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def libs():
    """GDBINIT compatibility alias for 'libs' command."""
    pwndbg.commands.vmmap.vmmap()

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def entry_point():
    """GDBINIT compatibility alias to print the entry point.
    See also the 'entry' command."""
    print(hex(int(pwndbg.elf.entry())))
