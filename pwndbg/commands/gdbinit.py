#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Compatibility functionality for GDBINIT users.

https://github.com/gdbinit/Gdbinit/blob/master/gdbinit
"""
from __future__ import print_function
import gdb
import pwndbg.commands

@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.Command
def init():
    """GDBINIT compatibility alias for 'start' command."""
    pwndbg.commands.start.start()

@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.Command
def sstart():
    """GDBINIT compatibility alias for 'tbreak __libc_start_main; run' command."""
    gdb.execute('tbreak __libc_start_main')
    gdb.execute('run')

@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.Command
def main():
    """GDBINIT compatibility alias for 'start' command."""
    pwndbg.commands.start.start()

@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.Command
def libs():
    """GDBINIT compatibility alias for 'start' command."""
    pwndbg.commands.vmmap.vmmap()

@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.Command
def entry_point():
    """GDBINIT compatibility alias to print the entry point.
    See also the 'entry' command."""
    print(hex(pwndbg.elf.entry()))

