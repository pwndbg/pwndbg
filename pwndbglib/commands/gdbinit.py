#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Compatibility functionality for GDBINIT users.

https://github.com/gdbinit/Gdbinit/blob/master/gdbinit
"""

import gdb

import pwndbglib.commands


@pwndbglib.commands.ArgparsedCommand("GDBINIT compatibility alias for 'start' command.")
@pwndbglib.commands.OnlyWhenRunning
def init():
    """GDBINIT compatibility alias for 'start' command."""
    pwndbglib.commands.start.start()

@pwndbglib.commands.ArgparsedCommand("GDBINIT compatibility alias for 'tbreak __libc_start_main; run' command.")
@pwndbglib.commands.OnlyWhenRunning
def sstart():
    """GDBINIT compatibility alias for 'tbreak __libc_start_main; run' command."""
    gdb.execute('tbreak __libc_start_main')
    gdb.execute('run')

@pwndbglib.commands.ArgparsedCommand("GDBINIT compatibility alias for 'main' command.")
@pwndbglib.commands.OnlyWhenRunning
def main():
    """GDBINIT compatibility alias for 'main' command."""
    pwndbglib.commands.start.start()

@pwndbglib.commands.ArgparsedCommand("GDBINIT compatibility alias for 'libs' command.")
@pwndbglib.commands.OnlyWhenRunning
def libs():
    """GDBINIT compatibility alias for 'libs' command."""
    pwndbglib.commands.vmmap.vmmap()

@pwndbglib.commands.ArgparsedCommand("GDBINIT compatibility alias to print the entry point. See also the 'entry' command.")
@pwndbglib.commands.OnlyWhenRunning
def entry_point():
    """GDBINIT compatibility alias to print the entry point.
    See also the 'entry' command."""
    print(hex(int(pwndbglib.elf.entry())))
