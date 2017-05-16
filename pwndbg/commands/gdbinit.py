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

import pwndbg.commands.vmmap
import pwndbg.commands.start


@pwndbg.commands.AliasCommand(pwndbg.commands.start.start)
def init():
    pass


@pwndbg.commands.AliasCommand(pwndbg.commands.start.start)
def main():
    pass


@pwndbg.commands.ArgparsedCommand("GDBINIT compatibility alias for 'tbreak __libc_start_main; run' command.")
@pwndbg.commands.OnlyWhenRunning
def sstart():
    gdb.execute('tbreak __libc_start_main')
    gdb.execute('run')


@pwndbg.commands.AliasCommand(pwndbg.commands.vmmap.vmmap)
def libs():
    pass


@pwndbg.commands.ArgparsedCommand(
    "GDBINIT compatibility alias to print the entry point. See also the 'entry' command."
)
@pwndbg.commands.OnlyWhenRunning
def entry_point():
    print(hex(int(pwndbg.elf.entry())))
