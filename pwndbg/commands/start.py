#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Launches the target process after setting a breakpoint at a convenient
entry point.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import gdb

import pwndbg.commands
import pwndbg.elf
import pwndbg.events
import pwndbg.symbol

# Py 2 vs Py 3
try:
    from shlex import quote
except ImportError:
    from pipes import quote




break_on_first_instruction = False


@pwndbg.events.start
def on_start():
    global break_on_first_instruction
    if break_on_first_instruction:
        spec = "*%#x" % (int(pwndbg.elf.entry()))
        gdb.Breakpoint(spec, temporary=True)
        break_on_first_instruction = False


@pwndbg.commands.Command
def start(*a):
    """
    Set a breakpoint at a convenient location in the binary,
    generally 'main', 'init', or the entry point.
    """
    run = 'run ' + ' '.join(a)

    symbols = ["main",
                "_main",
                "start",
                "_start",
                "init",
                "_init"]

    for symbol in symbols:
        address = pwndbg.symbol.address(symbol)

        if not address:
            continue

        b = gdb.Breakpoint(symbol, temporary=True)
        gdb.execute(run, from_tty=False, to_string=True)
        return

    # Try a breakpoint at the binary entry
    entry(*a)


@pwndbg.commands.Command
@pwndbg.commands.OnlyWithFile
def entry(*a):
    """
    Set a breakpoint at the first instruction executed in
    the target binary.
    """
    global break_on_first_instruction
    break_on_first_instruction = True
    run = 'run ' + ' '.join(map(quote, a))
    gdb.execute(run, from_tty=False)
