#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Launches the target process after setting a breakpoint at a convenient
entry point.
"""
import gdb
import pwndbg.commands
import pwndbg.symbol
import pwndbg.events
import pwndbg.elf

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
                "_init",
                pwndbg.elf.entry()]

    for address in filter(bool, map(pwndbg.symbol.address, symbols)):
        if address:
            b = gdb.Breakpoint('*%#x' % address, temporary=True)
            gdb.execute(run, from_tty=False, to_string=True)
            break

    else:
        entry(*a)


@pwndbg.commands.Command
def entry(*a):
    """
    Set a breakpoint at the first instruction executed in
    the target binary.
    """
    global break_on_first_instruction
    break_on_first_instruction = True
    run = 'run ' + ' '.join(a)
    gdb.execute(run, from_tty=False, to_string=True)
