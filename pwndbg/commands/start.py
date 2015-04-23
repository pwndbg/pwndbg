#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Launches the target process after setting a breakpoint at a convenient
entry point.
"""
import gdb
import pwndbg.commands
import pwndbg.elf
import pwndbg.events
import pwndbg.symbol

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

    # Try a symbolic breakpoint which GDB will automatically update.
    symbols = {s:pwndbg.symbol.address(s) for s in symbols}

    for name, address in symbols.items():
        if not address:
            continue

        b = gdb.Breakpoint(name, temporary=True)
        gdb.execute(run, from_tty=False, to_string=True)
        return

    # Try a breakpoint at the binary entry
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
