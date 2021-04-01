#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Launches the target process after setting a breakpoint at a convenient
entry point.
"""
import argparse
from shlex import quote

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


parser = argparse.ArgumentParser(description="""
    Set a breakpoint at a convenient location in the binary,
    generally 'main', 'init', or the entry point.""")
parser.add_argument("args", nargs="*", type=str, default=None, help="The arguments to run the binary with.")
@pwndbg.commands.ArgparsedCommand(parser)
def start(args=None):
    if args is None:
        args = []
    """
    Set a breakpoint at a convenient location in the binary,
    generally 'main', 'init', or the entry point.
    """
    run = 'run ' + ' '.join(args)

    symbols = ["main",
                "_main",
                "start",
                "_start",
                "init",
                "_init"]

    for symbol in symbols:
        address = pwndbg.symbol.address(symbol, allow_unmapped=True)

        if not address:
            continue

        b = gdb.Breakpoint(symbol, temporary=True)
        gdb.execute(run, from_tty=False, to_string=True)
        return

    # Try a breakpoint at the binary entry
    entry(args)


parser = argparse.ArgumentParser(description="""
    Set a breakpoint at the first instruction executed in
    the target binary.
    """)
parser.add_argument("args", nargs="*", type=str, default=None, help="The arguments to run the binary with.")
@pwndbg.commands.ArgparsedCommand(parser)
@pwndbg.commands.OnlyWithFile
def entry(args=None):
    if args is None:
        arg = []
    """
    Set a breakpoint at the first instruction executed in
    the target binary.
    """
    global break_on_first_instruction
    break_on_first_instruction = True
    run = 'run ' + ' '.join(map(quote, args))
    gdb.execute(run, from_tty=False)
