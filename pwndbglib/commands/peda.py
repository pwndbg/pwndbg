#!/usr/bin/env python
# -*- coding: utf-8 -*-

import argparse

import gdb

import pwndbglib.auxv
import pwndbglib.color.message as message
import pwndbglib.commands
import pwndbglib.commands.context
import pwndbglib.commands.telescope
import pwndbglib.proc


@pwndbglib.commands.ArgparsedCommand("Gets the current file.")
@pwndbglib.commands.OnlyWhenRunning
def getfile():
    print(repr(pwndbglib.auxv.get().AT_EXECFN))

@pwndbglib.commands.ArgparsedCommand("Get the pid.")
@pwndbglib.commands.OnlyWhenRunning
def getpid():
    print(pwndbglib.proc.pid)


parser = argparse.ArgumentParser(description='Continue execution until an address or function.')
parser.add_argument('target', type=str, help='Address or function to stop execution at')

@pwndbglib.commands.ArgparsedCommand(parser)
def xuntil(target):
    try:
        addr = int(target,0)
        
        if not pwndbglib.memory.peek(addr):
            print(message.error('Invalid address %#x' % addr))
            return

        spec = "*%#x" % (addr)
    except (TypeError, ValueError):
        #The following gdb command will throw an error if the symbol is not defined.
        try:
            result = gdb.execute('info address %s' % target, to_string=True, from_tty=False)
        except gdb.error:
            print(message.error("Unable to resolve %s" % target))
            return    
        spec = target

    b = gdb.Breakpoint(spec, temporary=True)
    if pwndbglib.proc.alive:
        gdb.execute("continue", from_tty=False)
    else:
        gdb.execute("run", from_tty=False)

xinfo = pwndbglib.commands.context.context
xprint = pwndbglib.commands.telescope.telescope
