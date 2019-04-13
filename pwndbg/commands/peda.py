#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import argparse
import sys

import gdb

import pwndbg.auxv
import pwndbg.color.message as message
import pwndbg.commands
import pwndbg.commands.context
import pwndbg.commands.telescope
import pwndbg.proc


@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def getfile():
    print(repr(pwndbg.auxv.get().AT_EXECFN))

@pwndbg.commands.Command
@pwndbg.commands.OnlyWhenRunning
def getpid():
    print(pwndbg.proc.pid)


parser = argparse.ArgumentParser(description='Continue execution until an address or function.')
parser.add_argument('target', help='Address or function to stop execution at')


@pwndbg.commands.ArgparsedCommand(parser)
def xuntil(target):
    addr = int(target)

    if not pwndbg.memory.peek(addr):
        print(message.error('Invalid address %#x' % addr))
        return

    spec = "*%#x" % (addr)
    b = gdb.Breakpoint(spec, temporary=True)
    if pwndbg.proc.alive:
        gdb.execute("continue", from_tty=False)
    else:
        gdb.execute("run", from_tty=False)

xinfo = pwndbg.commands.context.context
xprint = pwndbg.commands.telescope.telescope
