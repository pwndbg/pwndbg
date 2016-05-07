#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
import gdb
import sys

import pwndbg.auxv
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

xinfo = pwndbg.commands.context.context
xprint = pwndbg.commands.telescope.telescope
