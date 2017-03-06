#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import gdb

import pwndbg.arch
import pwndbg.events
import pwndbg.memory
import pwndbg.regs

#: Total number of arguments
argc = None

#: Pointer to argv on the stack
argv = None

#: Pointer to envp on the stack
envp = None

#: Total number of environment variables
envc = None

@pwndbg.events.start
def update():
    global argc
    global argv
    global envp
    global envc

    pwndbg.arch.update() # :-(

    sp = pwndbg.regs.sp
    ptrsize = pwndbg.arch.ptrsize
    ptrbits  = 8 * ptrsize

    try:
        argc = pwndbg.memory.u(sp, ptrbits)
    except:
        return

    sp += ptrsize

    argv = sp

    while pwndbg.memory.u(sp, ptrbits):
        sp += ptrsize

    sp += ptrsize

    envp = sp

    envc = 0
    try:
        while pwndbg.memory.u(sp, ptrbits):
            sp += ptrsize
            envc += 1
    except gdb.MemoryError:
        pass
