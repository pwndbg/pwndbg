#!/usr/bin/env python
# -*- coding: utf-8 -*-

import gdb

import pwndbglib.abi
import pwndbglib.arch
import pwndbglib.events
import pwndbglib.memory
import pwndbglib.regs

#: Total number of arguments
argc = None

#: Pointer to argv on the stack
argv = None

#: Pointer to envp on the stack
envp = None

#: Total number of environment variables
envc = None

@pwndbglib.events.start
@pwndbglib.abi.LinuxOnly()
def update():
    global argc
    global argv
    global envp
    global envc

    pwndbglib.arch.update() # :-(

    sp = pwndbglib.regs.sp
    ptrsize = pwndbglib.arch.ptrsize
    ptrbits  = 8 * ptrsize

    try:
        argc = pwndbglib.memory.u(sp, ptrbits)
    except:
        return

    sp += ptrsize

    argv = sp

    while pwndbglib.memory.u(sp, ptrbits):
        sp += ptrsize

    sp += ptrsize

    envp = sp

    envc = 0
    try:
        while pwndbglib.memory.u(sp, ptrbits):
            sp += ptrsize
            envc += 1
    except gdb.MemoryError:
        pass
