from __future__ import print_function
import gdb

import pwndbg.arch
import pwndbg.events
import pwndbg.memory
import pwndbg.regs

argc = None
argv = None
envp = None
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

