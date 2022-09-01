import gdb

import pwndbg.abi
import pwndbg.gdb.arch
import pwndbg.gdb.events
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


@pwndbg.gdb.events.start
@pwndbg.abi.LinuxOnly()
def update():
    global argc
    global argv
    global envp
    global envc

    pwndbg.gdb.arch_mod.update()  # :-(

    sp = pwndbg.regs.sp
    ptrsize = pwndbg.gdb.arch.ptrsize
    ptrbits = 8 * ptrsize

    try:
        argc = pwndbg.memory.u(sp, ptrbits)
    except Exception:
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
