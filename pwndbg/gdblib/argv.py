import gdb

import pwndbg.gdblib.abi
import pwndbg.gdblib.arch
import pwndbg.gdblib.events
import pwndbg.gdblib.memory
import pwndbg.gdblib.regs

#: Total number of arguments
argc = None

#: Pointer to argv on the stack
argv = None

#: Pointer to envp on the stack
envp = None

#: Total number of environment variables
envc = None


@pwndbg.gdblib.events.start
@pwndbg.gdblib.abi.LinuxOnly()
def update():
    global argc
    global argv
    global envp
    global envc

    pwndbg.gdblib.arch_mod.update()  # :-(

    sp = pwndbg.gdblib.regs.sp
    ptrsize = pwndbg.gdblib.arch.ptrsize
    ptrbits = 8 * ptrsize

    try:
        argc = pwndbg.gdblib.memory.u(sp, ptrbits)
    except Exception:
        return

    sp += ptrsize

    argv = sp

    while pwndbg.gdblib.memory.u(sp, ptrbits):
        sp += ptrsize

    sp += ptrsize

    envp = sp

    envc = 0
    try:
        while pwndbg.gdblib.memory.u(sp, ptrbits):
            sp += ptrsize
            envc += 1
    except gdb.MemoryError:
        pass
