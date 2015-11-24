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

    argc = pwndbg.memory.u(sp, ptrbits)
    sp += ptrsize

    argv = sp

    while pwndbg.memory.u(sp, ptrbits):
        sp += ptrsize

    sp += ptrsize

    envp = sp

    envc = 0
    while pwndbg.memory.u(sp, ptrbits):
        sp += ptrsize
        envc += 1


