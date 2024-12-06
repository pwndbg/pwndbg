from __future__ import annotations

import pwndbg
import pwndbg.aglib.arch
import pwndbg.aglib.memory
import pwndbg.aglib.regs
import pwndbg.gdblib.abi
from pwndbg.dbg import EventType

#: Total number of arguments
argc = None

#: Pointer to argv on the stack
argv = None

#: Pointer to envp on the stack
envp = None

#: Total number of environment variables
envc = None


@pwndbg.dbg.event_handler(EventType.START)
@pwndbg.gdblib.abi.LinuxOnly()
def update() -> None:
    global argc
    global argv
    global envp
    global envc

    pwndbg.aglib.arch_mod.update()  # :-(

    sp = pwndbg.aglib.regs.sp
    ptrsize = pwndbg.aglib.arch.ptrsize
    ptrbits = 8 * ptrsize

    try:
        argc = pwndbg.aglib.memory.u(sp, ptrbits)
    except Exception:
        return

    sp += ptrsize

    argv = sp

    while pwndbg.aglib.memory.u(sp, ptrbits):
        sp += ptrsize

    sp += ptrsize

    envp = sp

    envc = 0
    try:
        while pwndbg.aglib.memory.u(sp, ptrbits):
            sp += ptrsize
            envc += 1
    except pwndbg.dbg_mod.Error:
        pass
