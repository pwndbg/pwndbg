from __future__ import annotations

import pwndbg
import pwndbg.aglib.arch
import pwndbg.aglib.memory
import pwndbg.aglib.regs
import pwndbg.aglib.typeinfo
from pwndbg.dbg import EventType

#: Total number of arguments
argc_numbers: int = None

#: Pointer to argv on the stack
argv_ptr: int = None

#: Pointer to envp on the stack
envp_ptr: int = None

#: Total number of environment variables
envc_numbers: int = None


@pwndbg.dbg.event_handler(EventType.START)
def update() -> None:
    if not pwndbg.dbg.selected_inferior().is_linux():
        return None

    # FIXME: consider implementing priorities in `pwndbg.dbg.event_handler`,
    pwndbg.aglib.typeinfo.update()  # :-(
    pwndbg.aglib.arch_mod.update()  # :-(

    global argc_numbers
    global argv_ptr
    global envp_ptr
    global envc_numbers

    sp = pwndbg.aglib.regs.sp
    ptrsize = pwndbg.aglib.arch.ptrsize
    ptrbits = 8 * ptrsize

    try:
        argc_numbers = pwndbg.aglib.memory.u(sp, ptrbits)
    except Exception:
        return None

    sp += ptrsize
    argv_ptr = sp

    while pwndbg.aglib.memory.u(sp, ptrbits):
        sp += ptrsize

    sp += ptrsize
    envp_ptr = sp

    envc_numbers = 0
    try:
        while pwndbg.aglib.memory.u(sp, ptrbits):
            sp += ptrsize
            envc_numbers += 1
    except pwndbg.dbg_mod.Error:
        pass


def argv(number: int) -> pwndbg.dbg_mod.Value | None:
    global argc_numbers
    global argv_ptr

    if number > argc_numbers:
        return None

    ppchar = pwndbg.aglib.typeinfo.pchar.pointer()
    argv = pwndbg.dbg.selected_inferior().create_value(argv_ptr, ppchar)
    return (argv + number).dereference()


def envp(number: int) -> pwndbg.dbg_mod.Value | None:
    global envc_numbers
    global envp_ptr

    if number > envc_numbers:
        return None

    ppchar = pwndbg.aglib.typeinfo.pchar.pointer()
    envp = pwndbg.dbg.selected_inferior().create_value(envp_ptr, ppchar)
    return (envp + number).dereference()


def environ(name: str) -> pwndbg.dbg_mod.Value | None:
    global envc_numbers
    global envp_ptr

    if not name:
        return None

    name += "="
    ppchar = pwndbg.aglib.typeinfo.pchar.pointer()
    envp = pwndbg.dbg.selected_inferior().create_value(envp_ptr, ppchar)

    for i in range(envc_numbers):
        ptr = (envp + i).dereference()
        sz = ptr.string()
        if sz.startswith(name):
            return ptr

    return None
