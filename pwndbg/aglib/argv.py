from __future__ import annotations

import pwndbg
import pwndbg.aglib.arch
import pwndbg.aglib.memory
import pwndbg.aglib.regs
import pwndbg.aglib.typeinfo
from pwndbg.dbg import EventType

#: Total number of arguments
_argc_numbers: int = None

#: Pointer to argv on the stack
_argv_ptr: int = None

#: Pointer to envp on the stack
_envp_ptr: int = None

#: Total number of environment variables
_envc_numbers: int = None

# Internal stack ptr
_stack_ptr: int = None
_was_updated = False


@pwndbg.dbg.event_handler(EventType.START)
def update() -> None:
    if not pwndbg.dbg.selected_inferior().is_linux():
        return None

    global _stack_ptr
    global _was_updated
    # Captures the current stack pointer (SP) at the time of event START.
    # Note: This won't provide the SP value from the `_start` function
    # when attaching to an already running process, as `_start` has
    # already executed in that case.
    _stack_ptr = int(pwndbg.dbg.selected_frame().regs().by_name("sp"))
    _was_updated = False


def update_state() -> None:
    global _was_updated
    global _stack_ptr
    global _argc_numbers
    global _argv_ptr
    global _envp_ptr
    global _envc_numbers

    if _was_updated:
        return None
    _was_updated = True

    sp = _stack_ptr
    ptrsize = pwndbg.aglib.arch.ptrsize
    ptrbits = 8 * ptrsize

    try:
        _argc_numbers = pwndbg.aglib.memory.u(sp, ptrbits)
    except pwndbg.dbg_mod.Error:
        return None

    sp += ptrsize
    _argv_ptr = sp

    while pwndbg.aglib.memory.u(sp, ptrbits):
        sp += ptrsize

    sp += ptrsize
    _envp_ptr = sp

    _envc_numbers = 0
    try:
        while pwndbg.aglib.memory.u(sp, ptrbits):
            sp += ptrsize
            _envc_numbers += 1
    except pwndbg.dbg_mod.Error:
        pass


def argc() -> int:
    update_state()
    global _argc_numbers
    return _argc_numbers


def argv(number: int) -> pwndbg.dbg_mod.Value | None:
    update_state()

    global _argc_numbers
    global _argv_ptr

    if number > _argc_numbers:
        return None

    ppchar = pwndbg.aglib.typeinfo.pchar.pointer()
    argv = pwndbg.dbg.selected_inferior().create_value(_argv_ptr, ppchar)
    return (argv + number).dereference()


def envc() -> int:
    update_state()
    global _envc_numbers
    return _envc_numbers


def envp(number: int) -> pwndbg.dbg_mod.Value | None:
    update_state()

    global _envc_numbers
    global _envp_ptr

    if number > _envc_numbers:
        return None

    ppchar = pwndbg.aglib.typeinfo.pchar.pointer()
    envp = pwndbg.dbg.selected_inferior().create_value(_envp_ptr, ppchar)
    return (envp + number).dereference()


def environ(name: str) -> pwndbg.dbg_mod.Value | None:
    update_state()

    global _envc_numbers
    global _envp_ptr

    if not name:
        return None

    name += "="
    ppchar = pwndbg.aglib.typeinfo.pchar.pointer()
    envp = pwndbg.dbg.selected_inferior().create_value(_envp_ptr, ppchar)

    for i in range(_envc_numbers):
        ptr = (envp + i).dereference()
        sz = ptr.string()
        if sz.startswith(name):
            return ptr

    return None
