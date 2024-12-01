"""
Shellcode

This module implements functionality that allows for the execution of a small
amount of code in the context of the inferior.

"""

from __future__ import annotations

import gdb
import pwnlib.asm
import pwnlib.shellcraft

import pwndbg
import pwndbg.aglib.arch
import pwndbg.aglib.memory
import pwndbg.aglib.regs
import pwndbg.aglib.vmmap
import pwndbg.gdblib.prompt
import pwndbg.lib.regs


def _get_syscall_return_value():
    """
    Reads the value corresponding to the return value of a syscall that has
    just returned.
    """

    register_set = pwndbg.lib.regs.reg_sets[pwndbg.aglib.arch.current]
    return pwndbg.aglib.regs[register_set.retval]


def exec_syscall(
    syscall,
    arg0=None,
    arg1=None,
    arg2=None,
    arg3=None,
    arg4=None,
    arg5=None,
    arg6=None,
    disable_breakpoints=False,
):
    """
    Tries executing the given syscall in the context of the inferior.
    """

    # Build machine code that runs the requested syscall.
    syscall_asm = pwnlib.shellcraft.syscall(syscall, arg0, arg1, arg2, arg3, arg4, arg5)
    syscall_bin = pwnlib.asm.asm(syscall_asm)

    # Run the syscall and pass its return value onward to the caller.
    return exec_shellcode(
        syscall_bin,
        restore_context=True,
        capture=_get_syscall_return_value,
        disable_breakpoints=disable_breakpoints,
    )


def exec_shellcode(blob, restore_context=True, capture=None, disable_breakpoints=False):
    """
    Tries executing the given blob of machine code in the current context of the
    inferior, optionally restoring the values of the registers as they were
    before the shellcode ran, as a means to allow for execution of the inferior
    to continue uninterrupted. The value of the program counter is always
    restored.

    Additionally, the caller may specify an object to be called before the
    context is restored, so that information stored in the registers after the
    shellcode finishes can be retrieved. The return value of that call will be
    returned by this function.

    # Safety
    Seeing as this function injects code directly into the inferior and runs it,
    the caller must be careful to inject code that will (1) terminate and (2)
    not cause the inferior to misbehave. Otherwise, it is fairly easy to crash
    or currupt the memory in the inferior.
    """

    register_set = pwndbg.lib.regs.reg_sets[pwndbg.aglib.arch.current]
    preserve_set = register_set.gpr + register_set.args + (register_set.pc, register_set.stack)

    registers = {reg: pwndbg.aglib.regs[reg] for reg in preserve_set}
    starting_address = registers[register_set.pc]

    # Make sure the blob fits in the rest of the space we have in this page.
    #
    # NOTE: Technically, we could actually use anything from the whole page to
    # all of the pages currently mapped as executable for this. There is no
    # technical limitation stopping us from doing that, but seeing as doing it
    # is harder to make sure it works correctly, we don't (for now, at least).
    page = pwndbg.aglib.vmmap.find(starting_address)
    assert page is not None

    clearance = page.end - len(blob) - 1
    if clearance < 0:
        # The page isn't large enough to hold our shellcode.
        raise RuntimeError(
            f"Not enough space to execute code as inferior: \
            need at least {len(blob)} bytes, have {clearance} bytes available"
        )

    # Swap the code in the range with our shellcode.
    existing_code = pwndbg.aglib.memory.read(starting_address, len(blob))
    pwndbg.aglib.memory.write(starting_address, blob)

    # Disable breakpoints.
    #
    # We might not want to hit any breakpoints that aren't the ones that are
    # strictly necessary for this function to run to completion. So, if
    # requested, we temporarily disable breakpoints during the shellcode
    re_enable_list = []
    for bp in gdb.breakpoints():
        if bp.enabled and disable_breakpoints:
            bp.enabled = False
            re_enable_list.append(bp)

    # The continue we use here will trigger an event that would get the context
    # prompt to show, regardless of the circumstances. We don't want that, so
    # we preserve the state of the context skip.
    would_skip_context = pwndbg.gdblib.prompt.context_shown

    # Execute.
    target_address = starting_address + len(blob)
    bp = gdb.Breakpoint(f"*{target_address:#x}", internal=True, temporary=True)
    bp.silent = True
    gdb.execute("continue")

    # Restore the state of the context skip.
    pwndbg.gdblib.prompt.context_shown = would_skip_context

    # Re-enable breakpoints.
    for bp in re_enable_list:
        bp.enabled = True

    # Make sure we're in the right place.
    assert pwndbg.aglib.regs.pc == target_address

    # Give the caller a chance to collect information from the environment
    # before any of the context gets restored.
    captured = None
    if capture is not None:
        captured = capture()

    # Restore the code and the program counter and, if requested, the rest of
    # the registers.
    pwndbg.aglib.memory.write(starting_address, existing_code)
    setattr(pwndbg.aglib.regs, register_set.pc, starting_address)
    if restore_context:
        for reg, val in registers.items():
            setattr(pwndbg.aglib.regs, reg, val)

    return captured
