"""
Shellcode

This module implements functionality that allows for the execution of a small
amount of code in the context of the inferior.

"""

from __future__ import annotations

import contextlib
from asyncio import CancelledError
from typing import Iterator

import pwnlib.shellcraft

import pwndbg
import pwndbg.aglib.arch
import pwndbg.aglib.asm
import pwndbg.aglib.memory
import pwndbg.aglib.regs
import pwndbg.aglib.vmmap
from pwndbg.dbg import BreakpointLocation
from pwndbg.dbg import ExecutionController


def _get_syscall_return_value():
    """
    Reads the value corresponding to the return value of a syscall that has
    just returned.
    """

    register_set = pwndbg.lib.regs.reg_sets[pwndbg.aglib.arch.name]
    # FIXME: `retval` is syscall abi? or sysv abi?
    return pwndbg.aglib.regs[register_set.retval]


async def exec_syscall(
    ec: ExecutionController,
    syscall,
    arg0=None,
    arg1=None,
    arg2=None,
    arg3=None,
    arg4=None,
    arg5=None,
):
    """
    Tries executing the given syscall in the context of the inferior.
    """

    # Build machine code that runs the requested syscall.
    syscall_asm = pwnlib.shellcraft.syscall(syscall, arg0, arg1, arg2, arg3, arg4, arg5)
    syscall_bin = pwndbg.aglib.asm.asm(syscall_asm)

    # Run the syscall and pass its return value onward to the caller.
    async with exec_shellcode(
        ec,
        syscall_bin,
    ):
        return _get_syscall_return_value()


@contextlib.contextmanager
def _ctx_code(starting_address: int, blob) -> Iterator[None]:
    # Make sure the blob fits in the rest of the space we have in this page.
    #
    # NOTE: Technically, we could actually use anything from the whole page to
    # all of the pages currently mapped as executable for this. There is no
    # technical limitation stopping us from doing that, but seeing as doing it
    # is harder to make sure it works correctly, we don't (for now, at least).
    page = pwndbg.aglib.vmmap.find(starting_address)
    assert page is not None

    clearance = page.end - starting_address - len(blob) - 1
    if clearance < 0:
        # The page isn't large enough to hold our shellcode.
        raise RuntimeError(
            f"Not enough space to execute code as inferior: \
            need at least {len(blob)} bytes, have {clearance} bytes available"
        )

    # Swap the code in the range with our shellcode.
    existing_code = pwndbg.aglib.memory.read(starting_address, len(blob))
    pwndbg.aglib.memory.write(starting_address, blob)

    try:
        yield
    finally:
        pwndbg.aglib.memory.write(starting_address, existing_code)


@contextlib.contextmanager
def _ctx_registers() -> Iterator[int]:
    register_set = pwndbg.lib.regs.reg_sets[pwndbg.aglib.arch.name]
    preserve_set = register_set.gpr + register_set.args + (register_set.pc, register_set.stack)

    uncached_regs = pwndbg.dbg.selected_frame().regs()
    registers = {reg: int(uncached_regs.by_name(reg)) for reg in preserve_set}
    starting_address = registers[register_set.pc]

    # Advance by one instruction boundary.
    #
    # Some debuggers (LLDB) may fail to write to memory if any of the addresses
    # being written to overlap the program counter. By aiming at the next valid
    # instruction address, we avoid that issue.
    shell_starting_address = starting_address + pwndbg.aglib.arch.instruction_alignment

    # Failing this means our value for `instruction_alignment` is wrong.
    assert shell_starting_address % pwndbg.aglib.arch.instruction_alignment == 0

    try:
        # Jump to the target address in preparation.
        setattr(pwndbg.aglib.regs, register_set.pc, shell_starting_address)

        yield shell_starting_address
    finally:
        # Restore the code and the program counter and, if requested, the rest of
        # the registers.
        setattr(pwndbg.aglib.regs, register_set.pc, starting_address)
        for reg, val in registers.items():
            setattr(pwndbg.aglib.regs, reg, val)


async def _execute_until_addr(ec: ExecutionController, target_address: int) -> None:
    with pwndbg.dbg.selected_inferior().break_at(
        BreakpointLocation(target_address), internal=True
    ) as bp:
        while True:
            try:
                await ec.cont_selected_thread(bp)
                break
            except CancelledError:
                # We probably hit another breakpoint, but in this mode we're
                # supposed to ignore any breakpoints that aren't the one we put
                # at the end of the range, so just retry.
                continue

    assert pwndbg.dbg.selected_frame().pc() == target_address, "Target address is incorrect"


@contextlib.asynccontextmanager
async def exec_shellcode(ec: ExecutionController, blob):
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

    with _ctx_registers() as starting_address:
        target_address = starting_address + len(blob)
        with _ctx_code(starting_address, blob):
            try:
                with pwndbg.dbg.ctx_suspend_events(pwndbg.dbg_mod.EventType.SUSPEND_ALL):
                    await _execute_until_addr(ec, target_address)

                yield
            finally:
                pass
