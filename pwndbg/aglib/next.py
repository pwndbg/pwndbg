"""
Commands for setting temporary breakpoints on the next
instruction of some type (call, branch, etc.)
"""

from __future__ import annotations

import re
from itertools import chain

import capstone

import pwndbg.aglib.disasm
import pwndbg.aglib.proc
import pwndbg.aglib.regs
from pwndbg.color import message
from pwndbg.dbg import BreakpointLocation

interrupts = {capstone.CS_GRP_INT}


def next_int(address=None):
    """
    If there is a syscall in the current basic black,
    return the instruction of the one closest to $PC.

    Otherwise, return None.
    """
    if address is None:
        ins = pwndbg.aglib.disasm.one(pwndbg.aglib.regs.pc)
        if not ins:
            return None
        address = ins.next

    ins = pwndbg.aglib.disasm.one(address)
    while ins:
        if ins.jump_like:
            return None
        elif ins.groups & interrupts:
            return ins
        ins = pwndbg.aglib.disasm.one(ins.next)

    return None


def next_branch(address=None):
    if address is None:
        ins = pwndbg.aglib.disasm.one(pwndbg.aglib.regs.pc)
        if not ins:
            return None
        address = ins.next

    ins = pwndbg.aglib.disasm.one(address)
    while ins:
        if ins.jump_like:
            return ins
        ins = pwndbg.aglib.disasm.one(ins.next)

    return None


def next_matching_until_branch(address=None, mnemonic=None, op_str=None):
    """
    Finds the next instruction that matches the arguments between the given
    address and the branch closest to it.
    """
    if address is None:
        address = pwndbg.aglib.regs.pc

    ins = pwndbg.aglib.disasm.one(address)
    while ins:
        # Check whether or not the mnemonic matches if it was specified
        mnemonic_match = ins.mnemonic.casefold() == mnemonic.casefold() if mnemonic else True

        # Check whether or not the operands match if they were specified
        op_str_match = True
        if op_str is not None:
            op_str_match = False

            # Remove whitespace and fold the case of both targets.
            ops = "".join(ins.op_str.split()).casefold()
            if isinstance(op_str, str):
                op_str = "".join(op_str.split()).casefold()
            elif isinstance(op_str, list):
                op_str = "".join(chain.from_iterable(op.split() for op in op_str)).casefold()
            else:
                raise ValueError("op_str value is of an unsupported type")
            op_str_match = ops == op_str

        # If all of the parameters that were specified match, this is the
        # instruction we want to stop at.
        if mnemonic_match and op_str_match:
            return ins

        if ins.jump_like:
            # No matching instruction until the next branch, and we're
            # not trying to match the branch instruction itself.
            return None

        ins = pwndbg.aglib.disasm.one(ins.next)
    return None


async def break_next_branch(ec: pwndbg.dbg_mod.ExecutionController, address=None):
    ins = next_branch(address)

    proc = pwndbg.dbg.selected_inferior()
    if ins:
        bp = proc.break_at(BreakpointLocation(ins.address), internal=True)
        await ec.cont(bp)
        return ins


async def break_next_interrupt(ec: pwndbg.dbg_mod.ExecutionController, address=None):
    ins = next_int(address)

    proc = pwndbg.dbg.selected_inferior()
    if ins:
        bp = proc.break_at(BreakpointLocation(ins.address), internal=True)
        await ec.cont(bp)
        bp.remove()
        return ins


async def break_next_call(ec: pwndbg.dbg_mod.ExecutionController, symbol_regex=None):
    symbol_regex = re.compile(symbol_regex) if symbol_regex else None

    while pwndbg.aglib.proc.alive:
        # Break on signal as it may be a segfault
        if pwndbg.aglib.proc.stopped_with_signal:
            return

        ins = await break_next_branch(ec)

        if not ins:
            break

        # continue if not a call
        if not ins.call_like:
            continue

        # return call if we:
        # 1) don't search for a symbol
        # 2) match target address
        # 3) match symbol name
        if (
            not symbol_regex
            or (ins.target_const and symbol_regex.match(hex(ins.target)))
            or (ins.target_string and symbol_regex.match(ins.target_string))
        ):
            return ins


async def break_next_ret(ec: pwndbg.dbg_mod.ExecutionController, address=None):
    while pwndbg.aglib.proc.alive:
        # Break on signal as it may be a segfault
        if pwndbg.aglib.proc.stopped_with_signal:
            return

        ins = await break_next_branch(ec, address)

        if not ins:
            break

        if capstone.CS_GRP_RET in ins.groups:
            return ins


async def break_on_next_matching_instruction(
    ec: pwndbg.dbg_mod.ExecutionController, mnemonic=None, op_str=None
) -> bool:
    """
    Breaks on next instuction that matches the arguments.
    """
    # Make sure we have something to break on.
    if mnemonic is None and op_str is None:
        return False

    proc = pwndbg.dbg.selected_inferior()
    while pwndbg.aglib.proc.alive:
        ins = next_matching_until_branch(mnemonic=mnemonic, op_str=op_str)
        if ins is not None:
            if ins.address != pwndbg.aglib.regs.pc:
                print("Found instruction")
                # Only set breakpoints at a different PC location, otherwise we
                # will continue until we hit a breakpoint that's not related to
                # this opeeration, or the program halts.
                bp = proc.break_at(BreakpointLocation(ins.address), internal=True)
                await ec.cont(bp)
                bp.remove()
                return ins
            else:
                # We don't want to be spinning in place, nudge execution forward
                # and try again.
                pass
        else:
            # Move to the next branch instruction.
            print("Moving to next branch")
            nb = next_branch(pwndbg.aglib.regs.pc)
            if nb is not None:
                if nb.address != pwndbg.aglib.regs.pc:
                    # Stop right at the next branch instruction.
                    bp = proc.break_at(BreakpointLocation(nb.address), internal=True)
                    await ec.cont(bp)
                    bp.remove()
                else:
                    # Nudge execution so we take the branch we're on top of.
                    pass

        if pwndbg.aglib.proc.alive:
            await ec.single_step()

        # Break on signal as it may be a segfault
        if pwndbg.aglib.proc.stopped_with_signal:
            return False

    return False


async def break_on_program_code(ec: pwndbg.dbg_mod.ExecutionController) -> bool:
    """
    Breaks on next instruction that belongs to process' objfile code

    :return: True for success, False when process ended or when pc is not at the code or if a signal occurred
    """
    exe = pwndbg.aglib.proc.exe
    binary_exec_page_ranges = tuple(
        (p.start, p.end) for p in pwndbg.aglib.vmmap.get() if p.objfile == exe and p.execute
    )

    pc = pwndbg.aglib.regs.pc
    for start, end in binary_exec_page_ranges:
        if start <= pc < end:
            print(message.error("The pc is already at the binary objfile code. Not stepping."))
            return False

    proc = pwndbg.aglib.proc
    regs = pwndbg.aglib.regs

    while proc.alive:
        # Break on signal as it may be a segfault
        if proc.stopped_with_signal:
            return False

        await ec.single_step()

        for start, end in binary_exec_page_ranges:
            if start <= regs.pc < end:
                return True

    return False


async def break_on_next(ec: pwndbg.dbg_mod.ExecutionController, address=None) -> None:
    address = address or pwndbg.aglib.regs.pc
    ins = pwndbg.aglib.disasm.one(address)

    proc = pwndbg.dbg.selected_inferior()
    bp = proc.break_at(BreakpointLocation(ins.address + ins.size), internal=True)
    await ec.cont(bp)
    bp.remove()
