"""
Commands for setting temporary breakpoints on the next
instruction of some type (call, branch, etc.)
"""

from __future__ import annotations

import re
from itertools import chain

import capstone
import gdb

import pwndbg.gdblib.disasm
import pwndbg.gdblib.events
import pwndbg.gdblib.proc
import pwndbg.gdblib.regs
from pwndbg.color import message

jumps = {capstone.CS_GRP_CALL, capstone.CS_GRP_JUMP, capstone.CS_GRP_RET, capstone.CS_GRP_IRET}

interrupts = {capstone.CS_GRP_INT}


def clear_temp_breaks() -> None:
    if not pwndbg.gdblib.proc.alive:
        for bp in gdb.breakpoints():
            # visible is used instead of internal because older gdb's don't support internal
            if bp.temporary and not bp.visible:
                bp.delete()


def next_int(address=None):
    """
    If there is a syscall in the current basic black,
    return the instruction of the one closest to $PC.

    Otherwise, return None.
    """
    if address is None:
        ins = pwndbg.gdblib.disasm.one(pwndbg.gdblib.regs.pc)
        if not ins:
            return None
        address = ins.next

    ins = pwndbg.gdblib.disasm.one(address)
    while ins:
        ins_groups = set(ins.groups)
        if ins_groups & jumps:
            return None
        elif ins_groups & interrupts:
            return ins
        ins = pwndbg.gdblib.disasm.one(ins.next)

    return None


def next_branch(address=None):
    if address is None:
        ins = pwndbg.gdblib.disasm.one(pwndbg.gdblib.regs.pc)
        if not ins:
            return None
        address = ins.next

    ins = pwndbg.gdblib.disasm.one(address)
    while ins:
        if set(ins.groups) & jumps:
            return ins
        ins = pwndbg.gdblib.disasm.one(ins.next)

    return None


def next_matching_until_branch(address=None, mnemonic=None, op_str=None):
    """
    Finds the next instruction that matches the arguments between the given
    address and the branch closest to it.
    """
    if address is None:
        address = pwndbg.gdblib.regs.pc

    ins = pwndbg.gdblib.disasm.one(address)
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

        if set(ins.groups) & jumps:
            # No matching instruction until the next branch, and we're
            # not trying to match the branch instruction itself.
            return None

        ins = pwndbg.gdblib.disasm.one(ins.next)
    return None


def break_next_branch(address=None):
    ins = next_branch(address)

    if ins:
        gdb.Breakpoint("*%#x" % ins.address, internal=True, temporary=True)
        gdb.execute("continue", from_tty=False, to_string=True)
        return ins


def break_next_interrupt(address=None):
    ins = next_int(address)

    if ins:
        gdb.Breakpoint("*%#x" % ins.address, internal=True, temporary=True)
        gdb.execute("continue", from_tty=False, to_string=True)
        return ins


def break_next_call(symbol_regex=None):
    symbol_regex = re.compile(symbol_regex) if symbol_regex else None

    while pwndbg.gdblib.proc.alive:
        # Break on signal as it may be a segfault
        if pwndbg.gdblib.proc.stopped_with_signal:
            return

        ins = break_next_branch()

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


def break_next_ret(address=None):
    while pwndbg.gdblib.proc.alive:
        # Break on signal as it may be a segfault
        if pwndbg.gdblib.proc.stopped_with_signal:
            return

        ins = break_next_branch(address)

        if not ins:
            break

        if capstone.CS_GRP_RET in ins.groups:
            return ins


def break_on_next_matching_instruction(mnemonic=None, op_str=None) -> bool:
    """
    Breaks on next instuction that matches the arguments.
    """
    # Make sure we have something to break on.
    if mnemonic is None and op_str is None:
        return False

    while pwndbg.gdblib.proc.alive:
        # Break on signal as it may be a segfault
        if pwndbg.gdblib.proc.stopped_with_signal:
            return False

        ins = next_matching_until_branch(mnemonic=mnemonic, op_str=op_str)
        if ins is not None:
            if ins.address != pwndbg.gdblib.regs.pc:
                print("Found instruction")
                # Only set breakpoints at a different PC location, otherwise we
                # will continue until we hit a breakpoint that's not related to
                # this opeeration, or the program halts.
                gdb.Breakpoint("*%#x" % ins.address, internal=True, temporary=True)
                gdb.execute("continue", from_tty=False, to_string=True)
                return ins
            else:
                # We don't want to be spinning in place, nudge execution forward
                # and try again.
                pass
        else:
            # Move to the next branch instruction.
            print("Moving to next branch")
            nb = next_branch(pwndbg.gdblib.regs.pc)
            if nb is not None:
                if nb.address != pwndbg.gdblib.regs.pc:
                    # Stop right at the next branch instruction.
                    gdb.Breakpoint("*%#x" % nb.address, internal=True, temporary=True)
                    gdb.execute("continue", from_tty=False, to_string=True)
                else:
                    # Nudge execution so we take the branch we're on top of.
                    pass

        if pwndbg.gdblib.proc.alive:
            gdb.execute("si")

    return False


def break_on_program_code() -> bool:
    """
    Breaks on next instruction that belongs to process' objfile code

    :return: True for success, False when process ended or when pc is not at the code or if a signal occurred
    """
    exe = pwndbg.gdblib.proc.exe
    binary_exec_page_ranges = tuple(
        (p.start, p.end) for p in pwndbg.gdblib.vmmap.get() if p.objfile == exe and p.execute
    )

    pc = pwndbg.gdblib.regs.pc
    for start, end in binary_exec_page_ranges:
        if start <= pc < end:
            print(message.error("The pc is already at the binary objfile code. Not stepping."))
            return False

    proc = pwndbg.gdblib.proc
    regs = pwndbg.gdblib.regs

    while proc.alive:
        # Break on signal as it may be a segfault
        if proc.stopped_with_signal:
            return False

        gdb.execute("si", from_tty=False, to_string=True)

        for start, end in binary_exec_page_ranges:
            if start <= regs.pc < end:
                return True

    return False


def break_on_next(address=None) -> None:
    address = address or pwndbg.gdblib.regs.pc
    ins = pwndbg.gdblib.disasm.one(address)

    gdb.Breakpoint("*%#x" % (ins.address + ins.size), temporary=True)
    gdb.execute("continue", from_tty=False, to_string=True)
