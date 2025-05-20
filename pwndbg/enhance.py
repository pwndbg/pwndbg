"""
Given an address in memory which does not contain a pointer elsewhere
into memory, attempt to describe the data as best as possible.

Currently prints out code, integers, or strings, in a best-effort manner
dependent on page permissions, the contents of the data, and any
supplemental information sources (e.g. active IDA Pro connection).
"""

from __future__ import annotations

import string
from typing import Tuple

import pwndbg
import pwndbg.aglib.arch
import pwndbg.aglib.disasm.disassembly
import pwndbg.aglib.memory
import pwndbg.aglib.strings
import pwndbg.aglib.typeinfo
import pwndbg.aglib.vmmap
import pwndbg.color.enhance as E
import pwndbg.color.memory
import pwndbg.integration
import pwndbg.lib.cache
from pwndbg import color


def format_small_int(value: int) -> str:
    if value < 10:
        return str(value)
    else:
        return hex(value)


def format_small_int_pair(first: int, second: int) -> Tuple[str, str]:
    if first < 10 and second < 10:
        return (str(first), str(second))
    else:
        return (
            hex(first),
            hex(second),
        )


def int_str(value: int) -> str:
    retval = format_small_int(value)

    # Try to unpack the value as a string
    packed = pwndbg.aglib.arch.pack(int(value))
    if all(c in string.printable.encode("utf-8") for c in packed):
        if len(retval) > 4:
            retval = "{} ({!r})".format(retval, str(packed.decode("ascii", "ignore")))

    return retval


# @pwndbg.lib.cache.cache_until("stop")
def enhance(
    value: int,
    code: bool = True,
    safe_linking: bool = False,
    attempt_dereference=True,
    enhance_string_len: int = None,
) -> str:
    """
    Given the last pointer in a chain, attempt to characterize

    Note that 'the last pointer in a chain' may not at all actually be a pointer.

    Additionally, optimizations are made based on various sources of data for
    'value'. For example, if it is set to RWX, we try to get information on whether
    it resides on the stack, or in a RW section that *happens* to be RWX, to
    determine which order to print the fields.

    Arguments:
        value: Value to enhance
        code: Hint that indicates the value may be an instruction
        safe_linking: Whether this chain use safe-linking
        enhance_string_len: The length of string to display for enhancement of the last pointer
    """
    value = int(value)

    page = pwndbg.aglib.vmmap.find(value)

    # If it's not in a page we know about, try to dereference
    # it anyway just to test.
    can_read = True
    if not attempt_dereference or not page or None is pwndbg.aglib.memory.peek(value):
        can_read = False

    # If it's a pointer that we told we cannot deference, then color it accordingly and add symbol if can
    if page and not attempt_dereference:
        return pwndbg.color.memory.get_address_and_symbol(value)

    if not can_read:
        return E.integer(int_str(value))

    # It's mapped memory, or we can at least read it.
    # Try to find out if it's a string.
    instr: str | None = None
    exe = page and page.execute
    rwx = page and page.rwx

    # For the purpose of following pointers, don't display
    # anything on the stack or heap as 'code'
    if "[stack" in page.objfile or "[heap" in page.objfile:
        rwx = exe = False

    # If integration doesn't think it's in a function, don't display it as code.
    if not pwndbg.integration.provider.is_in_function(value):
        rwx = exe = False

    if exe:
        pwndbg_instr = pwndbg.aglib.disasm.disassembly.one(value)
        if pwndbg_instr:
            # For telescoping, we don't want the extra spaces between the mnemonic and operands
            # which are baked in during enhancement. This removes those spaces.
            instr = " ".join(pwndbg_instr.asm_string.split())

    szval = pwndbg.aglib.strings.get(value, maxlen=enhance_string_len) or None
    szval0 = szval
    if szval:
        szval = E.string(repr(szval))

    # Fix for case when we can't read the end address anyway (#946)
    if value + pwndbg.aglib.arch.ptrsize > page.end:
        return E.integer(int_str(value))

    intval = int(pwndbg.aglib.memory.get_typed_pointer_value(pwndbg.aglib.typeinfo.pvoid, value))
    if safe_linking:
        intval ^= value >> 12
    intval0 = intval
    if 0 <= intval < 10:
        intval = E.integer(str(intval))
    else:
        intval = E.integer("%#x" % int(intval & pwndbg.aglib.arch.ptrmask))

    retval = []

    # print([instr,intval0,szval])
    if not code:
        instr = None

    # If it's on the stack, don't display it as code in a chain.
    if instr and "[stack" in page.objfile:
        retval = [intval, szval]

    # If it's RWX but a small value, don't display it as code in a chain.
    elif instr and rwx and intval0 < 0x1000:
        retval = [intval, szval]

    # If it's an instruction and *not* RWX, display it unconditionally
    elif instr and exe:
        if not rwx:
            if szval:
                retval = [instr, szval]
            else:
                retval = [instr]
        else:
            retval = [instr, intval, szval]

    # Otherwise strings have preference
    elif szval:
        if len(szval0) < pwndbg.aglib.arch.ptrsize:
            retval = [intval, szval]
        else:
            retval = [szval]

    # And then integer
    else:
        # It might be a pointer or just a plain integer
        new_page = pwndbg.aglib.vmmap.find(intval0)
        if new_page:
            return pwndbg.color.memory.get_address_and_symbol(intval0)
        else:
            return E.integer(int_str(intval0))

    retval = tuple(filter(lambda x: x is not None, retval))

    if len(retval) == 0:
        return E.unknown("???")

    if len(retval) == 1:
        return retval[0]  # type: ignore[return-value]

    return retval[0] + E.comment(color.strip(f" /* {'; '.join(retval[1:])} */"))  # type: ignore[arg-type]
