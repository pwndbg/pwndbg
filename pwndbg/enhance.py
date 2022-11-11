"""
Given an address in memory which does not contain a pointer elsewhere
into memory, attempt to describe the data as best as possible.

Currently prints out code, integers, or strings, in a best-effort manner
dependent on page permissions, the contents of the data, and any
supplemental information sources (e.g. active IDA Pro connection).
"""

import string

import pwndbg.color as color
import pwndbg.color.enhance as E
import pwndbg.disasm
import pwndbg.gdblib.arch
import pwndbg.gdblib.config
import pwndbg.gdblib.memory
import pwndbg.gdblib.strings
import pwndbg.gdblib.symbol
import pwndbg.gdblib.typeinfo
import pwndbg.lib.memoize
from pwndbg.color.syntax_highlight import syntax_highlight

bad_instrs = [".byte", ".long", "rex.R", "rex.XB", ".inst", "(bad)"]


def good_instr(i):
    return not any(bad in i for bad in bad_instrs)


def int_str(value):
    retval = "%#x" % int(value & pwndbg.gdblib.arch.ptrmask)

    # Try to unpack the value as a string
    packed = pwndbg.gdblib.arch.pack(int(value))
    if all(c in string.printable.encode("utf-8") for c in packed):
        if len(retval) > 4:
            retval = "%s (%r)" % (retval, str(packed.decode("ascii", "ignore")))

    return retval


# @pwndbg.lib.memoize.reset_on_stop
def enhance(value, code=True, safe_linking=False):
    """
    Given the last pointer in a chain, attempt to characterize

    Note that 'the last pointer in a chain' may not at all actually be a pointer.

    Additionally, optimizations are made based on various sources of data for
    'value'. For example, if it is set to RWX, we try to get information on whether
    it resides on the stack, or in a RW section that *happens* to be RWX, to
    determine which order to print the fields.

    Arguments:
        value(obj): Value to enhance
        code(bool): Hint that indicates the value may be an instruction
        safe_linking(bool): Whether this chain use safe-linking
    """
    value = int(value)

    name = pwndbg.gdblib.symbol.get(value) or None
    page = pwndbg.gdblib.vmmap.find(value)

    # If it's not in a page we know about, try to dereference
    # it anyway just to test.
    can_read = True
    if not page or None is pwndbg.gdblib.memory.peek(value):
        can_read = False

    if not can_read:
        return E.integer(int_str(value))

    # It's mapped memory, or we can at least read it.
    # Try to find out if it's a string.
    instr = None
    exe = page and page.execute
    rwx = page and page.rwx

    # For the purpose of following pointers, don't display
    # anything on the stack or heap as 'code'
    if "[stack" in page.objfile or "[heap" in page.objfile:
        rwx = exe = False

    # If IDA doesn't think it's in a function, don't display it as code.
    if pwndbg.ida.available() and not pwndbg.ida.GetFunctionName(value):
        rwx = exe = False

    if exe:
        instr = pwndbg.disasm.one(value)
        if instr:
            instr = "%s %s" % (instr.mnemonic, instr.op_str)
            if pwndbg.gdblib.config.syntax_highlight:
                instr = syntax_highlight(instr)

    szval = pwndbg.gdblib.strings.get(value) or None
    szval0 = szval
    if szval:
        szval = E.string(repr(szval))

    # Fix for case when we can't read the end address anyway (#946)
    if value + pwndbg.gdblib.arch.ptrsize > page.end:
        return E.integer(int_str(value))

    intval = int(pwndbg.gdblib.memory.poi(pwndbg.gdblib.typeinfo.pvoid, value))
    if safe_linking:
        intval ^= value >> 12
    intval0 = intval
    if 0 <= intval < 10:
        intval = E.integer(str(intval))
    else:
        intval = E.integer("%#x" % int(intval & pwndbg.gdblib.arch.ptrmask))

    retval = []

    # print([instr,intval0,szval])
    if not code:
        instr = None

    # If it's on the stack, don't display it as code in a chain.
    if instr and "stack" in page.objfile:
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
        if len(szval0) < pwndbg.gdblib.arch.ptrsize:
            retval = [intval, szval]
        else:
            retval = [szval]

    # And then integer
    else:
        return E.integer(int_str(intval0))

    retval = tuple(filter(lambda x: x is not None, retval))

    if len(retval) == 0:
        return E.unknown("???")

    if len(retval) == 1:
        return retval[0]

    return retval[0] + E.comment(color.strip(" /* {} */".format("; ".join(retval[1:]))))
