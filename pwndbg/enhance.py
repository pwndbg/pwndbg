import gdb
import string
import pwndbg.symbol
import pwndbg.memory
import pwndbg.color
import pwndbg.typeinfo
import pwndbg.strings
import pwndbg.disasm
import pwndbg.memoize
import pwndbg.arch
import string

bad_instrs = [
'.byte',
'.long',
'rex.R',
'rex.XB',
'.inst',
'(bad)'
]

def good_instr(i):
    return not any(bad in i for bad in bad_instrs)

# @pwndbg.memoize.reset_on_stop
def enhance(value):
    """
    Given the last pointer in a chain, attempt to characterize

    Note that 'the last pointer in a chain' may not at all actually be a pointer.

    Additionally, optimizations are made based on various sources of data for
    'value'. For example, if it is set to RWX, we try to get information on whether
    it resides on the stack, or in a RW section that *happens* to be RWX, to
    determine which order to print the fields.
    """
    value = int(value)

    name = pwndbg.symbol.get(value) or None
    page = pwndbg.vmmap.find(value)

    # If it's not in a page we know about, try to dereference
    # it anyway just to test.
    can_read = True
    if not page and None == pwndbg.memory.peek(value):
        can_read = False

    if not can_read:
        retval = hex(int(value))

        # Try to unpack the value as a string
        packed = pwndbg.arch.pack(int(value))
        if all(c in string.printable.encode('utf-8') for c in packed):
            if len(retval) > 4:
                retval = '%s (%r)' % (retval, str(packed.decode('ascii', 'ignore')))

        return retval

    # It's mapped memory, or we can at least read it.
    # Try to find out if it's a string.
    instr  = None
    exe    = page and page.execute
    rwx    = page and page.rwx

    if exe:
        instr = pwndbg.disasm.get(value, 1)[0].asm

        # However, if it contains bad instructions, bail
        if not good_instr(instr):
            instr = None

    szval = pwndbg.strings.get(value) or None
    if szval and len(szval) > 5:
        szval = repr(szval)
    else:
        szval = None

    intval  = int(pwndbg.memory.poi(pwndbg.typeinfo.pvoid, value))
    intval0 = intval
    if 0 <= intval < 10:
        intval = str(intval)
    else:
        intval = hex(int(intval & pwndbg.arch.ptrmask))

    retval = []

    # print([instr,intval0,szval])

    # If it's on the stack, don't display it as code in a chain.
    if instr and 'stack' in page.objfile:
        retval = [intval, szval]

    # If it's RWX but a small value, don't display it as code in a chain.
    elif instr and rwx and intval0 < 0x1000:
        retval = [intval, szval]

    # If it's an instruction and *not* RWX, display it unconditionally
    elif instr and exe:
        if not rwx:
            retval = [instr]
        else:
            retval = [instr, intval, szval]

    # Otherwise strings have preference
    elif szval:
        if len(szval) < pwndbg.arch.ptrsize:
            retval = [szval, intval]
        else:
            retval = [szval]

    # And then integer
    else:
        retval = [intval]


    retval = tuple(filter(lambda x: x is not None, retval))

    if len(retval) == 0:
        return "???"

    if len(retval) == 1:
        return retval[0]

    return retval[0] + ' /* {} */'.format('; '.join(retval[1:]))