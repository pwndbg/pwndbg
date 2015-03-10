import gdb
import string
import pwndbg.symbol
import pwndbg.memory
import pwndbg.color
import pwndbg.types
import pwndbg.strings
import pwndbg.disasm
import pwndbg.memoize
import pwndbg.arch
import string

@pwndbg.memoize.reset_on_stop
def enhance(value):
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
            retval = '%s (%r)' % (retval, packed.decode())

        return retval

    else:
        # It's mapped memory, or we can at least read it.
        # Try to find out if it's a string.
        data = None
        if page and page.execute:
            data = pwndbg.disasm.get(value, 1)[0].asm

            # However, if it contains bad instructions, bail
            if '.byte' in data or '.long' in data:
                data = None

        if data is None:
            data = pwndbg.strings.get(value) or None
            if data:
                data = repr(data)

        if data is None:
            data = pwndbg.memory.poi(pwndbg.types.pvoid, value)

            # Try to unpack the value as a string
            try:
                packed = pwndbg.arch.pack(int(data))
                if all(c in string.printable.encode('utf-8') for c in packed):
                    data = repr(packed.decode())
            except:
                data = str(data)

    colored = pwndbg.color.get(value)

    if data and name:   return "%s (%s: %s)" % (colored, name, data)
    elif name:          return "%s (%s)" % (colored, name)
    elif data:          return "%s (%s)" % (colored, data)

    return colored

