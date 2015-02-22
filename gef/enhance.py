import gdb
import string
import gef.symbol
import gef.memory
import gef.color
import gef.types
import gef.strings
import gef.disasm
import gef.memoize
import gef.arch
import string

@gef.memoize.reset_on_stop
def enhance(value):
    value = int(value)

    name = gef.symbol.get(value) or None
    page = gef.vmmap.find(value)

    # If it's not in a page we know about, try to dereference
    # it anyway just to test.
    can_read = True
    if not page and None == gef.memory.peek(value):
        can_read = False

    if not can_read:
        retval = hex(int(value))

        # Try to unpack the value as a string
        packed = gef.arch.pack(int(value))
        if all(c in string.printable.encode('utf-8') for c in packed):
            retval = '%s (%r)' % (retval, packed.decode())

        return retval

    else:
        # It's mapped memory, or we can at least read it.
        # Try to find out if it's a string.
        data = None
        if page and page.execute:
            data = gef.disasm.get(value, 1)[0].asm

            # However, if it contains bad instructions, bail
            if '.byte' in data or '.long' in data:
                data = None

        if data is None:
            data = gef.strings.get(value) or None
            if data:
                data = repr(data)

        if data is None:
            data = gef.memory.poi(gef.types.pvoid, value)

            # Try to unpack the value as a string
            try:
                packed = gef.arch.pack(int(data))
                if all(c in string.printable.encode('utf-8') for c in packed):
                    data = repr(packed.decode())
            except:
                data = str(data)

    colored = gef.color.get(value)

    if data and name:   return "%s (%s: %s)" % (colored, name, data)
    elif name:          return "%s (%s)" % (colored, name)
    elif data:          return "%s (%s)" % (colored, data)

    return colored

