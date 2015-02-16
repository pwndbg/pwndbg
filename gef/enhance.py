import gdb
import gef.symbol
import gef.memory
import gef.color
import gef.types
import gef.string
import gef.disasm
import gef.memoize

@gef.memoize.reset_on_stop
def enhance(value):
    value = int(value)

    name = gef.symbol.get(value) or None
    page = gef.vmmap.find(value)

    # If it's not in a page we know about, try to dereference
    # it anyway just to test.
    can_read = True
    if not page and None == gef.memory.poke(value):
        can_read = False

    if not can_read:
        return hex(int(value))

    # It's mapped memory, or we can at least read it.
    # Try to find out if it's a string.
    data = None
    if page and page.execute:
        data = gef.disasm.get(value, 1)[0].asm

    if data is None:
        data = gef.string.get(value)
        if data:
            data = repr(data)

    if data is None and isinstance(data, int):
        data = hex(data)

    colored = gef.color.get(value)

    if data and name:   return "%s <%s: %s>" % (colored, name, data)
    elif name:          return "%s <%s>" % (colored, name)
    elif data:          return "%s <%s>" % (colored, data)

    return colored

