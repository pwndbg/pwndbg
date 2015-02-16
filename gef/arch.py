import gdb
import gef.memoize
import gef.events
import gef.types

current = None
ptrmask = 0xfffffffff

@gef.events.stop
def update():
    global current
    global ptrmask
    current = gdb.selected_frame().architecture().name()
    ptrmask = (1 << 8*gef.types.ptrsize)-1