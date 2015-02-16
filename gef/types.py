import sys
import gdb

import gef.events
import gef.memoize

module = sys.modules[__name__]

@gef.events.new_objfile
@gef.memoize.reset_on_exit
def update():
    module.char   = gdb.lookup_type('char')
    module.ulong  = gdb.lookup_type('unsigned long')
    module.uchar  = gdb.lookup_type('unsigned char')
    module.ushort = gdb.lookup_type('unsigned short')
    module.uint   = gdb.lookup_type('unsigned int')
    module.void   = gdb.lookup_type('void')
    module.uint8  = gdb.lookup_type('unsigned char')
    module.uint16 = gdb.lookup_type('unsigned short')
    module.uint32 = gdb.lookup_type('unsigned int')
    module.uint64 = gdb.lookup_type('unsigned long long')

    module.int8   = gdb.lookup_type('char')
    module.int16  = gdb.lookup_type('short')
    module.int32  = gdb.lookup_type('int')
    module.int64  = gdb.lookup_type('long long')

    module.pvoid  = void.pointer()
    module.ppvoid = pvoid.pointer()
    module.pchar  = char.pointer()

    module.ptrsize = pvoid.sizeof

# Call it once so we load all of the types
update()

# Reset the cache so that the first load isn't cached.
update.clear()