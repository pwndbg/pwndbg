import struct
import sys
import gdb
import pwndbg.memoize
import pwndbg.events
import pwndbg.types

current = None
ptrmask = 0xfffffffff
endian  = 'little'
ptrsize = pwndbg.types.ptrsize
fmt     = '=i'

@pwndbg.events.stop
def update():
    m = sys.modules[__name__]

    m.current = gdb.selected_frame().architecture().name()
    m.ptrsize = pwndbg.types.ptrsize
    m.ptrmask = (1 << 8*pwndbg.types.ptrsize)-1

    if 'little' in gdb.execute('show endian', to_string=True):
        m.endian = 'little'
    else:
        m.endian = 'big'

    m.fmt = {
    (4, 'little'): '<I',
    (4, 'big'):    '>I',
    (8, 'little'): '<Q',
    (8, 'big'):    '>Q',
    }.get((m.ptrsize, m.endian))


def pack(integer):
	return struct.pack(fmt, integer & ptrmask)

def unpack(data):
	return struct.unpack(fmt, data)[0]