import struct
import sys
import gdb
import pwndbg.memoize
import pwndbg.events
import pwndbg.typeinfo

current = None
ptrmask = 0xfffffffff
endian  = 'little'
ptrsize = pwndbg.typeinfo.ptrsize
fmt     = '=i'
disasm  = lambda: None

@pwndbg.events.stop
def update():
    m = sys.modules[__name__]

    m.current = gdb.selected_frame().architecture().name()
    m.ptrsize = pwndbg.typeinfo.ptrsize
    m.ptrmask = (1 << 8*pwndbg.typeinfo.ptrsize)-1

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

    m.disasm = gdb.selected_frame().architecture().disassemble


def pack(integer):
	return struct.pack(fmt, integer & ptrmask)

def unpack(data):
	return struct.unpack(fmt, data)[0]