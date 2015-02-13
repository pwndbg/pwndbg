import sys
import gdb

module = sys.modules[__name__]

def update(*a):
    print("Updating type info")
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
    module.pchar  = char.pointer()

def ptrsize(): return pvoid.sizeof()
def cont(a):   print(a, "cont", gdb.lookup_type("char").pointer().sizeof)
def exit2(a):  print(a, "exit", gdb.lookup_type("char").pointer().sizeof)
def stop(a):   print(a, "stop", gdb.lookup_type("char").pointer().sizeof)
def new_objfile(a): print(a, "new_objfile", gdb.lookup_type("char").pointer().sizeof)

gdb.events.cont.connect(update)
gdb.events.exited.connect(update)
gdb.events.new_objfile.connect(update)
gdb.events.stop.connect(update)
