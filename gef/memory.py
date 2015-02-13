#!/usr/bin/env python
# -*- coding: utf-8 -*-
import gdb
import gef.compat
import gef.types

PAGE_SIZE = 0x1000

def read(addr, count):
    result = gdb.selected_inferior().read_memory(addr, count)

    if gef.compat.python3:
        result = result.tobytes()

    return bytearray(result)

def readtype(gdb_type, addr):
    return int(gdb.Value(addr).cast(gdb_type.pointer()).dereference())

def byte(addr):   return readtype(gef.types.uchar, addr)
def uchar(addr):  return readtype(gef.types.uchar, addr)
def ushort(addr): return readtype(gef.types.ushort, addr)
def uint(addr):   return readtype(gef.types.uint, addr)

def u8(addr): return readtype(gef.types.uint8_t, addr)
def u16(addr): return readtype(gef.types.uint16_t, addr)
def u32(addr): return readtype(gef.types.uint32_t, addr)
def u64(addr): return readtype(gef.types.uint64_t, addr)

def s8(addr): return readtype(gef.types.int8_t, addr)
def s16(addr): return readtype(gef.types.int16_t, addr)
def s32(addr): return readtype(gef.types.int32_t, addr)
def s64(addr): return readtype(gef.types.int64_t, addr)

def write(addr, data):
    gdb.selected_inferior().write_memory(addr, data)

def poi(type, addr): return gdb.Value(addr).cast(type.pointer()).dereference()

def round_down(address, align): return address & ~(align-1)
def round_up(address, align):   return (address+(align-1))&(~(align-1))

align_down = round_down
align_up   = round_up

def page_align(address): return round_down(address, PAGE_SIZE)
def page_size_align(address): return round_up(address, PAGE_SIZE)
def page_offset(address): return (address & (PAGE_SIZE-1))

assert round_down(0xdeadbeef, 0x1000) == 0xdeadb000
assert round_up(0xdeadbeef, 0x1000)   == 0xdeadc000

def cont(a): print(a, "cont", gdb.lookup_type("char").pointer().sizeof)
def exit2(a): print(a, "exit", gdb.lookup_type("char").pointer().sizeof)
def stop(a): print(a, "stop", gdb.lookup_type("char").pointer().sizeof)
def new_objfile(a): print(a, "new_objfile", gdb.lookup_type("char").pointer().sizeof)

gdb.events.cont.connect(cont)
gdb.events.exited.connect(exit2)
gdb.events.new_objfile.connect(new_objfile)
gdb.events.stop.connect(stop)


class Page(object):
    """
    Represents the address space and page permissions of at least
    one page of memory.
    """
    vaddr   = 0 #: Starting virtual address
    memsz   = 0 #: Size of the address space, in bytes
    flags   = 0 #: Flags set by the ELF file, see PF_X, PF_R, PF_W
    offset  = 0 #: Offset into the original ELF file that the data is loaded from
    objfile = None #: Path to the ELF on disk
    def __init__(self, start, size, flags, offset):
        self.vaddr  = start
        self.memsz  = size
        self.flags  = flags
        self.offset = offset
    @property
    def read(self):
        return bool(self.flags & 4)
    @property
    def write(self):
        return bool(self.flags & 2)
    @property
    def execute(self):
        return bool(self.flags & 1)
    @property
    def rw(self):
        return self.read and self.write
    @property
    def rwx(self):
        return self.read and self.write and self.execute
    @property
    def permstr(self):
        flags = self.flags
        return ''.join(['r' if flags & 4 else '-',
                        'w' if flags & 2 else '-',
                        'x' if flags & 1 else '-',
                        'p'])
    def __str__(self):
        return "%x-%x %s x %-8x %-8x %s" % (self.vaddr,
                                     self.vaddr+self.memsz,
                                     self.permstr,
                                     self.memsz,
                                     self.offset,
                                     self.objfile or '')
    def __repr__(self):
        return "%s(%r)" % (self.__class__.__name__, self.__str__())
    def __contains__(self, a):
        return self.vaddr-1 < a < (self.vaddr + self.memsz)
    def __eq__(self, other):
        return self.vaddr == getattr(other, 'vaddr', other)
    def __lt__(self, other):
        return self.vaddr < getattr(other, 'vaddr', other)