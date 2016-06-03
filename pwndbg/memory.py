#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Reading, writing, and describing memory.
"""
from __future__ import print_function
import gdb
import pwndbg.arch
import pwndbg.compat
import pwndbg.typeinfo
import traceback

PAGE_SIZE = 0x1000
PAGE_MASK = ~(PAGE_SIZE-1)
MMAP_MIN_ADDR = 0x8000

def read(addr, count, partial=False):
    result = b''

    try:
        result = gdb.selected_inferior().read_memory(addr, count)
    except gdb.error as e:
        if not partial:
            raise

        if not hasattr(e, 'message'):
            e.message=str(e)

        stop_addr = int(e.message.split()[-1], 0)
        if stop_addr != addr:
            return read(addr, stop_addr-addr)

        # QEMU will return the start address as the failed
        # read address.  Try moving back a few pages at a time.
        stop_addr = addr + count

        # Move the stop address down to the previous page boundary
        stop_addr &= PAGE_MASK
        while stop_addr > addr:
            result = read(addr, stop_addr-addr)

            if result:
                return result

            # Move down by another page
            stop_addr -= PAGE_SIZE

    # if pwndbg.compat.python3:
        # result = bytes(result)

    return bytearray(result)

def readtype(gdb_type, addr):
    return int(gdb.Value(addr).cast(gdb_type.pointer()).dereference())

def write(addr, data):
    gdb.selected_inferior().write_memory(addr, data)

def peek(address):
    try:    return read(address, 1)
    except: pass
    return None

def poke(address):
    c = peek(address)
    if c is None: return False
    try:    write(address, c)
    except: return False
    return True

def string(addr):
    data = bytearray()
    while peek(addr):
        byte = read(addr, 1)
        if byte == b'\x00':
            break
        data += byte
        addr += 1
    return data

def byte(addr):   return readtype(pwndbg.typeinfo.uchar, addr)
def uchar(addr):  return readtype(pwndbg.typeinfo.uchar, addr)
def ushort(addr): return readtype(pwndbg.typeinfo.ushort, addr)
def uint(addr):   return readtype(pwndbg.typeinfo.uint, addr)
def pvoid(addr):  return readtype(pwndbg.typeinfo.pvoid, addr)

def u8(addr): return readtype(pwndbg.typeinfo.uint8, addr)
def u16(addr): return readtype(pwndbg.typeinfo.uint16, addr)
def u32(addr): return readtype(pwndbg.typeinfo.uint32, addr)
def u64(addr): return readtype(pwndbg.typeinfo.uint64, addr)

def u(addr, size=None):
    if size is None:
        size = pwndbg.arch.ptrsize * 8
    return {
        8: u8,
        16: u16,
        32: u32,
        64: u64
    }[size](addr)

def s8(addr): return readtype(pwndbg.typeinfo.int8, addr)
def s16(addr): return readtype(pwndbg.typeinfo.int16, addr)
def s32(addr): return readtype(pwndbg.typeinfo.int32, addr)
def s64(addr): return readtype(pwndbg.typeinfo.int64, addr)

def write(addr, data):
    gdb.selected_inferior().write_memory(addr, data)

def poi(type, addr): return gdb.Value(addr).cast(type.pointer()).dereference()

def round_down(address, align):
    return address & ~(align-1)
def round_up(address, align):   return (address+(align-1))&(~(align-1))

align_down = round_down
align_up   = round_up

def page_align(address): return round_down(address, PAGE_SIZE)
def page_size_align(address): return round_up(address, PAGE_SIZE)
def page_offset(address): return (address & (PAGE_SIZE-1))

assert round_down(0xdeadbeef, 0x1000) == 0xdeadb000
assert round_up(0xdeadbeef, 0x1000)   == 0xdeadc000

def find_upper_boundary(addr, max_pages=1024):
    addr = pwndbg.memory.page_align(int(addr))
    try:
        for i in range(max_pages):
            pwndbg.memory.read(addr, 1)
            # import sys
            # sys.stdout.write(hex(addr) + '\n')
            addr += pwndbg.memory.PAGE_SIZE
    except gdb.MemoryError:
        pass
    return addr

def find_lower_boundary(addr, max_pages=1024):
    addr = pwndbg.memory.page_align(int(addr))
    try:
        for i in range(max_pages):
            pwndbg.memory.read(addr, 1)
            addr -= pwndbg.memory.PAGE_SIZE
    except gdb.MemoryError:
        pass
    return addr

class Page(object):
    """
    Represents the address space and page permissions of at least
    one page of memory.
    """
    vaddr   = 0 #: Starting virtual address
    memsz   = 0 #: Size of the address space, in bytes
    flags   = 0 #: Flags set by the ELF file, see PF_X, PF_R, PF_W
    offset  = 0 #: Offset into the original ELF file that the data is loaded from
    objfile = '' #: Path to the ELF on disk
    def __init__(self, start, size, flags, offset, objfile=''):
        self.vaddr  = start
        self.memsz  = size
        self.flags  = flags
        self.offset = offset
        self.objfile = objfile

        # if self.rwx:
            # self.flags = self.flags ^ 1
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
        width = 2 + 2*pwndbg.typeinfo.ptrsize
        fmt_string = "%#{}x %#{}x %s %8x %-6x %s"
        fmt_string = fmt_string.format(width, width)
        return fmt_string % (self.vaddr,
                             self.vaddr+self.memsz,
                             self.permstr,
                             self.memsz,
                             self.offset,
                             self.objfile or '')
    def __repr__(self):
        return "%s(%r)" % (self.__class__.__name__, self.__str__())
    def __contains__(self, a):
        return self.vaddr <= a < (self.vaddr + self.memsz)
    def __eq__(self, other):
        return self.vaddr == getattr(other, 'vaddr', other)
    def __lt__(self, other):
        return self.vaddr < getattr(other, 'vaddr', other)
    def __hash__(self):
        return hash((self.vaddr, self.memsz, self.flags, self.offset, self.objfile))
