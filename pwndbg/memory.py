#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Reading, writing, and describing memory.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import os
import traceback

import gdb

import pwndbg.arch
import pwndbg.compat
import pwndbg.events
import pwndbg.qemu
import pwndbg.typeinfo

PAGE_SIZE = 0x1000
PAGE_MASK = ~(PAGE_SIZE-1)
MMAP_MIN_ADDR = 0x8000

def read(addr, count, partial=False):
    """read(addr, count, partial=False) -> bytearray

    Read memory from the program being debugged.

    Arguments:
        addr(int): Address to read
        count(int): Number of bytes to read
        partial(bool): Whether less than ``count`` bytes can be returned

    Returns:
        :class:`bytearray`: The memory at the specified address,
        or ``None``.
    """
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
    """readtype(gdb_type, addr) -> int

    Reads an integer-type (e.g. ``uint64``) and returns a Python
    native integer representation of the same.

    Arguments:
        gdb_type(gdb.Type): GDB type to read
        addr(int): Address at which the value to be read resides

    Returns:
        :class:`int`
    """
    return int(gdb.Value(addr).cast(gdb_type.pointer()).dereference())

def write(addr, data):
    """write(addr, data)

    Writes data into the memory of the process being debugged.

    Arguments:
        addr(int): Address to write
        data(str,bytes,bytearray): Data to write
    """
    gdb.selected_inferior().write_memory(addr, data)

def peek(address):
    """peek(address) -> str

    Read one byte from the specified address.

    Arguments:
        address(int): Address to read

    Returns:
        :class:`str`: A single byte of data, or ``None`` if the
        address cannot be read.
    """
    try:    return read(address, 1)
    except: pass
    return None

def poke(address):
    """poke(address)

    Checks whether an address is writable.

    Arguments:
        address(int): Address to check

    Returns:
        :class:`bool`: Whether the address is writable.
    """
    c = peek(address)
    if c is None: return False
    try:    write(address, c)
    except: return False
    return True

def string(addr, max=4096):
    """Reads a null-terminated string from memory.

    Arguments:
        addr(int): Address to read from
        max(int): Maximum string length (default 4096)

    Returns:
        An empty bytearray, or a NULL-terminated bytearray.
    """
    if peek(addr):
        data = bytearray(read(addr, max, partial=True))

        if b'\x00' in data:
            return data.split(b'\x00')[0]

    return bytearray()

def byte(addr):
    """byte(addr) -> int

    Read one byte at the specified address
    """
    return readtype(pwndbg.typeinfo.uchar, addr)

def uchar(addr):
    """uchar(addr) -> int

    Read one ``unsigned char`` at the specified address.
    """
    return readtype(pwndbg.typeinfo.uchar, addr)

def ushort(addr):
    """ushort(addr) -> int

    Read one ``unisgned short`` at the specified address.
    """
    return readtype(pwndbg.typeinfo.ushort, addr)

def uint(addr):
    """uint(addr) -> int

    Read one ``unsigned int`` at the specified address.
    """
    return readtype(pwndbg.typeinfo.uint, addr)

def pvoid(addr):
    """pvoid(addr) -> int

    Read one pointer from the specified address.
    """
    return readtype(pwndbg.typeinfo.pvoid, addr)

def u8(addr):
    """u8(addr) -> int

    Read one ``uint8_t`` from the specified address.
    """
    return readtype(pwndbg.typeinfo.uint8, addr)

def u16(addr):
    """u16(addr) -> int

    Read one ``uint16_t`` from the specified address.
    """
    return readtype(pwndbg.typeinfo.uint16, addr)

def u32(addr):
    """u32(addr) -> int

    Read one ``uint32_t`` from the specified address.
    """
    return readtype(pwndbg.typeinfo.uint32, addr)

def u64(addr):
    """u64(addr) -> int

    Read one ``uint64_t`` from the specified address.
    """
    return readtype(pwndbg.typeinfo.uint64, addr)

def u(addr, size=None):
    """u(addr, size=None) -> int

    Read one ``unsigned`` integer from the specified address,
    with the bit-width specified by ``size``, which defaults
    to the pointer width.
    """
    if size is None:
        size = pwndbg.arch.ptrsize * 8
    return {
        8: u8,
        16: u16,
        32: u32,
        64: u64
    }[size](addr)

def s8(addr):
    """s8(addr) -> int

    Read one ``int8_t`` from the specified address
    """
    return readtype(pwndbg.typeinfo.int8, addr)

def s16(addr):
    """s16(addr) -> int

    Read one ``int16_t`` from the specified address.
    """
    return readtype(pwndbg.typeinfo.int16, addr)

def s32(addr):
    """s32(addr) -> int

    Read one ``int32_t`` from the specified address.
    """
    return readtype(pwndbg.typeinfo.int32, addr)
def s64(addr):
    """s64(addr) -> int

    Read one ``int64_t`` from the specified address.
    """
    return readtype(pwndbg.typeinfo.int64, addr)

def poi(type, addr):
    """poi(addr) -> gdb.Value

    Read one ``gdb.Type`` object at the specified address.
    """
    return gdb.Value(addr).cast(type.pointer()).dereference()

def round_down(address, align):
    """round_down(address, align) -> int

    Round down ``address`` to the nearest increment of ``align``.
    """
    return address & ~(align-1)

def round_up(address, align):
    """round_up(address, align) -> int

    Round up ``address`` to the nearest increment of ``align``.
    """
    return (address+(align-1))&(~(align-1))

align_down = round_down
align_up   = round_up

def page_align(address):
    """page_align(address) -> int

    Round down ``address`` to the nearest page boundary.
    """
    return round_down(address, PAGE_SIZE)

def page_size_align(address): return round_up(address, PAGE_SIZE)
def page_offset(address): return (address & (PAGE_SIZE-1))

assert round_down(0xdeadbeef, 0x1000) == 0xdeadb000
assert round_up(0xdeadbeef, 0x1000)   == 0xdeadc000

def find_upper_boundary(addr, max_pages=1024):
    """find_upper_boundary(addr, max_pages=1024) -> int

    Brute-force search the upper boundary of a memory mapping,
    by reading the first byte of each page, until an unmapped
    page is found.
    """
    addr = pwndbg.memory.page_align(int(addr))
    try:
        for i in range(max_pages):
            pwndbg.memory.read(addr, 1)
            # import sys
            # sys.stdout.write(hex(addr) + '\n')
            addr += pwndbg.memory.PAGE_SIZE
            if addr > pwndbg.arch.ptrmask:
                break
    except gdb.MemoryError:
        pass
    return addr

def find_lower_boundary(addr, max_pages=1024):
    """find_lower_boundary(addr, max_pages=1024) -> int

    Brute-force search the lower boundary of a memory mapping,
    by reading the first byte of each page, until an unmapped
    page is found.
    """
    addr = pwndbg.memory.page_align(int(addr))
    try:
        for i in range(max_pages):
            pwndbg.memory.read(addr, 1)
            addr -= pwndbg.memory.PAGE_SIZE
            if addr < 0:
                break
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
        return ''.join(['r' if flags & os.R_OK else '-',
                        'w' if flags & os.W_OK else '-',
                        'x' if flags & os.X_OK else '-',
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

@pwndbg.events.start
def update_min_addr():
    global MMAP_MIN_ADDR
    if pwndbg.qemu.is_qemu_kernel():
        MMAP_MIN_ADDR=0
