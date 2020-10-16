#!/usr/bin/env python
# -*- coding: utf-8 -*-
import struct
import sys

import gdb
from capstone import *

import pwndbg.events
import pwndbg.memoize
import pwndbg.regs
import pwndbg.typeinfo

current = 'i386'
qemu    = current
ptrmask = 0xfffffffff
endian  = 'little'
ptrsize = pwndbg.typeinfo.ptrsize
fmt     = '=I'
native_endian = str(sys.byteorder)


def fix_arch(arch):
    for match in ['x86-64', 'i386', 'mips', 'powerpc', 'sparc', 'aarch64']:
        if match in arch:
            return match

    # Distinguish between Cortex-M and other ARM
    if 'arm' in arch:
        return 'armcm' if '-m' in arch else 'arm'

    return arch

@pwndbg.events.start
@pwndbg.events.stop
@pwndbg.events.new_objfile
def update():
    m = sys.modules[__name__]

    # GDB 7.7 (Ubuntu Trusty) does not like selected_frame() when EBP/RBP
    # is not mapped / pounts to an invalid address.
    #
    # As a work-around for Trusty users, handle the exception and bail.
    # This may lead to inaccurate results, but there's not much to be done.
    try:
        m.current = fix_arch(gdb.newest_frame().architecture().name())
    except Exception:
        return

    m.ptrsize = pwndbg.typeinfo.ptrsize
    m.ptrmask = (1 << 8*pwndbg.typeinfo.ptrsize)-1

    if 'little' in gdb.execute('show endian', to_string=True).lower():
        m.endian = 'little'
    else:
        m.endian = 'big'

    m.fmt = {
    (4, 'little'): '<I',
    (4, 'big'):    '>I',
    (8, 'little'): '<Q',
    (8, 'big'):    '>Q',
    }.get((m.ptrsize, m.endian))

    # Attempt to detect the qemu-user binary name
    if m.current == 'arm' and m.endian == 'big':
        m.qemu = 'armeb'
    elif m.current == 'mips' and m.endian == 'little':
        m.qemu = 'mipsel'
    else:
        m.qemu = m.current


def pack(integer):
    return struct.pack(fmt, integer & ptrmask)


def unpack(data):
    return struct.unpack(fmt, data)[0]


def signed(integer):
    return unpack(pack(integer), signed=True)


def unsigned(integer):
    return unpack(pack(integer))
