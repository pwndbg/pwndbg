#!/usr/bin/env python
# -*- coding: utf-8 -*-
import struct
import sys

import gdb
from capstone import *

import pwndbg.events
import pwndbg.regs
import pwndbg.typeinfo

current = 'i386'
qemu    = current
ptrmask = 0xfffffffff
endian  = 'little'
ptrsize = pwndbg.typeinfo.ptrsize
fmt     = '=I'
native_endian = str(sys.byteorder)


def _get_arch():
    not_exactly_arch = False

    if pwndbg.proc.alive:
        arch = gdb.newest_frame().architecture().name()
    else:
        arch = gdb.execute("show architecture", to_string=True).strip()
        not_exactly_arch = True

    # Below, we fix the fetched architecture
    for match in ('x86-64', 'i386', 'aarch64', 'mips', 'powerpc', 'sparc'):
        if match in arch:
            return match

    # Distinguish between Cortex-M and other ARM
    if 'arm' in arch:
        return 'armcm' if '-m' in arch else 'arm'

    if not_exactly_arch:
        raise RuntimeError("Could not deduce architecture from: %s" % arch)

    return arch



@pwndbg.events.start
@pwndbg.events.stop
@pwndbg.events.new_objfile
def update():
    m = sys.modules[__name__]

    m.current = _get_arch()
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
