#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
import collections
import struct
import sys

import gdb
import pwndbg.events
import pwndbg.memoize
import pwndbg.regs
import pwndbg.typeinfo

from capstone import *

current = 'i386'
qemu    = current
ptrmask = 0xfffffffff
endian  = 'little'
ptrsize = pwndbg.typeinfo.ptrsize
fmt     = '=I'

def fix_arch(arch):
    arches = ['x86-64', 'i386', 'mips', 'powerpc', 'sparc', 'arm', 'aarch64', arch]
    return next(a for a in arches if a in arch)

@pwndbg.events.start
@pwndbg.events.stop
def update():
    m = sys.modules[__name__]

    m.current = fix_arch(gdb.selected_frame().architecture().name())
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

