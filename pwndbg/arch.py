#!/usr/bin/env python
# -*- coding: utf-8 -*-
import collections
import struct
import sys

import gdb
import pwndbg.events
import pwndbg.memoize
import pwndbg.memory
import pwndbg.regs
import pwndbg.typeinfo

from capstone import *

current = 'i386'
ptrmask = 0xfffffffff
endian  = 'little'
ptrsize = pwndbg.typeinfo.ptrsize
fmt     = '=i'

def fix_arch(arch):
    arches = ['x86-64', 'i386', 'mips', 'powerpc', 'sparc', 'arm', 'aarch64', arch]
    return next(a for a in arches if a in arch)

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

def pack(integer):
	return struct.pack(fmt, integer & ptrmask)

def unpack(data):
	return struct.unpack(fmt, data)[0]

def signed(integer):
    return unpack(pack(integer), signed=True)

def unsigned(integer):
    return unpack(pack(integer))

