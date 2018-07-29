#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

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
    arches = ['x86-64', 'i386', 'mips', 'powerpc', 'sparc', 'arm', 'aarch64', arch]
    return next(a for a in arches if a in arch)


@pwndbg.events.start
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

    # Work around Python 2.7.6 struct.pack / unicode incompatibility
    # See https://github.com/pwndbg/pwndbg/pull/336 for more information.
    m.fmt = str(m.fmt)

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
