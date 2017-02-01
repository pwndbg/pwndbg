"""On-the-fly endianness switching for ctypes structures.

We cannot make use of ctypes.LittleEndianStructure and ctypes.BigEndianStructure,
since these use metaclass hooks to catch _fields_ being **set** when the class
is declared.

We need to catch on the fly.  We do this by swapping out the base classes of the
Structure type, and incurring a performance penalty for foreign-endianness targets.
"""
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import ctypes
import struct

import six

import pwndbg.arch
import pwndbg.events
import pwndbg.memory

endian = {'big': '>', 'little': '<'}

def getattribute(self, attrname):
    value = super(EndianAwareStructure, self).__getattribute__(attrname)

    if pwndbg.arch.endian == pwndbg.arch.native_endian:
        return value

    if attrname == '_fields_':
        return value

    for field in self._fields_:
        name = field[0]
        typ = field[1]

        if name != attrname:
            continue

        if isinstance(typ._type_, six.string_types):
            fmt_orig = typ._type_
            fmt_endian = endian[pwndbg.arch.endian] + fmt_orig
            value = struct.pack(fmt_orig, value)
            value = struct.unpack(fmt_endian, value)[0]

    return value


class EndianAwareStructure(ctypes.Structure):
    def __getattribute__(self, attrname):
        return getattribute(self, attrname)

class EndianAwareUnion(ctypes.Union):
    def __getattribute__(self, attrname):
        return getattribute(self, attrname)

Union = EndianAwareUnion
Structure = EndianAwareStructure
