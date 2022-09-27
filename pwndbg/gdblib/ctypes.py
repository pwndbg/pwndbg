"""On-the-fly endianness switching for ctypes structures.

We cannot make use of ctypes.LittleEndianStructure and ctypes.BigEndianStructure,
since these use metaclass hooks to catch _fields_ being **set** when the class
is declared.

We need to catch on the fly.  We do this by swapping out the base classes of the
Structure type, and incurring a performance penalty for foreign-endianness targets.
"""

import ctypes
import sys

import pwndbg.gdblib.arch
import pwndbg.gdblib.events

module = sys.modules[__name__]
Structure = ctypes.LittleEndianStructure  # default Structure type


@pwndbg.gdblib.events.start
@pwndbg.gdblib.events.new_objfile
def update():
    global module

    if pwndbg.gdblib.arch.endian == "little":
        Structure = ctypes.LittleEndianStructure
    else:
        Structure = ctypes.BigEndianStructure

    module.__dict__.update(locals())


update()
