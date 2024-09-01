"""On-the-fly endianness switching for ctypes structures.

We cannot make use of ctypes.LittleEndianStructure and ctypes.BigEndianStructure,
since these use metaclass hooks to catch _fields_ being **set** when the class
is declared.

We need to catch on the fly.  We do this by swapping out the base classes of the
Structure type, and incurring a performance penalty for foreign-endianness targets.
"""

from __future__ import annotations

import ctypes
import sys

import pwndbg
import pwndbg.aglib.arch
from pwndbg.dbg import EventType

module = sys.modules[__name__]
Structure = ctypes.LittleEndianStructure  # default Structure type


@pwndbg.dbg.event_handler(EventType.START)
@pwndbg.dbg.event_handler(EventType.NEW_MODULE)
def update() -> None:
    global Structure
    if pwndbg.aglib.arch.endian == "little":
        Structure = ctypes.LittleEndianStructure
    else:
        Structure = ctypes.BigEndianStructure

    module.__dict__.update(locals())
