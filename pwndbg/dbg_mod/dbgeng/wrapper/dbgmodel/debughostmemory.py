from ctypes import *
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ctypes import _Pointer

import comtypes.gen.DbgMod as DbgModel

from pwndbg.dbg.dbgeng.wrapper.dbgmodel.debughostcontext import DebugHostContext


class DebugHostMemory:
    def __init__(self, inner: "_Pointer[DbgModel.IDebugHostMemory]"):
        self.inner = inner

    def ReadBytes(self, context: DebugHostContext, location: DbgModel._Location, size: int) -> bytes:
        buffer = (c_ubyte * size)()
        bytes_read = c_ulonglong()
        self.inner.ReadBytes(context.inner, location, byref(buffer), size, byref(bytes_read))
        return bytes(buffer[:bytes_read.value])
