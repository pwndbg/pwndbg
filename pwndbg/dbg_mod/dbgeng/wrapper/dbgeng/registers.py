from __future__ import annotations

from ctypes import *
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ctypes import _Pointer

import comtypes.gen.DbgEng as DbgEng


class DebugRegisters:
    def __init__(self, inner: "_Pointer[DbgEng.IDebugRegisters]"):
        self.inner = inner
    
    def GetIndexByName(self, name: str) -> int:
        index = c_ulong()
        self.inner.GetIndexByName(name, byref(index))
        return index.value

    def GetValue(self, register: int) -> DbgEng._DEBUG_VALUE:
        value = DbgEng._DEBUG_VALUE()
        self.inner.GetValue(register, byref(value))
        return value
