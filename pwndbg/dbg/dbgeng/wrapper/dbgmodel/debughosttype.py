from ctypes import *
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ctypes import _Pointer

from comtypes import COMError, BSTR
import comtypes.gen.DbgMod as DbgModel
import comtypes.hresult as hresult


class DebugHostType:
    def __init__(self, inner: "_Pointer[DbgModel.IDebugHostType]"):
        self.inner = inner
    
    def GetName(self) -> str:
        name = BSTR()
        self.inner.GetName(byref(name))
        return name.value
    
    def GetSize(self) -> int:
        size = c_ulonglong()
        self.inner.GetSize(byref(size))
        return size.value

    def CreatePointerTo(self, kind: int) -> "DebugHostType":
        new_type = POINTER(DbgModel.IDebugHostType)()
        self.inner.CreatePointerTo(kind, byref(new_type))
        return DebugHostType(new_type)
