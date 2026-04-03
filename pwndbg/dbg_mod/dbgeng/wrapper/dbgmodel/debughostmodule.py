from ctypes import *
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ctypes import _Pointer

from comtypes import BSTR
import comtypes.gen.DbgMod as DbgModel

from pwndbg.dbg_mod.dbgeng.wrapper.dbgmodel.debughosttype import DebugHostType



class DebugHostModule:
    def __init__(self, inner: "_Pointer[DbgModel.IDebugHostModule]"):
        self.inner = inner
    
    def GetName(self) -> str:
        name = BSTR()
        self.inner.GetName(byref(name))
        return name.value
    
    def FindTypeByName(self, name: str) -> DebugHostType:
        buf = create_unicode_buffer(name)
        hostType = POINTER(DbgModel.IDebugHostType)()
        self.inner.FindTypeByName(cast(buf, POINTER(c_ushort)), byref(hostType))
        return DebugHostType(hostType)

    def GetBaseLocation(self) -> tuple[int, int]:
        location = DbgModel._Location()
        self.inner.GetBaseLocation(byref(location))
        return location.HostDefined, location.Offset
