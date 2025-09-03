from ctypes import *
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from ctypes import _Pointer

from comtypes import COMError
import comtypes.gen.DbgEng as DbgEng
import comtypes.hresult as hresult


class DebugDataSpaces:
    def __init__(self, inner: "_Pointer[DbgEng.IDebugDataSpaces2]"):
        self.inner = inner

    def QueryVirtual(self, offset: int) -> Optional[DbgEng._MEMORY_BASIC_INFORMATION64]:
        info = DbgEng._MEMORY_BASIC_INFORMATION64()
        try:
            self.inner.QueryVirtual(offset, byref(info))
        except COMError as e:
            if e.hresult == hresult.E_NOINTERFACE:
                return None
        return info
