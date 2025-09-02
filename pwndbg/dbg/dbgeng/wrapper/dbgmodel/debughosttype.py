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
