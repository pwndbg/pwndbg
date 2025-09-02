from ctypes import *
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ctypes import _Pointer

from comtypes import COMError
import comtypes.gen.DbgEng as DbgEng
import comtypes.hresult as hresult


class DebugControl:
    def __init__(self, inner: "_Pointer[DbgEng.IDebugControl]"):
        self.inner = inner

    def GetDebuggeeType(self) -> tuple[int, int]:
        debuggee_class = c_ulong()
        debuggee_qualifier = c_ulong()
        self.inner.GetDebuggeeType(byref(debuggee_class), byref(debuggee_qualifier))
        return debuggee_class.value, debuggee_qualifier.value
