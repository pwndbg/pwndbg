from ctypes import *
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ctypes import _Pointer

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

    def GetExecutingProcessorType(self) -> int:
        processor_type = c_ulong()
        self.inner.GetExecutingProcessorType(byref(processor_type))
        return processor_type.value

    def IsPointer64Bit(self) -> bool:
        return self.inner.IsPointer64Bit() == hresult.S_OK
