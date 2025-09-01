from ctypes import *

from comtypes import COMError
import comtypes.gen.DbgEng as DbgEng
import comtypes.hresult as hresult


class DebugRegisters:
    def __init__(self, inner: DbgEng.IDebugRegisters):
        self.inner = inner
    
    def GetIndexByName(self, name: str) -> int:
        index = c_ulong()
        self.inner.GetIndexByName(name, byref(index))
        return index.value

    def GetValue(self, register: int) -> DbgEng._DEBUG_VALUE:
        value = DbgEng._DEBUG_VALUE()
        self.inner.GetValue(register, byref(value))
        return value
