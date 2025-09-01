from ctypes import *

from comtypes import COMError
import comtypes.gen.DbgEng as DbgEng
import comtypes.hresult as hresult


class DebugSymbols:
    def __init__(self, inner: DbgEng.IDebugSymbols):
        self.inner = inner
    
    def GetTypeSize(self, module: int, type_id: int) -> int:
        size = c_ulong()
        self.inner.GetTypeSize(module, type_id, byref(size))
        return size.value
    
    def GetSymbolTypeId(self, symbol: str) -> tuple[int, int]:
        type_id = c_ulong()
        module = c_ulonglong()
        self.inner.GetSymbolTypeId(create_string_buffer(symbol.encode()), byref(type_id), byref(module))
        return type_id.value, module.value
