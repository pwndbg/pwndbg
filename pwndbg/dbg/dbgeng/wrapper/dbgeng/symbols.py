from ctypes import *
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ctypes import _Pointer

import comtypes.gen.DbgEng as DbgEng


class DebugSymbols:
    def __init__(self, inner: "_Pointer[DbgEng.IDebugSymbols]"):
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
