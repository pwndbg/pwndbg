from ctypes import *
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ctypes import _Pointer

from comtypes import COMError
import comtypes.gen.DbgMod as DbgModel
import comtypes.hresult as hresult

from pwndbg.dbg.dbgeng.wrapper.dbgmodel.debughostsymbols import DebugHostSymbols


class DebugHost:
    def __init__(self, inner: "_Pointer[DbgModel.IDebugHost]"):
        self.inner = inner
    
    def DebugHostSymbols(self) -> DebugHostSymbols:
        symbols = self.inner.QueryInterface(DbgModel.IDebugHostSymbols)
        return DebugHostSymbols(symbols)
