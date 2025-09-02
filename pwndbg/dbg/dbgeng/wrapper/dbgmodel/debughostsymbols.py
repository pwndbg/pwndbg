from ctypes import *
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from ctypes import _Pointer

from comtypes import COMError
import comtypes.gen.DbgMod as DbgModel
import comtypes.hresult as hresult

from pwndbg.dbg.dbgeng.wrapper.dbgmodel.debughostsymbol import DebugHostSymbol
from pwndbg.dbg.dbgeng.wrapper.dbgmodel.debughostcontext import DebugHostContext, USE_CURRENT_HOST_CONTEXT
from pwndbg.dbg.dbgeng.wrapper.dbgmodel.constants import *


class DebugHostSymbolEnumerator:
    def __init__(self, inner: "_Pointer[DbgModel.IDebugHostSymbolEnumerator]"):
        self.inner = inner
    
    def GetNext(self) -> Optional[DebugHostSymbol]:
        symbol = POINTER(DbgModel.IDebugHostSymbol)()
        try:
            self.inner.GetNext(byref(symbol))
            return DebugHostSymbol(symbol)
        except COMError as e:
            if e.hresult == E_BOUNDS:
                return None
            raise


class DebugHostSymbols:
    def __init__(self, inner: "_Pointer[DbgModel.IDebugHostSymbols]"):
        self.inner = inner
    
    def EnumerateModules(self, context: DebugHostContext = USE_CURRENT_HOST_CONTEXT
                         )-> DebugHostSymbolEnumerator:
        enumerator = POINTER(DbgModel.IDebugHostSymbolEnumerator)()
        self.inner.EnumerateModules(context.inner, byref(enumerator))
        return DebugHostSymbolEnumerator(enumerator)
