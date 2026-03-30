from ctypes import *
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ctypes import _Pointer

import comtypes.gen.DbgMod as DbgModel

from pwndbg.dbg.dbgeng.wrapper.dbgmodel.debughostmodule import DebugHostModule


class DebugHostSymbol:
    def __init__(self, inner: "_Pointer[DbgModel.IDebugHostSymbol]"):
        self.inner = inner
    
    def DebugHostModule(self) -> DebugHostModule:
        module = self.inner.QueryInterface(DbgModel.IDebugHostModule)
        return DebugHostModule(module)
