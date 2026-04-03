from ctypes import *
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ctypes import _Pointer

import comtypes.gen.DbgMod as DbgModel

from pwndbg.dbg_mod.dbgeng.wrapper.dbgmodel.debughostsymbols import DebugHostSymbols
from pwndbg.dbg_mod.dbgeng.wrapper.dbgmodel.debughostevaluator import DebugHostEvaluator
from pwndbg.dbg_mod.dbgeng.wrapper.dbgmodel.debughostcontext import DebugHostContext
from pwndbg.dbg_mod.dbgeng.wrapper.dbgmodel.debughostmemory import DebugHostMemory


class DebugHost:
    def __init__(self, inner: "_Pointer[DbgModel.IDebugHost]"):
        self.inner = inner
    
    def DebugHostSymbols(self) -> DebugHostSymbols:
        symbols = self.inner.QueryInterface(DbgModel.IDebugHostSymbols)
        return DebugHostSymbols(symbols)

    def DebugHostEvaluator(self) -> DebugHostEvaluator:
        evaluator = self.inner.QueryInterface(DbgModel.IDebugHostEvaluator)
        return DebugHostEvaluator(evaluator)

    def DebugHostMemory(self) -> DebugHostMemory:
        memory = self.inner.QueryInterface(DbgModel.IDebugHostMemory)
        return DebugHostMemory(memory)

    def GetCurrentContext(self) -> DebugHostContext:
        context = POINTER(DbgModel.IDebugHostContext)()
        self.inner.GetCurrentContext(byref(context))
        return DebugHostContext(context)
