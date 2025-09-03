from ctypes import *
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ctypes import _Pointer

import comtypes.gen.DbgMod as DbgModel

from pwndbg.dbg.dbgeng.wrapper.dbgmodel.debughostcontext import DebugHostContext
from pwndbg.dbg.dbgeng.wrapper.dbgmodel.modelobject import ModelObject
from pwndbg.dbg.dbgeng.wrapper.dbgmodel.keystore import KeyStore


class DebugHostEvaluator:
    def __init__(self, inner: "_Pointer[DbgModel.IDebugHostEvaluator]"):
        self.inner = inner
    
    def EvaluateExpression(self, context: DebugHostContext, expression: str,
                           binding_context: ModelObject) -> tuple[ModelObject, KeyStore]:
        result = POINTER(DbgModel.IModelObject)()
        metadata = POINTER(DbgModel.IKeyStore)()
        buffer = create_unicode_buffer(expression)
        self.inner.EvaluateExpression(
            context.inner,
            cast(buffer, POINTER(c_ushort)),
            binding_context.inner,
            byref(result),
            byref(metadata)
        )
        return ModelObject(result), KeyStore(metadata)
